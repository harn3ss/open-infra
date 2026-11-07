package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The separation-of-duties gate on grant approval (AC-5). Only a distinct, authenticated approver of a
// not-yet-approved grant may proceed; every other case is refused with a specific status.
func TestApprovalDecision(t *testing.T) {
	cases := []struct {
		name               string
		approver           string
		requestedBy        string
		existingApprovedBy string
		wantStatus         int // 0 == allowed
	}{
		{"distinct approver, unapproved", "carol", "alice", "", 0},
		{"requester known-empty (kubectl grant), distinct approver ok", "carol", "", "", 0},
		{"self-approval refused", "alice", "alice", "", http.StatusConflict},
		{"unauthenticated approver refused", "", "alice", "", http.StatusBadRequest},
		{"already approved refused", "dave", "alice", "carol", http.StatusConflict},
		{"already approved takes precedence over self-approval", "alice", "alice", "carol", http.StatusConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, msg := approvalDecision(c.approver, c.requestedBy, c.existingApprovedBy)
			if status != c.wantStatus {
				t.Fatalf("status = %d (%q), want %d", status, msg, c.wantStatus)
			}
			if (c.wantStatus == 0) != (msg == "") {
				t.Fatalf("status/msg disagree: status=%d msg=%q", status, msg)
			}
		})
	}
}

const grantsNS = "open-infra-console"

// grantAPI is an API server holding kind: Grants and kind: Policies in memory: it serves get, list,
// create, merge-patch and delete on them, and records every write.
type grantAPI struct {
	mu      sync.Mutex
	objects map[string]map[string]any // path -> object
	writes  []string                  // "POST <path>", "PATCH <path> <body>", "DELETE <path>"
}

func newGrantAPI(t *testing.T, policies ...string) (*grantAPI, kubernetes.Interface) {
	t.Helper()
	api := &grantAPI{objects: map[string]map[string]any{}}
	for _, p := range policies {
		api.objects[policiesAbsPath(grantsNS)+"/"+p] = map[string]any{"metadata": map[string]any{"name": p}}
	}
	srv := httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return api, cs
}

// notFound answers as the API server does for an object that does not exist.
func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"the object is not found","reason":"NotFound","code":404}`)
}

func (a *grantAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		if path == grantsAbsPath(grantsNS) {
			items := []any{}
			for p, o := range a.objects {
				if strings.HasPrefix(p, path+"/") {
					items = append(items, o)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
			return
		}
		o, ok := a.objects[path]
		if !ok {
			notFound(w)
			return
		}
		_ = json.NewEncoder(w).Encode(o)
	case http.MethodPost:
		var o map[string]any
		_ = json.Unmarshal(body, &o)
		md, _ := o["metadata"].(map[string]any)
		md["creationTimestamp"] = time.Now().UTC().Format(time.RFC3339)
		a.objects[path+"/"+md["name"].(string)] = o
		a.writes = append(a.writes, "POST "+path)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(o)
	case http.MethodPatch:
		o, ok := a.objects[path]
		if !ok {
			notFound(w)
			return
		}
		var patch map[string]any
		_ = json.Unmarshal(body, &patch)
		spec, _ := o["spec"].(map[string]any)
		for k, v := range patch["spec"].(map[string]any) {
			spec[k] = v
		}
		a.writes = append(a.writes, "PATCH "+path+" "+string(body))
		_ = json.NewEncoder(w).Encode(o)
	case http.MethodDelete:
		if _, ok := a.objects[path]; !ok {
			notFound(w)
			return
		}
		delete(a.objects, path)
		a.writes = append(a.writes, "DELETE "+path)
		_, _ = io.WriteString(w, `{"kind":"Status","status":"Success"}`)
	}
}

func (a *grantAPI) grant(name string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.objects[grantsAbsPath(grantsNS)+"/"+name]
}

func (a *grantAPI) put(name string, spec map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.objects[grantsAbsPath(grantsNS)+"/"+name] = map[string]any{
		"metadata": map[string]any{"name": name, "creationTimestamp": "2026-11-07T09:00:00Z"}, "spec": spec}
}

// grantCall runs one Grants handler as sub (signed in; the store's authorization is off, so the handler's
// own rules are what is tested), with the route's {name}.
func grantCall(h http.HandlerFunc, method, name, sub string, body any) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "/api/iam/grants", bytes.NewReader(b))
	ctx := context.WithValue(r.Context(), ctxUser{}, sessionClaims{Claims: iam.Claims{Sub: sub}})
	if name != "" {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("name", name)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	}
	w := httptest.NewRecorder()
	h(w, r.WithContext(ctx))
	return w
}

func errorOf(w *httptest.ResponseRecorder) (string, string) {
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out["error"], out["errorCode"]
}

// A grant is requested with the policies it attaches: requestedBy is the signed-in requester, approval is
// never written, and nothing else is. The old ClusterRole form, a policy that does not exist, no policy,
// and a duration over 24h are refused before anything is written.
func TestGrantCreate(t *testing.T) {
	api, cs := newGrantAPI(t, "aws-readonlyaccess", "aws-poweruseraccess")
	auth := &authStore{cs: cs, ns: grantsNS, mode: "none"}
	h := handleIAMGrantCreate(cs, auth, testLogger())

	w := grantCall(h, http.MethodPost, "", "alice", map[string]any{"name": "jit-alice", "subjectKind": "User", "subjectName": "alice",
		"policies": []string{"aws-poweruseraccess", " aws-readonlyaccess ", "aws-poweruseraccess"}, "duration": "4h", "reason": "incident 1234",
		"requestedBy": "mallory", "approval": map[string]any{"approvedBy": "mallory"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	g := api.grant("jit-alice")
	spec, _ := g["spec"].(map[string]any)
	if spec == nil {
		t.Fatalf("no grant written: %v", api.writes)
	}
	if got, _ := json.Marshal(spec["policies"]); string(got) != `["aws-poweruseraccess","aws-readonlyaccess"]` {
		t.Errorf("policies = %s", got)
	}
	if spec["requestedBy"] != "alice" || spec["approval"] != nil || spec["clusterRole"] != nil || spec["duration"] != "4h" {
		t.Errorf("spec = %v: requestedBy is the signed-in requester, and a request carries no approval", spec)
	}

	for _, c := range []struct {
		name string
		body map[string]any
		code int
		says string
	}{
		{"the old ClusterRole form", map[string]any{"clusterRole": "open-infra-poweruser"}, http.StatusBadRequest, "clusterRole is not supported"},
		{"a ClusterRole beside policies", map[string]any{"clusterRole": "open-infra-console", "policies": []string{"aws-readonlyaccess"}}, http.StatusBadRequest, "clusterRole is not supported"},
		{"no policy", map[string]any{"policies": []string{}}, http.StatusBadRequest, "policies is required"},
		{"a policy that does not exist", map[string]any{"policies": []string{"aws-readonlyaccess", "nope"}}, http.StatusBadRequest, "policy nope does not exist"},
		{"not a policy name", map[string]any{"policies": []string{"Admin Access"}}, http.StatusBadRequest, "is not a policy name"},
		{"over 24h", map[string]any{"policies": []string{"aws-readonlyaccess"}, "duration": "25h"}, http.StatusBadRequest, "at most 24h"},
		{"a fractional duration", map[string]any{"policies": []string{"aws-readonlyaccess"}, "duration": "0.5h"}, http.StatusBadRequest, "at most 24h"},
		{"a role subject", map[string]any{"policies": []string{"aws-readonlyaccess"}, "subjectKind": "Role"}, http.StatusBadRequest, "User or Group"},
		{"a subject in another namespace", map[string]any{"policies": []string{"aws-readonlyaccess"}, "subjectName": "team-b/alice"}, http.StatusBadRequest, "in this account"},
	} {
		body := map[string]any{"name": "jit-x", "subjectKind": "Group", "subjectName": "oncall", "duration": "1h"}
		for k, v := range c.body {
			body[k] = v
		}
		before := len(api.writes)
		w := grantCall(h, http.MethodPost, "", "alice", body)
		msg, _ := errorOf(w)
		if w.Code != c.code || !strings.Contains(msg, c.says) {
			t.Errorf("%s: %d %q, want %d saying %q", c.name, w.Code, msg, c.code, c.says)
		}
		if len(api.writes) != before {
			t.Errorf("%s: wrote %v", c.name, api.writes[before:])
		}
	}
}

// Approval is a second person's: the requester cannot approve their own grant, a grant is approved once,
// and the approval records the approver from the session and the time; revoking deletes the grant.
func TestGrantApproveAndRevoke(t *testing.T) {
	api, cs := newGrantAPI(t, "aws-poweruseraccess")
	auth := &authStore{cs: cs, ns: grantsNS, mode: "none"}
	api.put("jit-alice", map[string]any{"subject": map[string]any{"kind": "User", "name": "alice"},
		"policies": []any{"aws-poweruseraccess"}, "duration": "4h", "requestedBy": "alice"})
	approve := handleIAMGrantApprove(cs, auth, testLogger())

	if w := grantCall(approve, http.MethodPost, "jit-alice", "alice", map[string]string{"note": "mine"}); w.Code != http.StatusConflict {
		t.Fatalf("self-approval: %d %s, want 409", w.Code, w.Body)
	}
	if len(api.writes) != 0 {
		t.Fatalf("a refused approval wrote %v", api.writes)
	}
	before := time.Now().UTC().Truncate(time.Second)
	w := grantCall(approve, http.MethodPost, "jit-alice", "carol", map[string]string{"note": " verified on the bridge "})
	if w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	appr, _ := api.grant("jit-alice")["spec"].(map[string]any)["approval"].(map[string]any)
	at, err := time.Parse(time.RFC3339, appr["approvedAt"].(string))
	if appr["approvedBy"] != "carol" || appr["note"] != "verified on the bridge" || err != nil || at.Before(before) {
		t.Errorf("approval = %v", appr)
	}
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["expiresAt"] != at.Add(4*time.Hour).Format(time.RFC3339) {
		t.Errorf("approve answers its expiry: %v", out)
	}
	if w := grantCall(approve, http.MethodPost, "jit-alice", "dave", nil); w.Code != http.StatusConflict {
		t.Errorf("a second approval: %d, want 409", w.Code)
	}
	if w := grantCall(approve, http.MethodPost, "missing", "carol", nil); w.Code < 400 {
		t.Errorf("approving a grant that does not exist: %d %s, want a refusal", w.Code, w.Body)
	}

	revoke := handleIAMGrantDelete(cs, auth, testLogger())
	if w := grantCall(revoke, http.MethodDelete, "jit-alice", "carol", nil); w.Code != http.StatusOK || api.grant("jit-alice") != nil {
		t.Fatalf("revoke: %d %s, grant now %v", w.Code, w.Body, api.grant("jit-alice"))
	}
}

// The console shows where each grant stands exactly as the evaluator decides it: awaiting approval,
// active with the subject it is attached to and until when, expired, or attaching nothing.
func TestGrantList_Phases(t *testing.T) {
	api, cs := newGrantAPI(t)
	auth := &authStore{cs: cs, ns: grantsNS, mode: "none"}
	now := time.Now().UTC().Truncate(time.Second)
	spec := func(kind, subject, requestedBy, approvedBy string, approvedAt time.Time, duration string) map[string]any {
		s := map[string]any{"subject": map[string]any{"kind": kind, "name": subject}, "policies": []any{"aws-readonlyaccess"},
			"duration": duration, "requestedBy": requestedBy}
		if approvedBy != "" {
			s["approval"] = map[string]any{"approvedBy": approvedBy, "approvedAt": approvedAt.Format(time.RFC3339)}
		}
		return s
	}
	api.put("a-pending", spec("User", "alice", "alice", "", time.Time{}, "4h"))
	api.put("b-active", spec("Group", "oncall", "alice", "carol", now.Add(-time.Hour), "4h"))
	api.put("c-expired", spec("User", "bob", "bob", "carol", now.Add(-5*time.Hour), "4h"))
	api.put("d-self", spec("User", "mallory", "mallory", "mallory", now.Add(-time.Minute), "4h"))

	w := grantCall(handleIAMGrantsList(cs, auth, testLogger()), http.MethodGet, "", "carol", nil)
	var views []grantView
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil || len(views) != 4 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	want := []struct {
		phase  string
		active bool
		says   string
	}{
		{"AwaitingApproval", false, "awaiting approval"},
		{"Active", true, "aws-readonlyaccess attached to arn:aws:iam::000000000000:group/oncall until " + now.Add(3*time.Hour).Format(time.RFC3339)},
		{"Expired", false, "no longer attached"},
		{"NotGrantable", false, "someone other than the requester"},
	}
	for i, v := range views {
		if v.Phase != want[i].phase || v.Active != want[i].active || !strings.Contains(v.Message, want[i].says) {
			t.Errorf("%s: %s active=%v %q, want %s active=%v saying %q", v.Name, v.Phase, v.Active, v.Message,
				want[i].phase, want[i].active, want[i].says)
		}
	}
	if b := views[1]; b.AttachedTo != "arn:aws:iam::000000000000:group/oncall" || b.ExpiresAt != now.Add(3*time.Hour).Format(time.RFC3339) ||
		len(b.Policies) != 1 {
		t.Errorf("active view = %+v", b)
	}
	g := grantCall(handleIAMGrantGet(cs, auth, testLogger()), http.MethodGet, "a-pending", "carol", nil)
	var one grantView
	if err := json.Unmarshal(g.Body.Bytes(), &one); err != nil || one.Phase != "AwaitingApproval" || one.AttachedTo != "arn:aws:iam::000000000000:user/alice" {
		t.Errorf("get: %d %s", g.Code, g.Body)
	}
}

// A group is a container of policies: the console refuses the old permission-tier form on create and
// update, before authorizing or writing anything.
func TestGroupCreateAndUpdate_RefuseClusterRole(t *testing.T) {
	api, cs := newGrantAPI(t)
	auth := &authStore{cs: cs, ns: grantsNS, mode: "none"}
	for _, h := range []http.HandlerFunc{handleIAMGroupCreate(cs, auth, testLogger()), handleIAMGroupUpdate(cs, auth, testLogger())} {
		w := grantCall(h, http.MethodPost, "builders", "carol", map[string]any{"name": "builders", "clusterRole": "open-infra-poweruser",
			"policies": []string{"aws-poweruseraccess"}})
		msg, code := errorOf(w)
		if w.Code != http.StatusBadRequest || code != "ValidationError" || !strings.Contains(msg, "a group is a container of policies") {
			t.Errorf("clusterRole: %d %q %q, want a 400 ValidationError", w.Code, code, msg)
		}
	}
	if len(api.writes) != 0 {
		t.Errorf("a refused group wrote %v", api.writes)
	}
}
