package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

// fakeApps is an applicationIdentities that knows one token.
type fakeApps struct {
	token string
	app   applicationIdentity
}

func (f fakeApps) applicationOf(_ context.Context, token string) (applicationIdentity, bool) {
	return f.app, token == f.token && token != ""
}

func podPullHandler(t *testing.T, app applicationIdentity, role resolvedRole, roleFound bool, stmts ...policyengine.Statement) *ecrHandler {
	t.Helper()
	h := tokenModeECR(t, true, roleChecker(stmts...))
	h.podPull = &ecrPodPull{
		apps: fakeApps{token: "pod-token", app: app},
		roleOf: func(context.Context, string, string, string, string) (resolvedRole, string, bool) {
			return role, "", roleFound
		},
		iamHome: "open-infra-console", account: "111122223333",
	}
	return h
}

func podCredential(h *ecrHandler, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://shim/ecr/pod-credential", strings.NewReader(`{"image":"registry.example/app:1"}`))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.servePodCredential(w, r)
	return w
}

var (
	execApp     = applicationIdentity{namespace: "apps", name: "web", executionRole: ecrTestRole, pod: "web-5d9c7-abcde", username: "system:serviceaccount:apps:web"}
	ecsTrusting = resolvedRole{trust: []string{"Service::" + ecsTasksService}, groups: []string{"openinfra:users"}}
	// AmazonECSTaskExecutionRolePolicy's ECR half.
	execPolicy = []policyengine.Statement{dpAllow([]string{"ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
		"ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"}, "*")}
)

// An app's pod pulls its image as its execution role: the credential is the role's session, and the
// registry's token service grants the repositories the role's policies allow.
func TestPodCredential_ExecutionRolePulls(t *testing.T) {
	h := podPullHandler(t, execApp, ecsTrusting, true, execPolicy...)
	w := podCredential(h, "pod-token")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["username"] != "AWS" || out["password"] == "" || out["expiresAt"] == "" {
		t.Fatalf("response %v", out)
	}
	c, err := h.signer.verifyCaller(out["password"])
	if err != nil {
		t.Fatal(err)
	}
	if c.AssumedRole != ecrTestRole || c.Sub != "assumed-role/"+ecrTestRole+"/"+podID("apps", "web-5d9c7-abcde") {
		t.Fatalf("the credential is %+v; want the execution role's session, named after the task", c)
	}
	got, _ := realmGrant(t, h, out["password"], "repository:app:pull")
	if !equalGrants(got, map[string][]string{"app": {"pull"}}) {
		t.Fatalf("the role's pull grant %v; want app:pull", got)
	}
}

// Anything that is not an app's own pod naming an execution role is pulled with the node's own credential.
func TestPodCredential_NoExecutionRoleIsTheNodes(t *testing.T) {
	noExec := execApp
	noExec.executionRole = ""
	for name, c := range map[string]struct {
		h     *ecrHandler
		token string
	}{
		"no token":           {podPullHandler(t, execApp, ecsTrusting, true, execPolicy...), ""},
		"not an app's token": {podPullHandler(t, execApp, ecsTrusting, true, execPolicy...), "some-other-token"},
		"no execution role":  {podPullHandler(t, noExec, ecsTrusting, true, execPolicy...), "pod-token"},
	} {
		if w := podCredential(c.h, c.token); w.Code != http.StatusNoContent {
			t.Errorf("%s: %d %s; want 204", name, w.Code, w.Body)
		}
	}
}

// An execution role that cannot pull is a refusal, so the pull fails as ECS's does.
func TestPodCredential_RefusedRoles(t *testing.T) {
	otherAcct := execApp
	otherAcct.executionRole = "arn:aws:iam::444455556666:role/" + ecrTestRole
	suspended := execApp
	suspended.suspended = true
	for name, c := range map[string]struct {
		h    *ecrHandler
		want string
	}{
		"untrusting role": {podPullHandler(t, execApp, resolvedRole{trust: []string{"Service::lambda.amazonaws.com"}}, true, execPolicy...),
			"does not name ecs-tasks.amazonaws.com"},
		"conditioned trust": {podPullHandler(t, execApp, resolvedRole{trust: ecsTrusting.trust,
			trustDoc: `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}]}`}, true, execPolicy...),
			"has conditions"},
		"missing role":      {podPullHandler(t, execApp, resolvedRole{}, false, execPolicy...), "does not exist"},
		"another account's": {podPullHandler(t, otherAcct, ecsTrusting, true, execPolicy...), "another account"},
		"suspended account": {podPullHandler(t, suspended, ecsTrusting, true, execPolicy...), "suspended"},
		"no GetAuthorizationToken": {podPullHandler(t, execApp, ecsTrusting, true,
			dpAllow([]string{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"}, "*")), "ecr:GetAuthorizationToken"},
	} {
		w := podCredential(c.h, "pod-token")
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %s; want 403 naming %q", name, w.Code, w.Body, c.want)
		}
	}
}

// The endpoint is the cluster's alone: a request that came through a proxy is not served.
func TestPodCredential_InClusterOnly(t *testing.T) {
	h := podPullHandler(t, execApp, ecsTrusting, true, execPolicy...)
	r := httptest.NewRequest("POST", "http://shim/ecr/pod-credential", nil)
	r.Header.Set("Authorization", "Bearer pod-token")
	r.Header.Set("X-Forwarded-For", "192.0.2.10")
	w := httptest.NewRecorder()
	h.servePodCredential(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("a proxied request: %d; want 404", w.Code)
	}
}
