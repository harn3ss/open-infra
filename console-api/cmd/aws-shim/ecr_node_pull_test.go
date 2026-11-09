package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// nodePullHandler is an ECR handler that serves the node pull credential to the agent
// kube-system/ecr-node-pull-agent. Its token reviewer knows two tokens: the agent's and another
// ServiceAccount's; anything else does not authenticate.
func nodePullHandler(t *testing.T) *ecrHandler {
	t.Helper()
	h := newECRHandler(nil, "authz", "open-infra", "us-east-1", "open-infra-ecr", "", "", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.signer = newTestECRSigner(t)
	h.nodePull = &ecrNodePull{
		review: func(_ context.Context, token string) (string, bool) {
			switch token {
			case "agent-token":
				return "system:serviceaccount:kube-system:ecr-node-pull-agent", true
			case "other-token":
				return "system:serviceaccount:team-a:builder", true
			}
			return "", false
		},
		agents: parseNodePullAgents("kube-system/ecr-node-pull-agent"),
	}
	return h
}

func nodeCredential(h *ecrHandler, auth string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/ecr/node-credential", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.serveNodeCredential(w, r)
	return w
}

// #411: the node agent trades its own ServiceAccount token for the node puller's pull-only credential,
// signed with the current key, as a node's instance role gets its ECR credential on AWS.
func TestECRNodeCredential_TheAgentGetsThePullOnlyCredential(t *testing.T) {
	h := nodePullHandler(t)
	w := nodeCredential(h, "Bearer agent-token")
	if w.Code != http.StatusOK {
		t.Fatalf("the node agent: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("a credential must not be cached: %q", w.Header().Get("Cache-Control"))
	}
	var got struct{ Username, Password, ExpiresAt string }
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Username != "AWS" || got.Password == "" {
		t.Fatalf("answer: %+v", got)
	}
	c, err := h.signer.verifyCaller(got.Password)
	if err != nil {
		t.Fatalf("the credential does not verify with the current key: %v", err)
	}
	if c.Sub != ecrNodePuller || len(c.Groups) != 1 || c.Groups[0] != ecrNodePullersGroup || c.Role != "" || c.AssumedRole != "" || c.Account != "" {
		t.Fatalf("the credential is not the node puller's alone: %+v", c)
	}
	exp, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil || exp.Before(time.Now().Add(360*24*time.Hour)) {
		t.Errorf("expiresAt %q is not about a year away", got.ExpiresAt)
	}
}

// DENIAL: only the node agent gets it. Another ServiceAccount is refused (403); a missing, unknown or
// wrongly scheme'd token does not authenticate (401); a request through the LAN ingress does not reach it
// (404); a shim without node agents configured serves nothing (501).
func TestECRNodeCredential_OnlyTheNodeAgent(t *testing.T) {
	h := nodePullHandler(t)
	for _, c := range []struct {
		name, auth string
		hdr        []string
		code       int
	}{
		{"another ServiceAccount", "Bearer other-token", nil, http.StatusForbidden},
		{"no token", "", nil, http.StatusUnauthorized},
		{"an unknown token", "Bearer forged", nil, http.StatusUnauthorized},
		{"Basic, not Bearer", "Basic YWdlbnQtdG9rZW4=", nil, http.StatusUnauthorized},
		{"through the ingress", "Bearer agent-token", []string{"X-Forwarded-For", "192.0.2.10"}, http.StatusNotFound},
	} {
		w := nodeCredential(h, c.auth, c.hdr...)
		if w.Code != c.code {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body, c.code)
		}
		if strings.Contains(w.Body.String(), `"password"`) {
			t.Errorf("%s: a credential was answered: %s", c.name, w.Body)
		}
	}
	h.nodePull.agents = parseNodePullAgents("")
	if w := nodeCredential(h, "Bearer agent-token"); w.Code != http.StatusNotImplemented {
		t.Errorf("no node agents configured: %d %s", w.Code, w.Body)
	}
}

func TestParseNodePullAgents(t *testing.T) {
	got := parseNodePullAgents(" kube-system/ecr-node-pull-agent, bad, /x, a/b/c, ns/sa ")
	want := map[string]bool{"system:serviceaccount:kube-system:ecr-node-pull-agent": true, "system:serviceaccount:ns:sa": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %s in %v", k, got)
		}
	}
}

// #411: a changed token-certificate bundle rolls the registries that read it (their pod-template annotation
// becomes its hash); the same bundle again changes nothing, and a registry that is not deployed is skipped.
func TestRollTokenCertConsumers(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "ecr-registry", Namespace: "open-infra-ecr"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "ecr-registry-aws", Namespace: "open-infra-ecr"}},
	)
	ctx := context.Background()
	annotation := func(name string) string {
		d, err := cs.AppsV1().Deployments("open-infra-ecr").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return d.Spec.Template.Annotations[ecrTokenCertAnnotation]
	}
	if err := rollTokenCertConsumers(ctx, cs, "open-infra-ecr", ecrTokenCertConsumers, []byte("bundle-1")); err != nil {
		t.Fatalf("a registry not deployed must be skipped: %v", err)
	}
	first := annotation("ecr-registry")
	if first == "" || annotation("ecr-registry-aws") != first {
		t.Fatalf("the registries were not rolled onto the bundle: %q %q", first, annotation("ecr-registry-aws"))
	}
	_ = rollTokenCertConsumers(ctx, cs, "open-infra-ecr", ecrTokenCertConsumers, []byte("bundle-1"))
	if annotation("ecr-registry") != first {
		t.Error("the same bundle changed the pod template")
	}
	_ = rollTokenCertConsumers(ctx, cs, "open-infra-ecr", ecrTokenCertConsumers, []byte("bundle-2"))
	if annotation("ecr-registry") == first {
		t.Error("a new bundle did not roll the registry")
	}
}
