package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

// meOperator is /api/auth/me's capabilities.operator for a session of claims.
func meOperator(t *testing.T, a *authStore, claims iam.Claims) bool {
	t.Helper()
	tok, err := a.issueClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	handleMe(a)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/auth/me answered %d: %s", w.Code, w.Body)
	}
	var body struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	op, ok := body.Capabilities["operator"]
	if !ok {
		t.Fatalf("/api/auth/me has no capabilities.operator: %s", w.Body)
	}
	return op
}

// In enforce, the console's cluster views are the operator's: the evaluator decides openinfra-operator:*,
// which AdministratorAccess ("*") and an Allow naming the whole surface grant, and PowerUserAccess (its
// NotAction reserves the surface), a service's read access, or one operator action do not. Root always.
func TestMe_OperatorCapabilityInEnforceIsTheEvaluators(t *testing.T) {
	docs := map[string]string{
		"admin":      adminDoc,
		"poweruser":  powerUserDoc,
		"s3-read":    s3ReadDoc,
		"operator":   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"openinfra-operator:*","Resource":"*"}]}`,
		"list-pods":  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"openinfra-operator:ListPods","Resource":"*"}]}`,
		"admin-deny": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"openinfra-operator:*","Resource":"*"}]}`,
	}
	attach := map[string][]string{
		"User::alice": {"admin"}, "User::bob": {"poweruser"}, "User::carol": {"s3-read"},
		"User::dave": {"operator"}, "User::erin": {"list-pods"}, "User::frank": {"admin", "admin-deny"},
	}
	z := newTestAuthz(t, iamauthz.ModeEnforce, testWorld(t, docs, attach), true)
	z.auth.sessionKey = []byte("test-session-key")

	for name, want := range map[string]bool{
		"alice": true,  // AdministratorAccess
		"bob":   false, // PowerUserAccess
		"carol": false, // S3 reads only
		"dave":  true,  // the whole operator surface
		"erin":  false, // one operator action is not the operator's views
		"frank": false, // an explicit Deny of the surface
		"grace": false, // no policy
	} {
		// The legacy role is admin for all of them: in enforce it decides nothing.
		if got := meOperator(t, z.auth, iam.Claims{Sub: name, Role: "admin"}); got != want {
			t.Errorf("%s: operator = %v, want %v", name, got, want)
		}
	}
	if !meOperator(t, z.auth, iam.Claims{Sub: "root", Role: "root"}) {
		t.Error("the account's root user is not the operator")
	}
}

// In legacy and shadow the legacy administrator role decides, as those modes decide every request; IAM
// policy does not (shadow's evaluator answer would make the menu disagree with what the pages may do).
func TestMe_OperatorCapabilityOutsideEnforceIsTheLegacyRole(t *testing.T) {
	docs := map[string]string{"admin": adminDoc}
	attach := map[string][]string{"User::alice": {"admin"}}
	for _, mode := range []iamauthz.Mode{iamauthz.ModeLegacy, iamauthz.ModeShadow} {
		z := newTestAuthz(t, mode, testWorld(t, docs, attach), true)
		z.auth.sessionKey = []byte("test-session-key")
		if meOperator(t, z.auth, iam.Claims{Sub: "alice", Role: "poweruser"}) {
			t.Errorf("%s: a poweruser is the operator because IAM policy would allow it", mode)
		}
		if !meOperator(t, z.auth, iam.Claims{Sub: "bob", Role: "admin"}) {
			t.Errorf("%s: an admin is not the operator", mode)
		}
		if meOperator(t, z.auth, iam.Claims{Sub: "carol", Role: "readonly"}) {
			t.Errorf("%s: a reader is the operator", mode)
		}
		// A switched-role session outside enforce is refused everything, so it is no one's operator.
		if meOperator(t, z.auth, iam.Claims{Sub: "bob", Role: "admin", AssumedRole: "deployer"}) {
			t.Errorf("%s: a role session outside enforce is the operator", mode)
		}
	}
}

// With no evaluator (IAM not wired) the legacy role decides; with authentication off everyone is.
func TestMe_OperatorCapabilityWithoutEvaluatorOrAuth(t *testing.T) {
	prev := consoleIAM
	consoleIAM = nil
	t.Cleanup(func() { consoleIAM = prev })
	a := &authStore{mode: "local", sessionKey: []byte("test-session-key")}
	if !meOperator(t, a, iam.Claims{Sub: "bob", Role: "admin"}) || meOperator(t, a, iam.Claims{Sub: "carol", Role: "poweruser"}) {
		t.Error("without an evaluator, the operator is the legacy admin role")
	}
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()
	handleMe(&authStore{mode: "none"})(w, r)
	var body struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if !body.Capabilities["operator"] {
		t.Errorf("with authentication off every caller is the operator: %s", w.Body)
	}
}
