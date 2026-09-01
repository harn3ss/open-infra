package render

import (
	"strings"
	"testing"
)

const userpoolCompositionPath = "../../platform/abstraction/userpool-composition.yaml"

// userpoolCtx builds the go-templating context a UserPool claim produces.
func userpoolCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-000000000abc",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "mypool",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

// The pool's in-cluster OIDC issuer (what a consumer points OIDC_ISSUER at) and the
// imported realm must be consistent, and the realm must import a client. A bare pool
// (no hostname) must NOT render an Ingress.
func TestUserPool_RendersIssuerRealmAndClient(t *testing.T) {
	tmpl := extractInlineTemplate(t, userpoolCompositionPath)
	out := render(t, tmpl, userpoolCtx(map[string]any{}))

	if want := `ISSUER_URL: http://mypool.default.svc.cluster.local:8080/realms/mypool`; !strings.Contains(out, want) {
		t.Errorf("missing in-cluster issuer URL %q; got:\n%s", want, grepCtx(out, "ISSUER_URL"))
	}
	if !strings.Contains(out, `"realm": "mypool"`) {
		t.Errorf("realm import should declare realm=mypool; got:\n%s", grepCtx(out, "realm"))
	}
	if !strings.Contains(out, `"clientId": "openinfra"`) {
		t.Errorf("realm import should declare the default client; got:\n%s", grepCtx(out, "clientId"))
	}
	// The issuer default (registration on) must render a valid JSON bool, not "<no value>".
	if !strings.Contains(out, `"registrationAllowed": true`) {
		t.Errorf("registration should default on; got:\n%s", grepCtx(out, "registrationAllowed"))
	}
	if strings.Contains(out, "kind: Ingress") {
		t.Errorf("a pool with no hostname must not render an Ingress; got:\n%s", grepCtx(out, "Ingress"))
	}
}

// A hostname turns on the hosted-UI Ingress (TLS via the shared issuer) and adds the
// public issuer URL to the connection secret — while the in-cluster issuer is unchanged.
func TestUserPool_HostnameRendersIngress(t *testing.T) {
	tmpl := extractInlineTemplate(t, userpoolCompositionPath)
	out := render(t, tmpl, userpoolCtx(map[string]any{"hostname": "login.example.com"}))

	if !strings.Contains(out, "kind: Ingress") || !strings.Contains(out, "host: login.example.com") {
		t.Errorf("a hostname should render a TLS Ingress; got:\n%s", grepCtx(out, "Ingress"))
	}
	if !strings.Contains(out, "cert-manager.io/cluster-issuer: openinfra-issuer") {
		t.Errorf("the hosted-UI Ingress should terminate TLS via openinfra-issuer; got:\n%s", grepCtx(out, "cluster-issuer"))
	}
	if !strings.Contains(out, `PUBLIC_ISSUER_URL: https://login.example.com/realms/mypool`) {
		t.Errorf("a hostname should add PUBLIC_ISSUER_URL; got:\n%s", grepCtx(out, "PUBLIC"))
	}
}

// registrationAllowed:false must render as a real JSON false (Sprig's `default` treats
// false as empty, so this guards the hasKey branch that would otherwise force it on).
func TestUserPool_RegistrationOffIsHonored(t *testing.T) {
	tmpl := extractInlineTemplate(t, userpoolCompositionPath)
	out := render(t, tmpl, userpoolCtx(map[string]any{"registrationAllowed": false}))
	if !strings.Contains(out, `"registrationAllowed": false`) {
		t.Errorf("registrationAllowed:false must be honored; got:\n%s", grepCtx(out, "registrationAllowed"))
	}
}

// A custom realm and client id flow through to both the import and the issuer/secret.
func TestUserPool_CustomRealmAndClient(t *testing.T) {
	tmpl := extractInlineTemplate(t, userpoolCompositionPath)
	out := render(t, tmpl, userpoolCtx(map[string]any{"realm": "customers", "clientId": "web-app"}))
	if !strings.Contains(out, `/realms/customers`) || !strings.Contains(out, `REALM: customers`) {
		t.Errorf("custom realm should flow to the issuer + secret; got:\n%s", grepCtx(out, "realm"))
	}
	if !strings.Contains(out, `"clientId": "web-app"`) || !strings.Contains(out, `CLIENT_ID: web-app`) {
		t.Errorf("custom clientId should flow to the import + secret; got:\n%s", grepCtx(out, "client"))
	}
}
