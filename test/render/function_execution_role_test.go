package render

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// spec.role takes what Lambda's Role takes — a role ARN of the aws partition — or, for convenience, a role
// name; the legacy openinfra-partition ARN and anything else is refused at admission.
func TestFunction_ExecutionRoleShape(t *testing.T) {
	b, err := os.ReadFile("../../platform/abstraction/function-xrd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ {16}role:\n(?: {18}.*\n)*? {18}pattern: '([^']+)'`).FindSubmatch(b)
	if m == nil {
		t.Fatal("function-xrd.yaml: spec.role has no pattern")
	}
	re := regexp.MustCompile(string(m[1]))
	for _, ok := range []string{"orders-reader", "OrdersReader", "a", "role_with.chars+=,@",
		"arn:aws:iam::123456789012:role/OrdersReader", "arn:aws:iam::123456789012:role/service-role/x",
		"arn:aws-us-gov:iam::123456789012:role/x", strings.Repeat("r", 64)} {
		if !re.MatchString(ok) {
			t.Errorf("spec.role must accept %q", ok)
		}
	}
	for _, bad := range []string{"", "arn:openinfra:iam::open-infra:role/x", "arn:aws:iam::12345:role/x",
		"arn:aws:iam::123456789012:user/x", "arn:aws:sts::123456789012:assumed-role/x/y", "a/b", "has space",
		strings.Repeat("r", 65), "arn:aws:iam::123456789012:role/"} {
		if re.MatchString(bad) {
			t.Errorf("spec.role must refuse %q", bad)
		}
	}
}

// A Function's execution role (spec.role, Lambda's Role): the function's pods run as their own
// ServiceAccount fn-<name> with a projected STS-audience token, and the AWS SDK's web-identity env names
// the role by its ARN in the function's account — so the handler's SDK assumes the role on the aws-shim
// with no keys configured, as Lambda hands a function its role's credentials.

func fnRoleCtx(name, ns string, spec map[string]any, extra map[string]any) map[string]any {
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{"name": name + "-abcde", "labels": map[string]any{
			"crossplane.io/claim-name": name, "crossplane.io/claim-namespace": ns}},
	}}}}
	if extra != nil {
		ctx["extraResources"] = extra
	}
	return ctx
}

// fnRoleExtra is what Crossplane hands the composition on its second call: the install's identity and
// the kind: Accounts (each listing its namespaces).
func fnRoleExtra(mgmt, region string, accounts ...map[string]any) map[string]any {
	items := []any{}
	for _, a := range accounts {
		items = append(items, map[string]any{"resource": map[string]any{"spec": a}})
	}
	return map[string]any{
		"aws-identity": map[string]any{"items": []any{map[string]any{"resource": map[string]any{
			"data": map[string]any{"awsAccountId": mgmt, "awsRegion": region}}}}},
		"accounts": map[string]any{"items": items},
	}
}

func ksvcOf(t *testing.T, out string, name string) map[string]any {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse rendered function: %v\n%s", err, out)
	}
	o := objectFor(docs, "Service", name)
	if o == nil {
		t.Fatalf("no Knative Service %s rendered:\n%s", name, out)
	}
	return mget(o, "spec", "forProvider", "manifest").(map[string]any)
}

func envOf(ksvc map[string]any) map[string]string {
	env := map[string]string{}
	cs, _ := mget(ksvc, "spec", "template", "spec", "containers").([]any)
	if len(cs) == 0 {
		return env
	}
	list, _ := mget(cs[0], "env").([]any)
	for _, e := range list {
		env[mstr(e, "name")] = mstr(e, "value")
	}
	return env
}

func envCount(ksvc map[string]any, name string) int {
	cs, _ := mget(ksvc, "spec", "template", "spec", "containers").([]any)
	n := 0
	if len(cs) == 0 {
		return 0
	}
	list, _ := mget(cs[0], "env").([]any)
	for _, e := range list {
		if mstr(e, "name") == name {
			n++
		}
	}
	return n
}

func TestFunction_ExecutionRoleImage(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	spec := map[string]any{"image": "ghcr.io/me/app:1", "role": "orders-reader"}

	// The second call, with the install's identity and no account listing the namespace: the role is the
	// install's account's.
	out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, fnRoleExtra("123456789012", "eu-west-1")))
	ksvc := ksvcOf(t, out, "orders")
	if got := mstr(ksvc, "spec", "template", "spec", "serviceAccountName"); got != "fn-orders" {
		t.Errorf("the function must run as its own identity fn-orders, got %q", got)
	}
	env := envOf(ksvc)
	for k, v := range map[string]string{
		"AWS_ROLE_ARN":                "arn:aws:iam::123456789012:role/orders-reader",
		"AWS_ROLE_SESSION_NAME":       "orders",
		"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/openinfra/token",
		"AWS_ENDPOINT_URL_STS":        "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566",
		"AWS_ENDPOINT_URL":            "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566",
		"AWS_REGION":                  "eu-west-1",
		"AWS_DEFAULT_REGION":          "eu-west-1",
	} {
		if env[k] != v {
			t.Errorf("env %s = %q, want %q", k, env[k], v)
		}
	}
	// The token volume: projected for the aws-shim's STS audience, mounted read-only where the env says.
	if !strings.Contains(out, "mountPath: /var/run/secrets/openinfra, readOnly: true") ||
		!strings.Contains(out, "audience: sts.openinfra") || !strings.Contains(out, "path: token") {
		t.Errorf("the projected STS token must be mounted read-only:\n%s", grepCtx(out, "openinfra-sts-token"))
	}

	// The identity ServiceAccount: labelled as this function's, with no Kubernetes API token mounted.
	docs, _ := parseYAMLDocs(out)
	sa := objectFor(docs, "ServiceAccount", "fn-orders")
	if sa == nil {
		t.Fatalf("no ServiceAccount fn-orders rendered:\n%s", out)
	}
	m := mget(sa, "spec", "forProvider", "manifest")
	if mstr(m, "metadata", "namespace") != "team-a" || mstr(m, "metadata", "labels", "openinfra.dev/function") != "orders" ||
		mstr(m, "automountServiceAccountToken") != "false" {
		t.Errorf("the identity ServiceAccount must be fn-orders in team-a, labelled openinfra.dev/function=orders, no API token: %#v", m)
	}

	// The account lookup: the install's identity by name and the kinds: Account, read as extra resources.
	for _, want := range []string{"kind: ExtraResources", "kind: EnvironmentConfig", "matchName: openinfra-aws-identity",
		"apiVersion: organizations.openinfra.dev/v1", "kind: Account"} {
		if !strings.Contains(out, want) {
			t.Errorf("the role's account must be read as extra resources (%q):\n%s", want, grepCtx(out, "ExtraResources"))
		}
	}
}

// A function in a member account's namespace names its role in that account.
func TestFunction_ExecutionRoleMemberAccount(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	extra := fnRoleExtra("000000000000", "us-east-1",
		map[string]any{"accountId": "000000000000", "namespaces": []any{"open-infra-console", "open-infra-cfn"}},
		map[string]any{"accountId": "917640925667", "namespaces": []any{"shop-home", "shop"}})
	ksvc := ksvcOf(t, render(t, tmpl, fnRoleCtx("checkout", "shop", map[string]any{"image": "ghcr.io/me/app:1", "role": "Checkout"}, extra)), "checkout")
	if got := envOf(ksvc)["AWS_ROLE_ARN"]; got != "arn:aws:iam::917640925667:role/Checkout" {
		t.Errorf("a member account's function names its role in its account, got %q", got)
	}
	// A namespace no account lists is the install's own account's.
	ksvc = ksvcOf(t, render(t, tmpl, fnRoleCtx("checkout", "elsewhere", map[string]any{"image": "ghcr.io/me/app:1", "role": "Checkout"}, extra)), "checkout")
	if got := envOf(ksvc)["AWS_ROLE_ARN"]; got != "arn:aws:iam::000000000000:role/Checkout" {
		t.Errorf("an unlisted namespace's function names its role in the install's account, got %q", got)
	}
}

// A role named by ARN keeps its ARN (path and case as AWS writes them); a role of another account is
// refused, as AWS refuses passing another account's role.
func TestFunction_ExecutionRoleARN(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	extra := fnRoleExtra("123456789012", "us-east-1")
	arn := "arn:aws:iam::123456789012:role/service-role/OrdersReader"
	ksvc := ksvcOf(t, render(t, tmpl, fnRoleCtx("orders", "team-a", map[string]any{"image": "ghcr.io/me/app:1", "role": arn}, extra)), "orders")
	if got := envOf(ksvc)["AWS_ROLE_ARN"]; got != arn {
		t.Errorf("a role ARN must be used as given, got %q", got)
	}
	err := renderErr(tmpl, fnRoleCtx("orders", "team-a", map[string]any{"image": "ghcr.io/me/app:1",
		"role": "arn:aws:iam::210987654321:role/OrdersReader"}, extra))
	if err == nil || !strings.Contains(err.Error(), "must be a role of its own account (123456789012)") {
		t.Fatalf("another account's role must be refused, got %v", err)
	}
	// Before the account is known (the first call, before the extra resources), nothing is refused: the
	// requirement is asked for, and the render Crossplane applies is the one that has the answer.
	if err := renderErr(tmpl, fnRoleCtx("orders", "team-a", map[string]any{"image": "ghcr.io/me/app:1",
		"role": "arn:aws:iam::210987654321:role/OrdersReader"}, nil)); err != nil {
		t.Fatalf("the first call must not refuse before the account is read: %v", err)
	}
}

// A code function keeps the runtime's own region (one AWS_REGION), and its inline code beside the token.
func TestFunction_ExecutionRoleCode(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	spec := map[string]any{"role": "worker", "code": map[string]any{"runtime": "python3.12", "handler": "app.handler",
		"region": "ap-south-1", "source": map[string]any{"configMap": "worker-code"}}}
	out := render(t, tmpl, fnRoleCtx("worker", "team-a", spec, fnRoleExtra("123456789012", "eu-west-1")))
	ksvc := ksvcOf(t, out, "worker")
	if n := envCount(ksvc, "AWS_REGION"); n != 1 {
		t.Errorf("a code function must carry one AWS_REGION (its runtime's), got %d", n)
	}
	env := envOf(ksvc)
	if env["AWS_REGION"] != "ap-south-1" || env["AWS_ROLE_ARN"] != "arn:aws:iam::123456789012:role/worker" ||
		env["AWS_LAMBDA_FUNCTION_NAME"] != "worker" {
		t.Errorf("a code function with a role keeps its runtime env and gains the role's: %#v", env)
	}
	for _, want := range []string{"name: openinfra-code, mountPath: /var/task", "name: openinfra-sts-token, mountPath: /var/run/secrets/openinfra",
		`configMap: { name: "worker-code" }`, "audience: sts.openinfra"} {
		if !strings.Contains(out, want) {
			t.Errorf("a code function with a role must mount both its code and its token (%q):\n%s", want, grepCtx(out, "volume"))
		}
	}
}

// A package read with static keys would shadow the role in the handler's SDK (its environment's keys
// come first), so the two are refused together rather than the function silently acting as the keys.
func TestFunction_ExecutionRoleRefusesStaticCodeKeys(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	err := renderErr(tmpl, fnRoleCtx("worker", "team-a", map[string]any{"role": "worker", "code": map[string]any{
		"runtime": "python3.12", "handler": "app.handler",
		"source": map[string]any{"bucket": "code", "key": "w.zip", "secret": "code-read"}}}, nil))
	if err == nil || !strings.Contains(err.Error(), "can't be combined with a deployment package read with static keys") {
		t.Fatalf("a role with code.source.secret must be refused, got %v", err)
	}
}

// The identity ServiceAccount is the only one a function renders, and only with a role: an Application's
// ServiceAccount is named after the app and a VM's vm-<name>, so the fn- prefix keeps a function's apart
// from a VM's of any name.
func TestFunction_ExecutionRoleIdentityName(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	out := render(t, tmpl, fnRoleCtx("vm-web", "team-a", map[string]any{"image": "ghcr.io/me/app:1", "role": "r"}, fnRoleExtra("123456789012", "us-east-1")))
	if got := mstr(ksvcOf(t, out, "vm-web"), "spec", "template", "spec", "serviceAccountName"); got != "fn-vm-web" {
		t.Errorf("a function named vm-web runs as fn-vm-web (never the VM identity vm-web), got %q", got)
	}
	out = render(t, tmpl, fnRoleCtx("plain", "team-a", map[string]any{"image": "ghcr.io/me/app:1"}, nil))
	for _, forbidden := range []string{"kind: ServiceAccount", "serviceAccountName", "AWS_ROLE_ARN", "kind: ExtraResources", "openinfra-sts-token"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a function with no role must not render %q", forbidden)
		}
	}
}
