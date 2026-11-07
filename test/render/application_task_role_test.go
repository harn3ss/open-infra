package render

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// An Application's task role (spec.assumeRole, an ECS task's TaskRoleArn): the app's pods run as their own
// ServiceAccount with a projected STS-audience token, and the AWS SDK's web-identity env names the role by
// its ARN in the app's account and points STS (and every other service) at the aws-shim — so the app's SDK
// assumes the role with no keys configured, as an ECS task gets its task role's credentials.

// spec.assumeRole takes what ECS's TaskRoleArn takes — a role ARN of the aws partition, or a role name;
// the legacy openinfra-partition ARN and anything else is refused at admission, as for a Function's role.
func TestApplication_TaskRoleShape(t *testing.T) {
	b, err := os.ReadFile("../../platform/abstraction/xrd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ {16}assumeRole:\n(?: {18}.*\n)*? {18}pattern: '([^']+)'`).FindSubmatch(b)
	if m == nil {
		t.Fatal("xrd.yaml: spec.assumeRole has no pattern")
	}
	re := regexp.MustCompile(string(m[1]))
	for _, ok := range []string{"orders-reader", "OrdersReader", "a", "role_with.chars+=,@",
		"arn:aws:iam::123456789012:role/OrdersReader", "arn:aws:iam::123456789012:role/service-role/x",
		"arn:aws-us-gov:iam::123456789012:role/x", strings.Repeat("r", 64)} {
		if !re.MatchString(ok) {
			t.Errorf("spec.assumeRole must accept %q", ok)
		}
	}
	for _, bad := range []string{"", "arn:openinfra:iam::open-infra:role/x", "arn:aws:iam::12345:role/x",
		"arn:aws:iam::123456789012:user/x", "a/b", "has space", strings.Repeat("r", 65), "arn:aws:iam::123456789012:role/"} {
		if re.MatchString(bad) {
			t.Errorf("spec.assumeRole must refuse %q", bad)
		}
	}
	// The function's pattern and the app's are one rule: a role is named the same way everywhere.
	fb, err := os.ReadFile("../../platform/abstraction/function-xrd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fm := regexp.MustCompile(`(?m)^ {16}role:\n(?: {18}.*\n)*? {18}pattern: '([^']+)'`).FindSubmatch(fb)
	if fm == nil || string(fm[1]) != string(m[1]) {
		t.Errorf("spec.assumeRole and a Function's spec.role must take the same role forms")
	}
}

func appRoleCtx(name, ns string, spec map[string]any, extra map[string]any) map[string]any {
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{"name": name + "-abcde", "uid": "uid-" + name, "labels": map[string]any{
			"crossplane.io/claim-name": name, "crossplane.io/claim-namespace": ns}},
	}}}}
	if extra != nil {
		ctx["extraResources"] = extra
	}
	return ctx
}

// appDeployment is the rendered Deployment manifest of app name.
func appDeployment(t *testing.T, out, name string) map[string]any {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse rendered app: %v\n%s", err, out)
	}
	o := objectFor(docs, "Deployment", name)
	if o == nil {
		t.Fatalf("no Deployment %s rendered:\n%s", name, out)
	}
	return mget(o, "spec", "forProvider", "manifest").(map[string]any)
}

// appEnv is the primary container's env: name -> value (a valueFrom entry as "fieldRef:<path>").
func appEnv(t *testing.T, dep map[string]any) (map[string]string, map[string]int) {
	t.Helper()
	env, count := map[string]string{}, map[string]int{}
	cs, _ := mget(dep, "spec", "template", "spec", "containers").([]any)
	if len(cs) == 0 {
		t.Fatal("the Deployment has no containers")
	}
	list, _ := mget(cs[0], "env").([]any)
	for _, e := range list {
		n := mstr(e, "name")
		count[n]++
		if p := mstr(e, "valueFrom", "fieldRef", "fieldPath"); p != "" {
			env[n] = "fieldRef:" + p
			continue
		}
		env[n] = mstr(e, "value")
	}
	return env, count
}

const shimEndpoint = "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566"

func TestApplication_TaskRoleByName(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	spec := map[string]any{"image": "ghcr.io/me/app:1", "port": float64(8080), "assumeRole": "orders-reader",
		"env": []any{map[string]any{"name": "MODE", "value": "fast"}}}

	// The second call, with the install's identity and no account listing the namespace: the role is the
	// install's account's, and the region the install's.
	out := render(t, tmpl, appRoleCtx("orders", "team-a", spec, fnRoleExtra("123456789012", "eu-west-1")))
	dep := appDeployment(t, out, "orders")
	if got := mstr(dep, "spec", "template", "spec", "serviceAccountName"); got != "orders" {
		t.Errorf("the app must run as its own ServiceAccount orders, got %q", got)
	}
	env, count := appEnv(t, dep)
	for k, v := range map[string]string{
		"AWS_ROLE_ARN":                "arn:aws:iam::123456789012:role/orders-reader",
		"AWS_ROLE_SESSION_NAME":       "fieldRef:metadata.name", // the pod: ECS names a task role's session after the task
		"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/openinfra/token",
		"AWS_ENDPOINT_URL_STS":        shimEndpoint,
		"AWS_ENDPOINT_URL":            shimEndpoint,
		"AWS_REGION":                  "eu-west-1",
		"AWS_DEFAULT_REGION":          "eu-west-1",
		"MODE":                        "fast",
	} {
		if env[k] != v {
			t.Errorf("env %s = %q, want %q", k, env[k], v)
		}
		if count[k] != 1 {
			t.Errorf("env %s set %d times, want once", k, count[k])
		}
	}
	// No trace of the forms that never worked: the openinfra-partition ARN, a shim host that does not exist.
	for _, gone := range []string{"arn:openinfra:", "open-infra-aws-shim.open-infra-aws-shim"} {
		if strings.Contains(out, gone) {
			t.Errorf("the render still carries %q:\n%s", gone, grepCtx(out, gone))
		}
	}
	// The token volume: projected for the aws-shim's STS audience, mounted read-only where the env says.
	if !strings.Contains(out, "mountPath: /var/run/secrets/openinfra, readOnly: true") ||
		!strings.Contains(out, "audience: sts.openinfra") || !strings.Contains(out, "path: token") {
		t.Errorf("the projected STS token must be mounted read-only:\n%s", grepCtx(out, "openinfra-sts-token"))
	}
	// The app's identity ServiceAccount, labelled for the aws-shim's check.
	docs, _ := parseYAMLDocs(out)
	sa := objectFor(docs, "ServiceAccount", "orders")
	if sa == nil {
		t.Fatalf("no ServiceAccount rendered:\n%s", out)
	}
	if l := strMap(mget(sa, "spec", "forProvider", "manifest", "metadata", "labels")); l["openinfra.dev/application"] != "orders" ||
		l["app.kubernetes.io/name"] != "orders" {
		t.Errorf("the identity ServiceAccount's labels: %v", l)
	}
	// It asks for the account, the region and the role beside the app, read-only.
	for _, want := range []string{"kind: ExtraResources", "aws-identity:", "matchName: openinfra-aws-identity",
		"accounts:", "kind: Account", "assumed-role:", `crossplane.io/claim-name: "orders-reader"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the extra-resources request lacks %q:\n%s", want, grepCtx(out, "ExtraResources"))
		}
	}
}

// A member account's app: the role is a role of that account (the kind: Account listing the namespace).
func TestApplication_TaskRoleMemberAccount(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	spec := map[string]any{"image": "ghcr.io/me/app:1", "assumeRole": "Reader"}
	extra := fnRoleExtra("000000000000", "us-east-1",
		map[string]any{"accountId": "912345678901", "namespaces": []any{"team-b", "team-b-batch"}},
		map[string]any{"accountId": "923456789012", "namespaces": []any{"team-c"}})
	env, _ := appEnv(t, appDeployment(t, render(t, tmpl, appRoleCtx("worker", "team-b-batch", spec, extra)), "worker"))
	if env["AWS_ROLE_ARN"] != "arn:aws:iam::912345678901:role/Reader" {
		t.Errorf("a member account's app assumes its account's role, got %q", env["AWS_ROLE_ARN"])
	}
	// The ARN's role name keeps its case; the lookup beside the app uses the object's (lower-cased) name.
	if out := render(t, tmpl, appRoleCtx("worker", "team-b-batch", spec, extra)); !strings.Contains(out, `crossplane.io/claim-name: "reader"`) {
		t.Errorf("the role beside the app is looked up by its object name:\n%s", grepCtx(out, "claim-name"))
	}
}

// An ARN of the app's own account is used as given; another account's role is refused, as ECS refuses
// passing another account's role. Before the identity is read (Crossplane's first call), nothing is refused.
func TestApplication_TaskRoleARN(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	own := map[string]any{"image": "ghcr.io/me/app:1", "assumeRole": "arn:aws:iam::123456789012:role/service-role/Reader"}
	env, _ := appEnv(t, appDeployment(t, render(t, tmpl, appRoleCtx("web", "team-a", own, fnRoleExtra("123456789012", "us-east-1"))), "web"))
	if env["AWS_ROLE_ARN"] != "arn:aws:iam::123456789012:role/service-role/Reader" {
		t.Errorf("an ARN of the app's account is used as given, got %q", env["AWS_ROLE_ARN"])
	}
	other := map[string]any{"image": "ghcr.io/me/app:1", "assumeRole": "arn:aws:iam::999999999999:role/Reader"}
	err := renderErr(tmpl, appRoleCtx("web", "team-a", other, fnRoleExtra("123456789012", "us-east-1")))
	if err == nil || !strings.Contains(err.Error(), "is a role of account 999999999999") {
		t.Errorf("another account's role must be refused, got %v", err)
	}
	if err := renderErr(tmpl, appRoleCtx("web", "team-a", other, nil)); err != nil {
		t.Errorf("the first call (no identity yet) must render: %v", err)
	}
}

// The role lookup beside the app is a label selector, so a role name that is no valid label value (an AWS
// name with characters a Kubernetes name cannot hold) is not looked up; the app still renders its role.
func TestApplication_TaskRoleUnlabellableName(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	spec := map[string]any{"image": "ghcr.io/me/app:1", "assumeRole": "deploy+ci@team"}
	out := render(t, tmpl, appRoleCtx("web", "team-a", spec, fnRoleExtra("123456789012", "us-east-1")))
	if strings.Contains(out, "assumed-role:") {
		t.Errorf("a role name that is no label value must not be looked up by label:\n%s", grepCtx(out, "assumed-role"))
	}
	env, _ := appEnv(t, appDeployment(t, out, "web"))
	if env["AWS_ROLE_ARN"] != "arn:aws:iam::123456789012:role/deploy+ci@team" {
		t.Errorf("AWS_ROLE_ARN = %q", env["AWS_ROLE_ARN"])
	}
}
