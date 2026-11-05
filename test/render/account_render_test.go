package render

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// kind: Account (platform/abstraction/account-composition.yaml): a namespace is labeled into its account;
// a member account also gets the isolation baseline, Service Quotas defaults and its
// OrganizationAccountAccessRole; the management account (the install's own) gets the labels only.

func accountCtx(spec map[string]any, managementAccount string) map[string]any {
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account",
		"metadata": map[string]any{"name": spec["accountId"], "uid": "00000000-0000-0000-0000-00000000acc7"},
		"spec":     spec,
	}}}}
	if managementAccount != "" {
		ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"awsAccountId": managementAccount}}
	}
	return ctx
}

func accountDocs(t *testing.T, spec map[string]any, mgmt string) []map[string]any {
	t.Helper()
	out := render(t, extractInlineTemplate(t, "../../platform/abstraction/account-composition.yaml"), accountCtx(spec, mgmt))
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse rendered account: %v\n%s", err, out)
	}
	return docs
}

// byKind collects the manifests the rendered Objects carry, and the composite status, by kind.
func byKind(docs []map[string]any) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, d := range docs {
		if d["kind"] == "Object" {
			if m, ok := mget(d, "spec", "forProvider", "manifest").(map[string]any); ok {
				out[mstr(m, "kind")] = append(out[mstr(m, "kind")], m)
			}
			continue
		}
		out[mstr(d, "kind")] = append(out[mstr(d, "kind")], d)
	}
	return out
}

func objectFor(docs []map[string]any, kind, name string) map[string]any {
	for _, d := range docs {
		if d["kind"] == "Object" && mstr(d, "spec", "forProvider", "manifest", "kind") == kind &&
			mstr(d, "spec", "forProvider", "manifest", "metadata", "name") == name {
			return d
		}
	}
	return nil
}

// The management account renders no namespace Objects: its namespaces are the platform's own, which GitOps
// owns, so their account labels are in their manifests (TestAccount_ManagementNamespacesCarryTheirLabels).
// A provider-kubernetes Object applying labels to them as well would rewrite their last-applied
// configuration, and the next GitOps apply would then remove the labels.
func TestAccount_ManagementAccountRendersNoNamespaceObjects(t *testing.T) {
	docs := accountDocs(t, map[string]any{"accountId": "000000000000",
		"namespaces": []any{"open-infra-console", "open-infra-cfn"}}, "000000000000")
	k := byKind(docs)
	if len(k["Namespace"]) != 0 || len(k["NetworkPolicy"]) != 0 || len(k["ConfigMap"]) != 0 || len(k["Role"]) != 0 {
		t.Fatalf("the management account renders no resources of its own, got %v", keys(k))
	}
	st := k["Account"][0]
	if fmt.Sprint(mget(st, "status", "management")) != "true" || mget(st, "status", "accessRoleArn") != nil {
		t.Errorf("management status %v", st["status"])
	}
}

// The management account's namespaces carry its labels in their own manifests, home included.
func TestAccount_ManagementNamespacesCarryTheirLabels(t *testing.T) {
	want := map[string]string{
		"open-infra-console":      "../../platform/security/hardened-profile.yaml",
		"open-infra-cfn":          "../../platform/aws-shim/aws-shim.yaml",
		"open-infra-ecs":          "../../platform/aws-shim/aws-shim.yaml",
		"open-infra-s3":           "../../platform/aws-shim/aws-shim.yaml",
		"open-infra-ecr":          "../../platform/aws-shim/ecr-registry.yaml",
		"open-infra-rds":          "../../platform/aws-shim/rds-provisioning.yaml",
		"open-infra-open-appsync": "../../platform/open-appsync/open-appsync.yaml",
	}
	for ns, file := range want {
		found := false
		for _, d := range readYAMLDocs(t, file) {
			if mstr(d, "kind") != "Namespace" || mstr(d, "metadata", "name") != ns {
				continue
			}
			found = true
			if mstr(d, "metadata", "labels", "openinfra.dev/account-id") != "000000000000" ||
				mstr(d, "metadata", "labels", "openinfra.dev/account-status") != "ACTIVE" {
				t.Errorf("%s (%s) lacks the management account's labels: %v", ns, file, mget(d, "metadata", "labels"))
			}
			if home := mget(d, "metadata", "labels", "openinfra.dev/account-home") != nil; home != (ns == "open-infra-console") {
				t.Errorf("%s: account-home must be set on open-infra-console only", ns)
			}
		}
		if !found {
			t.Errorf("no Namespace %s in %s", ns, file)
		}
	}
}

// A namespace is labeled through an Object that never deletes it: closing an account keeps its data.
func TestAccount_NamespacesAreNeverDeleted(t *testing.T) {
	docs := accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"}}, "000000000000")
	o := objectFor(docs, "Namespace", "team-a")
	if o == nil {
		t.Fatal("no namespace Object")
	}
	if mstr(o, "spec", "deletionPolicy") != "Orphan" {
		t.Errorf("deletionPolicy %q, want Orphan", mstr(o, "spec", "deletionPolicy"))
	}
	for _, p := range mget(o, "spec", "managementPolicies").([]any) {
		if p == "Delete" || p == "*" {
			t.Errorf("the namespace Object may delete the namespace: %v", mget(o, "spec", "managementPolicies"))
		}
	}
}

func TestAccount_MemberGetsBaselineQuotasAndAccessRole(t *testing.T) {
	docs := accountDocs(t, map[string]any{"accountId": "912345678901",
		"namespaces": []any{"team-a", "team-a-data"}}, "000000000000")
	k := byKind(docs)
	if len(k["Namespace"]) != 2 || len(k["NetworkPolicy"]) != 2 || len(k["ConfigMap"]) != 1 || len(k["Role"]) != 1 {
		t.Fatalf("member account renders %v", keys(k))
	}
	for _, np := range k["NetworkPolicy"] {
		from := mget(np, "spec", "ingress").([]any)[0].(map[string]any)["from"].([]any)
		sameAccount := false
		for _, peer := range from {
			pm := peer.(map[string]any)
			if mstr(pm, "namespaceSelector", "matchLabels", "openinfra.dev/account-id") == "912345678901" {
				sameAccount = true
			}
			if sel, ok := pm["namespaceSelector"].(map[string]any); ok && len(sel) == 0 {
				t.Errorf("an empty namespaceSelector admits every namespace: %v", pm)
			}
		}
		if !sameAccount || mget(np, "spec", "podSelector") == nil {
			t.Errorf("baseline must select every pod and admit the account's own namespaces: %v", np)
		}
	}
	cm := k["ConfigMap"][0]
	if mstr(cm, "metadata", "namespace") != "team-a" || !strings.Contains(mstr(cm, "data", "quotas.json"), "L-B99A9384") {
		t.Errorf("quotas %v", cm)
	}
	role := k["Role"][0]
	trust := mget(role, "spec", "trust").([]any)
	if mstr(role, "metadata", "namespace") != "team-a" || mstr(role, "metadata", "annotations", "openinfra.dev/aws-name") != "OrganizationAccountAccessRole" ||
		len(trust) != 1 || trust[0] != "arn:aws:iam::000000000000:root" {
		t.Errorf("OrganizationAccountAccessRole %v", role)
	}
	st := k["Account"][0]
	if fmt.Sprint(mget(st, "status", "management")) != "false" || mstr(st, "status", "accessRoleArn") != "arn:aws:iam::912345678901:role/OrganizationAccountAccessRole" {
		t.Errorf("member status %v", st["status"])
	}
}

// A member account's applied Service Quotas are the defaults (AWS's codes and names) with spec.serviceQuotas
// over them, and Lambda's concurrent executions becomes the function-concurrency label on every namespace
// of the account (the policy that caps its function pods reads it).
func TestAccount_ServiceQuotasAppliedAndConcurrencyEnforced(t *testing.T) {
	quotasOf := func(k map[string][]map[string]any) map[string]float64 {
		t.Helper()
		var qs []map[string]any
		if err := json.Unmarshal([]byte(mstr(k["ConfigMap"][0], "data", "quotas.json")), &qs); err != nil {
			t.Fatalf("quotas.json: %v", err)
		}
		out := map[string]float64{}
		for _, q := range qs {
			out[fmt.Sprint(q["ServiceCode"], "/", q["QuotaCode"])], _ = q["Value"].(float64)
			if q["QuotaCode"] == "L-0485CB21" && q["QuotaName"] != "Stacks" {
				t.Errorf("CloudFormation's L-0485CB21 is named Stacks, as AWS names it: %v", q["QuotaName"])
			}
		}
		return out
	}
	k := byKind(accountDocs(t, map[string]any{"accountId": "912345678901",
		"namespaces": []any{"team-a", "team-a-data"}}, "000000000000"))
	q := quotasOf(k)
	if q["lambda/L-B99A9384"] != 1000 || q["s3/L-DC2B2D3D"] != 10000 || q["dynamodb/L-F98FE922"] != 2500 || len(q) != 6 {
		t.Errorf("default quotas %v", q)
	}
	for _, ns := range k["Namespace"] {
		if got := mstr(ns, "metadata", "labels", "openinfra.dev/function-concurrency"); got != "1000" {
			t.Errorf("%s: function-concurrency %q, want the Lambda quota 1000", mstr(ns, "metadata", "name"), got)
		}
	}

	k = byKind(accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"},
		"serviceQuotas": []any{map[string]any{"serviceCode": "lambda", "quotaCode": "L-B99A9384", "value": 50},
			map[string]any{"serviceCode": "dynamodb", "quotaCode": "L-F98FE922", "value": 3000}}}, "000000000000"))
	q = quotasOf(k)
	if q["lambda/L-B99A9384"] != 50 || q["dynamodb/L-F98FE922"] != 3000 || q["s3/L-DC2B2D3D"] != 10000 {
		t.Errorf("an approved quota must be applied over the default: %v", q)
	}
	if got := mstr(k["Namespace"][0], "metadata", "labels", "openinfra.dev/function-concurrency"); got != "50" {
		t.Errorf("function-concurrency %q, want the account's Lambda quota 50", got)
	}
}

// The role trusts the install's management account, whatever its id; without the environment it is the
// default account.
func TestAccount_AccessRoleTrustsTheManagementAccount(t *testing.T) {
	docs := accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"}}, "123456789012")
	if trust := mget(byKind(docs)["Role"][0], "spec", "trust").([]any); trust[0] != "arn:aws:iam::123456789012:root" {
		t.Errorf("trust %v", trust)
	}
	// An account whose id is the configured management account's is the management account.
	if k := byKind(accountDocs(t, map[string]any{"accountId": "123456789012", "namespaces": []any{"x"}}, "123456789012")); len(k["Role"]) != 0 {
		t.Error("the management account must not get an access role")
	}
	if trust := mget(byKind(accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"}}, ""))["Role"][0], "spec", "trust").([]any); trust[0] != "arn:aws:iam::000000000000:root" {
		t.Errorf("without the environment the management account is 000000000000, got %v", trust)
	}
}

func TestAccount_IsolationNoneAndSuspended(t *testing.T) {
	k := byKind(accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"},
		"isolation": "none", "suspended": true}, "000000000000"))
	if len(k["NetworkPolicy"]) != 0 {
		t.Error("isolation none renders no baseline")
	}
	if mstr(k["Namespace"][0], "metadata", "labels", "openinfra.dev/account-status") != "SUSPENDED" || mstr(k["Account"][0], "status", "state") != "SUSPENDED" {
		t.Errorf("a suspended account labels its namespaces SUSPENDED: %v / %v", k["Namespace"][0], k["Account"][0]["status"])
	}
}

func TestAccount_RefusesAMalformedAccount(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/account-composition.yaml")
	for _, spec := range []map[string]any{
		{"accountId": "12", "namespaces": []any{"a"}},
		{"accountId": "912345678901", "namespaces": []any{}},
	} {
		if err := renderErr(tmpl, accountCtx(spec, "000000000000")); err == nil {
			t.Errorf("spec %v rendered; want a fail guard", spec)
		}
	}
}

// The file's admission keeps an id and a namespace's account unique, and the providers hold what the
// composition needs (and the RBAC it adds grants no tenant anything).
func TestAccount_AdmissionAndProviderRBAC(t *testing.T) {
	raw, err := os.ReadFile("../../platform/abstraction/account-composition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := parseYAMLDocs(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	vap := map[string]map[string]any{}
	bound := map[string]bool{}
	for _, d := range docs {
		switch d["kind"] {
		case "ValidatingAdmissionPolicy":
			vap[mstr(d, "metadata", "name")] = d
		case "ValidatingAdmissionPolicyBinding":
			bound[mstr(d, "spec", "policyName")] = true
		case "ClusterRoleBinding":
			for _, s := range mget(d, "subjects").([]any) {
				sm := s.(map[string]any)
				if sm["kind"] != "ServiceAccount" || sm["namespace"] != "crossplane-system" {
					t.Errorf("%s binds %v: only the composition's own providers belong here", mstr(d, "metadata", "name"), sm)
				}
			}
		}
	}
	idRule := vap["openinfra-account-named-by-id"]
	if idRule == nil || !strings.Contains(mstr(mget(idRule, "spec", "validations").([]any)[0], "expression"), "object.metadata.name == object.spec.accountId") {
		t.Error("no admission naming an Account by its id")
	}
	owner := vap["openinfra-account-namespace-owner"]
	if owner == nil || !strings.Contains(mstr(mget(owner, "spec", "validations").([]any)[0], "expression"), "system:masters") {
		t.Error("no admission keeping a namespace in its account")
	}
	for name := range vap {
		if !bound[name] {
			t.Errorf("ValidatingAdmissionPolicy %s has no binding, so it enforces nothing", name)
		}
		if mstr(vap[name], "spec", "failurePolicy") != "Fail" {
			t.Errorf("%s must fail closed", name)
		}
	}
}

func keys(m map[string][]map[string]any) map[string]int {
	out := map[string]int{}
	for k, v := range m {
		out[k] = len(v)
	}
	return out
}

// readYAMLDocs reads a multi-document manifest file into maps (the render module's own parser).
func readYAMLDocs(t *testing.T, file string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var out []map[string]any
	for _, d := range splitDocs(string(raw)) {
		docs, err := parseYAMLDocs(d)
		if err != nil {
			continue // a document the subset parser can't read is not a Namespace we look for
		}
		out = append(out, docs...)
	}
	return out
}
