package render

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const loginGuardYAML = "../../platform/aws-shim/login-profile-guard.yaml"

// IAM login profiles (CreateLoginProfile, ChangePassword) keep a user's console password hash in the
// credential store namespace, never the console namespace where root's console-auth Secret lives. The
// admission guard pins that: the aws-shim writes no Secret in the console namespace, and in the store a
// login profile is exactly an iam-login-* Secret labelled as one. Its CEL is evaluated case by case in
// test/admission; this pins the objects, their scope and that they fail closed.
func TestLoginProfileGuard_Objects(t *testing.T) {
	p := yamlDoc(t, loginGuardYAML, "ValidatingAdmissionPolicy", "openinfra-login-profile-guard")
	mustContain(t, "login-profile guard", p,
		"failurePolicy: Fail",
		`apiGroups: [""]`, `resources: ["secrets"]`, `operations: ["CREATE", "UPDATE", "DELETE"]`,
		"request.namespace == 'open-infra-console' || request.namespace == 'open-infra-aws-shim'",
		"request.userInfo.username == 'system:serviceaccount:open-infra-aws-shim:aws-shim'",
		"request.operation == 'DELETE' ? oldObject : object",
		"startsWith('iam-login-')", "'openinfra.dev/login-profile'",
		"'openinfra.dev/iam-user'", "'openinfra.dev/iam-user-namespace'",
		"startsWith('iam-password-policy-')", "'openinfra.dev/password-policy'", "'openinfra.dev/account-id'")
	b := yamlDoc(t, loginGuardYAML, "ValidatingAdmissionPolicyBinding", "openinfra-login-profile-guard")
	mustContain(t, "login-profile guard binding", b, "policyName: openinfra-login-profile-guard", "validationActions: [Deny]")
	if strings.Contains(b, "matchResources") || strings.Contains(b, "paramRef") {
		t.Errorf("the binding must apply the policy as written: no matchResources or paramRef narrowing it")
	}
}

var rbacKind = regexp.MustCompile(`(?m)^kind: (Role|ClusterRole|RoleBinding|ClusterRoleBinding)\s*$`)

// The aws-shim holds no Secret rights in the console namespace — not through a Role there, and not
// through any ClusterRole bound cluster-wide — so it can neither read nor write root's console-auth.
// Every RBAC object under platform/ is read; a binding to the shim whose role is not found, or an RBAC
// document naming the shim that cannot be read, fails rather than passes unexamined.
func TestAWSShim_NoSecretRightsInTheConsoleNamespace(t *testing.T) {
	roles := map[string]map[string]any{}
	var bindings []map[string]any
	err := filepath.WalkDir("../../platform", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, doc := range splitDocs(string(raw)) {
			m := rbacKind.FindStringSubmatch(doc)
			if m == nil {
				continue
			}
			parsed, perr := parseYAMLDocs(doc)
			if perr != nil || len(parsed) != 1 {
				if strings.Contains(doc, "aws-shim") {
					t.Errorf("%s: an RBAC document naming the aws-shim could not be read: %v", path, perr)
				}
				continue
			}
			o := parsed[0]
			meta, _ := o["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			ns, _ := meta["namespace"].(string)
			switch m[1] {
			case "Role":
				roles["Role/"+ns+"/"+name] = o
			case "ClusterRole":
				roles["ClusterRole/"+name] = o
			default:
				bindings = append(bindings, o)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	examined := 0
	for _, b := range bindings {
		if !bindsShim(b) {
			continue
		}
		examined++
		meta, _ := b["metadata"].(map[string]any)
		ns, _ := meta["namespace"].(string)
		ref, _ := b["roleRef"].(map[string]any)
		refKind, _ := ref["kind"].(string)
		refName, _ := ref["name"].(string)
		key := "ClusterRole/" + refName
		if refKind == "Role" {
			key = "Role/" + ns + "/" + refName
		}
		role, ok := roles[key]
		if !ok {
			t.Errorf("binding %v binds the aws-shim to %s, which is not in platform/ — its rights cannot be checked", meta["name"], key)
			continue
		}
		clusterWide := b["kind"] == "ClusterRoleBinding"
		if (clusterWide || ns == "open-infra-console") && grantsSecrets(role) {
			where := "in the console namespace"
			if clusterWide {
				where = "cluster-wide"
			}
			t.Errorf("binding %v grants the aws-shim Secrets %s through %s: it could reach root's console-auth", meta["name"], where, key)
		}
	}
	if examined == 0 {
		t.Fatalf("found no binding to the aws-shim's ServiceAccount: the scan is not reading the manifests")
	}
}

func bindsShim(b map[string]any) bool {
	subs, _ := b["subjects"].([]any)
	for _, s := range subs {
		m, _ := s.(map[string]any)
		if m["kind"] == "ServiceAccount" && m["name"] == "aws-shim" && m["namespace"] == "open-infra-aws-shim" {
			return true
		}
	}
	return false
}

// grantsSecrets reports whether any rule of the role reaches core Secrets (by name or by wildcard).
func grantsSecrets(role map[string]any) bool {
	rules, _ := role["rules"].([]any)
	for _, r := range rules {
		m, _ := r.(map[string]any)
		groups, _ := m["apiGroups"].([]any)
		resources, _ := m["resources"].([]any)
		core := false
		for _, g := range groups {
			if g == "" || g == "*" {
				core = true
			}
		}
		for _, res := range resources {
			if core && (res == "secrets" || res == "*") {
				return true
			}
		}
	}
	return false
}
