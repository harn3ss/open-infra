package render

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// IAM policy is the only place a user's authority is written: the iam-compiler generates the RBAC that
// still enforces underneath (label openinfra.dev/generated-by: iam-compiler), and nothing in the repo may
// grant a console or shim principal (a User or Group named openinfra:*) authority by hand. This check
// fails on any RoleBinding or ClusterRoleBinding under platform/ — a manifest, or one a Composition
// renders — that binds an openinfra:* subject. The one exception is the break-glass binding
// (openinfra-root-break-glass), which binds exactly the management account's root and is checked below.
// There is no other allowance: no label and no composition exempts a binding.
//
// A grant of user authority belongs in IAM policy (a policy attached to a user, group or role, or for a
// while through a kind: Grant), not in a binding.

const (
	breakGlassBinding = "openinfra-root-break-glass"
	breakGlassSubject = "openinfra:000000000000:root"
)

var bindingKind = regexp.MustCompile(`(?m)^\s*kind:\s*(ClusterRoleBinding|RoleBinding)\s*$`)

func TestNoHandWrittenUserAuthority(t *testing.T) {
	var files []string
	if err := filepath.WalkDir("../../platform", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	breakGlassSeen := 0
	checked := 0
	for _, f := range files {
		raw := mustRead(t, f)
		if !bindingKind.MatchString(raw) {
			continue
		}
		rel := strings.TrimPrefix(filepath.ToSlash(f), "../../")
		if regexp.MustCompile(`(?m)^kind:\s*Composition\s*$`).MatchString(raw) {
			checked += checkCompositionBindings(t, rel, raw)
			continue
		}
		for _, doc := range splitDocs(raw) {
			if !regexp.MustCompile(`(?m)^kind:\s*(ClusterRoleBinding|RoleBinding)\s*$`).MatchString(doc) {
				continue
			}
			docs, err := parseYAMLDocs(doc)
			if err != nil || len(docs) != 1 {
				t.Errorf("%s: a binding document this check cannot read (%v): fix the YAML or the reader", rel, err)
				continue
			}
			checked++
			if checkManifestBinding(t, rel, docs[0]) {
				breakGlassSeen++
			}
		}
	}
	if breakGlassSeen != 1 {
		t.Errorf("the break-glass binding %s must exist exactly once, found %d", breakGlassBinding, breakGlassSeen)
	}
	if checked < 5 {
		t.Fatalf("checked only %d bindings: the walk is broken", checked)
	}
	t.Logf("checked %d bindings", checked)
}

// checkManifestBinding checks one binding manifest: a binding of an openinfra:* subject fails, unless it
// is the break-glass binding, which is pinned instead (and reported).
func checkManifestBinding(t *testing.T, file string, d map[string]any) (breakGlass bool) {
	t.Helper()
	md, _ := d["metadata"].(map[string]any)
	name := fmt.Sprint(md["name"])
	subjects := userSubjects(d)
	if len(subjects) == 0 {
		return false
	}
	if name == breakGlassBinding {
		checkBreakGlass(t, file, d)
		return true
	}
	t.Errorf("%s: %s %s binds %v by hand — user authority is written in IAM policy (the iam-compiler generates the RBAC)", file, d["kind"], name, subjects)
	return false
}

// checkBreakGlass pins the break-glass binding: exactly the management account's root, to the console's
// own ClusterRole, nothing else (it is the one hand-written user binding allowed).
func checkBreakGlass(t *testing.T, file string, d map[string]any) {
	t.Helper()
	if d["kind"] != "ClusterRoleBinding" {
		t.Errorf("%s: %s must be a ClusterRoleBinding", file, breakGlassBinding)
	}
	ref, _ := d["roleRef"].(map[string]any)
	if fmt.Sprint(ref["kind"]) != "ClusterRole" || fmt.Sprint(ref["name"]) != "open-infra-console" {
		t.Errorf("%s: %s must bind ClusterRole open-infra-console, got %v", file, breakGlassBinding, ref)
	}
	subs, _ := d["subjects"].([]any)
	if len(subs) != 1 {
		t.Fatalf("%s: %s must bind exactly one subject, got %v", file, breakGlassBinding, subs)
	}
	s, _ := subs[0].(map[string]any)
	if fmt.Sprint(s["kind"]) != "User" || fmt.Sprint(s["name"]) != breakGlassSubject {
		t.Errorf("%s: %s must bind only User %s, got %v", file, breakGlassBinding, breakGlassSubject, s)
	}
}

// userSubjects lists a binding's openinfra:* User and Group subjects.
func userSubjects(d map[string]any) []string {
	var out []string
	subs, _ := d["subjects"].([]any)
	for _, s := range subs {
		m, _ := s.(map[string]any)
		kind, name := fmt.Sprint(m["kind"]), fmt.Sprint(m["name"])
		if (kind == "User" || kind == "Group") && strings.HasPrefix(name, "openinfra:") {
			out = append(out, kind+" "+name)
		}
	}
	return out
}

// checkCompositionBindings checks the bindings a Composition's templates render (read from the template
// text: a templated subject cannot be shown not to be openinfra:*, so any binding a composition renders
// with a User or Group subject counts as user authority, and fails). It returns how many it checked.
func checkCompositionBindings(t *testing.T, file, raw string) int {
	t.Helper()
	lines := strings.Split(raw, "\n")
	n := 0
	for i, ln := range lines {
		if !bindingKind.MatchString(ln) {
			continue
		}
		n++
		name, userSubject := "", false
		for j := i + 1; j < len(lines) && j < i+40; j++ {
			l := strings.TrimSpace(lines[j])
			if l == "---" || strings.HasPrefix(l, "apiVersion:") && j > i+1 {
				break
			}
			if name == "" && strings.HasPrefix(l, "name:") {
				name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "name:")), `"`)
			}
			if strings.HasPrefix(l, "- kind:") || strings.HasPrefix(l, "kind:") {
				k := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(l, "- "), "kind:"))
				if k != "ServiceAccount" && k != "ClusterRole" && k != "Role" {
					userSubject = true
				}
			}
		}
		if userSubject {
			t.Errorf("%s: a Composition renders binding %q with a user or group subject — user authority is written in IAM policy (the iam-compiler generates the RBAC)", file, name)
		}
	}
	return n
}

func splitDocs(raw string) []string {
	var out []string
	var cur []string
	for _, ln := range strings.Split(raw, "\n") {
		if strings.TrimRight(ln, " ") == "---" {
			out = append(out, strings.Join(cur, "\n"))
			cur = nil
			continue
		}
		cur = append(cur, ln)
	}
	return append(out, strings.Join(cur, "\n"))
}

// The check has teeth: a binding to an openinfra:* group fails it (labelled legacy or not), a
// ServiceAccount binding does not, and a composition that renders a user binding fails it — including the
// group and grant compositions' old binding names.
func TestNoHandWrittenUserAuthority_Detects(t *testing.T) {
	bad := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sneaky
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
subjects:
  - kind: Group
    name: openinfra:powerusers
    apiGroup: rbac.authorization.k8s.io`
	docs, err := parseYAMLDocs(bad)
	if err != nil || len(userSubjects(docs[0])) != 1 {
		t.Fatalf("an openinfra:* group subject must be detected: %v %v", err, docs)
	}
	sa := strings.Replace(bad, "- kind: Group\n    name: openinfra:powerusers", "- kind: ServiceAccount\n    name: x\n    namespace: y", 1)
	if docs, _ := parseYAMLDocs(sa); len(userSubjects(docs[0])) != 0 {
		t.Fatal("a ServiceAccount subject is platform-internal, not user authority")
	}
	comp := "kind: Composition\nspec:\n  template: |\n    kind: ClusterRoleBinding\n    metadata:\n      name: openinfra-new-{{ $name }}\n    subjects:\n      - kind: User\n        name: \"openinfra:{{ $name }}\"\n"
	for _, c := range []struct{ file, name string }{
		{"platform/abstraction/new-composition.yaml", "openinfra-new-{{ $name }}"},
		{"platform/abstraction/group-composition.yaml", "openinfra-group-{{ $name }}"},
		{"platform/abstraction/grant-composition.yaml", "openinfra-grant-{{ $name }}"},
	} {
		ft := &testing.T{}
		if checkCompositionBindings(ft, c.file, strings.Replace(comp, "openinfra-new-{{ $name }}", c.name, 1)); !ft.Failed() {
			t.Errorf("%s rendering user binding %s must fail the check", c.file, c.name)
		}
	}
	legacy := strings.Replace(bad, "  name: sneaky\n", "  name: sneaky\n  labels: { openinfra.dev/legacy: \"true\" }\n", 1)
	if !strings.Contains(legacy, "openinfra.dev/legacy") {
		t.Fatal("fixture: the legacy label was not added")
	}
	for _, c := range []struct{ name, doc string }{{"unlabelled", bad}, {"labelled legacy", legacy}} {
		docs, err := parseYAMLDocs(c.doc)
		if err != nil || len(docs) != 1 {
			t.Fatalf("%s: %v", c.name, err)
		}
		ft := &testing.T{}
		if checkManifestBinding(ft, "platform/x.yaml", docs[0]); !ft.Failed() {
			t.Errorf("an %s binding to an openinfra:* group must fail the check", c.name)
		}
	}
	// The break-glass name with any other subject is not the break-glass binding.
	glass := strings.Replace(strings.Replace(bad, "name: sneaky", "name: "+breakGlassBinding, 1),
		"name: cluster-admin", "name: open-infra-console", 1)
	if docs, _ := parseYAMLDocs(glass); len(docs) == 1 {
		ft := &testing.T{}
		if checkManifestBinding(ft, "platform/x.yaml", docs[0]); !ft.Failed() {
			t.Error("the break-glass binding naming a group rather than the management account's root must fail the check")
		}
	}
}
