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
// renders — that binds an openinfra:* subject, except:
//
//   - the break-glass binding (openinfra-root-break-glass), which binds exactly the management
//     account's root and is checked below;
//   - the legacy tier bindings, which carry openinfra.dev/legacy: "true" until the IAM cutover deletes
//     them;
//   - the two legacy compositions listed in legacyCompositionBindings, with their reason.
//
// A new grant of user authority belongs in IAM policy, not in a binding.

const (
	breakGlassBinding = "openinfra-root-break-glass"
	breakGlassSubject = "openinfra:000000000000:root"
)

// legacyCompositionBindings are the composition-rendered bindings to openinfra:* subjects that predate
// IAM policy as the one plane, by file and binding-name prefix, each deleted at the IAM cutover.
var legacyCompositionBindings = map[string]string{
	"platform/abstraction/group-composition.yaml|openinfra-group-": "Group.spec.clusterRole, the legacy permission tier (groups are policy containers after the cutover)",
	"platform/abstraction/grant-composition.yaml|openinfra-grant-": "kind: Grant, time-boxed ClusterRole elevation (replaced by IAM-shaped temporary access)",
}

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
			d := docs[0]
			md, _ := d["metadata"].(map[string]any)
			name := fmt.Sprint(md["name"])
			labels, _ := md["labels"].(map[string]any)
			subjects := userSubjects(d)
			if len(subjects) == 0 {
				continue
			}
			switch {
			case name == breakGlassBinding:
				breakGlassSeen++
				checkBreakGlass(t, rel, d)
			case fmt.Sprint(labels["openinfra.dev/legacy"]) == "true":
			default:
				t.Errorf("%s: %s %s binds %v by hand — user authority is written in IAM policy (the iam-compiler generates the RBAC)", rel, d["kind"], name, subjects)
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
// with a User or Group subject counts as user authority). It returns how many it checked.
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
		if !userSubject {
			continue
		}
		allowed := false
		for k := range legacyCompositionBindings {
			f, prefix, _ := strings.Cut(k, "|")
			if f == file && strings.HasPrefix(name, prefix) {
				allowed = true
			}
		}
		if !allowed {
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

// The check has teeth: an unlabelled binding to an openinfra:* group fails it, a ServiceAccount binding
// does not, and a composition that renders a new user binding fails it.
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
	ft := &testing.T{}
	if checkCompositionBindings(ft, "platform/abstraction/new-composition.yaml", comp); !ft.Failed() {
		t.Fatal("a composition rendering a new user binding must fail the check")
	}
}
