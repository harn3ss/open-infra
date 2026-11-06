package render

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Service-linked roles (console-api/internal/iamcompile/servicelinked.go) are what a platform service
// does in a member account. The IAM compiler binds them in every member account's home and compiles the
// same grant into the iam-corpus, which the authorization webhook honours for those ServiceAccounts.
// Each is a ClusterRole named openinfra:service-linked:<service>, labelled, and naming its
// ServiceAccounts. Only the compiler binds one: a manifest binding it would grant it cluster-wide, or
// in the management account. None may grant what would let a service widen its own power: RBAC objects,
// impersonation, escalate/bind, or a wildcard.
func TestServiceLinkedRolesAreCompilerBoundAndNarrow(t *testing.T) {
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
	kindRe := regexp.MustCompile(`(?m)^kind:\s*(\S+)\s*$`)
	nameRe := regexp.MustCompile(`(?m)^  name:\s*"?([^"\s]+)"?\s*$`)
	principalsRe := regexp.MustCompile(`openinfra\.dev/service-principals:\s*([a-z0-9-]+/[a-z0-9.-]+(,[a-z0-9-]+/[a-z0-9.-]+)*)\s*[},\n]`)
	forbidden := regexp.MustCompile(`(?m)(\*|rbac\.authorization\.k8s\.io|\bimpersonate\b|\bescalate\b|\bbind\b|\bnodes\b|\bnamespaces\b|serviceaccounts/token)`)
	found := map[string]bool{}
	for _, f := range files {
		raw := mustRead(t, f)
		if !strings.Contains(raw, "service-linked") {
			continue
		}
		rel := strings.TrimPrefix(filepath.ToSlash(f), "../../")
		for _, doc := range splitDocs(raw) {
			km := kindRe.FindStringSubmatch(doc)
			if km == nil {
				continue
			}
			switch km[1] {
			case "ClusterRole":
				if !strings.Contains(doc, `openinfra.dev/service-linked-role: "true"`) {
					if strings.Contains(doc, "openinfra:service-linked:") {
						t.Errorf("%s: a ClusterRole named as service-linked must carry the label", rel)
					}
					continue
				}
				nm := nameRe.FindStringSubmatch(doc)
				if nm == nil || !strings.HasPrefix(nm[1], "openinfra:service-linked:") {
					t.Errorf("%s: a service-linked ClusterRole must be named openinfra:service-linked:<service>, got %v", rel, nm)
					continue
				}
				found[nm[1]] = true
				if !principalsRe.MatchString(doc) {
					t.Errorf("%s %s: openinfra.dev/service-principals must name <namespace>/<serviceaccount>[,...]", rel, nm[1])
				}
				_, rules, _ := strings.Cut(doc, "\nrules:\n")
				var body []string
				for _, l := range strings.Split(rules, "\n") {
					if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
						body = append(body, l)
					}
				}
				if m := forbidden.FindString(strings.Join(body, "\n")); m != "" {
					t.Errorf("%s %s: a service-linked role may not grant %q", rel, nm[1], m)
				}
			case "ClusterRoleBinding", "RoleBinding", "Composition":
				if strings.Contains(doc, "openinfra:service-linked:") {
					t.Errorf("%s: a %s names a service-linked role; only the IAM compiler binds one (in member account homes)", rel, km[1])
				}
			}
		}
	}
	for _, want := range []string{"openinfra:service-linked:aws-shim", "openinfra:service-linked:statemachine"} {
		if !found[want] {
			t.Errorf("service-linked role %s not found in the platform manifests", want)
		}
	}
}
