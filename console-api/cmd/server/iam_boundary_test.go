package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestPolicyBoundaryNoDrift enforces that the permission boundary — the openinfra.dev
// surface a kind: Policy may grant on — is identical in the FIVE places it is currently
// hand-maintained, against one curated source of truth (platform/abstraction/policy-boundary.yaml).
//
// Today these five drift silently, and the two that actually enforce anything at runtime (the
// composition and the provider RBAC) are the two nothing checks. This makes any disagreement a
// build failure that names the offending file, and — assertion 1 — turns "add an XRD" into a
// conscious decision to place the new kind in `boundary` or `excluded`, so a new kind can never
// silently widen a security boundary.
//
// It also folds in the built-in-groups mirror (mirror group 3): builtinGroups plus the `users`
// sentinel must equal the impersonator ClusterRole's resourceNames.
//
// Lives here, in package main, because assertions 5 and 6 compare against Go symbols
// (policyResources, builtinGroups) that a test outside this package could only read as text.

// platformDir is the repo's platform/ tree, relative to this test's working directory
// (console-api/cmd/server): up to console-api, up to the repo root, then platform.
const platformDir = "../../../platform"

func TestPolicyBoundaryNoDrift(t *testing.T) {
	bnd := loadBoundaryFile(t)
	boundary := bnd.boundary
	excluded := bnd.excluded

	// ── 2. boundary and excluded are disjoint (check first — the others assume it) ──
	t.Run("boundary_and_excluded_disjoint", func(t *testing.T) {
		set := toSet(boundary)
		for _, e := range excluded {
			if set[e] {
				t.Errorf("%q is in BOTH boundary and excluded — it must be in exactly one", e)
			}
		}
	})

	// ── 1. boundary ∪ excluded == every XRD claim plural ──
	t.Run("covers_every_xrd", func(t *testing.T) {
		plurals := allXRDClaimPlurals(t)
		declared := append(append([]string{}, boundary...), excluded...)
		if msg := diffSets("XRD claim plurals", declared, plurals,
			"add it to boundary (grantable) or excluded (with a reason) in policy-boundary.yaml"); msg != "" {
			t.Error(msg)
		}
	})

	// ── excluded reasons must be present (a name without a reason is a future mystery) ──
	t.Run("excluded_reasons_present", func(t *testing.T) {
		for name, reason := range bnd.excludedReasons {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("excluded %q has no reason — every exclusion must say why", name)
			}
		}
	})

	// ── 3. the $known dict in policy-composition.yaml == boundary (compile-time drop) ──
	t.Run("composition_known_matches", func(t *testing.T) {
		got := knownDictKeys(t)
		if msg := diffSets("policy-composition.yaml $known", got, boundary,
			"edit the $known dict on line ~43 of policy-composition.yaml"); msg != "" {
			t.Error(msg)
		}
	})

	// ── 4. the openinfra.dev resources in provider-setup.yaml == boundary (API-server fence) ──
	t.Run("provider_rbac_matches", func(t *testing.T) {
		got := providerOpenInfraResources(t)
		if msg := diffSets("provider-setup.yaml openinfra.dev resources", got, boundary,
			"edit the `- apiGroups: [openinfra.dev]` rule in provider-setup.yaml"); msg != "" {
			t.Error(msg)
		}
	})

	// ── 5. policyResources (the Go symbol) == boundary (BFF pre-validation) ──
	t.Run("bff_policyResources_matches", func(t *testing.T) {
		if msg := diffSets("policyResources (iam_policies.go)", policyResources, boundary,
			"edit the policyResources slice in iam_policies.go"); msg != "" {
			t.Error(msg)
		}
	})

	// ── 6. builtinGroups ∪ {users} == impersonator resourceNames (mirror group 3) ──
	t.Run("builtin_groups_match_impersonator", func(t *testing.T) {
		pinned := impersonatorGroupResourceNames(t) // e.g. openinfra:admins → admins
		// The `users` group is the auto-appended sentinel every identity lands in; it is
		// pinned in the impersonator but is NOT a selectable builtinGroup, so it is named
		// here explicitly rather than silently ignored.
		want := append(append([]string{}, builtinGroups...), "users")
		if msg := diffSets("impersonator group resourceNames (rbac-roles.yaml, minus openinfra: prefix)",
			pinned, want,
			"a pinned group is missing from builtinGroups (or vice versa) — if you pinned a new "+
				"impersonable group, add it to builtinGroups in iam.go; `users` is the known sentinel"); msg != "" {
			t.Error(msg)
		}
	})
}

// ── source-of-truth file ──────────────────────────────────────────────────────────

type boundaryData struct {
	boundary        []string
	excluded        []string
	excludedReasons map[string]string
}

func loadBoundaryFile(t *testing.T) boundaryData {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(platformDir, "abstraction", "policy-boundary.yaml"))
	if err != nil {
		t.Fatalf("read policy-boundary.yaml: %v", err)
	}
	var doc struct {
		Boundary []string            `json:"boundary"`
		Excluded []map[string]string `json:"excluded"` // list of single-key {name: reason}
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse policy-boundary.yaml: %v", err)
	}
	d := boundaryData{boundary: doc.Boundary, excludedReasons: map[string]string{}}
	for _, m := range doc.Excluded {
		for name, reason := range m {
			d.excluded = append(d.excluded, name)
			d.excludedReasons[name] = reason
		}
	}
	return d
}

// ── XRD claim plurals ─────────────────────────────────────────────────────────────

func allXRDClaimPlurals(t *testing.T) []string {
	t.Helper()
	// NOTE the glob: `*xrd.yaml`, not `*-xrd.yaml`. The Application XRD is the unprefixed
	// `xrd.yaml`, which a `*-xrd.yaml` glob silently misses — the exact bug this whole test
	// exists to prevent, so getting the glob right here is not optional.
	matches, err := filepath.Glob(filepath.Join(platformDir, "abstraction", "*xrd.yaml"))
	if err != nil {
		t.Fatalf("glob XRDs: %v", err)
	}
	if len(matches) < 15 {
		t.Fatalf("found only %d XRDs — the glob is wrong or the tree moved", len(matches))
	}
	var plurals []string
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("read %s: %v", m, err)
		}
		var xrd struct {
			Spec struct {
				ClaimNames struct {
					Plural string `json:"plural"`
				} `json:"claimNames"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &xrd); err != nil {
			t.Fatalf("parse %s: %v", m, err)
		}
		if p := xrd.Spec.ClaimNames.Plural; p != "" {
			plurals = append(plurals, p)
		} else {
			t.Errorf("%s has no spec.claimNames.plural", filepath.Base(m))
		}
	}
	return plurals
}

// ── $known dict in the composition ────────────────────────────────────────────────

var knownKeyRe = regexp.MustCompile(`"([a-z0-9]+)"\s+true`)

func knownDictKeys(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(platformDir, "abstraction", "policy-composition.yaml"))
	if err != nil {
		t.Fatalf("read policy-composition.yaml: %v", err)
	}
	// The dict is `{{- $known := dict "applications" true "functions" true ... }}` — every
	// key is a quoted token immediately followed by ` true`.
	idx := strings.Index(string(raw), "$known := dict")
	if idx < 0 {
		t.Fatal("could not find `$known := dict` in policy-composition.yaml")
	}
	// Bound the search to that template line so we don't pick up unrelated `"x" true` text.
	line := string(raw)[idx:]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	var keys []string
	for _, m := range knownKeyRe.FindAllStringSubmatch(line, -1) {
		keys = append(keys, m[1])
	}
	return keys
}

// ── RBAC docs (provider-setup.yaml, rbac-roles.yaml) ──────────────────────────────

type rbacRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames"`
}

type clusterRoleDoc struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Rules []rbacRule `json:"rules"`
}

// clusterRoles parses a multi-document YAML file into its ClusterRole documents.
func clusterRoles(t *testing.T, path string) []clusterRoleDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []clusterRoleDoc
	for _, doc := range splitYAMLDocs(string(raw)) {
		var cr clusterRoleDoc
		if err := yaml.Unmarshal([]byte(doc), &cr); err != nil {
			continue // non-ClusterRole docs (ProviderConfig, bindings, …) may not fit; skip
		}
		if cr.Kind == "ClusterRole" {
			out = append(out, cr)
		}
	}
	return out
}

func providerOpenInfraResources(t *testing.T) []string {
	t.Helper()
	for _, cr := range clusterRoles(t, filepath.Join(platformDir, "abstraction", "provider-setup.yaml")) {
		if cr.Metadata.Name != "openinfra-provider-kubernetes" {
			continue
		}
		for _, r := range cr.Rules {
			if contains(r.APIGroups, "openinfra.dev") {
				return r.Resources
			}
		}
	}
	t.Fatal("no openinfra.dev rule found on ClusterRole openinfra-provider-kubernetes")
	return nil
}

func impersonatorGroupResourceNames(t *testing.T) []string {
	t.Helper()
	for _, cr := range clusterRoles(t, filepath.Join(platformDir, "console", "manifests", "rbac-roles.yaml")) {
		if cr.Metadata.Name != "open-infra-console-impersonator" {
			continue
		}
		for _, r := range cr.Rules {
			if contains(r.Resources, "groups") && contains(r.Verbs, "impersonate") {
				var out []string
				for _, n := range r.ResourceNames {
					out = append(out, strings.TrimPrefix(n, "openinfra:"))
				}
				return out
			}
		}
	}
	t.Fatal("no impersonate-groups rule found on ClusterRole open-infra-console-impersonator")
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────────

func splitYAMLDocs(s string) []string {
	// Split on lines that are exactly `---` (the YAML document separator).
	re := regexp.MustCompile(`(?m)^---\s*$`)
	return re.Split(s, -1)
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// diffSets returns "" when got and want are equal as sets, else a message naming what is
// missing from got and what got has extra, plus a fix hint.
func diffSets(label string, got, want []string, hint string) string {
	gs, ws := toSet(got), toSet(want)
	var missing, extra []string
	for w := range ws {
		if !gs[w] {
			missing = append(missing, w)
		}
	}
	for g := range gs {
		if !ws[g] {
			extra = append(extra, g)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	sort.Strings(missing)
	sort.Strings(extra)
	msg := label + " drifted from the boundary:"
	if len(missing) > 0 {
		msg += "\n  missing: " + strings.Join(missing, ", ")
	}
	if len(extra) > 0 {
		msg += "\n  extra:   " + strings.Join(extra, ", ")
	}
	if hint != "" {
		msg += "\n  fix: " + hint
	}
	return msg
}
