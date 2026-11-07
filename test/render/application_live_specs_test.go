package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

// The estate canary for an application-composition change: render the platform's REAL Applications through
// the composition before the change and through the working tree's, and require every one that does not use
// the change (sets no spec.assumeRole) to render byte for byte the same — so the change rolls no app's pods.
//
// Opt-in, and run against an export the operator makes; it never reads a cluster:
//
//	LIVE_XR_DIR     a directory of *.json files, each one live XApplication (or Application claim) object as
//	                `kubectl get -o json` prints it (metadata, spec, status), or a List of them (items).
//	OLD_COMPOSITION the base composition, e.g. `git show <base>:platform/abstraction/composition.yaml`.
//
// Run it alone (-run TestLiveApplicationSpecsRenderIdentically): the Function canary reads the same variables.
//
// The specs are customer data, so the test reports COUNTS only. A spec that did not render identically is
// named by a short sha256 of its file name (and its index in a List), never by its name or any of its
// content; template errors (which can quote a spec) are counted, never printed.
//
// Each spec is rendered as Crossplane calls the composition: .observed.composite.resource is the composite
// (a claim is given the claim-name/claim-namespace labels its composite carries), .context is empty (the
// application composition has no environment step), and .extraResources is absent — an Application without
// spec.assumeRole requests none, so Crossplane calls it once without. An Application WITH spec.assumeRole is
// rendered by both compositions with the extra resources the new one requests: the install's identity
// (LIVE_AWS_ACCOUNT_ID, LIVE_AWS_REGION; default 000000000000, us-east-1 — set them to the install's, or a
// role ARN of the install's account reads as another account's), no kind: Account listing its namespace,
// and no role observed beside it. Those are counted apart, by outcome, and expected to differ: their AWS_ROLE_ARN, shim
// endpoint, region, session name and ServiceAccount label change.
//
// Composed resources are not exported (.observed.resources is absent for both renders), so the comparison
// proves what the template change does to these inputs; it does not re-prove the sprig subset's fidelity.
func TestLiveApplicationSpecsRenderIdentically(t *testing.T) {
	dir := os.Getenv("LIVE_XR_DIR")
	if dir == "" {
		t.Skip("set LIVE_XR_DIR to a directory of exported Applications and OLD_COMPOSITION to the base composition")
	}
	oldPath := os.Getenv("OLD_COMPOSITION")
	if oldPath == "" {
		t.Fatal("OLD_COMPOSITION must name the base application composition (git show <base>:platform/abstraction/composition.yaml)")
	}
	oldT := parseQuiet(t, extractInlineTemplate(t, oldPath), "OLD_COMPOSITION")
	newT := parseQuiet(t, extractInlineTemplate(t, compositionPath), "the working-tree composition")
	c := compareLiveApplications(t, dir, oldT, newT)

	t.Logf("live Applications: total %d, identical %d (of which both compositions refuse %d), differing %d, failing-old %d, failing-new %d, failing both differently %d; unreadable %d",
		c.total, c.identical, c.bothRefuse, c.differing, c.failingOld, c.failingNew, c.failingBoth, c.unreadable)
	t.Logf("with spec.assumeRole (expected to change; not a failure): %d — identical %d, differing %d, failing only on the new composition %d, other %d",
		c.withRole, c.roleOutcomes["identical"], c.roleOutcomes["differs"], c.roleOutcomes["fails only on the new composition"],
		len(c.roleChanged)-c.roleOutcomes["differs"]-c.roleOutcomes["fails only on the new composition"])
	t.Logf("with spec.assumeRole that the new XRD pattern would refuse on a CHANGE (an unchanged value is ratcheted; not a failure): %d", c.rolePatternMisses)
	t.Logf("without spec.assumeRole (must be identical): %d, of which changed %d", c.total-c.withRole, len(c.rolelessChanged))
	for _, k := range c.roleChanged {
		t.Logf("  with spec.assumeRole: %s", k)
	}
	for _, k := range c.flagged {
		t.Logf("  unreadable (not an Application object or not JSON): %s", k)
	}
	if c.total == 0 {
		t.Fatalf("no Application objects found in LIVE_XR_DIR")
	}
	if len(c.rolelessChanged) > 0 {
		for _, k := range c.rolelessChanged {
			t.Logf("  WITHOUT spec.assumeRole: %s", k)
		}
		t.Fatalf("%d live Application(s) without spec.assumeRole render differently: each would roll its pods", len(c.rolelessChanged))
	}
}

type appLiveCounts struct {
	liveCounts
	roleOutcomes      map[string]int // the outcome of each spec with assumeRole ("identical" included)
	rolePatternMisses int            // specs whose assumeRole the XRD's pattern does not accept
}

// assumeRolePattern is the XRD's admission pattern for spec.assumeRole.
func assumeRolePattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile("../../platform/abstraction/xrd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ {16}assumeRole:\n(?: {18}.*\n)*? {18}pattern: '([^']+)'`).FindSubmatch(b)
	if m == nil {
		t.Fatal("xrd.yaml: spec.assumeRole has no pattern")
	}
	return regexp.MustCompile(string(m[1]))
}

// compareLiveApplications renders every Application exported in dir through oldT and newT, as the canary
// describes, and counts the outcomes. It reports nothing itself.
func compareLiveApplications(t *testing.T, dir string, oldT, newT *template.Template) appLiveCounts {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("LIVE_XR_DIR holds no *.json files")
	}
	sort.Strings(files)
	pattern := assumeRolePattern(t)

	c := appLiveCounts{roleOutcomes: map[string]int{}}
	for _, f := range files {
		base := filepath.Base(f)
		raw, err := os.ReadFile(f)
		var doc map[string]any
		if err != nil || json.Unmarshal(raw, &doc) != nil {
			c.unreadable++
			c.flagged = append(c.flagged, shortHash(base))
			continue
		}
		objs := []any{doc}
		if items, ok := doc["items"].([]any); ok {
			objs = items
		}
		for i, o := range objs {
			key := shortHash(base)
			if len(objs) > 1 || doc["items"] != nil {
				key += "#" + strconv.Itoa(i)
			}
			xr, ok := liveCompositeOf(o, "XApplication", "Application")
			if !ok {
				c.unreadable++
				c.flagged = append(c.flagged, key)
				continue
			}
			c.total++
			spec, _ := xr["spec"].(map[string]any)
			withRole := spec != nil && spec["assumeRole"] != nil && spec["assumeRole"] != ""
			ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": xr}}, "context": map[string]any{}}
			if withRole {
				c.withRole++
				if s, _ := spec["assumeRole"].(string); !pattern.MatchString(s) {
					c.rolePatternMisses++
				}
				extra := liveRoleExtra()
				extra["assumed-role"] = map[string]any{"items": []any{}}
				ctx = map[string]any{"observed": ctx["observed"], "context": map[string]any{}, "extraResources": extra}
			}
			oldOut, oldErr := execQuiet(oldT, ctx)
			newOut, newErr := execQuiet(newT, ctx)
			outcome := ""
			switch {
			case oldErr == nil && newErr == nil && oldOut == newOut:
				c.identical++
			case oldErr != nil && newErr != nil && oldErr.Error() == newErr.Error():
				c.identical++
				c.bothRefuse++
			case oldErr == nil && newErr == nil:
				c.differing++
				outcome = "differs"
			case oldErr != nil && newErr == nil:
				c.failingOld++
				outcome = "fails only on the old composition"
			case oldErr == nil && newErr != nil:
				c.failingNew++
				outcome = "fails only on the new composition"
			default:
				c.failingBoth++
				outcome = "fails on both, differently"
			}
			if withRole {
				if outcome == "" {
					c.roleOutcomes["identical"]++
					continue
				}
				c.roleOutcomes[outcome]++
				c.roleChanged = append(c.roleChanged, key+" ("+outcome+")")
			} else if outcome != "" {
				c.rolelessChanged = append(c.rolelessChanged, key+" ("+outcome+")")
			}
		}
	}
	return c
}

// The canary's own check, on synthetic exports (no customer data): with the same composition as old and new
// every spec is identical; with an old composition that renders assumeRole-less apps differently, every
// such spec is flagged — by hash, never by name — and the assumeRole specs are counted apart; claims, XRs,
// Lists and non-Application objects are read as the canary says.
func TestLiveApplicationCanary_Harness(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	claim := func(name string, spec map[string]any) map[string]any {
		return map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Application",
			"metadata": map[string]any{"name": name, "namespace": "team-a", "uid": "uid-" + name}, "spec": spec}
	}
	xr := map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "XApplication",
		"metadata": map[string]any{"name": "secret-name-x1", "uid": "uid-x", "labels": map[string]any{
			"crossplane.io/claim-name": "secret-name", "crossplane.io/claim-namespace": "team-b"}},
		"spec": map[string]any{"image": "ghcr.io/me/x:1", "port": float64(8080), "database": map[string]any{"engine": "postgres"}}}
	write("a.json", claim("customer-app", map[string]any{"image": "ghcr.io/me/app:1", "port": float64(8080)}))
	write("b.json", map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{
		claim("worker", map[string]any{"image": "ghcr.io/me/w:1", "queues": []any{"q"}}),
		claim("with-role", map[string]any{"image": "ghcr.io/me/r:1", "assumeRole": "reader"}),
		xr,
	}})
	write("e.json", claim("legacy-role", map[string]any{"image": "ghcr.io/me/r:1", "assumeRole": "arn:openinfra:iam::open-infra:role/reader"}))
	write("c.json", map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Function", "metadata": map[string]any{"name": "f"}, "spec": map[string]any{}})
	if err := os.WriteFile(filepath.Join(dir, "d.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := extractInlineTemplate(t, compositionPath)
	newT := parseQuiet(t, src, "the working-tree composition")
	same := compareLiveApplications(t, dir, newT, newT)
	// The legacy-ARN app fails on both renders alike (another account's role): identical, both refuse.
	if same.total != 5 || same.identical != 5 || same.bothRefuse != 1 || same.withRole != 2 || same.unreadable != 2 ||
		len(same.rolelessChanged) != 0 || len(same.roleChanged) != 0 || same.roleOutcomes["identical"] != 2 ||
		same.rolePatternMisses != 1 {
		t.Errorf("same composition: %+v", same)
	}

	// An old composition whose assumeRole-less render differs (as a regression in the new one would).
	if !strings.Contains(src, "enableServiceLinks: false") {
		t.Fatal("the composition no longer renders enableServiceLinks: false; pick another marker")
	}
	oldT := parseQuiet(t, strings.ReplaceAll(src, "enableServiceLinks: false", "enableServiceLinks: true"), "a changed composition")
	diff := compareLiveApplications(t, dir, oldT, newT)
	if diff.total != 5 || len(diff.rolelessChanged) != 3 || diff.withRole != 2 || len(diff.roleChanged) != 1 ||
		diff.roleOutcomes["differs"] != 1 {
		t.Errorf("a changed composition must flag the 3 assumeRole-less apps and count the assumeRole ones apart: %+v", diff)
	}
	for _, k := range append(append([]string{}, diff.rolelessChanged...), diff.roleChanged...) {
		for _, leak := range []string{"customer-app", "worker", "with-role", "legacy-role", "secret-name", "team-a", "team-b", "ghcr.io", "reader"} {
			if strings.Contains(k, leak) {
				t.Errorf("a flagged spec is reported by its content (%q in %q)", leak, k)
			}
		}
	}
}
