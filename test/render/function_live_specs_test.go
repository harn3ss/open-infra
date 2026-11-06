package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"text/template"
)

// The estate canary for a function-composition change: render the platform's REAL Functions through the
// composition before the change and through the working tree's, and require every one that does not use the
// change (sets no spec.role) to render byte for byte the same — so the change rolls no revision of them.
//
// Opt-in, and run against an export the operator makes; it never reads a cluster:
//
//	LIVE_XR_DIR    a directory of *.json files, each one live XFunction (or Function claim) object as
//	               `kubectl get -o json` prints it (metadata, spec, status), or a List of them (items).
//	OLD_COMPOSITION the base composition, e.g. `git show <base>:platform/abstraction/function-composition.yaml`.
//
// The specs are customer data, so the test reports COUNTS only. A spec that did not render identically is
// named by a short sha256 of its file name (and its index in a List), never by its name or any of its
// content; template errors (which can quote a spec) are counted, never printed.
//
// Each spec is rendered as Crossplane calls the composition: .observed.composite.resource is the composite
// (a claim is given the claim-name/claim-namespace labels its composite carries), .context is empty (the
// function composition has no environment step), and .extraResources is absent — a Function without
// spec.role requests none, so Crossplane calls it once without. A Function with spec.role (which only the
// new composition knows) is rendered by the new one with the extra resources it requests: the install's
// identity (LIVE_AWS_ACCOUNT_ID, LIVE_AWS_REGION; default 000000000000, us-east-1) and no kind: Account
// listing its namespace. Those are counted apart, and expected to differ.
//
// Both renders use this package's sprig subset, so the comparison proves what the template change does to
// these inputs; it does not re-prove the subset's fidelity to Sprig.
func TestLiveSpecsRenderIdentically(t *testing.T) {
	dir := os.Getenv("LIVE_XR_DIR")
	if dir == "" {
		t.Skip("set LIVE_XR_DIR to a directory of exported Functions and OLD_COMPOSITION to the base composition")
	}
	oldPath := os.Getenv("OLD_COMPOSITION")
	if oldPath == "" {
		t.Fatal("OLD_COMPOSITION must name the base function composition (git show <base>:platform/abstraction/function-composition.yaml)")
	}
	oldT := parseQuiet(t, extractInlineTemplate(t, oldPath), "OLD_COMPOSITION")
	newT := parseQuiet(t, extractInlineTemplate(t, functionCompositionPath), "the working-tree composition")

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("LIVE_XR_DIR holds no *.json files")
	}
	sort.Strings(files)

	var c liveCounts
	flag := func(bucket *[]string, key string) { *bucket = append(*bucket, key) }
	for _, f := range files {
		base := filepath.Base(f)
		raw, err := os.ReadFile(f)
		if err != nil {
			c.unreadable++
			flag(&c.flagged, shortHash(base))
			continue
		}
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			c.unreadable++
			flag(&c.flagged, shortHash(base))
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
			xr, ok := liveComposite(o)
			if !ok {
				c.unreadable++
				flag(&c.flagged, key)
				continue
			}
			c.total++
			spec, _ := xr["spec"].(map[string]any)
			withRole := spec != nil && spec["role"] != nil && spec["role"] != ""
			oldCtx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": xr}}, "context": map[string]any{}}
			newCtx := oldCtx
			if withRole {
				c.withRole++
				newCtx = map[string]any{"observed": oldCtx["observed"], "context": map[string]any{}, "extraResources": liveRoleExtra()}
			}
			oldOut, oldErr := execQuiet(oldT, oldCtx)
			newOut, newErr := execQuiet(newT, newCtx)
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
			if outcome == "" {
				continue
			}
			if withRole {
				c.roleChanged = append(c.roleChanged, key+" ("+outcome+")")
			} else {
				c.rolelessChanged = append(c.rolelessChanged, key+" ("+outcome+")")
			}
		}
	}

	t.Logf("live Functions: total %d, identical %d (of which both compositions refuse %d), differing %d, failing-old %d, failing-new %d, failing both differently %d; unreadable %d",
		c.total, c.identical, c.bothRefuse, c.differing, c.failingOld, c.failingNew, c.failingBoth, c.unreadable)
	t.Logf("with spec.role (expected to differ; not a failure): %d, of which changed %d", c.withRole, len(c.roleChanged))
	for _, k := range c.roleChanged {
		t.Logf("  with spec.role: %s", k)
	}
	for _, k := range c.flagged {
		t.Logf("  unreadable (not a Function object or not JSON): %s", k)
	}
	if c.total == 0 {
		t.Fatalf("no Function objects found in LIVE_XR_DIR")
	}
	if len(c.rolelessChanged) > 0 {
		for _, k := range c.rolelessChanged {
			t.Logf("  WITHOUT spec.role: %s", k)
		}
		t.Fatalf("%d live Function(s) without spec.role render differently: each would roll a new revision", len(c.rolelessChanged))
	}
}

type liveCounts struct {
	total, identical, bothRefuse, differing, failingOld, failingNew, failingBoth, unreadable, withRole int
	rolelessChanged, roleChanged, flagged                                                              []string
}

// liveComposite turns an exported object into the composite the composition is called with: an XFunction
// as it is; a Function claim given the claim labels its composite carries.
func liveComposite(o any) (map[string]any, bool) {
	m, ok := o.(map[string]any)
	if !ok {
		return nil, false
	}
	md, _ := m["metadata"].(map[string]any)
	if md == nil || m["spec"] == nil {
		return nil, false
	}
	switch m["kind"] {
	case "XFunction":
		return m, true
	case "Function":
		labels := map[string]any{}
		if l, ok := md["labels"].(map[string]any); ok {
			for k, v := range l {
				labels[k] = v
			}
		}
		labels["crossplane.io/claim-name"] = md["name"]
		labels["crossplane.io/claim-namespace"] = md["namespace"]
		xmd := map[string]any{}
		for k, v := range md {
			xmd[k] = v
		}
		xmd["labels"] = labels
		xr := map[string]any{}
		for k, v := range m {
			xr[k] = v
		}
		xr["kind"], xr["metadata"] = "XFunction", xmd
		return xr, true
	}
	return nil, false
}

// liveRoleExtra is what Crossplane hands a Function with spec.role on its second call: the install's
// identity and the kinds: Account (none listing the namespace).
func liveRoleExtra() map[string]any {
	acct := os.Getenv("LIVE_AWS_ACCOUNT_ID")
	if acct == "" {
		acct = "000000000000"
	}
	region := os.Getenv("LIVE_AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	return map[string]any{
		"aws-identity": map[string]any{"items": []any{map[string]any{"resource": map[string]any{
			"data": map[string]any{"awsAccountId": acct, "awsRegion": region}}}}},
		"accounts": map[string]any{"items": []any{}},
	}
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func parseQuiet(t *testing.T, src, what string) *template.Template {
	t.Helper()
	tmpl, err := template.New("comp").Funcs(sprigLite()).Parse(src)
	if err != nil {
		t.Fatalf("%s does not parse: %v", what, err)
	}
	return tmpl
}

// execQuiet renders without failing the test or logging: an error may quote the spec, so it is only compared.
func execQuiet(tmpl *template.Template, ctx any) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, ctx)
	return buf.String(), err
}
