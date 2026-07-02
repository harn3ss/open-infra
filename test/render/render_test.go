package render

// Composition-render assertion tests. These render the ACTUAL committed
// go-templating template out of platform/abstraction/composition.yaml and assert
// on the emitted manifests. They exist because a composition-logic bug shipped to
// production once: the managed-DB CNPG "hibernation" annotation was only added when
// stopped, so pressing Start never wrote "off" and the DB stayed hibernated. A
// render test like TestManagedDB_HibernationAlwaysExplicit would have caught it.
//
// Faithful enough without the Crossplane runtime: composition.yaml uses only the
// sprig funcs re-implemented in sprigLite() (verified: default, sha256sum, trunc,
// dict, list, join). If a future edit introduces another func, Parse fails loudly
// (add it here) rather than silently mis-rendering.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"
)

const compositionPath = "../../platform/abstraction/composition.yaml"

func TestManagedDB_HibernationAlwaysExplicit(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)

	stopped := render(t, tmpl, dbCtx(true, false))
	if !strings.Contains(stopped, `cnpg.io/hibernation: "on"`) {
		t.Errorf("stopped DB must render hibernation \"on\"; got cluster:\n%s", grepCtx(stopped, "hibernation"))
	}

	// The regression guard: a RUNNING db must EXPLICITLY set the annotation to "off".
	// Omitting it does not reliably clear an existing "on" (that was the prod bug).
	running := render(t, tmpl, dbCtx(false, false))
	if !strings.Contains(running, `cnpg.io/hibernation: "off"`) {
		t.Errorf("running DB must render hibernation \"off\" EXPLICITLY (regression: omitting it never clears 'on'); got cluster:\n%s", grepCtx(running, "hibernation"))
	}
	if strings.Contains(running, `cnpg.io/hibernation: "on"`) {
		t.Errorf("running DB must not be hibernated")
	}
}

func TestManagedDB_HAInstancesAndAntiAffinity(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)

	ha := render(t, tmpl, dbCtx(false, true))
	if !strings.Contains(ha, "instances: 2") {
		t.Errorf("HA postgres must render instances: 2; got:\n%s", grepCtx(ha, "instances:"))
	}
	if !strings.Contains(ha, "enablePodAntiAffinity: true") {
		t.Errorf("HA postgres must set required pod anti-affinity (node-local PVs need one instance per node)")
	}

	single := render(t, tmpl, dbCtx(false, false))
	if !strings.Contains(single, "instances: 1") {
		t.Errorf("non-HA postgres must render instances: 1; got:\n%s", grepCtx(single, "instances:"))
	}
	if strings.Contains(single, "enablePodAntiAffinity") {
		t.Errorf("non-HA must not declare anti-affinity")
	}
}

// TestFileShare_NodeIPExternalIPs guards the masquerade-VM escape hatch: when a
// FileShare sets spec.nodeIP, the Service must also bind SMB 445 on that node IP
// (externalIPs) so a NAT'd VM can mount it; without nodeIP it must not.
func TestFileShare_NodeIPExternalIPs(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/fileshare-composition.yaml")

	// 192.0.2.0/24 is the RFC 5737 documentation range — never a real site IP.
	with := render(t, tmpl, fileshareCtx("192.0.2.50"))
	if !strings.Contains(with, "externalIPs: [192.0.2.50]") {
		t.Errorf("nodeIP set must render externalIPs; got:\n%s", grepCtx(with, "type:"))
	}
	without := render(t, tmpl, fileshareCtx(""))
	if strings.Contains(without, "externalIPs") {
		t.Errorf("no nodeIP must not render externalIPs; got:\n%s", grepCtx(without, "type:"))
	}
}

// ---- helpers ----

func fileshareCtx(nodeIP string) map[string]any {
	spec := map[string]any{"size": "100Gi", "expose": true}
	if nodeIP != "" {
		spec["nodeIP"] = nodeIP
	}
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000fs",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "iis-work",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

// dbCtx builds the minimal .observed.composite.resource context that reaches the
// managed-Postgres branch (spec.database.engine defaults to postgres). No image =>
// the workload section is skipped; no storage/securityGroups => those are skipped.
func dbCtx(stopped, ha bool) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"database": map[string]any{
					"engine":           "postgres",
					"name":             "appdb",
					"stopped":          stopped,
					"highAvailability": ha,
				},
			},
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-000000000abc",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "myapp",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

func render(t *testing.T, tmplStr string, ctx any) string {
	t.Helper()
	tmpl, err := template.New("comp").Funcs(sprigLite()).Parse(tmplStr)
	if err != nil {
		t.Fatalf("parse composition template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		t.Fatalf("execute composition template: %v", err)
	}
	return buf.String()
}

// extractInlineTemplate pulls the `template: |` block-scalar body out of the
// composition YAML and dedents it, reproducing the exact string the go-templating
// function receives — no YAML dependency needed.
func extractInlineTemplate(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	start, keyIndent := -1, 0
	for i, ln := range lines {
		trimmed := strings.TrimLeft(ln, " ")
		if strings.HasPrefix(trimmed, "template: |") {
			start = i + 1
			keyIndent = len(ln) - len(trimmed)
			break
		}
	}
	if start < 0 {
		t.Fatalf("no 'template: |' block found in %s", filepath.Base(path))
	}
	contentIndent := -1
	var out []string
	for _, ln := range lines[start:] {
		if strings.TrimSpace(ln) == "" {
			out = append(out, "")
			continue
		}
		ind := len(ln) - len(strings.TrimLeft(ln, " "))
		if ind <= keyIndent {
			break // dedented to a sibling key: block ended
		}
		if contentIndent < 0 {
			contentIndent = ind
		}
		if ind < contentIndent {
			break
		}
		out = append(out, ln[contentIndent:])
	}
	return strings.Join(out, "\n")
}

// grepCtx returns lines around the first match of needle, for readable failures.
func grepCtx(s, needle string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.Contains(ln, needle) {
			lo, hi := i-2, i+3
			if lo < 0 {
				lo = 0
			}
			if hi > len(lines) {
				hi = len(lines)
			}
			return strings.Join(lines[lo:hi], "\n")
		}
	}
	return "(needle " + needle + " not found in output)"
}

// sprigLite implements the exact subset of Sprig funcs composition.yaml uses,
// matching Sprig semantics (piped last-arg convention).
func sprigLite() template.FuncMap {
	return template.FuncMap{
		"default": func(d any, given ...any) any {
			if len(given) == 0 || isEmpty(given[0]) {
				return d
			}
			return given[0]
		},
		"sha256sum": func(s string) string {
			h := sha256.Sum256([]byte(s))
			return hex.EncodeToString(h[:])
		},
		"trunc": func(c int, s string) string {
			if c < 0 {
				if -c > len(s) {
					return s
				}
				return s[len(s)+c:]
			}
			if c > len(s) {
				return s
			}
			return s[:c]
		},
		"dict": func(v ...any) map[string]any {
			d := map[string]any{}
			for i := 0; i+1 < len(v); i += 2 {
				d[fmt.Sprint(v[i])] = v[i+1]
			}
			return d
		},
		"list": func(v ...any) []any { return v },
		"hasKey": func(m map[string]any, k string) bool {
			_, ok := m[k]
			return ok
		},
		"append": func(list any, v any) []any {
			var out []any
			if rv := reflect.ValueOf(list); rv.Kind() == reflect.Slice {
				for i := 0; i < rv.Len(); i++ {
					out = append(out, rv.Index(i).Interface())
				}
			}
			return append(out, v)
		},
		"join": func(sep string, v any) string {
			rv := reflect.ValueOf(v)
			if rv.Kind() != reflect.Slice {
				return ""
			}
			parts := make([]string, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				parts[i] = fmt.Sprint(rv.Index(i).Interface())
			}
			return strings.Join(parts, sep)
		},
	}
}

func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String, reflect.Slice, reflect.Map, reflect.Array:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	}
	return false
}
