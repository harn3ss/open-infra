package render

// A tenant's free-form strings must never become script text.
//
// Several compositions render shell scripts (setup Jobs, restore scripts, init containers). Pasting a
// claim's string field into one, even inside quotes, lets a quote or a $(…) in that field run commands
// as the Job's identity — a bucket policy containing `'` once reached a root-credentialed shell. The
// rule this test enforces: a free-form string reaches a script only as data (an env value, a mounted
// file, or a positional argument after the script), never inside the script itself.
//
// For every Composition with an inline template, and every string field of its XRD that admission
// does not already restrict (no enum, pattern or format), the test sets that one field to a payload
// carrying shell metacharacters, renders, and fails if the payload's marker appears in a shell `-c`
// script or a script-like ConfigMap entry. A render that refuses the value (a `fail` guard) passes.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

const tenantMarker = "Q7Z"

// tenantPayload carries the characters that break out of shell quoting, and a newline plus a key that
// would add a field to the manifest if the value were pasted into YAML unquoted.
var tenantPayload = tenantMarker + `'"$(id)` + "`id`;\n  injected: " + tenantMarker

type xrdSchema struct {
	file string
	spec map[string]any
}

// loadXRDSchemas maps each composite kind (XFoo) to its first version's spec schema.
func loadXRDSchemas(t *testing.T) map[string]xrdSchema {
	t.Helper()
	out := map[string]xrdSchema{}
	files, _ := filepath.Glob("../../platform/abstraction/*.yaml")
	more, _ := filepath.Glob("../../platform/networking/kube-ovn/*.yaml")
	for _, f := range append(files, more...) {
		b, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(b), "kind: CompositeResourceDefinition") {
			continue
		}
		docs, err := parseYAMLDocs(string(b))
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		for _, d := range docs {
			if d["kind"] != "CompositeResourceDefinition" {
				continue
			}
			spec, _ := d["spec"].(map[string]any)
			names, _ := spec["names"].(map[string]any)
			kind, _ := names["kind"].(string)
			vers, _ := spec["versions"].([]any)
			if kind == "" || len(vers) == 0 {
				continue
			}
			v0, _ := vers[0].(map[string]any)
			s := dig(v0, "schema", "openAPIV3Schema", "properties", "spec")
			if m, ok := s.(map[string]any); ok {
				out[kind] = xrdSchema{file: filepath.Base(f), spec: m}
			}
		}
	}
	return out
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

type compTemplate struct {
	file, kind, tmpl string
}

func loadCompositionTemplates(t *testing.T) []compTemplate {
	t.Helper()
	var out []compTemplate
	files, _ := filepath.Glob("../../platform/abstraction/*.yaml")
	more, _ := filepath.Glob("../../platform/networking/kube-ovn/*.yaml")
	for _, f := range append(files, more...) {
		b, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(b), "kind: Composition\n") || !strings.Contains(string(b), "template: |") {
			continue
		}
		docs, err := parseYAMLDocs(string(b))
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		kind := ""
		for _, d := range docs {
			if d["kind"] == "Composition" {
				kind, _ = dig(d, "spec", "compositeTypeRef", "kind").(string)
			}
		}
		if kind == "" {
			t.Fatalf("%s: no compositeTypeRef.kind", filepath.Base(f))
		}
		out = append(out, compTemplate{file: filepath.Base(f), kind: kind, tmpl: extractInlineTemplate(t, f)})
	}
	return out
}

// sampleFor returns a value admission would accept for a required string, so a base spec renders.
func sampleFor(s map[string]any) (any, bool) {
	switch s["type"] {
	case "integer", "number":
		if m, ok := s["minimum"].(string); ok {
			if n, err := strconv.Atoi(m); err == nil {
				return n, true
			}
		}
		if d, ok := s["default"].(string); ok {
			if n, err := strconv.Atoi(d); err == nil {
				return n, true
			}
		}
		return 1, true
	case "boolean":
		return s["default"] == "true", true
	case "array":
		items, _ := s["items"].(map[string]any)
		if v, ok := sampleFor(items); ok {
			return []any{v}, true
		}
		return []any{}, true
	case "object":
		return baseObject(s), true
	}
	if e, ok := s["enum"].([]any); ok && len(e) > 0 {
		return e[0], true
	}
	if def, ok := s["default"]; ok {
		return def, true
	}
	pat, _ := s["pattern"].(string)
	for _, c := range []string{"abc", "a1", "abc-1", "1", "1Gi", "10.0.0.1", "10.0.0.0/24", "ghcr.io/x/app:latest", "us-east-1", "1h", "app"} {
		if pat == "" {
			return c, true
		}
		if re, err := regexp.Compile(pat); err == nil && re.MatchString(c) {
			return c, true
		}
	}
	return nil, false
}

func baseObject(s map[string]any) map[string]any {
	out := map[string]any{}
	props, _ := s["properties"].(map[string]any)
	req, _ := s["required"].([]any)
	for _, r := range req {
		name, _ := r.(string)
		ps, _ := props[name].(map[string]any)
		if v, ok := sampleFor(ps); ok {
			out[name] = v
		}
	}
	return out
}

// freeStringPaths lists every string field admission accepts any value for, as paths through
// objects ("a.b") and arrays ("a[]"); map values (additionalProperties) are "a{}".
func freeStringPaths(s map[string]any, prefix string, out *[]string) {
	switch s["type"] {
	case "object":
		props, _ := s["properties"].(map[string]any)
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ps, _ := props[k].(map[string]any)
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			freeStringPaths(ps, p, out)
		}
		if ap, ok := s["additionalProperties"].(map[string]any); ok {
			freeStringPaths(ap, prefix+"{}", out)
		}
	case "array":
		if items, ok := s["items"].(map[string]any); ok {
			freeStringPaths(items, prefix+"[]", out)
		}
	case "string":
		if s["enum"] != nil || s["pattern"] != nil || s["format"] != nil || s["x-kubernetes-int-or-string"] == true {
			return
		}
		if ml, ok := s["maxLength"].(string); ok && len(tenantPayload) > atoiOr(ml, 1<<30) {
			return
		}
		*out = append(*out, prefix)
	}
}

func atoiOr(s string, d int) int {
	n := 0
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return d
	}
	return n
}

// setPath writes v at path into spec, creating each missing object or array element from its schema's
// required fields, so the surrounding block renders as it would for a real claim.
func setPath(spec map[string]any, schema map[string]any, path string, v any) {
	cur, cs := spec, schema
	parts := splitPath(path)
	for i, part := range parts {
		last := i == len(parts)-1
		name, kind := part.name, part.kind
		props, _ := cs["properties"].(map[string]any)
		ps, _ := props[name].(map[string]any)
		switch kind {
		case "":
			if last {
				cur[name] = v
				return
			}
			next, ok := cur[name].(map[string]any)
			if !ok {
				next = baseObject(ps)
				cur[name] = next
			}
			cur, cs = next, ps
		case "[]":
			items, _ := ps["items"].(map[string]any)
			if last {
				cur[name] = []any{v}
				return
			}
			el := baseObject(items)
			cur[name] = []any{el}
			cur, cs = el, items
		case "{}":
			ap, _ := ps["additionalProperties"].(map[string]any)
			if last {
				cur[name] = map[string]any{"k1": v}
				return
			}
			el := baseObject(ap)
			cur[name] = map[string]any{"k1": el}
			cur, cs = el, ap
		}
	}
}

type pathPart struct{ name, kind string }

func splitPath(p string) []pathPart {
	var out []pathPart
	for _, seg := range strings.Split(p, ".") {
		switch {
		case strings.HasSuffix(seg, "[]"):
			out = append(out, pathPart{strings.TrimSuffix(seg, "[]"), "[]"})
		case strings.HasSuffix(seg, "{}"):
			out = append(out, pathPart{strings.TrimSuffix(seg, "{}"), "{}"})
		default:
			out = append(out, pathPart{seg, ""})
		}
	}
	// a nested "a[].b" splits as a[] then b; "a{}.b" likewise. Arrays of arrays don't occur.
	return out
}

func tenantCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"apiVersion": "openinfra.dev/v1",
			"spec":       spec,
			"metadata": map[string]any{
				"name": "t1-x7k2p", "uid": "00000000-0000-0000-0000-000000000abc",
				"creationTimestamp": "2026-11-01T00:00:00Z",
				"labels": map[string]any{
					"crossplane.io/claim-name": "t1", "crossplane.io/claim-namespace": "tenant",
				},
			},
		}}},
		"context": map[string]any{},
	}
}

var shells = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true,
	"python": true, "python3": true, "node": true, "perl": true, "ruby": true}

// scriptTexts walks rendered manifests and returns every script body: the argument after `-c`/`-e`
// of a shell or interpreter command (command + args together), and script-like ConfigMap entries.
func scriptTexts(v any, where string, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if cmd, ok := t["command"].([]any); ok {
			all := append(append([]any{}, cmd...), asList(t["args"])...)
			if len(all) > 0 {
				exe, _ := all[0].(string)
				if shells[filepath.Base(exe)] {
					for i := 1; i+1 < len(all); i++ {
						if f, _ := all[i].(string); f == "-c" || f == "-e" || f == "-ec" || f == "-ce" {
							if s, ok := all[i+1].(string); ok {
								*out = append(*out, where+": "+s)
							}
							break
						}
					}
				}
			}
		}
		if t["kind"] == "ConfigMap" {
			if data, ok := t["data"].(map[string]any); ok {
				for k, dv := range data {
					s, _ := dv.(string)
					if strings.HasSuffix(k, ".sh") || strings.HasSuffix(k, ".py") || strings.HasPrefix(s, "#!") {
						*out = append(*out, where+" ConfigMap "+k+": "+s)
					}
				}
			}
		}
		for _, c := range t {
			scriptTexts(c, where, out)
		}
	case []any:
		for _, c := range t {
			scriptTexts(c, where, out)
		}
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// A tenant's free-form string must never reach a shell/interpreter script body (RCE), and must never
// break or inject the rendered manifest (an injected document can be a provider-kubernetes Object,
// applied with the provider's ServiceAccount). For each composition and each XRD string field
// admission does not already constrain, the test sets that one field to a payload of shell/YAML
// metacharacters, renders, and asserts the marker never lands in a script and never corrupts the YAML.
//
// Coverage note: one field is set on a base (minimal) spec, so a field that only renders under a
// deeper condition (e.g. database.restoreFrom) is not exercised here — those fields are guarded at
// admission by an XRD pattern instead (see the SQL-identifier pattern on Application spec.database.name).
func TestTenantStrings_NeverReachScripts(t *testing.T) {
	schemas := loadXRDSchemas(t)
	comps := loadCompositionTemplates(t)
	if len(comps) < 40 {
		t.Fatalf("found only %d compositions with inline templates; the glob is wrong", len(comps))
	}
	checked, refused := 0, 0
	for _, c := range comps {
		sc, ok := schemas[c.kind]
		if !ok {
			t.Errorf("%s: no XRD for composite kind %s", c.file, c.kind)
			continue
		}
		var paths []string
		freeStringPaths(sc.spec, "", &paths)
		for _, p := range paths {
			spec := baseObject(sc.spec)
			setPath(spec, sc.spec, p, tenantPayload)
			out, err := renderTenant(c.tmpl, tenantCtx(spec))
			if err != nil {
				refused++ // a fail guard refused it (or the field gates a branch this base can't render)
				continue
			}
			checked++
			docs, perr := parseYAMLDocs(out)
			if perr != nil || injectedStructure(docs) {
				if strings.Contains(out, tenantMarker) {
					t.Errorf("%s spec.%s: the value breaks or injects the rendered manifest (quote it with | toJson, or add an XRD pattern): %v", c.file, p, perr)
				}
				continue
			}
			var scripts []string
			for _, d := range docs {
				scriptTexts(d, c.file, &scripts)
			}
			for _, s := range scripts {
				if i := strings.Index(s, tenantMarker); i >= 0 {
					lo := strings.LastIndex(s[:i], "\n") + 1
					hi := strings.Index(s[i:], "\n")
					if hi < 0 {
						hi = len(s) - i
					}
					t.Errorf("%s spec.%s reaches script text (pass it as an env value or file instead):\n    %s", c.file, p, strings.TrimSpace(s[lo:i+hi]))
					break
				}
			}
		}
	}
	t.Logf("rendered %d field payloads; %d refused or not reachable from a base spec", checked, refused)
	if checked < 150 {
		t.Errorf("only %d payloads rendered; the base specs no longer reach most templates", checked)
	}
}

// injectedStructure reports whether the tenant marker appears as YAML STRUCTURE (a mapping key or a new
// top-level document) rather than only inside a scalar value — i.e. the payload closed its quoting and
// added structure. A marker inside a quoted value is fine; a marker that became a key is an injection.
func injectedStructure(docs []map[string]any) bool {
	var walk func(any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			for k, c := range t {
				if strings.Contains(k, tenantMarker) {
					return true
				}
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range t {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	for _, d := range docs {
		if walk(d) {
			return true
		}
	}
	return false
}

func renderTenant(tmpl string, ctx any) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var b strings.Builder
	tp, err := template.New("comp").Funcs(sprigLite()).Parse(tmpl)
	if err != nil {
		return "", err
	}
	if err := tp.Execute(&b, ctx); err != nil {
		return "", err
	}
	return b.String(), nil
}
