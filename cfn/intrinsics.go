// Intrinsic-function and condition resolution for the CFN engine (Phase 1).
//
// The resolver walks a value (a resource's Properties, a condition, an output), resolving
// the supported intrinsics and — crucially for the honesty rail — recording a FINDING for
// any intrinsic it does not support (Fn::ImportValue, Fn::Transform, an unknown Fn::*, an
// unknown pseudo-parameter). It never silently passes an unknown intrinsic through. It also
// collects the resource references (Ref / GetAtt / Sub) it sees, which feed dependency
// ordering. Resolved values are best-effort placeholders — Phase 1 is read-only and has no
// live attribute values — since the plan's job is to surface findings and ordering, not to
// produce final property values.
package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Finding is one thing the engine cannot honor — the fail-loud unit.
type Finding struct {
	Where  string // e.g. "Resource MyBucket" or "Condition IsProd"
	Reason string
}

type resolver struct {
	t        *Template
	params   map[string]any
	pseudo   map[string]any
	conds    map[string]bool // evaluated named conditions
	where    string          // current location, for findings
	findings []Finding
	refs     map[string]bool // resource logical ids referenced by the current item
}

func newResolver(t *Template, params, pseudo map[string]any) *resolver {
	return &resolver{t: t, params: params, pseudo: pseudo, conds: map[string]bool{}, refs: map[string]bool{}}
}

func (r *resolver) find(reason string) {
	r.findings = append(r.findings, Finding{Where: r.where, Reason: reason})
}

// evalConditions evaluates every named condition once, up front (so Fn::If and resource
// Condition checks can look them up). A condition using an unsupported intrinsic produces a
// finding and is treated as false.
func (r *resolver) evalConditions() {
	for name, expr := range r.t.Conditions {
		r.where = "Condition " + name
		r.conds[name] = truthy(r.resolve(expr))
	}
}

// resolveResource walks a resource's Properties (for findings) and returns the set of
// resource ids it depends on via Ref/GetAtt/Sub.
func (r *resolver) resolveResource(id string, res Resource) []string {
	r.where = "Resource " + id
	r.refs = map[string]bool{}
	r.resolve(res.Properties)
	var deps []string
	for d := range r.refs {
		if d != id {
			deps = append(deps, d)
		}
	}
	return deps
}

// resolve walks a value, resolving supported intrinsics and recording findings for the rest.
func (r *resolver) resolve(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 1 {
			for k, arg := range t {
				if handled, out := r.intrinsic(k, arg); handled {
					return out
				}
			}
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = r.resolve(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = r.resolve(e)
		}
		return out
	default:
		return v
	}
}

// intrinsic handles a single-key map that may be an intrinsic. Returns handled=false when
// the key is not intrinsic-shaped (a normal property that happens to be a one-key object).
func (r *resolver) intrinsic(key string, arg any) (bool, any) {
	switch key {
	case "Ref":
		return true, r.ref(fmt.Sprint(arg))
	case "Condition":
		name := fmt.Sprint(arg)
		if b, ok := r.conds[name]; ok {
			return true, b
		}
		r.find("references undefined condition " + name)
		return true, false
	case "Fn::GetAtt":
		return true, r.getAtt(arg)
	case "Fn::Sub":
		return true, r.sub(arg)
	case "Fn::Join":
		return true, r.join(arg)
	case "Fn::Select":
		return true, r.selectIdx(arg)
	case "Fn::FindInMap":
		return true, r.findInMap(arg)
	case "Fn::If":
		return true, r.ifFn(arg)
	case "Fn::Equals":
		l := r.list(arg)
		return true, len(l) == 2 && fmt.Sprint(r.resolve(l[0])) == fmt.Sprint(r.resolve(l[1]))
	case "Fn::And":
		for _, c := range r.list(arg) {
			if !truthy(r.resolve(c)) {
				return true, false
			}
		}
		return true, true
	case "Fn::Or":
		for _, c := range r.list(arg) {
			if truthy(r.resolve(c)) {
				return true, true
			}
		}
		return true, false
	case "Fn::Not":
		l := r.list(arg)
		return true, len(l) == 1 && !truthy(r.resolve(l[0]))
	case "Fn::Split":
		l := r.list(arg)
		if len(l) == 2 {
			return true, strings.Split(fmt.Sprint(r.resolve(l[1])), fmt.Sprint(l[0]))
		}
		return true, nil
	case "Fn::Base64":
		// If the inner value fully resolves (no unresolved placeholder), encode it for real so a
		// literal UserData/script translates. Otherwise keep an opaque marker — a value that still
		// carries a reference can't be statically base64-encoded.
		v := fmt.Sprint(r.resolve(arg))
		if !placeholderRe.MatchString(v) {
			return true, base64.StdEncoding.EncodeToString([]byte(v))
		}
		return true, fmt.Sprintf("<base64:%v>", v)
	// Explicitly unsupported intrinsics — fail loud, never pass through.
	case "Fn::ImportValue":
		r.find("Fn::ImportValue (cross-stack import) is not supported in v1")
		return true, "<unsupported:Fn::ImportValue>"
	case "Fn::GetAZs":
		r.find("Fn::GetAZs (AWS availability zones) is not supported")
		return true, "<unsupported:Fn::GetAZs>"
	case "Fn::Cidr":
		r.find("Fn::Cidr is not supported")
		return true, "<unsupported:Fn::Cidr>"
	case "Fn::Transform":
		r.find("Fn::Transform (macros) is not supported")
		return true, "<unsupported:Fn::Transform>"
	}
	if key == "Ref" || strings.HasPrefix(key, "Fn::") {
		r.find("unsupported intrinsic " + key)
		return true, "<unsupported:" + key + ">"
	}
	return false, nil
}

func (r *resolver) ref(name string) any {
	if strings.HasPrefix(name, "AWS::") {
		if v, ok := r.pseudo[name]; ok {
			return v
		}
		r.find("unknown pseudo-parameter " + name)
		return "<" + name + ">"
	}
	if v, ok := r.params[name]; ok {
		return v
	}
	if _, ok := r.t.Resources[name]; ok {
		r.refs[name] = true
		return "<ref:" + name + ">"
	}
	r.find("Ref to undefined name " + name)
	return "<ref:" + name + ">"
}

func (r *resolver) getAtt(arg any) any {
	var id, attr string
	switch a := arg.(type) {
	case []any:
		if len(a) >= 2 {
			id, attr = fmt.Sprint(a[0]), fmt.Sprint(r.resolve(a[1]))
		}
	case string:
		parts := strings.SplitN(a, ".", 2)
		id = parts[0]
		if len(parts) > 1 {
			attr = parts[1]
		}
	}
	if _, ok := r.t.Resources[id]; ok {
		r.refs[id] = true
	} else if id != "" {
		r.find("Fn::GetAtt on undefined resource " + id)
	}
	return "<" + id + "." + attr + ">"
}

func (r *resolver) sub(arg any) any {
	var tmpl string
	extra := map[string]any{}
	switch a := arg.(type) {
	case string:
		tmpl = a
	case []any:
		if len(a) >= 1 {
			tmpl = fmt.Sprint(a[0])
		}
		if len(a) >= 2 {
			if m, ok := a[1].(map[string]any); ok {
				for k, v := range m {
					extra[k] = r.resolve(v)
				}
			}
		}
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '$' && i+1 < len(tmpl) && tmpl[i+1] == '{' {
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				b.WriteByte(tmpl[i])
				continue
			}
			name := tmpl[i+2 : i+end]
			i += end
			if strings.HasPrefix(name, "!") { // ${!Literal} escape
				b.WriteString("${" + name[1:] + "}")
				continue
			}
			if v, ok := extra[name]; ok {
				b.WriteString(fmt.Sprint(v))
			} else if strings.Contains(name, ".") {
				b.WriteString(fmt.Sprint(r.getAtt(name)))
			} else {
				b.WriteString(fmt.Sprint(r.ref(name)))
			}
			continue
		}
		b.WriteByte(tmpl[i])
	}
	return b.String()
}

func (r *resolver) join(arg any) any {
	l := r.list(arg)
	if len(l) != 2 {
		return ""
	}
	delim := fmt.Sprint(l[0])
	items := r.list(r.resolve(l[1]))
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = fmt.Sprint(it)
	}
	return strings.Join(parts, delim)
}

func (r *resolver) selectIdx(arg any) any {
	l := r.list(arg)
	if len(l) != 2 {
		return nil
	}
	items := r.list(r.resolve(l[1]))
	idx := toInt(r.resolve(l[0]))
	if idx < 0 || idx >= len(items) {
		return nil
	}
	return items[idx]
}

func (r *resolver) findInMap(arg any) any {
	l := r.list(arg)
	if len(l) != 3 {
		return nil
	}
	mapName := fmt.Sprint(r.resolve(l[0]))
	top := fmt.Sprint(r.resolve(l[1]))
	second := fmt.Sprint(r.resolve(l[2]))
	m, _ := r.t.Mappings[mapName].(map[string]any)
	tm, _ := m[top].(map[string]any)
	if v, ok := tm[second]; ok {
		return v
	}
	r.find(fmt.Sprintf("Fn::FindInMap [%s,%s,%s] not found", mapName, top, second))
	return nil
}

func (r *resolver) ifFn(arg any) any {
	l := r.list(arg)
	if len(l) != 3 {
		return nil
	}
	name := fmt.Sprint(l[0])
	if r.conds[name] {
		return r.resolve(l[1])
	}
	return r.resolve(l[2])
}

func (r *resolver) list(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func truthy(v any) bool {
	b, _ := v.(bool)
	return b
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		var i int
		fmt.Sscanf(n, "%d", &i)
		return i
	}
	return 0
}
