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
package cfn

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
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
	exports  map[string]any // cross-stack Exports supplied to Fn::ImportValue (export name -> value)
	pseudo   map[string]any
	conds    map[string]bool // evaluated named conditions
	where    string          // current location, for findings
	findings []Finding
	refs     map[string]bool // resource logical ids referenced by the current item
}

func newResolver(t *Template, params, exports, pseudo map[string]any) *resolver {
	if exports == nil {
		exports = map[string]any{}
	}
	return &resolver{t: t, params: params, exports: exports, pseudo: pseudo, conds: map[string]bool{}, refs: map[string]bool{}}
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
	case "Fn::ImportValue":
		return true, r.importValue(arg)
	case "Fn::GetAZs":
		return true, r.getAZs(arg)
	case "Fn::Cidr":
		return true, r.cidr(arg)
	// Explicitly unsupported intrinsics — fail loud, never pass through.
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

// importValue resolves Fn::ImportValue against the cross-stack Exports supplied to the engine (export
// name -> value, passed with -import NAME=VALUE / an exports file). An export that was not supplied is
// a FINDING, never a faked value — the engine stays fail-loud; the operator supplies the exporting
// stacks' output values. (AWS resolves these from the account's live exports; a stateless CLI resolves
// them from what it is given.)
func (r *resolver) importValue(arg any) any {
	name := fmt.Sprint(r.resolve(arg))
	if v, ok := r.exports[name]; ok {
		return v
	}
	r.find("Fn::ImportValue: no export named " + name + " was supplied (pass -import " + name + "=… with the exporting stack's output value)")
	return "<importvalue:" + name + ">"
}

// getAZs resolves Fn::GetAZs to a deterministic set of AZ names for the region (the pseudo AWS::Region
// when the argument is empty). open-infra is a single cluster, so these are documented plan-time
// stand-ins (<region>a/b/c) — enough for a template's Fn::Select over the list to resolve; the
// translate layer maps subnet/AZ placement to the cluster's own topology, not to real AWS zones.
func (r *resolver) getAZs(arg any) any {
	region := fmt.Sprint(r.resolve(arg))
	if region == "" || region == "<nil>" {
		if v, ok := r.pseudo["AWS::Region"]; ok {
			region = fmt.Sprint(v)
		}
	}
	if region == "" {
		region = "us-east-1"
	}
	return []any{region + "a", region + "b", region + "c"}
}

// cidr resolves Fn::Cidr [ipBlock, count, cidrBits] to `count` sequential IPv4 subnet CIDRs carved from
// ipBlock, each with a /(32-cidrBits) mask (AWS semantics: cidrBits is the subnet/host-bit count). Pure
// deterministic subnet math. An unparseable/IPv6 ipBlock or a count/bits that overflow the block is a
// finding.
func (r *resolver) cidr(arg any) any {
	l := r.list(arg)
	if len(l) != 3 {
		r.find("Fn::Cidr requires [ipBlock, count, cidrBits]")
		return "<unsupported:Fn::Cidr>"
	}
	ipBlock := fmt.Sprint(r.resolve(l[0]))
	count, cerr := strconv.Atoi(strings.TrimSpace(fmt.Sprint(r.resolve(l[1]))))
	cidrBits, berr := strconv.Atoi(strings.TrimSpace(fmt.Sprint(r.resolve(l[2]))))
	if cerr != nil || berr != nil || count < 1 || cidrBits < 0 || cidrBits > 32 {
		r.find("Fn::Cidr: count and cidrBits must be integers (count>=1, 0<=cidrBits<=32)")
		return "<unsupported:Fn::Cidr>"
	}
	out, err := fnCidr(ipBlock, count, cidrBits)
	if err != nil {
		r.find("Fn::Cidr: " + err.Error())
		return "<unsupported:Fn::Cidr>"
	}
	return out
}

// fnCidr carves count sequential /(32-cidrBits) IPv4 subnets from ipBlock, starting at its network
// address. Pure (no resolver state) so it is directly unit-testable.
func fnCidr(ipBlock string, count, cidrBits int) ([]any, error) {
	_, ipnet, err := net.ParseCIDR(ipBlock)
	if err != nil {
		return nil, fmt.Errorf("ipBlock %q is not a valid CIDR", ipBlock)
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 ipBlocks are supported")
	}
	newMask := 32 - cidrBits
	basePrefix, _ := ipnet.Mask.Size()
	if newMask < basePrefix {
		return nil, fmt.Errorf("cidrBits %d makes a /%d larger than the ipBlock /%d", cidrBits, newMask, basePrefix)
	}
	maxSubnets := uint64(1) << uint(newMask-basePrefix)
	if uint64(count) > maxSubnets {
		return nil, fmt.Errorf("count %d exceeds the %d /%d subnets that fit in %s", count, maxSubnets, newMask, ipBlock)
	}
	base := ipToU32(ipnet.IP.To4())
	step := uint64(1) << uint(cidrBits) // addresses per subnet
	out := make([]any, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, fmt.Sprintf("%s/%d", u32ToIP(base+uint32(uint64(i)*step)), newMask))
	}
	return out, nil
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIP(v uint32) net.IP { return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)) }

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
