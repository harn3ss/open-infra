// Stack Outputs (#347).
//
// After a create or update reaches *_COMPLETE, the template's Outputs are evaluated against the DEPLOYED
// stack and persisted on the stack record — the values DescribeStacks returns, and (an Output with an
// Export.Name) the cross-stack exports Fn::ImportValue reads. Evaluation runs the same resolver as
// plan/deploy, so everything the template itself determines resolves directly: literals, parameters,
// pseudo-parameters, mappings, conditions, Fn::Sub/Join/Select/…, Fn::ImportValue against the supplied
// exports, a custom resource's returned Data, a CloudFront distribution's DomainName and an Elastic IP's
// AllocationId. On top of that a small, documented set of attributes that exist only once the stack is
// running resolve from the deployed claims' status (deployedAttrs.lookup):
//
//	Ref <AWS::EC2::EIP> / Fn::GetAtt <EIP>.PublicIp  -> the associated VM's LAN IP (status.lanIp), or the
//	                                                     address an allocation of its own holds
//	Fn::GetAtt <AWS::EC2::Instance>.PublicIp          -> the VM's LAN IP, when it is exposed
//	Fn::GetAtt <AWS::EC2::Instance>.PrivateDnsName    -> ip-a-b-c-d.ec2.internal for the VM's address
//	Fn::GetAtt <AWS::EC2::Instance>.PublicDnsName     -> ec2-<LAN IP>.<public DNS suffix>, or ""
//	Ref <AWS::S3::Bucket>                             -> the bucket name (status.bucket)
//
// A post-deploy attribute that is supported but not populated yet (MetalLB has not assigned the IP) is
// waited for, bounded. An Output whose value still does not resolve is OMITTED, with its reason recorded
// on the record (OutputsOmitted) — never a fabricated or placeholder value.
package cfn

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// StackOutput is one resolved template Output (the DescribeStacks Outputs member).
type StackOutput struct {
	OutputKey   string `json:"outputKey"`
	OutputValue string `json:"outputValue"`
	Description string `json:"description,omitempty"`
	ExportName  string `json:"exportName,omitempty"`
}

// OutputOmission records an Output that was left out because its value did not resolve, and why.
type OutputOmission struct {
	OutputKey string `json:"outputKey"`
	Reason    string `json:"reason"`
}

// StatusReader is an optional Applier capability: read a live resource's .status (found=false when the
// object is absent). Outputs naming a post-deploy attribute resolve through it; an Applier without it
// (a test double) leaves those Outputs omitted.
type StatusReader interface {
	GetStatus(ctx context.Context, apiVersion, kind, name string) (status map[string]any, found bool, err error)
}

// outputPollInterval / outputWaitCap bound how long a completing stack waits for a post-deploy attribute
// (a LAN IP being assigned) before recording its Output as omitted. On AWS an Elastic IP has its address
// by CREATE_COMPLETE, so waiting is the faithful choice; the address reaches a VM's status only when
// Crossplane next reconciles it, which can take minutes while many composites re-render.
var outputPollInterval = 3 * time.Second

const outputWaitCap = 10 * time.Minute

// outputBootWaitCap bounds the longer wait for an instance with an encrypted root. Its OS image is copied
// onto the encrypted disk before the VM first starts, so its address arrives minutes after the instance
// resource completed (several such instances created together share the copy's disk bandwidth). While
// one is still copying, or has finished copying and is starting, the wait goes on past outputWaitCap up
// to this bound; a VM that finished copying gets the ordinary wait (outputWaitCap, within -timeout) from
// then to report its address, as an instance with an unencrypted root gets from the start. On AWS
// PrivateIp is known at launch.
var outputBootWaitCap = 45 * time.Minute

// outputRecordReserve is the part of the operation's deadline the wait leaves for what follows it: the
// stack's *_COMPLETE record. Waiting into that time would let the deadline expire before the record is
// written, and the next front door would then roll back a stack that was fully built.
var outputRecordReserve = time.Minute

// setOutputs evaluates the template's Outputs against the deployed record and stores them (plus the
// omissions and the exports this stack imports) on rec. customData is a custom resource's returned Data
// from an interleaved deploy (nil otherwise).
func setOutputs(ctx context.Context, data []byte, opts DeployOptions, rec *StackRecord, ap Applier, customData map[string]map[string]any) {
	t, err := Parse(data)
	if err != nil {
		rec.Outputs, rec.OutputsOmitted, rec.Imports = nil, []OutputOmission{{Reason: "template could not be re-read: " + err.Error()}}, nil
		return
	}
	rec.Imports = templateImports(t, opts)
	sr, _ := ap.(StatusReader)
	defer setPhysicalIDs(ctx, t, opts, rec, sr)
	if len(t.Outputs) == 0 {
		rec.Outputs, rec.OutputsOmitted = nil, nil
		return
	}
	var deadline, bootDeadline time.Time
	var wait time.Duration
	if opts.Wait {
		wait = opts.Timeout
		if wait <= 0 || wait > outputWaitCap {
			wait = outputWaitCap
		}
		start := time.Now()
		deadline, bootDeadline = start.Add(wait), start.Add(outputBootWaitCap)
		// Never into the time the completing record needs (outputRecordReserve).
		if dl, ok := ctx.Deadline(); ok {
			last := dl.Add(-outputRecordReserve)
			if last.Before(deadline) {
				deadline = last
			}
			if last.Before(bootDeadline) {
				bootDeadline = last
			}
		}
	}
	started := map[string]time.Time{} // VM -> when its encrypted root was first seen copied (it is starting)
	for {
		outs, omitted, pending, booting := evaluateOutputs(ctx, t, opts, rec, sr, customData)
		now := time.Now()
		for vm, st := range booting {
			if _, seen := started[vm]; st == vmStarting && !seen {
				started[vm] = now
			}
		}
		more := pending && now.Before(deadline)
		if pending && !more && now.Before(bootDeadline) {
			for vm, st := range booting {
				if st == vmCopyingRoot || now.Before(started[vm].Add(wait)) {
					more = true
					break
				}
			}
		}
		if !more || ctx.Err() != nil {
			rec.Outputs, rec.OutputsOmitted = outs, omitted
			return
		}
		select {
		case <-ctx.Done():
			rec.Outputs, rec.OutputsOmitted = outs, omitted
			return
		case <-time.After(outputPollInterval):
		}
	}
}

// evaluateOutputs resolves every included Output once. pending reports that at least one Output is
// waiting on a supported post-deploy attribute that is not populated yet (worth polling again); booting
// names each VM with an encrypted root that such an attribute waits on, and where it is in coming up.
func evaluateOutputs(ctx context.Context, t *Template, opts DeployOptions, rec *StackRecord, sr StatusReader,
	customData map[string]map[string]any) (outs []StackOutput, omitted []OutputOmission, pending bool, booting map[string]vmBoot) {
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParams(opts.StackName))
	r.evalConditions()
	r.customData = customData
	sctx := &stackCtx{template: t, resolver: r, caps: opts.Caps, namer: newPhysNamer(opts.StackName, rec.Resources), signalURL: opts.SignalURL}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, sctx) }
	d := &deployedAttrs{ctx: ctx, sr: sr, sctx: sctx, namespace: opts.Namespace,
		byID: map[string]StackResource{}, status: map[string]map[string]any{}, booting: map[string]vmBoot{}}
	for _, res := range rec.Resources {
		d.byID[res.LogicalID] = res
	}
	r.deployed = d.lookup
	booting = d.booting

	for _, k := range sortedKeys(t.Outputs) {
		o, _ := t.Outputs[k].(map[string]any)
		if o == nil {
			omitted = append(omitted, OutputOmission{k, "the Output is not an object with a Value"})
			continue
		}
		if cond, _ := o["Condition"].(string); cond != "" && !r.conds[cond] {
			continue // conditioned off — not an Output of this stack
		}
		r.where = "Output " + k
		nf := len(r.findings)
		d.notes, d.waiting, d.missed = nil, nil, map[string]bool{}
		v := r.resolve(o["Value"])
		val, reason := outputString(v, t)
		if reason == "" && len(r.findings) > nf {
			reason = r.findings[nf].Reason
		}
		if reason != "" {
			why, wait := d.omissionReason(v, reason, t)
			pending = pending || wait
			omitted = append(omitted, OutputOmission{k, why})
			continue
		}
		out := StackOutput{OutputKey: k, OutputValue: val}
		if desc, ok := o["Description"]; ok {
			out.Description, _ = concrete(r.resolve(desc))
		}
		if ex, ok := o["Export"].(map[string]any); ok {
			en, eok := concrete(r.resolve(ex["Name"]))
			if !eok || strings.TrimSpace(en) == "" {
				omitted = append(omitted, OutputOmission{k, "Export.Name does not resolve to a concrete name — the Output is not exported (an export nothing can name would be unreachable)"})
				continue
			}
			out.ExportName = en
		}
		outs = append(outs, out)
	}
	return outs, omitted, pending, booting
}

// outputPlaceholderRe finds the resolver placeholders a value can still carry ("<ref:X>", "<X.attr>",
// "<importvalue:N>", "<param:P>", …) — each one an unresolved reference, never a value.
var outputPlaceholderRe = regexp.MustCompile(`<(ref:[A-Za-z0-9]+|importvalue:[^>]*|param:[^>]*|unsupported:[^>]*|base64:[^>]*|AWS::[A-Za-z]+|[A-Za-z0-9]+\.[A-Za-z0-9.]+)>`)

// outputString renders a resolved Output value as the string DescribeStacks returns, or the reason it
// can't be: an unresolved reference, AWS::NoValue, or a non-scalar (AWS requires a string Value).
func outputString(v any, t *Template) (string, string) {
	switch x := v.(type) {
	case nil:
		return "", "the Value resolves to nothing (AWS::NoValue)"
	case map[string]any:
		return "", "the Value did not resolve to a string"
	case []any:
		return "", "the Value is a list, not a string (join it with Fn::Join)"
	case string:
		if m := outputPlaceholderRe.FindStringSubmatch(x); m != nil {
			return "", unresolvedReason(m[1], t)
		}
		return x, ""
	default:
		return fmt.Sprint(x), ""
	}
}

func unresolvedReason(body string, t *Template) string {
	return describePlaceholder(body, t) + " does not resolve on open-infra (see docs/cloudformation.md, Stack outputs, for the attributes that do)"
}

// placeholderKey is the deployedAttrs.missed key ("id|attr", attr "" = Ref) behind a placeholder body.
func placeholderKey(body string) string {
	if strings.HasPrefix(body, "ref:") {
		return strings.TrimPrefix(body, "ref:") + "|"
	}
	if i := strings.Index(body, "."); i > 0 && !strings.Contains(body, ":") {
		return body[:i] + "|" + body[i+1:]
	}
	return ""
}

// omissionReason explains an unresolved Output from EVERY reference it still carries: a supported
// post-deploy attribute that missed says why (not exposed / not assigned yet), anything else is named as
// not resolving here. wait = the only misses are attributes still being assigned (worth polling again).
func (d *deployedAttrs) omissionReason(v any, fallback string, t *Template) (string, bool) {
	var parts []string
	unsupported := false
	if s, ok := v.(string); ok {
		for _, m := range outputPlaceholderRe.FindAllStringSubmatch(s, -1) {
			if d.missed[placeholderKey(m[1])] {
				continue // explained by its note / waiting entry below
			}
			unsupported = true
			parts = append(parts, unresolvedReason(m[1], t))
		}
	}
	if len(parts) == 0 && len(d.notes) == 0 && len(d.waiting) == 0 {
		return fallback, false
	}
	parts = append(parts, d.notes...)
	parts = append(parts, d.waiting...)
	return strings.Join(dedupStrings(parts), "; "), len(d.waiting) > 0 && !unsupported && len(d.notes) == 0
}

// describePlaceholder names the reference behind a placeholder body, e.g. "ref:Web" -> "Ref Web
// (AWS::EC2::Instance)", "Web.PrivateIp" -> "Fn::GetAtt Web.PrivateIp (AWS::EC2::Instance)".
func describePlaceholder(body string, t *Template) string {
	typeOf := func(id string) string {
		if r, ok := t.Resources[id]; ok {
			return " (" + r.Type + ")"
		}
		return ""
	}
	switch {
	case strings.HasPrefix(body, "ref:"):
		id := strings.TrimPrefix(body, "ref:")
		return "Ref " + id + typeOf(id)
	case strings.HasPrefix(body, "importvalue:"):
		return "Fn::ImportValue " + strings.TrimPrefix(body, "importvalue:")
	case strings.Contains(body, ":"):
		return "an unresolved " + body
	default:
		id := body[:strings.Index(body, ".")]
		return "Fn::GetAtt " + body + typeOf(id)
	}
}

// deployedAttrs resolves the documented post-deploy attributes from the deployed claims' status.
type deployedAttrs struct {
	ctx       context.Context
	sr        StatusReader
	sctx      *stackCtx
	namespace string                    // the stack's namespace (in-cluster DNS names)
	byID      map[string]StackResource  // the deployed record, by logical id
	props     map[string]map[string]any // each resource's resolved properties (cache)
	status    map[string]map[string]any // live .status cache, "Kind/name" -> status
	notes     []string                  // why an attribute definitively does not resolve
	waiting   []string                  // a supported attribute not populated yet (poll again)
	missed    map[string]bool           // "id|attr" of each supported attribute that missed (explained above)
	booting   map[string]vmBoot         // VMs with an encrypted root a waiting attribute is on (nil = not tracked)
}

// vmBoot is where a VM with an encrypted root is in coming up, while an attribute waits on it.
type vmBoot int

const (
	vmCopyingRoot vmBoot = iota + 1 // the OS image is still being copied onto the encrypted root
	vmStarting                      // copied; the VM has not reported the attribute yet
)

// encryptedRoot reports whether a deployed VM's spec asks for an encrypted root disk.
func encryptedRoot(sr StackResource) bool {
	rd, _ := sr.Spec["rootDisk"].(map[string]any)
	enc, _ := rd["encrypted"].(bool)
	return sr.Kind == "VirtualMachine" && enc
}

// lookup resolves one reference (attr "" = Ref); a supported attribute that misses records why.
func (d *deployedAttrs) lookup(id, attr string) (any, bool) {
	nn, nw := len(d.notes), len(d.waiting)
	v, ok := d.resolveAttr(id, attr)
	if !ok && (len(d.notes) > nn || len(d.waiting) > nw) && d.missed != nil {
		d.missed[id+"|"+attr] = true
	}
	return v, ok
}

func (d *deployedAttrs) resolveAttr(id, attr string) (any, bool) {
	res, ok := d.sctx.template.Resources[id]
	if !ok || !d.sctx.included(res) {
		return nil, false
	}
	if isCustomResourceType(res.Type) {
		// A custom resource's Ref is the PhysicalResourceId its handler returned; its attributes are the
		// Data it returned, which the resolver reads itself.
		if sr, ok := d.byID[id]; ok && attr == "" && sr.PhysicalID != "" {
			return sr.PhysicalID, true
		}
		return nil, false
	}
	v, ok := resolveResourceAttr(d.env(id, res), attr)
	if !ok {
		return nil, false
	}
	return v, true
}

// env builds the attribute environment of in-stack resource id: its deployed entry and its properties,
// resolved without letting a property's own findings count against the Output being evaluated.
func (d *deployedAttrs) env(id string, res Resource) *attrEnv {
	e := &attrEnv{id: id, typ: res.Type, sctx: d.sctx, d: d}
	if sr, ok := d.byID[id]; ok {
		e.res = &sr
	}
	if d.props == nil {
		d.props = map[string]map[string]any{}
	}
	if p, ok := d.props[id]; ok {
		e.props = p
		return e
	}
	r := d.sctx.resolver
	where, nf := r.where, len(r.findings)
	d.props[id] = map[string]any{} // re-entrancy guard: a property that refers back to this resource
	p, _ := r.resolve(res.Properties).(map[string]any)
	r.where, r.findings = where, r.findings[:nf]
	d.props[id] = p
	e.props = p
	return e
}

// eipAddress is Elastic IP id's address: the LAN IP of the in-stack instance it is associated with.
func (d *deployedAttrs) eipAddress(id string) (any, bool) {
	inst := ""
	all := d.sctx.eipBindings()
	for _, b := range all {
		if b.eip == id && eipConflict(b, all) == "" {
			inst = b.instance
			break
		}
	}
	if inst == "" {
		// An allocation of its own (KindEC2Address): the address it holds, from the allocation's status.
		if sr, ok := d.byID[id]; ok && sr.Kind == KindEC2Address {
			return d.statusString(id, "publicIp", "Elastic IP "+id+"'s address")
		}
		d.notes = append(d.notes, "Elastic IP "+id+" is not associated with an in-stack instance, so it has no address")
		return nil, false
	}
	return d.vmLanIP(inst)
}

// vmLanIP returns instance instID's VM LAN IP (status.lanIp) — only for an exposed VM.
func (d *deployedAttrs) vmLanIP(instID string) (any, bool) {
	sr, ok := d.byID[instID]
	if !ok || sr.Kind != "VirtualMachine" {
		d.notes = append(d.notes, "instance "+instID+" was not deployed as a kind: VirtualMachine")
		return nil, false
	}
	expose, _ := sr.Spec["expose"].(bool)
	ports, _ := sr.Spec["ports"].([]any)
	if !expose && len(ports) == 0 {
		d.notes = append(d.notes, "instance "+instID+"'s VM is not exposed (no AssociatePublicIpAddress or Elastic IP), so it has no LAN IP")
		return nil, false
	}
	return d.statusString(instID, "lanIp", "VM "+sr.Name+"'s LAN IP")
}

// statusString reads a string field of the deployed resource's live status; an empty/absent value is
// pending (populated asynchronously), a missing reader or object a definitive miss.
func (d *deployedAttrs) statusString(id, field, what string) (any, bool) {
	sr, ok := d.byID[id]
	if !ok {
		d.notes = append(d.notes, id+" is not in the deployed stack")
		return nil, false
	}
	if d.sr == nil {
		d.notes = append(d.notes, what+" is read from the live resource's status, which this deploy path cannot read")
		return nil, false
	}
	key := sr.Kind + "/" + sr.Name
	st, cached := d.status[key]
	if !cached {
		s, found, err := d.sr.GetStatus(d.ctx, sr.APIVersion, sr.Kind, sr.Name)
		switch {
		case err != nil:
			d.notes = append(d.notes, "reading "+key+" status failed: "+err.Error())
			return nil, false
		case !found:
			d.notes = append(d.notes, key+" no longer exists")
			return nil, false
		}
		st = s
		d.status[key] = st
	}
	if v, _ := st[field].(string); v != "" {
		return v, true
	}
	why := " (it appears on the " + sr.Kind + "'s status." + field + " once assigned)"
	if encryptedRoot(sr) {
		// Its OS image is copied onto the encrypted root before the VM first starts (status.rootPopulated).
		state := vmStarting
		why = " (the OS image was copied onto its encrypted root, and the VM had not reported it on status." + field + " yet)"
		if p, _ := st["rootPopulated"].(bool); !p && st["rootPopulated"] != "true" {
			state = vmCopyingRoot
			why = " (the VM was still copying its OS image onto its encrypted root, so it had not started yet)"
		}
		if d.booting != nil && d.booting[sr.Name] < state {
			d.booting[sr.Name] = state
		}
	}
	d.waiting = append(d.waiting, what+" was not assigned before the stack completed"+why)
	return nil, false
}

// templateImports returns the export names this stack reads through Fn::ImportValue (resources +
// Outputs, included only), sorted — recorded so a stack whose exports are in use can't be deleted.
func templateImports(t *Template, opts DeployOptions) []string {
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParams(opts.StackName))
	r.evalConditions()
	r.imported = map[string]bool{}
	for _, id := range t.rawOrder {
		res := t.Resources[id]
		if res.Condition != "" && !r.conds[res.Condition] {
			continue
		}
		r.resolve(res.Properties)
	}
	for _, k := range sortedKeys(t.Outputs) {
		o, _ := t.Outputs[k].(map[string]any)
		if cond, _ := o["Condition"].(string); cond != "" && !r.conds[cond] {
			continue
		}
		r.resolve(o["Value"])
	}
	var out []string
	for n := range r.imported {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TemplateExportNames returns the Export.Name of every included Output that resolves statically (from the
// template, parameters and supplied exports) — what a create/update would export, so a front door can
// refuse an export name another stack already owns BEFORE deploying (AWS's rule). Names that only resolve
// after deploy are not returned.
func TemplateExportNames(data []byte, params, exports map[string]string, stackName string) ([]string, error) {
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	r := newResolver(t, resolveParams(t, params), strMapToAny(exports), pseudoParams(stackName))
	r.evalConditions()
	var out []string
	for _, k := range sortedKeys(t.Outputs) {
		o, _ := t.Outputs[k].(map[string]any)
		if cond, _ := o["Condition"].(string); cond != "" && !r.conds[cond] {
			continue
		}
		ex, ok := o["Export"].(map[string]any)
		if !ok {
			continue
		}
		if n, ok := concrete(r.resolve(ex["Name"])); ok && strings.TrimSpace(n) != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

// subTokenRe finds the ${…} references in an Fn::Sub string (${!Literal} is an escaped literal).
var subTokenRe = regexp.MustCompile(`\$\{([^!}][^}]*)\}`)

// outputReferenceBlockers refuses, at plan time, an Output whose Ref or Fn::GetAtt names an in-stack
// resource attribute that does not resolve on open-infra (resource_attrs.go) — so the stack is refused
// before anything is created, as AWS refuses a template naming an attribute a type does not have, rather
// than completing without the Output.
func outputReferenceBlockers(t *Template, conds map[string]bool) []string {
	var out []string
	for _, k := range sortedKeys(t.Outputs) {
		o, _ := t.Outputs[k].(map[string]any)
		if o == nil {
			continue
		}
		if cond, _ := o["Condition"].(string); cond != "" && !conds[cond] {
			continue
		}
		seen := map[string]bool{}
		walkOutputRefs(o["Value"], t, conds, nil, func(id, attr string) {
			res, ok := t.Resources[id]
			if !ok || attrKnown(res.Type, attr) || seen[id+"."+attr] {
				return
			}
			seen[id+"."+attr] = true
			what := "Ref " + id
			if attr != "" {
				what = "Fn::GetAtt " + id + "." + attr
			}
			hint := ""
			if names := AttrNames(res.Type); len(names) > 0 {
				hint = " (on open-infra " + res.Type + " has: " + strings.Join(names, ", ") + ")"
			} else if _, known := resourceAttrs[res.Type]; !known {
				hint = " (" + res.Type + " has no attributes that resolve on open-infra)"
			}
			out = append(out, fmt.Sprintf("Output %s: %s (%s) does not resolve on open-infra%s", k, what, res.Type, hint))
		})
	}
	return out
}

// walkOutputRefs calls f for every in-stack resource reference in v: Ref X (attr ""), Fn::GetAtt X.A, and
// ${X} / ${X.A} in Fn::Sub — following only the branch an Fn::If's condition picks. subVars are names an
// enclosing Fn::Sub defines (not references).
func walkOutputRefs(v any, t *Template, conds map[string]bool, subVars map[string]bool, f func(id, attr string)) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			walkOutputRefs(e, t, conds, subVars, f)
		}
	case map[string]any:
		if len(x) == 1 {
			for key, arg := range x {
				switch key {
				case "Ref":
					if s, ok := arg.(string); ok {
						if _, isRes := t.Resources[s]; isRes {
							f(s, "")
						}
					}
					return
				case "Fn::GetAtt":
					id, attr := "", ""
					switch a := arg.(type) {
					case []any:
						if len(a) >= 2 {
							id, _ = a[0].(string)
							s, ok := a[1].(string)
							if !ok {
								return // a computed attribute name: nothing static to check
							}
							attr = s
						}
					case string:
						id, attr, _ = strings.Cut(a, ".")
					}
					if id != "" {
						f(id, attr)
					}
					return
				case "Fn::If":
					if a, ok := arg.([]any); ok && len(a) == 3 {
						name, _ := a[0].(string)
						if conds[name] {
							walkOutputRefs(a[1], t, conds, subVars, f)
						} else {
							walkOutputRefs(a[2], t, conds, subVars, f)
						}
					}
					return
				case "Fn::Sub":
					str := ""
					vars := map[string]bool{}
					switch a := arg.(type) {
					case string:
						str = a
					case []any:
						if len(a) > 0 {
							str, _ = a[0].(string)
						}
						if len(a) > 1 {
							if m, ok := a[1].(map[string]any); ok {
								for name, val := range m {
									vars[name] = true
									walkOutputRefs(val, t, conds, subVars, f)
								}
							}
						}
					}
					for _, m := range subTokenRe.FindAllStringSubmatch(str, -1) {
						tok := strings.TrimSpace(m[1])
						if vars[tok] || strings.HasPrefix(tok, "AWS::") {
							continue
						}
						id, attr, _ := strings.Cut(tok, ".")
						if vars[id] {
							continue
						}
						if _, isRes := t.Resources[id]; isRes {
							f(id, attr)
						}
					}
					return
				}
			}
		}
		for _, e := range x {
			walkOutputRefs(e, t, conds, subVars, f)
		}
	}
}

// setPhysicalIDs records each deployed resource's physical id — its Ref value — on the record, the
// PhysicalResourceId DescribeStackResources reports. A companion object (an inline policy) is its own
// name. A Ref that does not resolve leaves the resource's name.
func setPhysicalIDs(ctx context.Context, t *Template, opts DeployOptions, rec *StackRecord, sr StatusReader) {
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParams(opts.StackName))
	r.evalConditions()
	sctx := &stackCtx{template: t, resolver: r, caps: opts.Caps, namer: newPhysNamer(opts.StackName, rec.Resources), signalURL: opts.SignalURL}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, sctx) }
	d := &deployedAttrs{ctx: ctx, sr: sr, sctx: sctx, namespace: opts.Namespace,
		byID: map[string]StackResource{}, status: map[string]map[string]any{}, missed: map[string]bool{}}
	for _, res := range rec.Resources {
		d.byID[res.LogicalID] = res
	}
	r.deployed = d.lookup
	for i := range rec.Resources {
		res := &rec.Resources[i]
		if res.PhysicalID != "" {
			continue // out of band (a custom resource's PhysicalResourceId, a REST API's id)
		}
		if strings.Contains(res.LogicalID, "/") {
			res.PhysicalID = res.Name
			continue
		}
		tr, ok := t.Resources[res.LogicalID]
		if !ok {
			res.PhysicalID = res.Name
			continue
		}
		if v, ok := resolveResourceAttr(d.env(res.LogicalID, tr), ""); ok && v != "" {
			res.PhysicalID = v
		} else {
			res.PhysicalID = res.Name
		}
	}
}

// outputFailure is the error a stack whose Outputs did not all resolve fails with: AWS never completes a
// stack with an Output missing, so neither does open-infra.
func outputFailure(rec *StackRecord) error {
	if len(rec.OutputsOmitted) == 0 {
		return nil
	}
	parts := make([]string, 0, len(rec.OutputsOmitted))
	for _, o := range rec.OutputsOmitted {
		if o.OutputKey == "" {
			parts = append(parts, o.Reason)
			continue
		}
		parts = append(parts, "Output "+o.OutputKey+": "+o.Reason)
	}
	return fmt.Errorf("the stack's Outputs did not all resolve:\n  - %s", strings.Join(parts, "\n  - "))
}

// outputsEqual reports whether two Output sets (and their omissions/imports) are identical.
func outputsEqual(a, b *StackRecord) bool {
	return fmt.Sprint(a.Outputs) == fmt.Sprint(b.Outputs) && fmt.Sprint(a.OutputsOmitted) == fmt.Sprint(b.OutputsOmitted) &&
		fmt.Sprint(a.Imports) == fmt.Sprint(b.Imports)
}
