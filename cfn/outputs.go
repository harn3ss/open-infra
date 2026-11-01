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
//	Ref <AWS::EC2::EIP> / Fn::GetAtt <EIP>.PublicIp  -> the associated VM's LAN IP (status.lanIp)
//	Fn::GetAtt <AWS::EC2::Instance>.PublicIp          -> the VM's LAN IP, when it is exposed
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
	if len(t.Outputs) == 0 {
		rec.Outputs, rec.OutputsOmitted = nil, nil
		return
	}
	sr, _ := ap.(StatusReader)
	var deadline time.Time
	if opts.Wait {
		wait := opts.Timeout
		if wait <= 0 || wait > outputWaitCap {
			wait = outputWaitCap
		}
		deadline = time.Now().Add(wait)
		// Never into the time the completing record needs (outputRecordReserve).
		if dl, ok := ctx.Deadline(); ok {
			if last := dl.Add(-outputRecordReserve); last.Before(deadline) {
				deadline = last
			}
		}
	}
	for {
		outs, omitted, pending := evaluateOutputs(ctx, t, opts, rec, sr, customData)
		if !pending || !time.Now().Before(deadline) || ctx.Err() != nil {
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
// waiting on a supported post-deploy attribute that is not populated yet (worth polling again).
func evaluateOutputs(ctx context.Context, t *Template, opts DeployOptions, rec *StackRecord, sr StatusReader,
	customData map[string]map[string]any) (outs []StackOutput, omitted []OutputOmission, pending bool) {
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParams(opts.StackName))
	r.evalConditions()
	r.customData = customData
	sctx := &stackCtx{template: t, resolver: r, caps: opts.Caps, namer: newPhysNamer(opts.StackName, rec.Resources)}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	d := &deployedAttrs{ctx: ctx, sr: sr, sctx: sctx, byID: map[string]StackResource{}, status: map[string]map[string]any{}}
	for _, res := range rec.Resources {
		d.byID[res.LogicalID] = res
	}
	r.deployed = d.lookup

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
	return outs, omitted, pending
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
	ctx     context.Context
	sr      StatusReader
	sctx    *stackCtx
	byID    map[string]StackResource  // the deployed record, by logical id
	status  map[string]map[string]any // live .status cache, "Kind/name" -> status
	notes   []string                  // why an attribute definitively does not resolve
	waiting []string                  // a supported attribute not populated yet (poll again)
	missed  map[string]bool           // "id|attr" of each supported attribute that missed (explained above)
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
	switch res.Type {
	case "AWS::EC2::EIP":
		if attr != "" && attr != "PublicIp" {
			return nil, false
		}
		inst := ""
		all := d.sctx.eipBindings()
		for _, b := range all {
			if b.eip == id && eipConflict(b, all) == "" {
				inst = b.instance
				break
			}
		}
		if inst == "" {
			d.notes = append(d.notes, "Elastic IP "+id+" is not associated with an in-stack instance, so it has no address")
			return nil, false
		}
		return d.vmLanIP(inst)
	case "AWS::EC2::Instance":
		if attr == "PublicIp" {
			return d.vmLanIP(id)
		}
	case "AWS::S3::Bucket":
		if attr == "" {
			return d.statusString(id, "bucket", "bucket "+id+"'s name")
		}
	}
	return nil, false
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
	d.waiting = append(d.waiting, what+" was not assigned before the stack completed (it appears on the "+sr.Kind+"'s status."+field+" once assigned)")
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

// outputsEqual reports whether two Output sets (and their omissions/imports) are identical.
func outputsEqual(a, b *StackRecord) bool {
	return fmt.Sprint(a.Outputs) == fmt.Sprint(b.Outputs) && fmt.Sprint(a.OutputsOmitted) == fmt.Sprint(b.OutputsOmitted) &&
		fmt.Sprint(a.Imports) == fmt.Sprint(b.Imports)
}
