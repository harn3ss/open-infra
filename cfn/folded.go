package cfn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Folded resources (#350 Y): a template resource that provisions nothing of its own — an InternetGateway
// and its attachment, a route table, a route and their associations, an Elastic IP folded onto its
// instance's VM, a VolumeAttachment, a WaitConditionHandle, a bucket policy riding its bucket — is still a
// resource of the stack on AWS: ListStackResources, DescribeStackResources and DescribeStackEvents list it
// with its own physical id. The engine records only what it applies, so these are derived from the
// stack's template: each one's physical id is its Ref (the same value a template's !Ref gets), and its
// status follows the provisioned resources it is part of (its carriers).

// FoldedResource is one resource of a stack's template that provisions nothing of its own.
type FoldedResource struct {
	LogicalID  string
	Type       string
	PhysicalID string // its Ref; "" when the Ref does not resolve (yet)
	// Carriers are the provisioned resources of the stack it is part of — the ones its properties name
	// (followed through other folded resources), else the ones naming it. Its status follows theirs.
	// None means it exists as soon as the stack's create begins: a WaitConditionHandle (AWS creates it
	// at once; the condition waits, not the handle), or a resource nothing provisioned is tied to.
	Carriers []string
}

// FoldedResources lists the folded resources of a deployed stack, in template order. opts are the
// options the stack is deployed with (its parameters, capabilities and signal URLs — the same Ref values
// the deploy computed); sr reads live status for a Ref that needs it (an Elastic IP's address), and may be
// nil. A record whose template does not parse has none.
func FoldedResources(ctx context.Context, rec *StackRecord, opts DeployOptions, sr StatusReader) []FoldedResource {
	if rec == nil || rec.Template == "" {
		return nil
	}
	t, err := Parse([]byte(rec.Template))
	if err != nil {
		return nil
	}
	params := opts.Params
	if params == nil {
		params = rec.Parameters
	}
	r := newResolver(t, resolveParams(t, params), strMapToAny(opts.Exports), pseudoParams(rec.Name))
	r.evalConditions()
	sctx := &stackCtx{template: t, resolver: r, caps: opts.Caps, namer: newPhysNamer(rec.Name, rec.Resources), signalURL: opts.SignalURL}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, sctx) }

	recorded := map[string]bool{}
	for _, list := range [][]StackResource{rec.Resources, rec.Pending} {
		for _, res := range list {
			recorded[strings.SplitN(res.LogicalID, "/", 2)[0]] = true
		}
	}
	// Each included resource's references (what its properties name), and which provision nothing.
	refs := map[string][]string{}
	folded := map[string]bool{}
	var ids []string
	for _, id := range t.rawOrder {
		res := t.Resources[id]
		if !sctx.included(res) {
			continue
		}
		ids = append(ids, id)
		refs[id] = dedupSorted(r.resolveResource(id, res))
		if recorded[id] {
			continue
		}
		tr := translatorFor(res.Type)
		if tr == nil || isCustomResourceType(res.Type) {
			continue
		}
		props, _ := sctx.resolveProps(id)
		if m, f := tr(id, props, sctx); m == nil && len(f) == 0 {
			folded[id] = true
		}
	}
	referrers := map[string][]string{}
	for _, id := range ids {
		for _, to := range refs[id] {
			referrers[to] = append(referrers[to], id)
		}
	}
	included := map[string]bool{}
	for _, id := range ids {
		included[id] = true
	}
	// carriersVia follows edges from id through folded resources to the provisioned resources they reach.
	var carriersVia func(id string, edges map[string][]string, seen map[string]bool, out map[string]bool)
	carriersVia = func(id string, edges map[string][]string, seen map[string]bool, out map[string]bool) {
		for _, n := range edges[id] {
			if seen[n] || !included[n] {
				continue
			}
			seen[n] = true
			if folded[n] {
				carriersVia(n, refs, seen, out) // a folded resource is part of what IT names
				continue
			}
			out[n] = true
		}
	}

	d := &deployedAttrs{ctx: ctx, sr: sr, sctx: sctx, namespace: rec.Namespace,
		byID: map[string]StackResource{}, status: map[string]map[string]any{}, missed: map[string]bool{}}
	for _, res := range rec.Resources {
		d.byID[res.LogicalID] = res
	}
	r.deployed = d.lookup

	var out []FoldedResource
	for _, id := range ids {
		if !folded[id] {
			continue
		}
		res := t.Resources[id]
		fr := FoldedResource{LogicalID: id, Type: res.Type}
		if v, ok := resolveResourceAttr(d.env(id, res), ""); ok {
			fr.PhysicalID = v
		} else if ta, known := resourceAttrs[res.Type]; !known || ta.ref == nil {
			// A type with no Ref of its own (a VolumeAttachment): the id AWS generates for an unnamed
			// resource, <stack>-<logical id>-<suffix>, stable for the stack.
			fr.PhysicalID = generatedPhysicalID(rec.Name, id)
		}
		if res.Type != waitConditionHandleType {
			set := map[string]bool{}
			carriersVia(id, refs, map[string]bool{id: true}, set)
			if len(set) == 0 {
				// Nothing it names is provisioned (an InternetGateway names nothing): it is part of what
				// names it — the VPC its attachment joins it to.
				seen := map[string]bool{id: true}
				for _, n := range referrers[id] {
					if seen[n] {
						continue
					}
					seen[n] = true
					if folded[n] {
						carriersVia(n, refs, seen, set)
					} else {
						set[n] = true
					}
				}
			}
			for c := range set {
				fr.Carriers = append(fr.Carriers, c)
			}
			sort.Strings(fr.Carriers)
		}
		out = append(out, fr)
	}
	return out
}

// generatedPhysicalID is the physical id CloudFormation gives an unnamed resource with no Ref of its own:
// <stack>-<logical id>-<12 upper-case characters>, here derived from the stack and logical id.
func generatedPhysicalID(stack, id string) string {
	sum := sha256.Sum256([]byte(stack + "/" + id))
	return stack + "-" + id + "-" + strings.ToUpper(hex.EncodeToString(sum[:6]))
}

// FoldedStatus is a folded resource's status, given its carriers' statuses ("" for a carrier not
// started yet): being deleted (or deleted) once any carrier is, failed if a carrier's create failed, being
// created until every carrier exists, and created after. A carrier's update does not update what is
// folded into it (an attachment is not changed by an update of its VPC). listed is false while no carrier
// has started: on AWS a resource is listed once its creation begins.
func FoldedStatus(carriers []string) (status string, listed bool) {
	started, notStarted := 0, 0
	has := func(s string) bool {
		for _, c := range carriers {
			if c == s {
				return true
			}
		}
		return false
	}
	deleting, deleted := false, true
	for _, c := range carriers {
		if c == "" {
			notStarted++
			continue
		}
		started++
		if strings.HasPrefix(c, "DELETE_") {
			deleting = true
		}
		if c != "DELETE_COMPLETE" && c != "DELETE_SKIPPED" {
			deleted = false
		}
	}
	switch {
	case started == 0:
		return "", false
	case has("DELETE_FAILED"):
		return "DELETE_FAILED", true
	case deleting && deleted && notStarted == 0:
		return "DELETE_COMPLETE", true
	case deleting:
		return "DELETE_IN_PROGRESS", true
	case has("CREATE_FAILED"):
		return "CREATE_FAILED", true
	case has("CREATE_IN_PROGRESS") || notStarted > 0:
		return "CREATE_IN_PROGRESS", true
	}
	return "CREATE_COMPLETE", true
}

// FoldedStatusWithoutCarrier is the status of a folded resource with no carrier, given the stack's: it
// exists from the moment the stack's create begins until the stack (or its rolled-back create) is
// deleted. Deleting what provisions nothing cannot fail.
func FoldedStatusWithoutCarrier(stackStatus string) string {
	switch stackStatus {
	case "DELETE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS":
		return "DELETE_IN_PROGRESS"
	case "DELETE_COMPLETE", "DELETE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED":
		return "DELETE_COMPLETE"
	}
	return "CREATE_COMPLETE"
}
