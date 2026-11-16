// Change sets for the CFN engine (Phase 3, update).
//
// A change set is the diff between a new template and the stack as it stands now — the
// resources that would be Added, Modified, Removed, or left Unchanged. It compares the new
// template's translated specs against the specs recorded when the stack was last applied (the
// CloudFormation model: diff the new template against the current stack, not against live
// cluster drift — that is Phase 5's job). Computing a change set is read-only; `cfn update`
// applies one.
package cfn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type ChangeAction string

const (
	Add       ChangeAction = "Add"
	Modify    ChangeAction = "Modify"
	Remove    ChangeAction = "Remove"
	Unchanged ChangeAction = "Unchanged"
)

type Change struct {
	LogicalID string
	Kind      string
	Type      string // the resource's CloudFormation type (AWS::S3::Bucket); "" on a record from before it was kept
	Name      string
	Action    ChangeAction
	Caveats   []string
	// Folded marks a resource that provisions nothing of its own (folded.go): the change set lists its
	// change, as AWS does, but an update has no object of its to apply or delete — it records the change
	// (the new template, and the resource's events). Name is its physical id (its Ref).
	Folded bool `json:",omitempty"`
	// Replacement is whether a Modify replaces the resource, as AWS's change set says: True when a property
	// that changes is Immutable, Conditional when one may replace it, else False ("" = not a Modify).
	Replacement string `json:",omitempty"`
	// Details are the properties a Modify changes, each with whether it recreates the resource
	// (RequiresRecreation Never, Conditionally or Always).
	Details []PropertyChange `json:",omitempty"`
}

// PropertyChange is one property a change modifies.
type PropertyChange struct {
	Name               string
	RequiresRecreation string
}

type ChangeSet struct {
	StackName string
	Namespace string
	Exists    bool // whether a current stack record was found
	Changes   []Change
}

// BuildChangeSet translates the new template (fail-closed) and diffs it against the current
// stack record. It returns the change set, the desired resources in dependency order (for
// update to apply), and the current record (nil if the stack does not yet exist).
func BuildChangeSet(ctx context.Context, data []byte, opts DeployOptions, ap Applier) (*ChangeSet, []builtResource, *StackRecord, error) {
	// The current stack first: its resources keep the names they were created with (naming.go).
	current, found, err := ap.GetStack(ctx, opts.StackName)
	if err != nil {
		return nil, nil, nil, err
	}
	var owned ownedObjects
	if found {
		opts.prior = current.Resources
		opts.instance = current.CreatedAt // a bucket the update adds is named for this stack instance
		owned = ownedFrom(current.Resources)
		opts.adoptStackID(current) // AWS::StackId is the stack's own, as its create resolved it
		// Its nested stacks' Outputs, as they are now: what its resources' Fn::GetAtt read.
		nd, nerr := nestedOutputsOf(ctx, opts, current.Resources)
		if nerr != nil {
			return nil, nil, nil, nerr
		}
		if len(nd) > 0 {
			opts.nestedData = nd
		}
		if sr, ok := ap.(StatusReader); ok {
			opts.status = sr // the addresses of the stack's Elastic IP allocations, for what embeds them
		}
	}
	// A new stack with a Lambda-backed custom resource is created resource by resource (deployInterleaved):
	// the custom resource's Data, which later resources may read, is known only once its handler has run. The
	// change set is built with that Data known after apply (KnownAfterApply), as AWS's change set shows it, so
	// every other property is still checked and refused here; ExecuteChangeSet then creates the stack as
	// CreateStack does, with the real Data.
	if !found {
		if pt, perr := Parse(data); perr == nil && hasCustomResources(pt) {
			opts.afterApply = true
		}
	}
	// A resource the update adds is named around anything an earlier stack of this name (or an earlier
	// update that removed a Retain resource) left behind; what the stack recorded keeps its name.
	desired, err := buildAvoidingLeftovers(ctx, data, opts, ap, owned)
	if err != nil {
		return nil, nil, nil, err
	}

	currentByID := map[string]StackResource{}
	if found {
		for _, r := range current.Resources {
			currentByID[r.LogicalID] = r
		}
	}

	cs := &ChangeSet{StackName: opts.StackName, Namespace: opts.Namespace, Exists: found}
	desiredIDs := map[string]bool{}
	for _, b := range desired {
		desiredIDs[b.res.LogicalID] = true
		ch := Change{LogicalID: b.res.LogicalID, Kind: b.res.Kind, Type: b.res.Type, Name: b.res.Name, Caveats: b.cav}
		cur, ok := currentByID[b.res.LogicalID]
		switch {
		case !ok:
			ch.Action = Add
		case !specEqual(b.res.Spec, cur.Spec):
			ch.Action = Modify
		case !strings.EqualFold(policyOrDelete(b.res.DeletionPolicy), policyOrDelete(cur.DeletionPolicy)) || b.res.Protected != cur.Protected:
			// The object is unchanged, but what a delete does to it is not: a DeletionPolicy or
			// DeletionProtection change is an update on AWS (it is how a resource is retained before it is
			// removed, and how protection is turned off), so the stack record must take it.
			ch.Action = Modify
			ch.Caveats = append(ch.Caveats, fmt.Sprintf("only the deletion behavior changes: DeletionPolicy %s -> %s, deletion protection %v -> %v (the object itself is not modified)",
				policyOrDelete(cur.DeletionPolicy), policyOrDelete(b.res.DeletionPolicy), cur.Protected, b.res.Protected))
		default:
			ch.Action = Unchanged
		}
		cs.Changes = append(cs.Changes, ch)
	}
	// Removals: in the current stack but not the new template, reverse dependency order (the
	// record is stored in create order, so reverse it).
	if found {
		for i := len(current.Resources) - 1; i >= 0; i-- {
			r := current.Resources[i]
			if !desiredIDs[r.LogicalID] {
				cs.Changes = append(cs.Changes, Change{
					LogicalID: r.LogicalID, Kind: r.Kind, Type: r.Type, Name: r.Name, Action: Remove,
				})
			}
		}
	}
	var cur *StackRecord
	if found {
		cur = current
	}
	cs.Changes = append(cs.Changes, foldedChanges(ctx, cur, data, opts, desired)...)
	if cur != nil {
		markReplacements(cs.Changes, cur, data, opts)
	}
	return cs, desired, current, nil
}

// markReplacements sets each Modify's Replacement and Details from the properties that change between the
// current template and the new one, each as its stack resolves it, and AWS's update type for each
// (updateTypes, from AWS's resource specification): an Immutable property replaces the resource, a
// Conditional one may.
func markReplacements(changes []Change, current *StackRecord, data []byte, opts DeployOptions) {
	stackID := opts.StackID
	if stackID == "" {
		stackID = current.StackID
	}
	newRes, err := templateResources(data, opts.Params, opts.Exports, opts.StackName, stackID, current.Resources, current.CreatedAt, nil)
	if err != nil {
		return
	}
	// The current template resolves with the parameters it was deployed with (a NoEcho value is not
	// recorded: it is the one this operation passes).
	params := map[string]string{}
	for k, v := range current.Parameters {
		params[k] = v
	}
	for _, k := range current.NoEchoParameters {
		if v, ok := opts.Params[k]; ok {
			params[k] = v
		}
	}
	oldRes, err := templateResources([]byte(current.Template), params, opts.Exports, current.Name, current.StackID, current.Resources, current.CreatedAt, nil)
	if err != nil {
		return
	}
	byID := func(rs []TemplateResource) map[string]TemplateResource {
		m := map[string]TemplateResource{}
		for _, r := range rs {
			m[r.LogicalID] = r
		}
		return m
	}
	olds, news := byID(oldRes), byID(newRes)
	for i := range changes {
		c := &changes[i]
		if c.Action != Modify && c.Action != Unchanged { // Unchanged: a companion's change may make it a Modify
			continue
		}
		id := strings.SplitN(c.LogicalID, "/", 2)[0]
		o, had := olds[id]
		n, has := news[id]
		if !had || !has {
			c.Replacement = "False"
			continue
		}
		c.Replacement, c.Details = replacementOf(n.Type, o.Properties, n.Properties)
		if c.Action == Modify && c.Replacement != "False" {
			var props []string
			for _, d := range c.Details {
				if d.RequiresRecreation != "Never" {
					props = append(props, d.Name)
				}
			}
			verb := "replaces"
			if c.Replacement == "Conditional" {
				verb = "may replace"
			}
			c.Caveats = append(c.Caveats, fmt.Sprintf("changing %s %s it on AWS (a new physical id); open-infra updates it in place, keeping its physical id",
				strings.Join(props, ", "), verb))
		}
	}
}

// replacementOf is a resource's Replacement for a change of its properties from old to new, and the
// properties that change, in name order.
func replacementOf(typ string, old, new map[string]any) (string, []PropertyChange) {
	names := map[string]bool{}
	for k := range old {
		names[k] = true
	}
	for k := range new {
		names[k] = true
	}
	var details []PropertyChange
	replacement := "False"
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if specEqual(map[string]any{"v": old[k]}, map[string]any{"v": new[k]}) {
			continue
		}
		rec := "Never"
		switch updateTypes[typ][k] {
		case "Immutable":
			rec, replacement = "Always", "True"
		case "Conditional":
			rec = "Conditionally"
			if replacement == "False" {
				replacement = "Conditional"
			}
		}
		details = append(details, PropertyChange{Name: k, RequiresRecreation: rec})
	}
	return replacement, details
}

// foldedChanges are the changes of the resources that provision nothing of their own (folded.go) between
// the current stack (nil for a create) and the new template: one that only the new template has is an Add,
// one only the current stack has a Remove, and one whose type or resolved properties differ a Modify. A
// logical id provisioned on either side is not listed here: its provisioned change covers it.
func foldedChanges(ctx context.Context, current *StackRecord, data []byte, opts DeployOptions, desired []builtResource) []Change {
	next := &StackRecord{Name: opts.StackName, Namespace: opts.Namespace, StackID: opts.StackID, Template: string(data), Parameters: opts.Params}
	if next.StackID == "" && current != nil {
		next.StackID = current.StackID // an update keeps the stack's StackId
	}
	provisioned := map[string]bool{}
	for _, b := range desired {
		next.Resources = append(next.Resources, b.res)
		provisioned[strings.SplitN(b.res.LogicalID, "/", 2)[0]] = true
	}
	newF := FoldedResources(ctx, next, opts, nil)
	var oldF []FoldedResource
	if current != nil {
		for _, r := range current.Resources {
			provisioned[strings.SplitN(r.LogicalID, "/", 2)[0]] = true
		}
		// The current stack resolves with the parameters it was deployed with. A NoEcho value is not
		// recorded, so it is taken as the one this operation passes (an unchanged NoEcho parameter is
		// passed with its previous value).
		old := opts
		old.Params = map[string]string{}
		for k, v := range current.Parameters {
			old.Params[k] = v
		}
		for _, k := range current.NoEchoParameters {
			if v, ok := opts.Params[k]; ok {
				old.Params[k] = v
			}
		}
		oldF = FoldedResources(ctx, current, old, nil)
	}
	oldByID := map[string]FoldedResource{}
	for _, f := range oldF {
		oldByID[f.LogicalID] = f
	}
	var out []Change
	inNew := map[string]bool{}
	for _, f := range newF {
		inNew[f.LogicalID] = true
		if provisioned[f.LogicalID] {
			continue
		}
		ch := Change{LogicalID: f.LogicalID, Type: f.Type, Name: f.PhysicalID, Folded: true}
		prev, had := oldByID[f.LogicalID]
		switch {
		case !had:
			ch.Action = Add
		case prev.Type != f.Type || !specEqual(prev.props, f.props):
			ch.Action, ch.Name = Modify, prev.PhysicalID
		default:
			continue
		}
		out = append(out, ch)
	}
	for i := len(oldF) - 1; i >= 0; i-- { // removals in reverse template order, as the provisioned ones
		f := oldF[i]
		if inNew[f.LogicalID] || provisioned[f.LogicalID] {
			continue
		}
		out = append(out, Change{LogicalID: f.LogicalID, Type: f.Type, Name: f.PhysicalID, Action: Remove, Folded: true})
	}
	return out
}

// hasChanges reports whether the change set would actually change anything.
func (cs *ChangeSet) hasChanges() bool {
	for _, c := range cs.Changes {
		if c.Action != Unchanged {
			return true
		}
	}
	return false
}

// policyOrDelete is a recorded DeletionPolicy with the default spelled out.
func policyOrDelete(p string) string {
	if p == "" {
		return "Delete"
	}
	return p
}

// specEqual compares two specs through canonical JSON, so the number-typing difference between
// a freshly-built spec (int) and one round-tripped through the stored record (float64) does
// not read as a spurious Modify. An empty spec equals none: the stored record omits an empty one (a VPC's
// spec is {}), so it reads back as nil.
func specEqual(a, b map[string]any) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}
