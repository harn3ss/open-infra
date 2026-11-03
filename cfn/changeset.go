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
	return cs, desired, current, nil
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
// not read as a spurious Modify.
func specEqual(a, b map[string]any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}
