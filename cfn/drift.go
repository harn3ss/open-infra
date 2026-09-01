// Drift detection for the CFN engine (Phase 5) — the read-only capstone.
//
// DetectDrift compares what the stack record says was applied against what is actually running
// on the cluster, and surfaces the disagreement. It never reconciles: a stack record that
// claims one thing while the cluster runs another is exactly the drift open-infra exists to
// catch, so the disagreement IS the finding — not something to quietly paper over.
//
// It compares only the fields the stack DECLARES (the keys in each recorded spec). A CRD or
// composition fills in defaults the stack never set (a Function's port, a scaler's target);
// those are not drift, and flagging them would be noise that hides real drift. A field the
// stack set that has since changed, or the whole resource deleted out of band, is drift.
package main

import (
	"bytes"
	"context"
	"encoding/json"
)

type DriftStatus string

const (
	InSync   DriftStatus = "IN_SYNC"
	Modified DriftStatus = "MODIFIED" // a declared field changed on the live object
	Deleted  DriftStatus = "DELETED"  // recorded, but gone from the cluster
)

type ResourceDrift struct {
	LogicalID     string
	Kind          string
	Name          string
	Status        DriftStatus
	DriftedFields []string // declared fields whose live value differs
}

type DriftReport struct {
	StackName string
	Namespace string
	InSync    bool
	Resources []ResourceDrift
}

// DetectDrift reads the stack record and diffs each recorded resource against its live spec.
func DetectDrift(ctx context.Context, opts DeployOptions, ap Applier) (*DriftReport, error) {
	rec, found, err := ap.GetStack(ctx, opts.StackName)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errNoStack(opts)
	}

	report := &DriftReport{StackName: opts.StackName, Namespace: opts.Namespace, InSync: true}
	for _, r := range rec.Resources {
		rd := ResourceDrift{LogicalID: r.LogicalID, Kind: r.Kind, Name: r.Name, Status: InSync}
		live, exists, err := ap.GetSpec(ctx, r.APIVersion, r.Kind, r.Name)
		if err != nil {
			return nil, err
		}
		if !exists {
			rd.Status = Deleted
			report.InSync = false
			report.Resources = append(report.Resources, rd)
			continue
		}
		for _, k := range sortedKeys(r.Spec) {
			if !jsonEqual(r.Spec[k], live[k]) {
				rd.DriftedFields = append(rd.DriftedFields, k)
			}
		}
		if len(rd.DriftedFields) > 0 {
			rd.Status = Modified
			report.InSync = false
		}
		report.Resources = append(report.Resources, rd)
	}
	return report, nil
}

func errNoStack(opts DeployOptions) error {
	return &noStackError{opts.StackName, opts.Namespace}
}

type noStackError struct{ name, ns string }

func (e *noStackError) Error() string {
	return "no stack " + e.name + " in namespace " + e.ns + " to check for drift"
}

// jsonEqual compares two values through canonical JSON, so the int↔float typing difference
// between a freshly-recorded spec and the live object read back as JSON is not false drift.
func jsonEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}
