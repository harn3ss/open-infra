// Deleted stacks (#350 Y), as AWS keeps them.
//
// AWS keeps a deleted stack for 90 days: ListStacks lists it (DELETE_COMPLETE, with its DeletionTime), and
// DescribeStacks, DescribeStackEvents, DescribeStackResources, ListStackResources, DescribeStackResource,
// GetTemplate and GetTemplateSummary answer for it when it is named by its StackId — by name, a stack name
// means only the stack of that name now in use. Each stack instance therefore has its own StackId
// (awsidentity NewStackID): a stack re-created under a deleted stack's name gets a new one, and the
// deleted stack stays known by its own. A stack created before StackIds were per instance keeps its
// derived StackId, and is kept under it once deleted.
//
// The kept record is the deleted stack's, compacted: its status history (events), template, parameters
// (never a NoEcho value) and each resource's logical id, type, physical id and last status — not the
// resources' applied specs, their outputs or its exports. It is a record of the front door's store, as
// stack records are (cfn_records.go), and is removed 90 days after the delete. So that churn cannot grow
// the store without bound, at most cfnDeletedLimit deleted stacks are kept (the oldest removed first),
// and a template over cfnDeletedTemplateMax bytes is not kept (GetTemplate then says so).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// cfnDeletedRetention is how long a deleted stack is kept, as on AWS.
	cfnDeletedRetention = 90 * 24 * time.Hour
	// cfnDeletedLimit bounds how many deleted stacks are kept; past it the oldest go first.
	cfnDeletedLimit = 1000
	// cfnDeletedTemplateMax is the largest template a deleted stack's record keeps.
	cfnDeletedTemplateMax = 256 << 10
	// cfnDeletedManagedBy labels a deleted stack's record (apart from live stack records, which
	// allRecords, the exports and recovery read).
	cfnDeletedManagedBy = "cfn-deleted"
)

// idOf is a stack's StackId: its record's own, else (a stack from before StackIds were per instance) the
// derived StackId of its name.
func (h *cfnDoorway) idOf(rec *cfn.StackRecord) string {
	if rec.StackID != "" {
		return rec.StackID
	}
	return h.stackID(rec.Name)
}

// changeSetStackID is the StackId of the stack a change set is for.
func (h *cfnDoorway) changeSetStackID(cs *changeSet) string {
	if cs.StackID != "" {
		return cs.StackID
	}
	return h.stackID(cs.StackName)
}

// liveStackID is the StackId of the stack of that name now in use (the derived one when there is none).
func (h *cfnDoorway) liveStackID(ctx context.Context, name string) string {
	if rec, found, err := h.getRecord(ctx, name); err == nil && found {
		return h.idOf(rec)
	}
	return h.stackID(name)
}

// newStackID is a new stack instance's StackId.
func (h *cfnDoorway) newStackID(name string) string {
	return awsidentity.Identity{AccountID: h.account, Region: h.region, StackNamespace: h.ns}.NewStackID(name)
}

type cfnStackARNKey struct{}

// withStackARN carries the StackId a request named its stack by (its StackName was a stack ARN, which
// normalizeStackArgs reduced to the name).
func withStackARN(r *http.Request, arn string) *http.Request {
	if arn == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), cfnStackARNKey{}, arn))
}

// stackARNOf is the StackId a request named its stack by ("" = it named the stack by name).
func stackARNOf(r *http.Request) string {
	s, _ := r.Context().Value(cfnStackARNKey{}).(string)
	return s
}

// namesLive reports whether a StackId names the live stack rec: its own StackId — or, for a stack from
// before StackIds were per instance, any StackId of its name that no deleted stack has (before, every
// ARN of a stack's name named it, and a client may have kept one).
func (h *cfnDoorway) namesLive(ctx context.Context, rec *cfn.StackRecord, arn string) bool {
	if awsidentity.SameStackID(h.idOf(rec), arn) {
		return true
	}
	if rec.StackID != "" {
		return false
	}
	_, deleted := h.deletedStack(ctx, rec.Name, arn)
	return !deleted
}

// readStack is the stack a read names: by name, the live stack of that name; by StackId, the live stack
// if it is that instance, else the deleted stack with that StackId (deleted=true). found=false when there
// is neither.
func (h *cfnDoorway) readStack(r *http.Request, ap *impersonatingApplier) (rec *cfn.StackRecord, deleted, found bool, err error) {
	ctx := r.Context()
	name, arn := r.PostFormValue("StackName"), stackARNOf(r)
	live, liveFound, err := ap.GetStack(ctx, name)
	if err != nil {
		return nil, false, false, err
	}
	if arn == "" {
		return live, false, liveFound, nil
	}
	if liveFound && h.namesLive(ctx, live, arn) {
		return live, false, true, nil
	}
	if d, ok := h.deletedStack(ctx, name, arn); ok {
		return d, true, true, nil
	}
	return nil, false, false, nil
}

// stackGone answers a request that named, by its StackId, a stack instance that is not the live one: a
// DeleteStack of a deleted stack is the no-op AWS makes of it; anything else does not find the stack.
// It reports whether it answered.
func (h *cfnDoorway) stackGone(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, action, requestID string) bool {
	arn := stackARNOf(r)
	if arn == "" {
		return false
	}
	live, found, err := ap.GetStack(r.Context(), r.PostFormValue("StackName"))
	if err == nil && found && h.namesLive(r.Context(), live, arn) {
		return false
	}
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
		return true
	}
	if action == "DeleteStack" {
		h.writeResult(w, requestID, "DeleteStack", "")
		return true
	}
	writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+arn+" does not exist", cfnXMLNamespace)
	return true
}

// readsDeleted reports whether an action answers for a deleted stack named by its StackId, as on AWS.
func readsDeleted(action string) bool {
	switch action {
	case "DescribeStacks", "DescribeStackEvents", "DescribeStackResources", "ListStackResources",
		"DescribeStackResource", "GetTemplate", "GetTemplateSummary":
		return true
	}
	return false
}

// deletedTemplateGone is the answer for a deleted stack whose template was too large to keep.
func deletedTemplateGone(rec *cfn.StackRecord) string {
	return "Stack " + rec.StackID + " was deleted, and its template (over " + strconv.Itoa(cfnDeletedTemplateMax>>10) +
		" KiB) was not kept with it on open-infra."
}

// deletedRecordName is a deleted stack's record name: its name and a digest of its StackId, so the
// stacks deleted under one name are kept apart.
func deletedRecordName(name, stackID string) string {
	sum := sha256.Sum256([]byte(stackID))
	return "cfn-deleted-" + name + "." + hex.EncodeToString(sum[:])[:12]
}

// keepDeleted keeps a stack whose delete completed. before is its record as the delete began (every
// resource it had); after is the record the delete ended with (DELETE_COMPLETE, its events through the
// delete), or nil when only before is known (a delete that recovery resumed). Each resource keeps the
// last status its events give it (DELETE_COMPLETE, or DELETE_SKIPPED for a retained one). Best effort:
// the delete has happened either way.
func (h *cfnDoorway) keepDeleted(ctx context.Context, before, after *cfn.StackRecord) {
	if before == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	kept := cfn.StackRecord{
		Name: before.Name, Namespace: before.Namespace, StackID: h.idOf(before), Status: "DELETE_COMPLETE",
		CreatedAt: before.CreatedAt, UpdatedAt: now, Owner: before.Owner, ParentID: before.ParentID, RootID: before.RootID,
		Template: before.Template, Parameters: before.Parameters, NoEchoParameters: before.NoEchoParameters,
		Description: before.Description, Fidelity: before.Fidelity, DeletedAt: now,
	}
	if len(kept.Template) > cfnDeletedTemplateMax {
		kept.Template = ""
	}
	evs := before.Events
	if after != nil && len(after.Events) > len(evs) {
		evs = after.Events
	}
	if side := h.sideEvents(ctx, before.Name); len(side) > len(evs) {
		evs = side
	}
	kept.Events = append([]cfn.StackEvent(nil), evs...)
	if n := len(kept.Events); n == 0 || kept.Events[n-1].Type != cfn.StackTypeName || kept.Events[n-1].Status != "DELETE_COMPLETE" {
		// A resumed delete's final event was never recorded: the stack's DELETE_COMPLETE is its last.
		kept.Events = append(kept.Events, cfn.StackEvent{EventID: shortHash(kept.StackID + "/DELETE_COMPLETE"),
			LogicalID: kept.Name, Type: cfn.StackTypeName, Status: "DELETE_COMPLETE", Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z")})
	}
	last := map[string]cfn.StackEvent{}
	for _, e := range kept.Events { // oldest first: the last one per resource wins
		last[e.LogicalID] = e
	}
	for _, r := range before.Resources {
		kr := cfn.StackResource{LogicalID: r.LogicalID, Type: r.Type, Kind: r.Kind, Name: r.Name, PhysicalID: r.PhysicalID,
			Status: "DELETE_COMPLETE", Timestamp: kept.Events[len(kept.Events)-1].Timestamp, DeletionPolicy: r.DeletionPolicy}
		if e, ok := last[r.LogicalID]; ok && strings.HasPrefix(e.Status, "DELETE_") {
			kr.Status, kr.StatusReason, kr.Timestamp = e.Status, e.Reason, e.Timestamp
		}
		kept.Resources = append(kept.Resources, kr)
	}
	data, err := json.Marshal(kept)
	if err != nil {
		return
	}
	if err := h.recs().apply(ctx, deletedRecordName(kept.Name, kept.StackID),
		map[string]any{"app.kubernetes.io/managed-by": cfnDeletedManagedBy, "cfn.openinfra.dev/stack": kept.Name},
		map[string]string{"stack.json": string(data)}); err != nil {
		h.logger.Warn("cfn: could not keep the deleted stack's record (ListStacks will not list it)", "stack", kept.Name, "error", err.Error())
	}
}

// sideEvents is the events record a stack's operations keep apart from its record (nil when none).
func (h *cfnDoorway) sideEvents(ctx context.Context, stack string) []cfn.StackEvent {
	st := h.recs()
	u, err := st.client().Get(ctx, eventsRecordName(stack), metav1.GetOptions{})
	if err != nil {
		return nil
	}
	var side []cfn.StackEvent
	if json.Unmarshal([]byte(st.value(u, "events.json")), &side) != nil {
		return nil
	}
	return side
}

// deletedStacks lists the kept deleted stacks (of one name, or every name when name is ""), newest delete
// first.
func (h *cfnDoorway) deletedStacks(ctx context.Context, name string) []*cfn.StackRecord {
	sel := "app.kubernetes.io/managed-by=" + cfnDeletedManagedBy
	if name != "" {
		sel += ",cfn.openinfra.dev/stack=" + name
	}
	st := h.recs()
	list, err := st.client().List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil
	}
	var out []*cfn.StackRecord
	for i := range list.Items {
		if !strings.HasPrefix(list.Items[i].GetName(), "cfn-deleted-") {
			continue
		}
		if rec, ok := st.stackRecord(&list.Items[i]); ok && rec.DeletedAt != "" && (name == "" || rec.Name == name) {
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DeletedAt > out[j].DeletedAt })
	return out
}

// deletedStack is the kept deleted stack of that name with that StackId.
func (h *cfnDoorway) deletedStack(ctx context.Context, name, arn string) (*cfn.StackRecord, bool) {
	for _, rec := range h.deletedStacks(ctx, name) {
		if awsidentity.SameStackID(rec.StackID, arn) {
			return rec, true
		}
	}
	return nil, false
}

// pruneDeleted removes the deleted stacks kept longer than cfnDeletedRetention, and the oldest past
// cfnDeletedLimit. Run with every recovery pass.
func (h *cfnDoorway) pruneDeleted(ctx context.Context, now time.Time) {
	all := h.deletedStacks(ctx, "")
	for i, rec := range all {
		t, err := time.Parse(time.RFC3339, rec.DeletedAt)
		if err == nil && now.Sub(t) <= cfnDeletedRetention && i < cfnDeletedLimit {
			continue
		}
		if err := h.recs().client().Delete(ctx, deletedRecordName(rec.Name, rec.StackID), metav1.DeleteOptions{}); err != nil {
			h.logger.Warn("cfn: could not remove a deleted stack past its retention (retried next pass)", "stack", rec.Name, "error", err.Error())
		}
	}
}
