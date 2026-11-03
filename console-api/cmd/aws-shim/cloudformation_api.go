// The rest of the CloudFormation API surface CI tools and the helper scripts use (#347 item I):
// DescribeStackEvents, ListStackResources, DescribeStackResource (singular — what cfn-init reads),
// ListChangeSets, ListImports and SignalResource (what cfn-signal calls), plus the WaitConditionHandle URL
// a guest PUTs its signal to.
//
// Events are kept apart from the stack record (cfn-events-<stack>, written as the engine records them, so a
// caller sees an operation progress resource by resource), and signals in cfn-signals-<stack> — both in the
// front door's record store.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// stackOpts are the engine options for a create or update a request starts: the front door's own, the
// exports, and the operation's fidelity line (shown by DescribeStacks and the stack's first event). A
// stack's queue URLs are built on SQS_QUEUE_URL_BASE (the caps), never on the host this request came in on.
func (h *cfnDoorway) stackOpts(name string, params map[string]string, ex stackExports, body string) cfn.DeployOptions {
	o := h.optsFor(name, params, ex)
	if p, err := cfn.BuildPlanWithCaps([]byte(body), params, ex.values, name, h.caps()); err == nil {
		o.Fidelity = fidelityLine(p)
	}
	return o
}

// --- events ---

func eventsRecordName(stack string) string  { return "cfn-events-" + stack }
func signalsRecordName(stack string) string { return "cfn-signals-" + stack }

// PutEvents makes the caller's applier a cfn.EventSink: the stack's events, kept apart from its record.
func (a *impersonatingApplier) PutEvents(ctx context.Context, stack string, events []cfn.StackEvent) error {
	b, err := json.Marshal(events)
	if err != nil {
		return err
	}
	st := a.recordStore()
	return st.apply(ctx, eventsRecordName(stack), map[string]any{"app.kubernetes.io/managed-by": "cfn-events", "cfn.openinfra.dev/stack": stack},
		map[string]string{"events.json": string(b)})
}

// stackEvents is a stack's events, newest first: the events record when it is newer than the stack
// record's own copy, else the record's. A deleted stack's are its kept record's alone (an events record
// of its name is a later stack's).
func (h *cfnDoorway) stackEvents(ctx context.Context, rec *cfn.StackRecord) []cfn.StackEvent {
	evs := rec.Events
	if rec.DeletedAt == "" {
		if side := h.sideEvents(ctx, rec.Name); len(side) > len(evs) {
			evs = side
		}
	}
	tmp := &cfn.StackRecord{Events: evs}
	return cfn.EventsNewestFirst(tmp)
}

func (h *cfnDoorway) describeStackEvents(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	rec, _, found, err := h.readStack(r, ap)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+stackRef(r)+"] does not exist", cfnXMLNamespace)
		return
	}
	stackID := h.idOf(rec)
	var b strings.Builder
	evs := withFoldedEvents(h.stackEvents(r.Context(), rec), h.foldedResources(r.Context(), rec, ap), rec.Name)
	for _, e := range evs {
		phys := e.PhysicalID
		if e.Type == cfn.StackTypeName {
			phys = stackID
		}
		b.WriteString("<member>")
		b.WriteString("<StackId>" + xesc(stackID) + "</StackId>")
		b.WriteString("<EventId>" + xesc(e.EventID) + "</EventId>")
		b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
		b.WriteString("<LogicalResourceId>" + xesc(e.LogicalID) + "</LogicalResourceId>")
		b.WriteString("<PhysicalResourceId>" + xesc(phys) + "</PhysicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(e.Type) + "</ResourceType>")
		b.WriteString("<Timestamp>" + xesc(e.Timestamp) + "</Timestamp>")
		b.WriteString("<ResourceStatus>" + xesc(e.Status) + "</ResourceStatus>")
		if e.Reason != "" {
			b.WriteString("<ResourceStatusReason>" + xesc(e.Reason) + "</ResourceStatusReason>")
		}
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "DescribeStackEvents", "<StackEvents>"+b.String()+"</StackEvents>")
}

// --- resources ---

// resourceRow is one resource as the Describe/List calls report it.
type resourceRow struct {
	logicalID, physicalID, typ, status, reason, timestamp string
}

// foldedResources is the stack's resources that provision nothing of their own (cfn.FoldedResources),
// with the Ref values its deploy computed: its parameters, the exports it imports, its signal URLs. sr
// reads the live status a Ref needs (an Elastic IP's address); nil leaves such a Ref unresolved.
func (h *cfnDoorway) foldedResources(ctx context.Context, rec *cfn.StackRecord, sr cfn.StatusReader) []cfn.FoldedResource {
	ex := stackExports{}
	if strings.Contains(rec.Template, "ImportValue") {
		ex = h.exportsFor(ctx, rec.Name)
	}
	return cfn.FoldedResources(ctx, rec, h.optsFor(rec.Name, rec.Parameters, ex), sr)
}

// stackResourceRows lists a stack's resources (companion objects folded into their parent), each with its
// CloudFormation type, physical id and own last status — from its latest event when the record predates
// per-resource status. A resource that provisions nothing of its own (an InternetGateway, a route, a
// WaitConditionHandle) is listed too, as AWS lists it: with its Ref as its physical id, and the status of
// the resources it is part of.
func (h *cfnDoorway) stackResourceRows(ctx context.Context, rec *cfn.StackRecord, sr cfn.StatusReader) []resourceRow {
	rows := h.provisionedResourceRows(ctx, rec)
	return append(rows, foldedRows(rec, rows, h.foldedResources(ctx, rec, sr))...)
}

// foldedRows are the rows of a stack's folded resources, each following its carriers' rows; one whose
// carriers have not started is not listed (on AWS a resource is listed once its creation begins).
func foldedRows(rec *cfn.StackRecord, rows []resourceRow, folded []cfn.FoldedResource) []resourceRow {
	byID := map[string]resourceRow{}
	for _, r := range rows {
		byID[r.logicalID] = r
	}
	var out []resourceRow
	for _, f := range folded {
		if _, own := byID[f.LogicalID]; own {
			continue // it has a row of its own (its events, or the record, list it)
		}
		row := resourceRow{logicalID: f.LogicalID, physicalID: f.PhysicalID, typ: f.Type}
		if len(f.Carriers) == 0 {
			if createNotStarted(rec) {
				continue
			}
			row.status, row.timestamp = cfn.FoldedStatusWithoutCarrier(rec.Status), recTime(rec)
		} else {
			var sts []string
			var latest resourceRow
			for _, c := range f.Carriers {
				cr, ok := byID[c]
				sts = append(sts, cr.status) // "" for a carrier not started (or not listed)
				if ok && cr.timestamp > latest.timestamp {
					latest = cr
				}
				if ok && strings.HasSuffix(cr.status, "_FAILED") && row.reason == "" {
					row.reason = "part of " + c + ": " + cr.reason
				}
			}
			st, listed := cfn.FoldedStatus(sts)
			if !listed {
				continue
			}
			if !strings.HasSuffix(st, "_FAILED") {
				row.reason = ""
			}
			row.status, row.timestamp = st, latest.timestamp
			if row.timestamp == "" {
				row.timestamp = recTime(rec)
			}
		}
		if row.physicalID == "" {
			row.physicalID = f.LogicalID // its Ref is not known yet (an Elastic IP's address is pending)
		}
		out = append(out, row)
	}
	return out
}

// createNotStarted reports whether a stack's create has not begun: no event of it is recorded.
func createNotStarted(rec *cfn.StackRecord) bool {
	return len(rec.Events) == 0 && rec.Status == "CREATE_IN_PROGRESS"
}

// withFoldedEvents adds, to a stack's events (newest first), the events of its folded resources: each
// one's status changes as its carriers' events move it (cfn.FoldedStatus), stamped like the carrier event
// that moved it; one with no carrier is created with the stack's create and deleted with its delete.
func withFoldedEvents(evs []cfn.StackEvent, folded []cfn.FoldedResource, stackName string) []cfn.StackEvent {
	if len(folded) == 0 {
		return evs
	}
	own := map[string]bool{}
	for _, e := range evs {
		own[e.LogicalID] = true
	}
	carriedBy := map[string][]int{} // carrier logical id -> indexes into folded
	for i, f := range folded {
		for _, c := range f.Carriers {
			carriedBy[c] = append(carriedBy[c], i)
		}
	}
	carrierStatus := make([]map[string]string, len(folded))
	last := make([]string, len(folded))
	for i := range folded {
		carrierStatus[i] = map[string]string{}
	}
	emit := func(out []cfn.StackEvent, i int, trigger cfn.StackEvent, status, suffix string) []cfn.StackEvent {
		f := folded[i]
		last[i] = status
		return append(out, cfn.StackEvent{EventID: f.LogicalID + "-" + status + "-" + trigger.EventID + suffix, LogicalID: f.LogicalID,
			PhysicalID: f.PhysicalID, Type: f.Type, Status: status, Timestamp: trigger.Timestamp})
	}
	var chrono []cfn.StackEvent // oldest first, with the folded events after the event that moved them
	for k := len(evs) - 1; k >= 0; k-- {
		e := evs[k]
		chrono = append(chrono, e)
		if e.Type == cfn.StackTypeName && e.LogicalID == stackName {
			for i, f := range folded {
				if len(f.Carriers) > 0 || own[f.LogicalID] {
					continue
				}
				switch {
				case e.Status == "CREATE_IN_PROGRESS" && last[i] == "":
					chrono = emit(chrono, i, e, "CREATE_IN_PROGRESS", "")
					chrono = emit(chrono, i, e, "CREATE_COMPLETE", "-done")
				case (e.Status == "DELETE_IN_PROGRESS" || e.Status == "ROLLBACK_IN_PROGRESS") && last[i] == "CREATE_COMPLETE":
					chrono = emit(chrono, i, e, "DELETE_IN_PROGRESS", "")
				case (e.Status == "DELETE_COMPLETE" || e.Status == "ROLLBACK_COMPLETE") && last[i] == "DELETE_IN_PROGRESS":
					chrono = emit(chrono, i, e, "DELETE_COMPLETE", "")
				}
			}
			continue
		}
		for _, i := range carriedBy[e.LogicalID] {
			if own[folded[i].LogicalID] {
				continue
			}
			carrierStatus[i][e.LogicalID] = e.Status
			sts := make([]string, 0, len(folded[i].Carriers))
			for _, c := range folded[i].Carriers {
				sts = append(sts, carrierStatus[i][c])
			}
			if st, listed := cfn.FoldedStatus(sts); listed && st != last[i] {
				chrono = emit(chrono, i, e, st, "")
			}
		}
	}
	out := make([]cfn.StackEvent, 0, len(chrono))
	for k := len(chrono) - 1; k >= 0; k-- {
		out = append(out, chrono[k])
	}
	return out
}

// provisionedResourceRows lists the resources the stack's record and events know.
func (h *cfnDoorway) provisionedResourceRows(ctx context.Context, rec *cfn.StackRecord) []resourceRow {
	latest := map[string]cfn.StackEvent{}
	for _, e := range h.stackEvents(ctx, rec) { // newest first
		if _, seen := latest[e.LogicalID]; !seen {
			latest[e.LogicalID] = e
		}
	}
	var rows []resourceRow
	for _, res := range rec.Resources {
		if strings.Contains(res.LogicalID, "/") {
			continue // a companion object (an inline policy) is part of its parent resource
		}
		row := resourceRow{logicalID: res.LogicalID, physicalID: res.PhysicalID, typ: res.Type, status: res.Status,
			reason: res.StatusReason, timestamp: res.Timestamp}
		if row.physicalID == "" {
			row.physicalID = res.Name
		}
		if row.typ == "" {
			row.typ = res.Kind
		}
		if e, ok := latest[res.LogicalID]; ok && (row.status == "" || e.Timestamp > row.timestamp) {
			row.status, row.reason, row.timestamp = e.Status, e.Reason, e.Timestamp
		}
		if row.status == "" && createNotFinished(rec.Status) {
			// Planned (the record lists every resource of a create before the first is applied) but not
			// started: AWS lists a resource once its creation begins.
			continue
		}
		if row.status == "" {
			row.status = completeStatusOf(rec.Status)
		}
		if row.timestamp == "" {
			row.timestamp = recTime(rec)
		}
		rows = append(rows, row)
	}
	// A resource whose create is under way but not yet in the record (a create interleaved with custom
	// resources records each one as it completes) is listed from its latest event, as AWS lists it.
	listed := map[string]bool{rec.Name: true}
	for _, r := range rows {
		listed[r.logicalID] = true
	}
	var pending []string
	for id := range latest {
		if !listed[id] && !strings.Contains(id, "/") {
			pending = append(pending, id)
		}
	}
	sort.Strings(pending)
	for _, id := range pending {
		e := latest[id]
		rows = append(rows, resourceRow{logicalID: id, physicalID: e.PhysicalID, typ: e.Type, status: e.Status,
			reason: e.Reason, timestamp: e.Timestamp})
	}
	return rows
}

// createNotFinished reports whether a stack's create is under way or ended without completing (it
// failed, or was rolled back): a resource of it with no status and no event was never started.
func createNotFinished(stackStatus string) bool {
	return stackStatus == "CREATE_IN_PROGRESS" || stackStatus == "CREATE_FAILED" || strings.HasPrefix(stackStatus, "ROLLBACK_")
}

// completeStatusOf is the resource status a record with no per-resource status implies.
func completeStatusOf(stackStatus string) string {
	switch {
	case strings.HasPrefix(stackStatus, "UPDATE"):
		return "UPDATE_COMPLETE"
	case strings.HasPrefix(stackStatus, "DELETE"):
		return stackStatus
	default:
		return "CREATE_COMPLETE"
	}
}

func (h *cfnDoorway) listStackResources(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	rec, _, found, err := h.readStack(r, ap)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+stackRef(r)+" does not exist", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	for _, row := range h.stackResourceRows(r.Context(), rec, ap) {
		b.WriteString("<member>")
		b.WriteString("<LogicalResourceId>" + xesc(row.logicalID) + "</LogicalResourceId>")
		b.WriteString("<PhysicalResourceId>" + xesc(row.physicalID) + "</PhysicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(row.typ) + "</ResourceType>")
		b.WriteString("<LastUpdatedTimestamp>" + xesc(row.timestamp) + "</LastUpdatedTimestamp>")
		b.WriteString("<ResourceStatus>" + xesc(row.status) + "</ResourceStatus>")
		if row.reason != "" {
			b.WriteString("<ResourceStatusReason>" + xesc(row.reason) + "</ResourceStatusReason>")
		}
		b.WriteString("<DriftInformation><StackResourceDriftStatus>NOT_CHECKED</StackResourceDriftStatus></DriftInformation>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "ListStackResources", "<StackResourceSummaries>"+b.String()+"</StackResourceSummaries>")
}

// describeStackResource serves DescribeStackResource: one resource, with its Metadata (from the template the
// stack was deployed with) — what cfn-init reads for AWS::CloudFormation::Init.
func (h *cfnDoorway) describeStackResource(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	rec, _, found, err := h.readStack(r, ap)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+stackRef(r)+" does not exist", cfnXMLNamespace)
		return
	}
	h.describeStackResourceOf(w, r, rec, ap, requestID)
}

// describeStackResourceOf answers DescribeStackResource for a stack record already read (and authorized).
// sr reads the live status a folded resource's Ref needs (an Elastic IP's address); nil leaves it unresolved.
func (h *cfnDoorway) describeStackResourceOf(w http.ResponseWriter, r *http.Request, rec *cfn.StackRecord, sr cfn.StatusReader, requestID string) {
	name, lid := r.PostFormValue("StackName"), r.PostFormValue("LogicalResourceId")
	// A resource that provisions nothing of its own (a WaitConditionHandle, an InternetGateway) is listed
	// like any other, with its Ref as its physical id; one not started yet — or gated off by its
	// Condition — does not exist, as on AWS.
	var row *resourceRow
	for _, rr := range h.stackResourceRows(r.Context(), rec, sr) {
		if rr.logicalID == lid {
			rr := rr
			row = &rr
			break
		}
	}
	if row == nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Resource "+lid+" does not exist for stack "+name, cfnXMLNamespace)
		return
	}
	meta := ""
	if t, perr := cfn.Parse([]byte(rec.Template)); perr == nil {
		if res, ok := t.Resources[lid]; ok && len(res.Metadata) > 0 {
			if b, merr := json.Marshal(res.Metadata); merr == nil {
				meta = string(b)
			}
		}
	}
	var b strings.Builder
	b.WriteString("<StackResourceDetail>")
	b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
	b.WriteString("<StackId>" + xesc(h.idOf(rec)) + "</StackId>")
	b.WriteString("<LogicalResourceId>" + xesc(row.logicalID) + "</LogicalResourceId>")
	b.WriteString("<PhysicalResourceId>" + xesc(row.physicalID) + "</PhysicalResourceId>")
	b.WriteString("<ResourceType>" + xesc(row.typ) + "</ResourceType>")
	b.WriteString("<LastUpdatedTimestamp>" + xesc(row.timestamp) + "</LastUpdatedTimestamp>")
	b.WriteString("<ResourceStatus>" + xesc(row.status) + "</ResourceStatus>")
	if meta != "" {
		b.WriteString("<Metadata>" + xesc(meta) + "</Metadata>")
	}
	b.WriteString("</StackResourceDetail>")
	h.writeResult(w, requestID, "DescribeStackResource", b.String())
}

// --- change sets, imports ---

func (h *cfnDoorway) listChangeSets(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	st := h.recs()
	list, err := st.client().List(r.Context(), metav1.ListOptions{LabelSelector: "cfn.openinfra.dev/changeset=" + stack})
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	var names []string
	for _, u := range list.Items {
		names = append(names, u.GetName())
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		csName := strings.TrimPrefix(n, "cfn-changeset-"+stack+".")
		cs, gerr := h.getChangeSet(r.Context(), stack, csName)
		if gerr != nil {
			continue
		}
		b.WriteString("<member>")
		b.WriteString("<StackId>" + xesc(h.changeSetStackID(cs)) + "</StackId>")
		b.WriteString("<StackName>" + xesc(stack) + "</StackName>")
		b.WriteString("<ChangeSetId>" + xesc(h.changeSetID(stack, csName)) + "</ChangeSetId>")
		b.WriteString("<ChangeSetName>" + xesc(csName) + "</ChangeSetName>")
		b.WriteString("<ExecutionStatus>" + xesc(changeSetExecutionStatus(cs)) + "</ExecutionStatus>")
		b.WriteString("<Status>" + xesc(changeSetStatus(cs)) + "</Status>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "ListChangeSets", "<Summaries>"+b.String()+"</Summaries>")
}

// listImports serves ListImports: the stacks that import an export.
func (h *cfnDoorway) listImports(w http.ResponseWriter, r *http.Request, requestID string) {
	export := r.PostFormValue("ExportName")
	if export == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "ExportName is required.", cfnXMLNamespace)
		return
	}
	ex := h.exportsFor(r.Context(), "")
	if _, ok := ex.values[export]; !ok {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Export '"+export+"' does not exist.", cfnXMLNamespace)
		return
	}
	var users []string
	for _, rec := range h.allRecords(r.Context()) {
		for _, imp := range rec.Imports {
			if imp == export {
				users = append(users, rec.Name)
			}
		}
	}
	sort.Strings(users)
	var b strings.Builder
	for _, u := range users {
		b.WriteString("<member>" + xesc(u) + "</member>")
	}
	h.writeResult(w, requestID, "ListImports", "<Imports>"+b.String()+"</Imports>")
}

// --- signals ---

// signalStore keeps the signals a stack's resources receive (cfn-signals-<stack>: one data key per
// resource or handle logical id, a JSON list). It is the engine's cfn.SignalSource.
type signalStore struct {
	h  *cfnDoorway
	mu sync.Mutex
}

func (s *signalStore) Signals(ctx context.Context, stack, id string) ([]cfn.Signal, error) {
	st := s.h.recs()
	u, err := st.client().Get(ctx, signalsRecordName(stack), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []cfn.Signal
	if v := st.value(u, id); v != "" {
		if err := json.Unmarshal([]byte(v), &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// add records one signal for resource (or handle) id of stack — a read-modify-write retried on conflict.
func (s *signalStore) add(ctx context.Context, stack, id string, sig cfn.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.h.recs()
	for attempt := 0; attempt < 5; attempt++ {
		u, err := st.client().Get(ctx, signalsRecordName(stack), metav1.GetOptions{})
		var list []cfn.Signal
		if err == nil {
			_ = json.Unmarshal([]byte(st.value(u, id)), &list)
		} else if !apierrors.IsNotFound(err) {
			return err
		}
		if len(list) >= 100 {
			return fmt.Errorf("resource %s has already received the maximum number of signals", id)
		}
		list = append(list, sig)
		b, _ := json.Marshal(list)
		data := map[string]string{id: string(b)}
		if err == nil {
			for k := range u.Object["data"].(map[string]any) {
				if k != id {
					data[k] = st.value(u, k)
				}
			}
			obj := st.object(signalsRecordName(stack), map[string]any{"app.kubernetes.io/managed-by": "cfn-signals", "cfn.openinfra.dev/stack": stack}, nil, data)
			obj.SetResourceVersion(u.GetResourceVersion())
			if _, uerr := st.client().Update(ctx, obj, metav1.UpdateOptions{}); uerr == nil {
				return nil
			} else if !apierrors.IsConflict(uerr) {
				return uerr
			}
			continue
		}
		obj := st.object(signalsRecordName(stack), map[string]any{"app.kubernetes.io/managed-by": "cfn-signals", "cfn.openinfra.dev/stack": stack}, nil, data)
		if _, cerr := st.client().Create(ctx, obj, metav1.CreateOptions{}); cerr == nil {
			return nil
		} else if !apierrors.IsAlreadyExists(cerr) {
			return cerr
		}
	}
	return fmt.Errorf("could not record the signal (the record kept changing)")
}

// deleteStackSide removes a deleted stack's events, signals and its distributions' invalidations.
func (h *cfnDoorway) deleteStackSide(ctx context.Context, stack string) {
	st := h.recs()
	for _, n := range []string{eventsRecordName(stack), signalsRecordName(stack), invalidationsRecordName(stack)} {
		_ = st.client().Delete(ctx, n, metav1.DeleteOptions{})
	}
}

// signalResource serves SignalResource (cfn-signal --stack/--resource). The caller must be allowed to
// signal: a User with update rights on the stack, a role whose policy allows cloudformation:SignalResource
// on it — or an instance of the stack itself, i.e. a session of a role one of the stack's own instances
// runs as (cfn-signal needs no extra permission on AWS, and a template written for AWS grants none).
func (h *cfnDoorway) signalResource(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	stack, lid := r.PostFormValue("StackName"), r.PostFormValue("LogicalResourceId")
	uid, status := r.PostFormValue("UniqueId"), strings.ToUpper(r.PostFormValue("Status"))
	if stack == "" || lid == "" || uid == "" || (status != "SUCCESS" && status != "FAILURE") {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"StackName, LogicalResourceId, UniqueId and Status (SUCCESS or FAILURE) are required.", cfnXMLNamespace)
		return
	}
	rec, found, err := h.getRecord(r.Context(), stack)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+stack+"] does not exist", cfnXMLNamespace)
		return
	}
	if !h.maySignal(r, claims, rec) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			"not authorized to perform cloudformation:SignalResource on stack "+stack, cfnXMLNamespace)
		return
	}
	h.recordSignal(w, r, rec, requestID)
}

// recordSignal records an authorized SignalResource on a stack record already read.
func (h *cfnDoorway) recordSignal(w http.ResponseWriter, r *http.Request, rec *cfn.StackRecord, requestID string) {
	stack, lid := rec.Name, r.PostFormValue("LogicalResourceId")
	uid, status := r.PostFormValue("UniqueId"), strings.ToUpper(r.PostFormValue("Status"))
	if lid == "" || uid == "" || (status != "SUCCESS" && status != "FAILURE") {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"StackName, LogicalResourceId, UniqueId and Status (SUCCESS or FAILURE) are required.", cfnXMLNamespace)
		return
	}
	if !strings.HasSuffix(rec.Status, "_IN_PROGRESS") {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Stack "+stack+" is in "+rec.Status+" state and cannot be signaled", cfnXMLNamespace)
		return
	}
	if err := h.signals.add(r.Context(), stack, lid, cfn.Signal{UniqueID: uid, Status: status, Time: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "SignalResource", "")
}

// maySignal decides SignalResource authorization (see signalResource).
func (h *cfnDoorway) maySignal(r *http.Request, claims iam.Claims, rec *cfn.StackRecord) bool {
	if claims.AssumedRole != "" {
		for _, res := range rec.Resources {
			if role, _ := res.Spec["instanceRole"].(string); role != "" && role == roleNameOf(claims.AssumedRole) {
				return true
			}
		}
		denied, _ := deniedByDataPlane(r.Context(), h.authz, claims, "cloudformation:SignalResource", "Stack", rec.Name, r)
		return !denied
	}
	if ok, _ := h.canDo(r.Context(), claims, "update", rec.Name); !ok {
		return false
	}
	denied, _ := deniedByDataPlane(r.Context(), h.authz, claims, "cloudformation:SignalResource", "Stack", rec.Name, r)
	return !denied
}

// roleNameOf is the role name of an assumed-role identity (a bare name, or a role ARN's last segment).
func roleNameOf(role string) string {
	if i := strings.LastIndex(role, "/"); i >= 0 {
		return role[i+1:]
	}
	return role
}

// getRecord reads a stack record with the shim's own client.
func (h *cfnDoorway) getRecord(ctx context.Context, stack string) (*cfn.StackRecord, bool, error) {
	st := h.recs()
	u, err := st.client().Get(ctx, "cfn-stack-"+stack, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rec, ok := st.stackRecord(u)
	return rec, ok, nil
}

// --- wait-condition handles ---

// waitConditionPath is where a WaitConditionHandle's URL points: /cfn-signal/<stack>/<handle>?sig=<hmac>.
const waitConditionPath = "/cfn-signal/"

// signalKey is the HMAC key that signs handle URLs: CFN_SIGNAL_KEY, else a key kept in the record store
// (created once, shared by every replica).
func (h *cfnDoorway) signalKey(ctx context.Context) ([]byte, error) {
	h.keyOnce.Do(func() {
		if k := os.Getenv("CFN_SIGNAL_KEY"); k != "" {
			h.sigKey = []byte(k)
			return
		}
		st := h.recs()
		const name = "cfn-signal-key"
		for i := 0; i < 3 && h.sigKey == nil; i++ {
			if u, err := st.client().Get(ctx, name, metav1.GetOptions{}); err == nil {
				if v := st.value(u, "key"); v != "" {
					h.sigKey = []byte(v)
					return
				}
			}
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				return
			}
			obj := st.object(name, map[string]any{"app.kubernetes.io/managed-by": "cfn-signals"}, nil, map[string]string{"key": hex.EncodeToString(buf)})
			if _, err := st.client().Create(ctx, obj, metav1.CreateOptions{}); err == nil {
				h.sigKey = []byte(hex.EncodeToString(buf))
			}
		}
	})
	if h.sigKey == nil {
		return nil, fmt.Errorf("no signal key")
	}
	return h.sigKey, nil
}

func signHandle(key []byte, stack, handle string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(stack + "\x00" + handle))
	return hex.EncodeToString(m.Sum(nil))
}

// signalURL is a WaitConditionHandle's Ref: a URL on this shim, signed for that stack and handle, that a
// guest PUTs its signal to (CFN_SIGNAL_BASE_URL, default the in-cluster TLS address guests already trust).
func (h *cfnDoorway) signalURL(stack, handle string) string {
	key, err := h.signalKey(context.Background())
	if err != nil {
		return ""
	}
	base := strings.TrimSuffix(h.signalBase, "/")
	return base + waitConditionPath + url.PathEscape(stack) + "/" + url.PathEscape(handle) + "?sig=" + signHandle(key, stack, handle)
}

// waitConditionHandler serves PUTs to WaitConditionHandle URLs, ahead of SigV4: the signed URL is the
// credential, as AWS's pre-signed handle URL is. The body is AWS's: {"Status","UniqueId","Data","Reason"}.
func (h *cfnDoorway) waitConditionHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, waitConditionPath) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			http.Error(w, "PUT the signal JSON to this URL", http.StatusMethodNotAllowed)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, waitConditionPath), "/", 2)
		if len(parts) != 2 {
			http.Error(w, "not a wait-condition handle URL", http.StatusNotFound)
			return
		}
		stack, err1 := url.PathUnescape(parts[0])
		handle, err2 := url.PathUnescape(parts[1])
		key, kerr := h.signalKey(r.Context())
		if err1 != nil || err2 != nil || kerr != nil ||
			!hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(signHandle(key, stack, handle))) {
			http.Error(w, "the signature does not match", http.StatusForbidden)
			return
		}
		var body struct {
			Status, UniqueId, Data, Reason string
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err := json.Unmarshal(raw, &body); err != nil || body.UniqueId == "" ||
			(!strings.EqualFold(body.Status, "SUCCESS") && !strings.EqualFold(body.Status, "FAILURE")) {
			http.Error(w, `the body must be {"Status":"SUCCESS"|"FAILURE","UniqueId":…,"Data":…,"Reason":…}`, http.StatusBadRequest)
			return
		}
		rec, found, err := h.getRecord(r.Context(), stack)
		if err != nil || !found || !strings.HasSuffix(rec.Status, "_IN_PROGRESS") {
			http.Error(w, "the stack is not waiting for signals", http.StatusConflict)
			return
		}
		if err := h.signals.add(r.Context(), stack, handle, cfn.Signal{UniqueID: body.UniqueId, Status: strings.ToUpper(body.Status),
			Data: body.Data, Reason: body.Reason, Time: time.Now().UTC().Format(time.RFC3339)}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
