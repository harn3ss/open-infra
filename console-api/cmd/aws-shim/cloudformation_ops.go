// Durable stack operations for the CloudFormation front door (#347).
//
// A long stack operation (CreateStack / UpdateStack / DeleteStack / ExecuteChangeSet) runs in the
// background of the shim process that accepted it. A front-door restart mid-operation — an ordinary
// rolling update — used to kill the operation with the process and leave the stack record *_IN_PROGRESS
// forever: DescribeStacks reported it in progress indefinitely and the resources it had created sat
// without the engine's rollback. AWS never strands a stack. Neither does this front door:
//
//   - OWNERSHIP. Every operation is owned by exactly one process, recorded as annotations on the stack
//     record's ConfigMap (cfn-stack-<name>): the owner (<pod>/<per-process instance id>, so a restarted
//     container is a new owner), a lease timestamp the running operation renews every cfnLeaseRefresh, the
//     lease duration, the action, and the CALLER identity the operation runs under (the impersonated
//     openinfra:<sub> + groups). The annotations are written under their own field manager and only by
//     merge patch, never server-side apply: the engine's own record writes (SSA, field manager
//     cfn-doorway) neither carry nor prune them, and a renewal can never re-create a record that a
//     completed delete removed.
//   - ATOMIC CLAIMS. CreateStack creates the record with a plain Create carrying the lease (two replicas
//     cannot both create a stack); an operation on an existing stack — and a recovery — claims it with a
//     patch conditional on the record's resourceVersion, so two claimants cannot both proceed.
//   - SELF-FENCING. A holder that cannot renew for cfnRenewDeadline (well inside the lease duration)
//     cancels its own operation before anyone else may consider the lease stale; one whose record was
//     claimed by another owner stops at once — the leader-election discipline.
//   - RECOVERY. On startup and every cfnRecoveryInterval, one List of the stack records finds every
//     *_IN_PROGRESS record that no live operation owns: not running in THIS process, and owned by this
//     process's own ended operation, or holding a lease older than its duration, or — a record written
//     before leases existed — not updated for longer than any operation may run. The pass claims it, then
//     runs cfn.RecoverInterrupted under the operation's RECORDED caller: an interrupted create is rolled
//     back (ROLLBACK_COMPLETE, Retain honored), an update is rolled back to the prior stack
//     (UPDATE_ROLLBACK_COMPLETE), a delete is resumed — with a StackStatusReason naming the interruption.
//     A record with no usable recorded caller is never rolled back under any other authority (not the
//     shim's): it is settled *_FAILED, and DeleteStack (under the caller's own authority) cleans it up.
//   - SHUTDOWN. On SIGTERM the front door accepts no new stack operation (503 ServiceUnavailable, which
//     SDKs retry) and waits a bounded time for those in flight; one still running when the process exits
//     is recovered by the next front door once its lease lapses.
//
// Trust: the recorded caller is read back only from the stack-record ConfigMap in the CFN namespace, which
// only the shim's ServiceAccount (and cluster admins) can write — powerusers deliberately cannot create
// ConfigMaps — and impersonation itself is RBAC-pinned to the four openinfra: groups. A recorded identity
// that is not one this front door could have minted (openinfra:<sub>, openinfra: groups) is refused.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Operation annotations on a cfn-stack-<name> record.
const (
	annOpOwner   = "cfn.openinfra.dev/operation-owner"         // <pod>/<instance id> of the process running it
	annOpRenewed = "cfn.openinfra.dev/operation-renewed-at"    // RFC3339Nano; renewed every cfnLeaseRefresh
	annOpLease   = "cfn.openinfra.dev/operation-lease-seconds" // the owner's lease duration
	annOpAction  = "cfn.openinfra.dev/operation"               // CreateStack | UpdateStack | DeleteStack | ExecuteChangeSet
	annOpCaller  = "cfn.openinfra.dev/operation-caller"        // JSON {"user","groups"}: the authority it runs (and is recovered) under

	cfnLeaseManager = "cfn-doorway-lease" // field manager for the annotations — never the engine's cfn-doorway
)

var opAnnotations = []string{annOpOwner, annOpRenewed, annOpLease, annOpAction, annOpCaller}

const (
	cfnLeaseRefresh     = 15 * time.Second
	cfnLeaseDuration    = 4 * cfnLeaseRefresh
	cfnRecoveryInterval = 30 * time.Second
	// A record from before leases has no owner to ask. Only a front door from before leases writes one,
	// and those bounded every operation at 15 minutes, so one not updated for longer than this is
	// certainly orphaned (today's longer cfnAsyncTimeout applies only to leased operations).
	cfnLegacyGrace = 16 * time.Minute
	// How long shutdown waits for in-flight operations. Kept inside the Deployment's
	// terminationGracePeriodSeconds (platform/aws-shim/aws-shim.yaml) after the HTTP drain.
	cfnDrainTimeout = 40 * time.Second
)

var (
	errCFNTerminating = errors.New("the CloudFormation front door is shutting down and is not accepting new stack operations; retry the request")
	errCFNStackBusy   = errors.New("another operation on this stack is in progress")
)

// cfnOps tracks this process's stack operations. The zero value is ready to use; the duration fields
// override the defaults (tests).
type cfnOps struct {
	mu          sync.Mutex
	live        map[string]bool // stack -> an operation (or a recovery) is running in THIS process
	terminating bool
	wg          sync.WaitGroup
	ownerOnce   sync.Once
	owner       string

	refresh, lease, recoveryEvery, legacyGrace time.Duration
}

func (o *cfnOps) refreshEvery() time.Duration { return orDefault(o.refresh, cfnLeaseRefresh) }
func (o *cfnOps) leaseFor() time.Duration     { return orDefault(o.lease, cfnLeaseDuration) }
func (o *cfnOps) recoveryInterval() time.Duration {
	return orDefault(o.recoveryEvery, cfnRecoveryInterval)
}
func (o *cfnOps) legacyGraceFor() time.Duration { return orDefault(o.legacyGrace, cfnLegacyGrace) }

// renewDeadline: a holder that has not renewed for this long fences itself. Two refresh intervals inside
// the lease, so it stops (checked once per refresh) before another front door can see the lease stale.
func (o *cfnOps) renewDeadline() time.Duration {
	d := o.leaseFor() - 2*o.refreshEvery()
	if d < o.refreshEvery() {
		d = o.refreshEvery()
	}
	return d
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// ownerID identifies this process: the pod (POD_NAME, else the hostname — the pod name in Kubernetes)
// plus a random per-process id, so a container restarted in the same pod is a different owner.
func (o *cfnOps) ownerID() string {
	o.ownerOnce.Do(func() {
		if o.owner != "" {
			return
		}
		pod := os.Getenv("POD_NAME")
		if pod == "" {
			pod, _ = os.Hostname()
		}
		if pod == "" {
			pod = "aws-shim"
		}
		var b [6]byte
		_, _ = rand.Read(b[:])
		o.owner = pod + "/" + hex.EncodeToString(b[:])
	})
	return o.owner
}

// begin registers an operation on stack in this process: refused once terminating, or while another one
// on the same stack is live here. Every successful begin is paired with exactly one end.
func (o *cfnOps) begin(stack string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.terminating {
		return errCFNTerminating
	}
	if o.live[stack] {
		return errCFNStackBusy
	}
	if o.live == nil {
		o.live = map[string]bool{}
	}
	o.live[stack] = true
	o.wg.Add(1)
	return nil
}

func (o *cfnOps) end(stack string) {
	o.mu.Lock()
	delete(o.live, stack)
	o.mu.Unlock()
	o.wg.Done()
}

func (o *cfnOps) isLive(stack string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.live[stack]
}

// shutdown stops this process accepting new stack operations (and starting recoveries).
func (o *cfnOps) shutdown() {
	o.mu.Lock()
	o.terminating = true
	o.mu.Unlock()
}

func (o *cfnOps) isTerminating() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.terminating
}

func (o *cfnOps) running() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]string, 0, len(o.live))
	for s := range o.live {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// drain waits up to timeout for every live operation to end; false if some are still running.
func (o *cfnOps) drain(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { o.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// recordedCaller is the identity an operation runs under, as recorded on its stack record.
type recordedCaller struct {
	User   string   `json:"user"`
	Groups []string `json:"groups,omitempty"`
	// AssumedRole is the kind: Role an assumed-role caller acted as (its data-plane principal).
	AssumedRole string `json:"assumedRole,omitempty"`
}

// usable reports whether a recorded caller is one this front door could itself have impersonated — the
// shape iam.Identity mints: an openinfra:<sub> user and openinfra: groups only. Anything else is refused,
// so a recovery never runs under an identity the front door did not mint.
func (c *recordedCaller) usable() bool {
	const p = "openinfra:"
	if c == nil || !strings.HasPrefix(c.User, p) || len(c.User) == len(p) || strings.Contains(c.User, ",") {
		return false
	}
	for _, g := range c.Groups {
		if !strings.HasPrefix(g, p) || len(g) == len(p) || strings.Contains(g, ",") {
			return false
		}
	}
	return true
}

// opLease is the parsed operation annotations of a stack record.
type opLease struct {
	owner    string
	renewed  time.Time
	duration time.Duration
	action   string
	caller   *recordedCaller
}

func leaseOf(u *unstructured.Unstructured) (opLease, bool) {
	ann := u.GetAnnotations()
	if ann[annOpOwner] == "" {
		return opLease{}, false
	}
	l := opLease{owner: ann[annOpOwner], action: ann[annOpAction]}
	l.renewed, _ = time.Parse(time.RFC3339Nano, ann[annOpRenewed]) // unparsable = zero = stale
	if s, err := strconv.Atoi(ann[annOpLease]); err == nil && s > 0 {
		l.duration = time.Duration(s) * time.Second
	}
	if c := ann[annOpCaller]; c != "" {
		var rc recordedCaller
		if json.Unmarshal([]byte(c), &rc) == nil {
			l.caller = &rc
		}
	}
	return l, true
}

// recordOf parses a stack record's stack.json.
func (h *cfnDoorway) recordOf(u *unstructured.Unstructured) (*cfn.StackRecord, bool) {
	return h.recs().stackRecord(u)
}

func inProgress(status string) bool { return strings.HasSuffix(status, "_IN_PROGRESS") }

func stackRecordName(stack string) string { return "cfn-stack-" + stack }

// leaseAnnotations are this process's operation annotations, renewed now. caller nil = leave the
// recorded caller as it is (a recovery claim keeps the interrupted operation's caller).
func (h *cfnDoorway) leaseAnnotations(action string, caller *recordedCaller) map[string]any {
	secs := int(h.ops.leaseFor() / time.Second)
	if secs < 1 {
		secs = 1
	}
	ann := map[string]any{
		annOpOwner:   h.ops.ownerID(),
		annOpRenewed: time.Now().UTC().Format(time.RFC3339Nano),
		annOpLease:   strconv.Itoa(secs),
		annOpAction:  action,
	}
	if caller != nil {
		b, _ := json.Marshal(caller)
		ann[annOpCaller] = string(b)
	}
	return ann
}

// patchLease merge-patches operation annotations onto a stack record (a nil value removes one). A
// non-empty rv makes it conditional: 409 Conflict if the record changed since it was read. A merge patch
// never creates an object, so it cannot resurrect a deleted record.
func (h *cfnDoorway) patchLease(ctx context.Context, stack, rv string, ann map[string]any) error {
	meta := map[string]any{"annotations": ann}
	if rv != "" {
		meta["resourceVersion"] = rv
	}
	body, err := json.Marshal(map[string]any{"metadata": meta})
	if err != nil {
		return err
	}
	_, err = h.recs().client().Patch(ctx, stackRecordName(stack), types.MergePatchType, body,
		metav1.PatchOptions{FieldManager: cfnLeaseManager})
	return err
}

func (h *cfnDoorway) getRecordObject(ctx context.Context, stack string) (*unstructured.Unstructured, error) {
	return h.recs().client().Get(ctx, stackRecordName(stack), metav1.GetOptions{})
}

// seedRecord creates a new stack's CREATE_IN_PROGRESS record already carrying this process's lease and
// the caller — one atomic Create, so a stack cannot be created twice (AlreadyExists) and is never in
// progress without an owner.
func (h *cfnDoorway) seedRecord(ctx context.Context, rec *cfn.StackRecord, action string, caller *recordedCaller) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	st := h.recs()
	obj := st.object(stackRecordName(rec.Name),
		map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name},
		h.leaseAnnotations(action, caller), map[string]string{"stack.json": string(data)})
	_, err = st.client().Create(ctx, obj, metav1.CreateOptions{FieldManager: cfnLeaseManager})
	return err
}

// stackInProgressError: the stack already has an operation in progress (live, or awaiting recovery).
type stackInProgressError struct{ status string }

func (e *stackInProgressError) Error() string { return "stack is in " + e.status + " state" }

// claimRecord takes this process's lease on an existing, settled stack record before an operation starts
// on it, recording the caller. It refuses a record that is *_IN_PROGRESS, and is conditional on the
// record's resourceVersion, so a concurrent claimant makes it fail (errCFNStackBusy) rather than both
// proceed. Not found → (nil, nil).
func (h *cfnDoorway) claimRecord(ctx context.Context, stack, action string, caller *recordedCaller) (*cfn.StackRecord, error) {
	u, err := h.getRecordObject(ctx, stack)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec, ok := h.recordOf(u)
	if !ok {
		return nil, nil
	}
	if inProgress(rec.Status) {
		return rec, &stackInProgressError{status: rec.Status}
	}
	if err := h.patchLease(ctx, stack, u.GetResourceVersion(), h.leaseAnnotations(action, caller)); err != nil {
		if apierrors.IsConflict(err) {
			return rec, errCFNStackBusy
		}
		return rec, err
	}
	return rec, nil
}

// releaseLease removes this process's operation annotations once the record is settled. A record still
// *_IN_PROGRESS keeps them — the recovery pass needs the recorded caller to roll it back.
func (h *cfnDoorway) releaseLease(ctx context.Context, stack string) {
	u, err := h.getRecordObject(ctx, stack)
	if err != nil {
		return // gone (a completed delete) or unreadable: nothing to release now
	}
	if l, ok := leaseOf(u); !ok || l.owner != h.ops.ownerID() {
		return
	}
	if rec, ok := h.recordOf(u); ok && inProgress(rec.Status) {
		return
	}
	clear := map[string]any{}
	for _, k := range opAnnotations {
		clear[k] = nil
	}
	if err := h.patchLease(ctx, stack, u.GetResourceVersion(), clear); err != nil && !apierrors.IsNotFound(err) {
		h.logger.Warn("cfn: could not release a settled stack's operation lease (harmless: settled records are never recovered)",
			"stack", stack, "error", err.Error())
	}
}

type renewResult int

const (
	renewOK     renewResult = iota
	renewGone               // the record no longer exists (a delete completed)
	renewLost               // another owner holds the record
	renewFailed             // transient: could not reach / write the record
)

// renewLease refreshes this process's lease, if it still holds it. A Conflict (the engine wrote the
// record between the read and the patch) is retried.
func (h *cfnDoorway) renewLease(ctx context.Context, stack string) renewResult {
	for attempt := 0; attempt < 3; attempt++ {
		u, err := h.getRecordObject(ctx, stack)
		if apierrors.IsNotFound(err) {
			return renewGone
		}
		if err != nil {
			return renewFailed
		}
		if l, ok := leaseOf(u); !ok || l.owner != h.ops.ownerID() {
			return renewLost
		}
		err = h.patchLease(ctx, stack, u.GetResourceVersion(), map[string]any{annOpRenewed: time.Now().UTC().Format(time.RFC3339Nano)})
		switch {
		case err == nil:
			return renewOK
		case apierrors.IsNotFound(err):
			return renewGone
		case !apierrors.IsConflict(err):
			return renewFailed
		}
	}
	return renewFailed
}

// holdLease keeps this process's lease on a stack record fresh while an operation runs. It returns the
// operation's context (bounded by cfnAsyncTimeout) and a stop func that reports whether the lease was
// lost. The context is cancelled when the lease is lost — the record was claimed by another owner, or
// could not be renewed for renewDeadline — so a fenced operation stops before another front door may
// take the stack over.
func (h *cfnDoorway) holdLease(stack string) (context.Context, func() bool) {
	ctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
	var lost atomic.Bool
	stopc, done := make(chan struct{}), make(chan struct{})
	refresh := h.ops.refreshEvery()
	go func() {
		defer close(done)
		t := time.NewTicker(refresh)
		defer t.Stop()
		lastOK := time.Now()
		for {
			select {
			case <-stopc:
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}
			rctx, rcancel := context.WithTimeout(ctx, refresh)
			res := h.renewLease(rctx, stack)
			rcancel()
			switch res {
			case renewOK:
				lastOK = time.Now()
			case renewGone:
				return // nothing left to hold
			case renewLost:
				h.logger.Warn("cfn stack operation lost its lease to another owner; stopping it", "stack", stack)
				lost.Store(true)
				cancel()
				return
			case renewFailed:
				if time.Since(lastOK) > h.ops.renewDeadline() {
					h.logger.Warn("cfn stack operation could not renew its lease; stopping it before another front door may take the stack over",
						"stack", stack, "lastRenewed", lastOK.UTC().Format(time.RFC3339))
					lost.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	var once sync.Once
	return ctx, func() bool {
		once.Do(func() { close(stopc); <-done; cancel() })
		return lost.Load()
	}
}

// runStackOp runs a long stack operation in the background as this process's leased operation. The
// handler has already begun it (h.ops.begin) and stamped the record (seedRecord / claimRecord). run returns
// the engine's error; failStatus is backstopped onto a record the engine left *_IN_PROGRESS after failing
// on its own (e.g. refusing before it wrote anything).
func (h *cfnDoorway) runStackOp(stack, action, failStatus string, ap *impersonatingApplier, run func(ctx context.Context) error) {
	go func() {
		defer h.ops.end(stack)
		ctx, stop := h.holdLease(stack)
		err := run(ctx)
		interrupted := ctx.Err() != nil // out of time, or fenced: the engine could not finish (or roll back)
		lost := stop()
		if err != nil {
			h.logger.Warn("cfn "+action+" failed", "stack", stack, "error", err.Error())
		}
		if lost {
			return // another front door holds the stack now and resolves it
		}
		bctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err != nil && !interrupted {
			ap.backstopTerminal(bctx, stack, failStatus, err.Error())
		}
		// Settled: drop the lease. Still in progress (it ran out of time mid-flight): keep it, and the
		// recovery pass rolls it back under the recorded caller.
		h.releaseLease(bctx, stack)
	}()
}

// refuseOp answers a stack operation the front door will not start now: 503 while shutting down (SDKs
// retry it), else the given AWS error.
func (h *cfnDoorway) refuseOp(w http.ResponseWriter, requestID string, err error, code, msg string) {
	if errors.Is(err, errCFNTerminating) {
		writeQueryError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	writeQueryError(w, http.StatusBadRequest, code, requestID, msg, cfnXMLNamespace)
}

// notUpdatable is AWS's refusal for UpdateStack / an UPDATE change set on a stack that cannot be updated
// now: one with an operation in progress, or one an interrupted create/update left rolled back or failed.
func (h *cfnDoorway) notUpdatable(stack, status string) string {
	switch {
	case inProgress(status), status == "ROLLBACK_COMPLETE", status == "ROLLBACK_FAILED", status == "UPDATE_ROLLBACK_FAILED":
		return "Stack:" + h.liveStackID(context.Background(), stack) + " is in " + status + " state and can not be updated."
	}
	return ""
}

// claimRefusal maps a claimRecord failure to the AWS answer.
func (h *cfnDoorway) claimRefusal(w http.ResponseWriter, requestID, stack, verb string, err error) {
	var ip *stackInProgressError
	switch {
	case errors.As(err, &ip) && verb == "delete":
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Stack ["+stack+"] cannot be deleted while in status "+ip.status+".", cfnXMLNamespace)
	case errors.As(err, &ip):
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, h.notUpdatable(stack, ip.status), cfnXMLNamespace)
	case errors.Is(err, errCFNStackBusy):
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Stack ["+stack+"] is being changed by another operation; retry once it settles.", cfnXMLNamespace)
	default:
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID,
			"could not take ownership of the stack record: "+err.Error(), cfnXMLNamespace)
	}
}

// --- recovery ---

// runRecovery resolves orphaned stack operations on startup and every recovery interval until ctx ends,
// first moving any record an earlier front door kept as a ConfigMap into the record store.
func (h *cfnDoorway) runRecovery(ctx context.Context) {
	h.migrateLegacyRecords(ctx)
	h.recoverOrphans(ctx)
	h.pruneDeleted(ctx, time.Now()) // deleted stacks past their 90 days (cfn_deleted.go)
	t := time.NewTicker(h.ops.recoveryInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.migrateLegacyRecords(ctx)
			h.recoverOrphans(ctx)
			h.pruneDeleted(ctx, time.Now())
		}
	}
}

// recoverOrphans is one recovery pass: one List of the stack records; every *_IN_PROGRESS record no live
// operation owns is claimed (conditionally — at most one front door wins) and resolved in the background.
func (h *cfnDoorway) recoverOrphans(ctx context.Context) {
	if h.ops.isTerminating() {
		return
	}
	list, err := h.recs().client().List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		h.logger.Warn("cfn recovery: could not list stack records", "error", err.Error())
		return
	}
	now := time.Now()
	for i := range list.Items {
		u := &list.Items[i]
		if !strings.HasPrefix(u.GetName(), "cfn-stack-") {
			continue
		}
		stack := strings.TrimPrefix(u.GetName(), "cfn-stack-")
		rec, ok := h.recordOf(u)
		if !ok || !inProgress(rec.Status) || h.ops.isLive(stack) {
			continue
		}
		why, orphaned := h.orphaned(rec, u, now)
		if !orphaned {
			continue
		}
		if h.ops.begin(stack) != nil {
			continue
		}
		l, _ := leaseOf(u)
		action := l.action
		if action == "" {
			action = "The stack operation"
		}
		// Claim: our owner + a fresh lease, the recorded caller kept as is; conditional on what we read.
		if err := h.patchLease(ctx, stack, u.GetResourceVersion(), h.leaseAnnotations(l.action, nil)); err != nil {
			h.ops.end(stack)
			if !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) {
				h.logger.Warn("cfn recovery: could not claim an orphaned stack", "stack", stack, "error", err.Error())
			}
			continue // changed under us (another front door claimed it, or it moved on): re-evaluated next pass
		}
		h.logger.Warn("cfn recovery: resolving an interrupted stack operation", "stack", stack, "status", rec.Status, "why", why)
		reason := fmt.Sprintf("%s was interrupted before it finished: %s.", action, why)
		go h.recoverStack(stack, l.caller, reason)
	}
}

// orphaned decides whether an *_IN_PROGRESS record (not live in this process) has no live owner.
func (h *cfnDoorway) orphaned(rec *cfn.StackRecord, u *unstructured.Unstructured, now time.Time) (string, bool) {
	l, leased := leaseOf(u)
	if !leased {
		// Written by a front door that predates operation leases: no owner to ask, so wait out the longest
		// any operation may run.
		if t, err := time.Parse(time.RFC3339, rec.UpdatedAt); err == nil && now.Sub(t) <= h.ops.legacyGraceFor() {
			return "", false
		}
		return "the front door running it stopped (the record has no operation lease and was last updated " + rec.UpdatedAt + ")", true
	}
	if l.owner == h.ops.ownerID() {
		return "it ran out of time or lost contact with the cluster in the front door running it (" + l.owner + ")", true
	}
	d := l.duration
	if d <= 0 {
		d = h.ops.leaseFor()
	}
	if now.Sub(l.renewed) <= d {
		return "", false // a live operation in another front door
	}
	return "the front door running it (" + l.owner + ") stopped renewing its lease at " + l.renewed.UTC().Format(time.RFC3339), true
}

// recoverStack resolves one claimed orphan: cfn.RecoverInterrupted under the operation's recorded caller,
// or — with no usable recorded caller — settleWithoutAuthority. The record stays claimed by this process
// until it is settled; a recovery that cannot finish (cluster unreachable) is retried by the next pass.
func (h *cfnDoorway) recoverStack(stack string, caller *recordedCaller, reason string) {
	defer h.ops.end(stack)
	ctx, stop := h.holdLease(stack)
	var err error
	var out *cfn.StackRecord
	if caller.usable() {
		var ap *impersonatingApplier
		if ap, err = h.applierForIdentity(caller.User, caller.Groups); err == nil {
			ap.assumedRole = caller.AssumedRole
			before, found, _ := h.getRecord(ctx, stack)
			out, err = cfn.RecoverInterrupted(ctx, h.asCaller(h.opts(stack, nil), ap), ap, reason)
			if err == nil && out == nil && found && before.Status == "DELETE_IN_PROGRESS" {
				h.keepDeleted(ctx, before, nil) // the resumed delete completed: kept as any deleted stack is
			}
		}
	} else {
		out, err = h.settleWithoutAuthority(ctx, stack, reason)
	}
	lost := stop()
	switch {
	case err != nil:
		h.logger.Warn("cfn recovery: interrupted stack operation not fully resolved", "stack", stack, "error", err.Error())
	case out == nil:
		h.logger.Info("cfn recovery: interrupted delete resumed and completed", "stack", stack)
	default:
		h.logger.Info("cfn recovery: interrupted stack operation resolved", "stack", stack, "status", out.Status)
	}
	if lost {
		return
	}
	bctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.releaseLease(bctx, stack)
}

// settleWithoutAuthority resolves an orphaned record whose operation's caller was not recorded (a record
// from a front door that predates caller recording) or is not one this front door could have
// impersonated. The rollback is never run under any other authority — not the shim's own. An interrupted
// create that recorded nothing is simply ROLLBACK_COMPLETE (there is nothing to undo); anything else is
// settled ROLLBACK_FAILED / UPDATE_ROLLBACK_FAILED / DELETE_FAILED, keeping what it recorded, so DeleteStack
// — run under the deleting caller's own authority — removes it.
func (h *cfnDoorway) settleWithoutAuthority(ctx context.Context, stack, reason string) (*cfn.StackRecord, error) {
	rs := h.recs()
	sa := &impersonatingApplier{shim: h.shimDyn, mapper: h.mapper, ns: h.ns, records: &rs}
	rec, found, err := sa.GetStack(ctx, stack)
	if err != nil || !found || !inProgress(rec.Status) {
		return rec, err
	}
	out := *rec
	out.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	createLike := rec.Status == "CREATE_IN_PROGRESS" || rec.Status == "ROLLBACK_IN_PROGRESS"
	if createLike && len(rec.Resources) == 0 && len(rec.Pending) == 0 {
		out.Status = "ROLLBACK_COMPLETE"
		out.Message = reason
	} else {
		out.Status = cfn.RecoveryFailedStatus(rec.Status)
		out.Message = reason + " The operation's caller was not recorded, so it was not rolled back under any other authority: delete the stack (DeleteStack) to remove what it created."
	}
	if err := sa.putRecord(ctx, &out); err != nil {
		return rec, err
	}
	return &out, nil
}

// drainOps (shutdown) waits up to cfnDrainTimeout for in-flight stack operations. One still running when
// the process exits is recovered by the next front door once its lease lapses.
func (h *cfnDoorway) drainOps() {
	if h.ops.drain(cfnDrainTimeout) {
		return
	}
	h.logger.Warn("cfn: stack operations still running at shutdown; the next front door resolves them once their leases lapse",
		"stacks", strings.Join(h.ops.running(), ","))
}
