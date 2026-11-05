// The EC2 front door's instance state operations (ec2.go): StartInstances, StopInstances, RebootInstances
// and TerminateInstances over kind: VirtualMachine, as EC2 answers them.
//
// Each named instance is authorized on its own, as ec2:<Action> on Instance::<id> (an assumed role needs a
// grant on it; a User's grant is additive over its RBAC), and the claim is changed with the CALLER's own
// Kubernetes authority (impersonation, as DeleteVolume does), so RBAC decides as well:
//   - StopInstances / StartInstances set spec.running (KubeVirt's runStrategy Halted / Always): the disks are
//     kept, as an EBS-backed instance's are;
//   - TerminateInstances deletes the claim, refused (OperationNotPermitted) while the instance's
//     DisableApiTermination is set (its AWS view, cfn.AWSView). An instance a stack made can be terminated,
//     as on AWS: the stack then reports the drift, and its record is not changed;
//   - RebootInstances restarts the VM in place: the caller's authority is proven by recording the request on
//     the claim (an annotation, as the caller), then the shim restarts the VM through KubeVirt's restart
//     subresource.
//
// Every instance is checked before any is changed: an unknown id is InvalidInstanceID.NotFound, one in a
// state the operation cannot leave is IncorrectInstanceState, and nothing is changed. DryRun answers
// DryRunOperation once the request would be authorized.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ec2InstanceStateOp reports whether op is one of the instance state operations.
func ec2InstanceStateOp(op string) bool {
	switch op {
	case "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances":
		return true
	}
	return false
}

// rebootAnnotation records, on the claim, when a caller last asked RebootInstances to restart it.
const rebootAnnotation = "openinfra.dev/reboot-requested-at"

// ec2StateChange is one item of an instancesSet answer.
type ec2StateChange struct {
	id                  string
	prevCode, curCode   int
	prevState, curState string
}

func (c ec2StateChange) xml() string {
	return "<item><instanceId>" + xesc(c.id) + "</instanceId>" +
		"<currentState><code>" + strconv.Itoa(c.curCode) + "</code><name>" + c.curState + "</name></currentState>" +
		"<previousState><code>" + strconv.Itoa(c.prevCode) + "</code><name>" + c.prevState + "</name></previousState></item>"
}

// instanceStateOp serves the four instance state operations.
func (h *ec2Handler) instanceStateOp(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, op, requestID string) {
	ids := ec2List(r.Form, "InstanceId")
	if len(ids) == 0 {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter InstanceId")
		return
	}
	for _, id := range ids {
		if !instanceIDRe.MatchString(id) {
			writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.Malformed", requestID, "Invalid id: \""+id+"\"")
			return
		}
	}
	if op == "StopInstances" && r.Form.Get("Hibernate") == "true" {
		writeEC2Error(w, http.StatusBadRequest, "UnsupportedHibernationConfiguration", requestID,
			"For hibernation, the instance must be enabled for hibernation. Hibernation is not supported here.")
		return
	}
	// Authorization, per instance, before anything is read or changed (as EC2's: every named instance).
	for _, id := range ids {
		// decide: in legacy the data-plane refinement (the caller's RBAC acts below, as the caller), in
		// enforce IAM policy alone.
		if ok, reason := decide(ctx, r, h.door.authz, claims, "ec2:"+op, "Instance", id,
			dataPlaneOnly(ctx, r, h.door.authz, claims, "ec2:"+op, "Instance", id)); !ok {
			h.audit(ctx, op, id, reason)
			writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
			return
		}
	}
	all, denied, err := h.instancesAsCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "instances", denied, err)
		return
	}
	byID := map[string]ec2Instance{}
	for _, in := range all {
		byID[in.id] = in
	}
	var missing []string
	for _, id := range ids {
		if _, ok := byID[id]; !ok {
			missing = append(missing, id)
		}
	}
	switch len(missing) {
	case 0:
	case 1:
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance ID '"+missing[0]+"' does not exist")
		return
	default:
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance IDs '"+strings.Join(missing, ", ")+"' do not exist")
		return
	}
	// Every instance must be in a state the operation can leave, before any is changed.
	for _, id := range ids {
		if msg := incorrectState(op, byID[id]); msg != "" {
			writeEC2Error(w, http.StatusBadRequest, "IncorrectInstanceState", requestID, msg)
			return
		}
		if op == "TerminateInstances" && cfn.ParseAWSView(byID[id].claim.GetAnnotations()).DisableApiTermination {
			writeEC2Error(w, http.StatusBadRequest, "OperationNotPermitted", requestID,
				"The instance '"+id+"' may not be terminated. Modify its 'disableApiTermination' instance attribute and try again.")
			return
		}
	}
	if r.Form.Get("DryRun") == "true" {
		writeEC2Error(w, http.StatusPreconditionFailed, "DryRunOperation", requestID, "Request would have succeeded, but DryRun flag is set.")
		return
	}
	ap, err := h.door.applierFor(claims)
	if err != nil {
		h.readFailed(w, requestID, "instance", true, err)
		return
	}
	var changes []string
	for _, id := range ids {
		in := byID[id]
		name := in.claim.GetName()
		var aerr error
		change := ec2StateChange{id: id, prevCode: in.code, prevState: in.state, curCode: in.code, curState: in.state}
		switch op {
		case "StopInstances":
			if in.state != "stopped" && in.state != "stopping" {
				aerr = h.setRunning(ctx, ap, name, false)
				change.curCode, change.curState = 64, "stopping"
			}
		case "StartInstances":
			if in.state == "stopped" {
				aerr = h.setRunning(ctx, ap, name, true)
				change.curCode, change.curState = 0, "pending"
			}
		case "TerminateInstances":
			if in.state != "shutting-down" {
				policy := metav1.DeletePropagationBackground
				aerr = ap.caller.Resource(vmClaimGVR).Namespace(h.door.ns).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &policy})
				change.curCode, change.curState = 32, "shutting-down"
			}
		case "RebootInstances":
			aerr = h.reboot(ctx, ap, name)
		}
		switch {
		case aerr == nil:
		case apierrors.IsForbidden(aerr) || apierrors.IsUnauthorized(aerr):
			h.audit(ctx, op, id, aerr.Error())
			writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+aerr.Error())
			return
		case apierrors.IsNotFound(aerr):
			writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance ID '"+id+"' does not exist")
			return
		default:
			if h.logger != nil {
				h.logger.Warn("ec2: "+op+" failed", "instance", id, "error", aerr.Error())
			}
			writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "The instance "+id+" could not be changed; retry.")
			return
		}
		changes = append(changes, change.xml())
	}
	if op == "RebootInstances" {
		writeEC2(w, requestID, op, "<return>true</return>")
		return
	}
	writeEC2(w, requestID, op, "<instancesSet>"+strings.Join(changes, "")+"</instancesSet>")
}

// incorrectState is EC2's IncorrectInstanceState message when op cannot act on the instance in its state
// ("" when it can, including the no-op of stopping a stopped instance or starting a running one).
func incorrectState(op string, in ec2Instance) string {
	switch op {
	case "StartInstances":
		if in.state == "stopping" || in.state == "shutting-down" || in.state == "terminated" {
			return "The instance '" + in.id + "' is not in a state from which it can be started."
		}
	case "StopInstances":
		if in.state == "shutting-down" || in.state == "terminated" {
			return "The instance '" + in.id + "' is not in a state from which it can be stopped."
		}
	case "RebootInstances":
		if in.state != "running" {
			return "The instance '" + in.id + "' is not in a state from which it can be rebooted."
		}
	}
	return ""
}

// setRunning sets the claim's spec.running, as the caller.
func (h *ec2Handler) setRunning(ctx context.Context, ap *impersonatingApplier, name string, running bool) error {
	patch, _ := json.Marshal(map[string]any{"spec": map[string]any{"running": running}})
	_, err := ap.caller.Resource(vmClaimGVR).Namespace(h.door.ns).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// reboot restarts a running VM: the request is recorded on the claim as the caller (which proves the
// caller may change the instance), then the shim asks KubeVirt to restart the VM in place.
func (h *ec2Handler) reboot(ctx context.Context, ap *impersonatingApplier, name string) error {
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		rebootAnnotation: time.Now().UTC().Format(time.RFC3339)}}})
	if _, err := ap.caller.Resource(vmClaimGVR).Namespace(h.door.ns).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}
	if h.restartVM != nil {
		return h.restartVM(ctx, h.door.ns, name)
	}
	if h.door.cs == nil {
		return errNoRestart
	}
	return h.door.cs.CoreV1().RESTClient().Put().
		AbsPath("/apis/subresources.kubevirt.io/v1/namespaces/" + h.door.ns + "/virtualmachines/" + name + "/restart").
		Body([]byte("{}")).Do(ctx).Error()
}

var errNoRestart = apierrors.NewServiceUnavailable("the shim cannot restart virtual machines (no cluster client)")
