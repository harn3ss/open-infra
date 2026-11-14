package main

// EC2 GetConsoleOutput and GetConsoleScreenshot: what an instance's console shows, as EC2's "Get system
// log" and "Get instance screenshot". Each names one instance, is decided on that instance
// (ec2:GetConsoleOutput, ec2:GetConsoleScreenshot), and reads it in the caller's account: the guest's
// serial console output (the last 64 KB) or a JPEG of its display (internal/vmconsole).

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

func ec2ConsoleOp(op string) bool { return op == "GetConsoleOutput" || op == "GetConsoleScreenshot" }

func (h *ec2Handler) readConsoleOutput(ctx context.Context, ns, name string) ([]byte, error) {
	if h.consoleOutput != nil {
		return h.consoleOutput(ctx, ns, name)
	}
	if h.door.cs == nil {
		return nil, errNoConsole
	}
	return vmconsole.Output(ctx, h.door.cs, ns, name)
}

func (h *ec2Handler) readScreenshot(ctx context.Context, ns, name string, wake bool) ([]byte, error) {
	if h.consoleScreenshot != nil {
		return h.consoleScreenshot(ctx, ns, name, wake)
	}
	if h.door.cs == nil {
		return nil, errNoConsole
	}
	return vmconsole.Screenshot(ctx, h.door.cs, ns, name, wake)
}

var errNoConsole = errors.New("the shim cannot read instance consoles (no cluster client)")

func (h *ec2Handler) consoleOp(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, op, requestID string) {
	id := r.Form.Get("InstanceId")
	if id == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter InstanceId")
		return
	}
	if !instanceIDRe.MatchString(id) {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.Malformed", requestID, "Invalid id: \""+id+"\"")
		return
	}
	// Decided on the instance before anything is read (in legacy the data-plane refinement too).
	if ok, reason := decide(ctx, r, h.door.authz, claims, "ec2:"+op, "Instance", id,
		dataPlaneOnly(ctx, r, h.door.authz, claims, "ec2:"+op, "Instance", id)); !ok {
		h.audit(ctx, op, id, reason)
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
		return
	}
	all, denied, err := h.instancesForCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "instances", denied, err)
		return
	}
	var in *ec2Instance
	for i := range all {
		if all[i].id == id {
			in = &all[i]
		}
	}
	if in == nil {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance ID '"+id+"' does not exist")
		return
	}
	if r.Form.Get("DryRun") == "true" {
		writeEC2Error(w, http.StatusPreconditionFailed, "DryRunOperation", requestID, "Request would have succeeded, but DryRun flag is set.")
		return
	}
	ns, name := h.accountNS(ctx), in.claim.GetName()
	switch op {
	case "GetConsoleOutput":
		out, err := h.readConsoleOutput(ctx, ns, name)
		switch {
		case err == nil:
		case errors.Is(err, vmconsole.ErrNotRunning), errors.Is(err, vmconsole.ErrNoLog):
			// As EC2 for an instance with no buffered output: the instance and the time, no output.
			out = nil
		default:
			h.consoleUnavailable(w, requestID, op, id, err)
			return
		}
		body := xtag("instanceId", id) + xtag("timestamp", ec2Time(time.Now()))
		if len(out) > 0 {
			body += xtag("output", base64.StdEncoding.EncodeToString(out))
		}
		writeEC2(w, requestID, op, body)
	case "GetConsoleScreenshot":
		img, err := h.readScreenshot(ctx, ns, name, r.Form.Get("WakeUp") == "true")
		switch {
		case err == nil:
		case errors.Is(err, vmconsole.ErrNotRunning):
			writeEC2Error(w, http.StatusBadRequest, "IncorrectInstanceState", requestID,
				"The instance '"+id+"' is not in a state from which a screenshot can be taken; it must be running.")
			return
		default:
			h.consoleUnavailable(w, requestID, op, id, err)
			return
		}
		writeEC2(w, requestID, op, xtag("imageData", base64.StdEncoding.EncodeToString(img))+xtag("instanceId", id))
	}
}

func (h *ec2Handler) consoleUnavailable(w http.ResponseWriter, requestID, op, id string, err error) {
	if h.logger != nil {
		h.logger.Warn("ec2: "+op+" failed", "instance", id, "error", err.Error())
	}
	writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "The console of instance "+id+" could not be read; retry.")
}
