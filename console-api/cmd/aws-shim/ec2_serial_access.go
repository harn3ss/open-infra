package main

// EC2 Serial Console's account setting on the EC2 front door: EnableSerialConsoleAccess,
// DisableSerialConsoleAccess and GetSerialConsoleAccessStatus, as EC2 answers them. Access is off until the
// account turns it on, and while it is off EC2 Instance Connect refuses SendSerialConsoleSSHPublicKey and the
// serial console gateway refuses every session of the account (ec2_instance_connect.go,
// serial_console_gateway.go). Each is decided as ec2:<Action> on "*" (none names a resource, as on AWS); the
// setting is internal/serialconsole's, shared with the console.

import (
	"context"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
)

func ec2SerialAccessOp(op string) bool {
	return op == "EnableSerialConsoleAccess" || op == "DisableSerialConsoleAccess" || op == "GetSerialConsoleAccessStatus"
}

// serialAccount is the account the request acts in (the management account unless the router put a
// member's on it).
func (h *ec2Handler) serialAccount(ctx context.Context) string {
	if a := callerAccount(ctx); a != "" {
		return a
	}
	return h.door.account
}

func (h *ec2Handler) serialAccessOp(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, op, requestID string) {
	if ok, reason := decide(ctx, r, h.door.authz, claims, "ec2:"+op, "Account", "",
		dataPlaneOnly(ctx, r, h.door.authz, claims, "ec2:"+op, "Account", "")); !ok {
		h.audit(ctx, op, "", reason)
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
		return
	}
	if r.Form.Get("DryRun") == "true" {
		writeEC2Error(w, http.StatusPreconditionFailed, "DryRunOperation", requestID, "Request would have succeeded, but DryRun flag is set.")
		return
	}
	if h.door.cs == nil || h.settingsNS == "" {
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "EC2 Serial Console is not configured on this endpoint.")
		return
	}
	account := h.serialAccount(ctx)
	var on bool
	var err error
	switch op {
	case "GetSerialConsoleAccessStatus":
		on, err = serialconsole.Enabled(ctx, h.door.cs, h.settingsNS, account)
	case "EnableSerialConsoleAccess", "DisableSerialConsoleAccess":
		on = op == "EnableSerialConsoleAccess"
		err = serialconsole.SetEnabled(ctx, h.door.cs, h.settingsNS, account, on)
	}
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("ec2: "+op+" failed", "error", err.Error())
		}
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "The serial console access setting could not be read or written; retry.")
		return
	}
	body := xbool("serialConsoleAccessEnabled", on)
	if op == "GetSerialConsoleAccessStatus" {
		body += xtag("managedBy", "account")
	}
	writeEC2(w, requestID, op, body)
}
