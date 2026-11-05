// SSM Run Command (#347 item 22): SendCommand with the AWS-RunShellScript document, GetCommandInvocation
// (what `aws ssm wait command-executed` polls), ListCommandInvocations, ListCommands and
// DescribeInstanceInformation. A command runs on its instances through their metadata agents
// (vmcommands.go); its state is the SSM store's (ssm_runcommand_store.go).
//
// The instances are the account namespace's VMs the caller may read (the EC2 front door's view, read
// with the caller's own authority), by the i- ids their guests report. An instance is managed — a target
// SendCommand accepts, listed by DescribeInstanceInformation — once its agent has registered (its role
// allows the SSM agent's actions: AmazonSSMManagedInstanceCore).
//
// Authorization, as AWS evaluates it: ssm:SendCommand on each instance (Instance::<id>) AND on the
// document (Document::AWS-RunShellScript); a User also needs RBAC update on the VM itself (running
// commands as root on it changes it). The output is read with ssm:GetCommandInvocation /
// ssm:ListCommandInvocations on the instance.
//
// Refused rather than accepted and ignored: other documents, S3 / CloudWatch output, notifications and a
// service role, alarms, and document hashes. The output is kept for the API (24,000 characters of each
// stream), as AWS keeps it without an output bucket.
package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const (
	ssmRunShellScript = "AWS-RunShellScript"
	ssmPluginName     = "aws:runShellScript"
	// ssmOnlineWithin is how recently an instance's agent must have polled to be Online (it polls every
	// 20 seconds at most).
	ssmOnlineWithin = 2 * time.Minute
)

var ssmRunCommandOps = map[string]bool{
	"SendCommand": true, "GetCommandInvocation": true, "ListCommandInvocations": true, "ListCommands": true,
	"DescribeInstanceInformation": true,
}

func awsEpoch(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }

func ssmISOTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ssmStrings reads a JSON list of strings (or one string).
func ssmStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ssmDocument is a DocumentName as a document's name (an ARN names it after document/).
func ssmDocument(s string) string {
	if i := strings.Index(s, ":document/"); strings.HasPrefix(s, "arn:") && i >= 0 {
		return s[i+len(":document/"):]
	}
	return s
}

func (h *ssmHandler) instanceARN(id string) string {
	return "arn:aws:ec2:" + h.region + ":" + h.account + ":instance/" + id
}

func (h *ssmHandler) serveRunCommand(ctx context.Context, w http.ResponseWriter, r *http.Request, op string, body map[string]any, claims iam.Claims, requestID string) {
	if h.store == nil {
		writeSSMError(w, http.StatusNotImplemented, "InternalServerError", requestID, "the SSM data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}
	if h.ec2 == nil || h.ec2.door == nil {
		writeSSMError(w, http.StatusNotImplemented, "InternalServerError", requestID, "Run Command needs the account namespace of the CloudFormation front door, which is not configured on this shim")
		return
	}
	_ = h.store.sweep(ctx)
	// The instances the caller may see (RBAC on the VMs, as the caller).
	insts, denied, err := h.ec2.instancesAsCaller(ctx, claims)
	if err != nil {
		if denied {
			writeSSMError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "not authorized to read the account's instances: "+err.Error())
			return
		}
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the instances could not be read; retry")
		return
	}
	visible := map[string]ec2Instance{}
	for _, in := range insts {
		if in.id != "" {
			visible[in.id] = in
		}
	}
	switch op {
	case "SendCommand":
		h.sendCommand(ctx, w, r, body, claims, visible, requestID)
	case "GetCommandInvocation":
		h.getCommandInvocation(ctx, w, r, body, claims, visible, requestID)
	case "ListCommandInvocations":
		h.listCommandInvocations(ctx, w, r, body, claims, visible, requestID)
	case "ListCommands":
		h.listCommands(ctx, w, r, body, claims, visible, requestID)
	case "DescribeInstanceInformation":
		h.describeInstanceInformation(ctx, w, r, body, claims, visible, requestID)
	}
}

// --- SendCommand ---

func (h *ssmHandler) sendCommand(ctx context.Context, w http.ResponseWriter, r *http.Request, body map[string]any, claims iam.Claims, visible map[string]ec2Instance, requestID string) {
	bad := func(code, msg string) { writeSSMError(w, http.StatusBadRequest, code, requestID, msg) }
	doc := ssmDocument(strFromBody(body, "DocumentName"))
	switch {
	case doc == "":
		bad("ValidationException", "1 validation error detected: Value null at 'documentName' failed to satisfy constraint: Member must not be null")
		return
	case doc == "AWS-RunPowerShellScript":
		bad("InvalidDocument", "Document AWS-RunPowerShellScript is not served: Windows guests run no metadata agent on open-infra; use AWS-RunShellScript on a Linux instance")
		return
	case doc != ssmRunShellScript:
		bad("InvalidDocument", "Document with name "+doc+" does not exist. (open-infra serves the AWS-RunShellScript document.)")
		return
	}
	for _, k := range []string{"OutputS3BucketName", "OutputS3KeyPrefix", "ServiceRoleArn", "DocumentHash", "AlarmConfiguration", "NotificationConfig"} {
		if v, ok := body[k]; ok && v != nil && fmt.Sprint(v) != "" && fmt.Sprint(v) != "map[]" {
			bad("InvalidParameters", k+" is not served by the open-infra shim: a command's output is kept for GetCommandInvocation (24,000 characters of each stream), and nothing is notified")
			return
		}
	}
	if cw, ok := body["CloudWatchOutputConfig"].(map[string]any); ok {
		if on, _ := cw["CloudWatchOutputEnabled"].(bool); on {
			bad("InvalidParameters", "CloudWatchOutputConfig is not served by the open-infra shim: a command's output is kept for GetCommandInvocation")
			return
		}
	}
	// Parameters: commands (required), workingDirectory, executionTimeout.
	params := map[string][]string{}
	if raw, ok := body["Parameters"].(map[string]any); ok {
		for k, v := range raw {
			switch k {
			case "commands", "workingDirectory", "executionTimeout":
				params[k] = ssmStrings(v)
			default:
				bad("InvalidParameters", "Parameter \""+k+"\" is not a parameter of document AWS-RunShellScript (commands, workingDirectory, executionTimeout)")
				return
			}
		}
	}
	if len(params["commands"]) == 0 {
		bad("InvalidParameters", "Parameter \"commands\" is required and must not be empty")
		return
	}
	execTimeout := 3600
	if v := params["executionTimeout"]; len(v) > 0 {
		n, err := strconv.Atoi(strings.TrimSpace(v[0]))
		if err != nil || n < 1 || n > 172800 {
			bad("InvalidParameters", "Parameter \"executionTimeout\" must be a number of seconds from 1 to 172800")
			return
		}
		execTimeout = n
	}
	if len(params["workingDirectory"]) > 1 || len(params["executionTimeout"]) > 1 {
		bad("InvalidParameters", "workingDirectory and executionTimeout take one value")
		return
	}
	timeout := 3600
	if v, ok := body["TimeoutSeconds"].(float64); ok {
		timeout = int(v)
		if timeout < 30 || timeout > 2592000 {
			bad("ValidationException", "TimeoutSeconds must be from 30 to 2592000")
			return
		}
	}
	comment := strFromBody(body, "Comment")
	if len(comment) > 100 {
		bad("ValidationException", "Comment must be at most 100 characters")
		return
	}
	// Targets: InstanceIds, or Targets by instance id or tag.
	ids := ssmStrings(body["InstanceIds"])
	targets, _ := body["Targets"].([]any)
	if len(ids) > 0 && len(targets) > 0 {
		bad("InvalidParameters", "Specify InstanceIds or Targets, not both")
		return
	}
	var tgts []map[string]any
	for _, t := range targets {
		tm, _ := t.(map[string]any)
		key, vals := strFromBody(tm, "Key"), ssmStrings(tm["Values"])
		tgts = append(tgts, map[string]any{"Key": key, "Values": vals})
		switch {
		case key == "InstanceIds":
			ids = append(ids, vals...)
		case strings.HasPrefix(key, "tag:") || key == "tag-key":
			want := setOf(vals)
			var match []string
			for id, in := range visible {
				for k, v := range in.tags {
					if (key == "tag-key" && want[k]) || (key == "tag:"+k && want[v]) {
						match = append(match, id)
						break
					}
				}
			}
			sort.Strings(match)
			ids = append(ids, match...)
		default:
			bad("InvalidTarget", "Target key "+key+" is not served (InstanceIds, tag:<key>, tag-key)")
			return
		}
	}
	ids = uniqueStrings(ids)
	if len(ids) == 0 {
		if len(targets) > 0 {
			bad("InvalidTarget", "the targets match no instance")
			return
		}
		bad("ValidationException", "Specify the instances to run the command on (InstanceIds or Targets)")
		return
	}
	if len(ids) > 50 {
		bad("ValidationException", "A command takes at most 50 instance ids")
		return
	}
	managed, err := h.store.managedInstances(ctx)
	if err != nil {
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the SSM store is unavailable; retry")
		return
	}
	var invalid []string
	for _, id := range ids {
		in, seen := visible[id]
		m, reg := managed[id]
		if !instanceIDRe.MatchString(id) || !seen || !reg || m.Namespace != h.ec2.door.ns || in.windows {
			invalid = append(invalid, id)
		}
	}
	if len(invalid) > 0 {
		bad("InvalidInstanceId", "Instances [["+strings.Join(invalid, ", ")+"]] not in a valid state for account "+h.account)
		return
	}
	// Authorization: the document, then each instance (and, for a User, RBAC update on its VM).
	if ok, reason := decide(ctx, r, h.authz, claims, "ssm:SendCommand", "Document", ssmRunShellScript,
		dataPlaneOnly(ctx, r, h.authz, claims, "ssm:SendCommand", "Document", ssmRunShellScript)); !ok {
		writeSSMError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "User: "+claims.PrincipalID()+" is not authorized to perform: ssm:SendCommand on resource: arn:aws:ssm:"+h.region+"::document/"+ssmRunShellScript+" ("+reason+")")
		return
	}
	for _, id := range ids {
		// ssm:SendCommand on the instance (decide): in legacy the data-plane refinement, then — running a
		// command changes the instance — RBAC update on its kind: VirtualMachine; in enforce IAM policy.
		vm := visible[id].name
		if ok, reason := decide(ctx, r, h.authz, claims, "ssm:SendCommand", "Instance", id, func() (bool, string) {
			if denied, reason := dataPlaneDenied(ctx, h.authz, claims, "ssm:SendCommand", "Instance", id, r); denied {
				return false, reason
			}
			if allowed, reason := iam.CanDo(ctx, h.cs, claims, "update", "openinfra.dev", "virtualmachines", h.ec2.door.ns, vm); !allowed {
				return false, "running a command changes the instance; it needs update on kind: VirtualMachine " + vm + ": " + reason
			}
			return true, ""
		}); !ok {
			writeSSMError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "User: "+claims.PrincipalID()+" is not authorized to perform: ssm:SendCommand on resource: "+h.instanceARN(id)+" ("+reason+")")
			return
		}
	}
	maxConc, maxErr := strFromBody(body, "MaxConcurrency"), strFromBody(body, "MaxErrors")
	if maxConc == "" {
		maxConc = "50"
	}
	if maxErr == "" {
		maxErr = "0"
	}
	if tgts == nil {
		tgts = []map[string]any{}
	}
	c, err := h.store.createCommand(ctx, ssmCommand{ID: uuidLike(), Document: ssmRunShellScript, Comment: comment, RequestedBy: claims.PrincipalType() + "::" + claims.PrincipalID(),
		Parameters: params, Targets: tgts, InstanceIDs: ids, TimeoutSeconds: timeout, MaxConcurrency: maxConc, MaxErrors: maxErr}, execTimeout)
	if err != nil {
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the command could not be recorded; retry")
		return
	}
	h.bus.notify(ids...)
	if h.logger != nil {
		h.logger.InfoContext(ctx, "ssm audit", "service", "ssm", "op", "SendCommand", "decision", "allow", "principal", principalFromCtx(ctx), "command", c.ID, "instances", strings.Join(ids, ","))
	}
	invs := make([]ssmInvocation, 0, len(ids))
	for _, id := range ids {
		invs = append(invs, ssmInvocation{CommandID: c.ID, InstanceID: id, Status: "Pending", StatusDetails: "Pending", ResponseCode: -1})
	}
	writeSSMJSON(w, requestID, map[string]any{"Command": h.commandJSON(c, ids, invs)})
}

func uniqueStrings(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// commandStatus is a command's status from its invocations'.
func commandStatus(invs []ssmInvocation) (status string, completed, errors, deliveryTimedOut int) {
	open, delivered, success, cancelled, failed, timedOut := 0, 0, 0, 0, 0, 0
	for _, v := range invs {
		switch v.Status {
		case "Pending":
			open++
		case "InProgress":
			open++
			delivered++
		case "Success":
			success++
		case "Cancelled":
			cancelled++
		case "TimedOut":
			timedOut++
			if v.StatusDetails == "DeliveryTimedOut" {
				deliveryTimedOut++
			} else {
				errors++
			}
		default:
			failed++
			errors++
		}
	}
	completed = len(invs) - open
	switch {
	case open > 0 && (delivered > 0 || completed > 0):
		status = "InProgress"
	case open > 0:
		status = "Pending"
	case success == len(invs):
		status = "Success"
	case cancelled > 0:
		status = "Cancelled"
	case failed > 0:
		status = "Failed"
	case timedOut > 0:
		status = "TimedOut"
	default:
		status = "Failed"
	}
	return status, completed, errors, deliveryTimedOut
}

func (h *ssmHandler) commandJSON(c ssmCommand, ids []string, invs []ssmInvocation) map[string]any {
	status, completed, errs, dto := commandStatus(invs)
	params := map[string]any{}
	for k, v := range c.Parameters {
		params[k] = v
	}
	if ids == nil {
		ids = []string{}
	}
	targets := c.Targets
	if targets == nil {
		targets = []map[string]any{}
	}
	return map[string]any{
		"CommandId": c.ID, "DocumentName": c.Document, "DocumentVersion": "1", "Comment": c.Comment,
		"ExpiresAfter": awsEpoch(c.Expires), "Parameters": params, "InstanceIds": ids, "Targets": targets,
		"RequestedDateTime": awsEpoch(c.Requested), "Status": status, "StatusDetails": status,
		"OutputS3Region": h.region, "OutputS3BucketName": "", "OutputS3KeyPrefix": "",
		"MaxConcurrency": c.MaxConcurrency, "MaxErrors": c.MaxErrors, "TargetCount": len(invs),
		"CompletedCount": completed, "ErrorCount": errs, "DeliveryTimedOutCount": dto, "ServiceRole": "",
		"NotificationConfig":     map[string]any{"NotificationArn": "", "NotificationEvents": []string{}, "NotificationType": ""},
		"CloudWatchOutputConfig": map[string]any{"CloudWatchLogGroupName": "", "CloudWatchOutputEnabled": false},
		"TimeoutSeconds":         c.TimeoutSeconds,
	}
}

// --- invocations ---

// mayRead reports whether the caller may read instance id's invocations with action (it can see the
// instance, and the data-plane policy allows the action on it).
func (h *ssmHandler) mayRead(ctx context.Context, r *http.Request, claims iam.Claims, visible map[string]ec2Instance, action, id string) bool {
	if _, ok := visible[id]; !ok {
		return false
	}
	ok, _ := decide(ctx, r, h.authz, claims, action, "Instance", id, dataPlaneOnly(ctx, r, h.authz, claims, action, "Instance", id))
	return ok
}

func elapsed(v ssmInvocation) string {
	if !v.Delivered.Valid {
		return ""
	}
	end := time.Now()
	if v.Finished.Valid {
		end = v.Finished.Time
	}
	return fmt.Sprintf("PT%.3fS", end.Sub(v.Delivered.Time).Seconds())
}

func (h *ssmHandler) getCommandInvocation(ctx context.Context, w http.ResponseWriter, r *http.Request, body map[string]any, claims iam.Claims, visible map[string]ec2Instance, requestID string) {
	cid, iid := strFromBody(body, "CommandId"), strFromBody(body, "InstanceId")
	if cid == "" || iid == "" {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "CommandId and InstanceId are required")
		return
	}
	if p := strFromBody(body, "PluginName"); p != "" && p != ssmPluginName {
		writeSSMError(w, http.StatusBadRequest, "InvalidPluginName", requestID, "The plugin name "+p+" is not valid for document "+ssmRunShellScript+" ("+ssmPluginName+")")
		return
	}
	if _, ok := visible[iid]; ok {
		if ok, reason := decide(ctx, r, h.authz, claims, "ssm:GetCommandInvocation", "Instance", iid,
			dataPlaneOnly(ctx, r, h.authz, claims, "ssm:GetCommandInvocation", "Instance", iid)); !ok {
			writeSSMError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "User: "+claims.PrincipalID()+" is not authorized to perform: ssm:GetCommandInvocation on resource: "+h.instanceARN(iid)+" ("+reason+")")
			return
		}
	}
	invs, err := h.store.invocations(ctx, cid, iid)
	if err != nil {
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the SSM store is unavailable; retry")
		return
	}
	if len(invs) == 0 || !h.mayRead(ctx, r, claims, visible, "ssm:GetCommandInvocation", iid) {
		// Nothing to reveal about an instance the caller cannot see.
		writeSSMError(w, http.StatusBadRequest, "InvocationDoesNotExist", requestID, "")
		return
	}
	v := invs[0]
	out := map[string]any{
		"CommandId": v.CommandID, "InstanceId": v.InstanceID, "Comment": v.Command.Comment, "DocumentName": v.Command.Document,
		"DocumentVersion": "1", "PluginName": ssmPluginName, "ResponseCode": v.ResponseCode,
		"ExecutionStartDateTime": "", "ExecutionElapsedTime": elapsed(v), "ExecutionEndDateTime": "",
		"Status": v.Status, "StatusDetails": v.StatusDetails,
		"StandardOutputContent": v.Stdout, "StandardOutputUrl": "", "StandardErrorContent": v.Stderr, "StandardErrorUrl": "",
		"CloudWatchOutputConfig": map[string]any{"CloudWatchLogGroupName": "", "CloudWatchOutputEnabled": false},
	}
	if v.Delivered.Valid {
		out["ExecutionStartDateTime"] = ssmISOTime(v.Delivered.Time)
	}
	if v.Finished.Valid {
		out["ExecutionEndDateTime"] = ssmISOTime(v.Finished.Time)
	}
	writeSSMJSON(w, requestID, out)
}

// ssmListFilter is ListCommands/ListCommandInvocations' Filters: InvokedAfter, InvokedBefore, Status,
// ExecutionStage (Executing | Complete) and DocumentName.
func ssmListFilter(body map[string]any) (func(ssmInvocation) bool, string) {
	raw, _ := body["Filters"].([]any)
	type f struct{ key, value string }
	var fs []f
	for _, x := range raw {
		m, _ := x.(map[string]any)
		k, v := strFromBody(m, "key"), strFromBody(m, "value")
		switch k {
		case "InvokedAfter", "InvokedBefore":
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return nil, "the " + k + " filter takes an ISO 8601 time"
			}
		case "Status", "ExecutionStage", "DocumentName":
		default:
			return nil, "the filter key " + k + " is not valid (InvokedAfter, InvokedBefore, Status, ExecutionStage, DocumentName)"
		}
		fs = append(fs, f{k, v})
	}
	return func(v ssmInvocation) bool {
		for _, x := range fs {
			switch x.key {
			case "InvokedAfter":
				t, _ := time.Parse(time.RFC3339, x.value)
				if v.Command.Requested.Before(t) {
					return false
				}
			case "InvokedBefore":
				t, _ := time.Parse(time.RFC3339, x.value)
				if v.Command.Requested.After(t) {
					return false
				}
			case "Status":
				if !strings.EqualFold(v.Status, x.value) {
					return false
				}
			case "ExecutionStage":
				done := v.Status != "Pending" && v.Status != "InProgress"
				if (x.value == "Complete") != done {
					return false
				}
			case "DocumentName":
				if v.Command.Document != x.value {
					return false
				}
			}
		}
		return true
	}, ""
}

// ssmPage applies MaxResults/NextToken (an offset) to n items.
func ssmPage(body map[string]any, n, max int) (start, end int, next string, ok bool) {
	start, end = 0, n
	if t := strFromBody(body, "NextToken"); t != "" {
		v, err := strconv.Atoi(t)
		if err != nil || v < 0 {
			return 0, 0, "", false
		}
		start = min(v, n)
	}
	limit := max
	if v, ok := body["MaxResults"].(float64); ok {
		limit = int(v)
		if limit < 1 || limit > max {
			return 0, 0, "", false
		}
	}
	if start+limit < n {
		end = start + limit
		next = strconv.Itoa(end)
	}
	return start, end, next, true
}

func (h *ssmHandler) listCommandInvocations(ctx context.Context, w http.ResponseWriter, r *http.Request, body map[string]any, claims iam.Claims, visible map[string]ec2Instance, requestID string) {
	keep, msg := ssmListFilter(body)
	if keep == nil {
		writeSSMError(w, http.StatusBadRequest, "InvalidFilterKey", requestID, msg)
		return
	}
	cid, iid := strFromBody(body, "CommandId"), strFromBody(body, "InstanceId")
	if cid != "" {
		if ok, err := h.store.commandExists(ctx, cid); err == nil && !ok {
			writeSSMError(w, http.StatusBadRequest, "InvalidCommandId", requestID, "")
			return
		}
	}
	invs, err := h.store.invocations(ctx, cid, iid)
	if err != nil {
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the SSM store is unavailable; retry")
		return
	}
	details, _ := body["Details"].(bool)
	var sel []ssmInvocation
	for _, v := range invs {
		if keep(v) && h.mayRead(ctx, r, claims, visible, "ssm:ListCommandInvocations", v.InstanceID) {
			sel = append(sel, v)
		}
	}
	start, end, next, ok := ssmPage(body, len(sel), 50)
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "InvalidNextToken", requestID, "MaxResults (1 to 50) or NextToken is not valid")
		return
	}
	items := make([]map[string]any, 0, end-start)
	for _, v := range sel[start:end] {
		plugins := []map[string]any{}
		if details {
			p := map[string]any{"Name": ssmPluginName, "Status": v.Status, "StatusDetails": v.StatusDetails, "ResponseCode": v.ResponseCode,
				"Output": pluginOutput(v), "StandardOutputUrl": "", "StandardErrorUrl": "", "OutputS3Region": h.region,
				"OutputS3BucketName": "", "OutputS3KeyPrefix": ""}
			if v.Delivered.Valid {
				p["ResponseStartDateTime"] = awsEpoch(v.Delivered.Time)
			}
			if v.Finished.Valid {
				p["ResponseFinishDateTime"] = awsEpoch(v.Finished.Time)
			}
			plugins = append(plugins, p)
		}
		items = append(items, map[string]any{
			"CommandId": v.CommandID, "InstanceId": v.InstanceID, "InstanceName": visible[v.InstanceID].name, "Comment": v.Command.Comment,
			"DocumentName": v.Command.Document, "DocumentVersion": "1", "RequestedDateTime": awsEpoch(v.Command.Requested),
			"Status": v.Status, "StatusDetails": v.StatusDetails, "TraceOutput": "", "StandardOutputUrl": "", "StandardErrorUrl": "",
			"CommandPlugins": plugins, "ServiceRole": "",
			"NotificationConfig":     map[string]any{"NotificationArn": "", "NotificationEvents": []string{}, "NotificationType": ""},
			"CloudWatchOutputConfig": map[string]any{"CloudWatchLogGroupName": "", "CloudWatchOutputEnabled": false},
		})
	}
	out := map[string]any{"CommandInvocations": items}
	if next != "" {
		out["NextToken"] = next
	}
	writeSSMJSON(w, requestID, out)
}

// pluginOutput is a plugin's Output as AWS reports it: the first 2,500 characters of stdout, then stderr.
func pluginOutput(v ssmInvocation) string {
	s := v.Stdout
	if v.Stderr != "" {
		s += "\n\n----------ERROR-------\n" + v.Stderr
	}
	if rs := []rune(s); len(rs) > 2500 {
		s = string(rs[:2500])
	}
	return s
}

func (h *ssmHandler) listCommands(ctx context.Context, w http.ResponseWriter, r *http.Request, body map[string]any, claims iam.Claims, visible map[string]ec2Instance, requestID string) {
	keep, msg := ssmListFilter(body)
	if keep == nil {
		writeSSMError(w, http.StatusBadRequest, "InvalidFilterKey", requestID, msg)
		return
	}
	cid, iid := strFromBody(body, "CommandId"), strFromBody(body, "InstanceId")
	if cid != "" {
		if ok, err := h.store.commandExists(ctx, cid); err == nil && !ok {
			writeSSMError(w, http.StatusBadRequest, "InvalidCommandId", requestID, "")
			return
		}
	}
	invs, err := h.store.invocations(ctx, cid, "")
	if err != nil {
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the SSM store is unavailable; retry")
		return
	}
	// Group by command (invocations come newest command first); a command is listed when the caller may
	// read one of its instances, and an InstanceId filter keeps the commands sent to it.
	var order []string
	byCmd := map[string][]ssmInvocation{}
	for _, v := range invs {
		if _, seen := byCmd[v.CommandID]; !seen {
			order = append(order, v.CommandID)
		}
		byCmd[v.CommandID] = append(byCmd[v.CommandID], v)
	}
	var sel []string
	for _, c := range order {
		vs := byCmd[c]
		readable, hasInst := false, iid == ""
		for _, v := range vs {
			if v.InstanceID == iid {
				hasInst = true
			}
			if h.mayRead(ctx, r, claims, visible, "ssm:ListCommands", v.InstanceID) {
				readable = true
			}
		}
		if readable && hasInst && keep(vs[0]) {
			sel = append(sel, c)
		}
	}
	start, end, next, ok := ssmPage(body, len(sel), 50)
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "InvalidNextToken", requestID, "MaxResults (1 to 50) or NextToken is not valid")
		return
	}
	cmds := make([]map[string]any, 0, end-start)
	for _, c := range sel[start:end] {
		vs := byCmd[c]
		ids := make([]string, 0, len(vs))
		for _, v := range vs {
			ids = append(ids, v.InstanceID)
		}
		cmds = append(cmds, h.commandJSON(vs[0].Command, ids, vs))
	}
	out := map[string]any{"Commands": cmds}
	if next != "" {
		out["NextToken"] = next
	}
	writeSSMJSON(w, requestID, out)
}

// --- managed instances ---

func (h *ssmHandler) describeInstanceInformation(ctx context.Context, w http.ResponseWriter, r *http.Request, body map[string]any, claims iam.Claims, visible map[string]ec2Instance, requestID string) {
	if ok, reason := decide(ctx, r, h.authz, claims, "ssm:DescribeInstanceInformation", "Instance", "",
		dataPlaneOnly(ctx, r, h.authz, claims, "ssm:DescribeInstanceInformation", "Instance", "")); !ok {
		writeSSMError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
		return
	}
	managed, err := h.store.managedInstances(ctx)
	if err != nil {
		writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "the SSM store is unavailable; retry")
		return
	}
	// Filters: InstanceInformationFilterList [{key, valueSet}] and Filters [{Key, Values}].
	type f struct {
		key  string
		vals map[string]bool
	}
	var fs []f
	for _, x := range anyList(body["InstanceInformationFilterList"]) {
		m, _ := x.(map[string]any)
		fs = append(fs, f{strFromBody(m, "key"), setOf(ssmStrings(m["valueSet"]))})
	}
	for _, x := range anyList(body["Filters"]) {
		m, _ := x.(map[string]any)
		fs = append(fs, f{strFromBody(m, "Key"), setOf(ssmStrings(m["Values"]))})
	}
	for _, x := range fs {
		switch x.key {
		case "InstanceIds", "AgentVersion", "PingStatus", "PlatformTypes", "ResourceType", "IamRole":
		default:
			if !strings.HasPrefix(x.key, "tag:") && x.key != "tag-key" {
				writeSSMError(w, http.StatusBadRequest, "InvalidInstanceInformationFilterValue", requestID, "the filter key "+x.key+" is not valid")
				return
			}
		}
	}
	ids := make([]string, 0, len(managed))
	for id, m := range managed {
		if _, ok := visible[id]; ok && m.Namespace == h.ec2.door.ns && !visible[id].windows {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var items []map[string]any
	for _, id := range ids {
		m, in := managed[id], visible[id]
		ping := "ConnectionLost"
		if time.Since(m.LastPing) < ssmOnlineWithin {
			ping = "Online"
		}
		match := true
		for _, x := range fs {
			var have []string
			switch x.key {
			case "InstanceIds":
				have = []string{id}
			case "AgentVersion":
				have = []string{m.AgentVersion}
			case "PingStatus":
				have = []string{ping}
			case "PlatformTypes":
				have = []string{"Linux"}
			case "ResourceType":
				have = []string{"EC2Instance"}
			case "IamRole":
				have = []string{m.Role}
			case "tag-key":
				for k := range in.tags {
					have = append(have, k)
				}
			default:
				if v, ok := in.tags[strings.TrimPrefix(x.key, "tag:")]; ok {
					have = []string{v}
				}
			}
			hit := false
			for _, v := range have {
				if x.vals[v] {
					hit = true
				}
			}
			if !hit {
				match = false
			}
		}
		if !match {
			continue
		}
		items = append(items, map[string]any{
			"InstanceId": id, "PingStatus": ping, "LastPingDateTime": awsEpoch(m.LastPing), "AgentVersion": m.AgentVersion,
			"IsLatestVersion": true, "PlatformType": "Linux", "PlatformName": m.PlatformName, "PlatformVersion": m.PlatformVersion,
			"ResourceType": "EC2Instance", "IPAddress": m.IPAddress, "ComputerName": m.ComputerName, "IamRole": m.Role,
			"SourceId": id, "SourceType": "AWS::EC2::Instance",
		})
	}
	start, end, next, ok := ssmPage(body, len(items), 50)
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "InvalidNextToken", requestID, "MaxResults (1 to 50) or NextToken is not valid")
		return
	}
	page := items[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	out := map[string]any{"InstanceInformationList": page}
	if next != "" {
		out["NextToken"] = next
	}
	writeSSMJSON(w, requestID, out)
}

func anyList(v any) []any { l, _ := v.([]any); return l }
