// EventBridge front door for the aws-shim (polyhedron#163).
//
// Recognizes EventBridge requests in the AWS JSON protocol (X-Amz-Target: AWSEvents.<Op>), authenticates
// them through the shared SigV4 path, authorizes them with the one policy world (coarse SubjectAccessReview
// + fine-grained Cedar at rule/bus granularity), and drives two patterns:
//   - SCHEDULED rules: an in-process scheduler fires rate()/cron() rules and delivers the AWS "Scheduled
//     Event" envelope to their targets.
//   - EVENT-PATTERN rules: PutEvents matches an event against enabled rules and delivers to their targets.
//
// Delivery rides the DURABLE paths already in the shim: Lambda targets via the JetStream asyncInvoker
// (retry + dead-letter), SQS targets via the Postgres SQS store. A target type we cannot deliver durably
// is REFUSED at PutTargets — never accepted into a rule that then silently never fires.
//
// Invocation authority (the sharp security question): a triggered invocation runs under the RULE CREATOR's
// authority, verified at PutTargets against the caller's live claims — you can only wire a target you could
// invoke yourself, so a rule is not a privilege-escalation path. It is NEVER the shim's own ambient
// authority. RoleArn on a target is refused in v1. Every fire is audited to the creating principal.
// (Divergence from AWS: authority is verified at PutTargets, not re-checked per-fire; documented.)
//
// See docs/aws-shim.md for supported targets, the pattern operators, the cron translation, and divergences.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type ebHandler struct {
	cs      kubernetes.Interface
	authzNS string
	fnNS    string
	account string
	region  string
	store   *ebStore
	async   *asyncInvoker // Lambda target delivery (durable); nil => Lambda targets refused
	sqs     *sqsStore     // SQS target delivery; nil => SQS targets refused
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger

	schedMu sync.Mutex
}

func newEBHandler(cs kubernetes.Interface, authzNS, fnNS, account, region string, store *ebStore, async *asyncInvoker, sqs *sqsStore, logger *slog.Logger) *ebHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &ebHandler{cs: cs, authzNS: authzNS, fnNS: fnNS, account: account, region: region, store: store, async: async, sqs: sqs, logger: logger}
}

// --- error dialect (AWS JSON 1.1) ---

func writeEBError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeEBJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *ebHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeEBError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func verbForEBOp(op string) (string, bool) {
	switch op {
	case "DescribeRule", "ListRules", "ListTargetsByRule", "ListEventBuses", "TestEventPattern":
		return "get", true
	case "PutRule", "PutTargets", "PutEvents", "EnableRule", "DisableRule", "CreateEventBus":
		return "create", true
	case "DeleteRule", "RemoveTargets", "DeleteEventBus":
		return "delete", true
	}
	return "", false
}

func (h *ebHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"No operation named in the X-Amz-Target header (expected AWSEvents.<Op>).")
		return
	}
	verb, known := verbForEBOp(op)
	if !known {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"EventBridge "+op+" is not implemented by the open-infra shim.")
		return
	}
	body := readJSONBody(r)

	// The resource this op scopes to (Cedar + coarse gate): a Rule name for rule/target ops, an EventBus
	// name for bus/PutEvents ops.
	resType, resID := "Rule", ""
	switch op {
	case "CreateEventBus", "DeleteEventBus":
		resType, resID = "EventBus", strFromBody(body, "Name")
	case "PutEvents", "ListEventBuses", "TestEventPattern":
		resType, resID = "EventBus", "default"
	default:
		resID = strFromBody(body, "Name") // PutRule/DescribeRule/etc carry Name; PutTargets/RemoveTargets carry Rule
		if resID == "" {
			resID = strFromBody(body, "Rule")
		}
	}

	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, resID); !allowed {
		h.auditDeny(ctx, op, resID, reason)
		writeEBError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if resID != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "events:"+op, resType, resID, r); denied {
			h.auditDeny(ctx, op, resID, reason)
			writeEBError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}
	if h.store == nil {
		writeEBError(w, http.StatusNotImplemented, "InternalException", requestID,
			"the EventBridge data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}

	switch op {
	case "CreateEventBus":
		h.createEventBus(ctx, w, requestID, body)
	case "DeleteEventBus":
		h.deleteEventBus(ctx, w, requestID, body)
	case "ListEventBuses":
		h.listEventBuses(ctx, w, requestID)
	case "PutRule":
		h.putRule(ctx, w, requestID, body)
	case "DeleteRule":
		h.deleteRule(ctx, w, requestID, body)
	case "DescribeRule":
		h.describeRule(ctx, w, requestID, body)
	case "ListRules":
		h.listRules(ctx, w, requestID, body)
	case "EnableRule":
		h.setRuleState(ctx, w, requestID, body, "ENABLED")
	case "DisableRule":
		h.setRuleState(ctx, w, requestID, body, "DISABLED")
	case "PutTargets":
		h.putTargets(ctx, w, r, requestID, body, claims)
	case "RemoveTargets":
		h.removeTargets(ctx, w, requestID, body)
	case "ListTargetsByRule":
		h.listTargetsByRule(ctx, w, requestID, body)
	case "PutEvents":
		h.putEvents(ctx, w, requestID, body)
	case "TestEventPattern":
		h.testEventPattern(ctx, w, requestID, body)
	default:
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"EventBridge "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

func busOf(body map[string]any) string {
	if b := strFromBody(body, "EventBusName"); b != "" {
		return b
	}
	return "default"
}

// --- buses ---

func (h *ebHandler) createEventBus(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := strFromBody(body, "Name")
	if name == "" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "CreateEventBus requires a Name.")
		return
	}
	arn := "arn:aws:events:" + h.region + ":" + h.account + ":event-bus/" + name
	created, err := h.store.createBus(ctx, name, arn)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !created {
		writeEBError(w, http.StatusBadRequest, "ResourceAlreadyExistsException", requestID, "Event bus "+name+" already exists.")
		return
	}
	h.audit(ctx, "CreateEventBus", name)
	writeEBJSON(w, requestID, map[string]any{"EventBusArn": arn})
}

func (h *ebHandler) deleteEventBus(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := strFromBody(body, "Name")
	if name == "default" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "The default event bus cannot be deleted.")
		return
	}
	ok, err := h.store.deleteBus(ctx, name)
	if err == errBusNotEmpty {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "The event bus still has rules; delete them first.")
		return
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeEBError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Event bus "+name+" does not exist.")
		return
	}
	h.audit(ctx, "DeleteEventBus", name)
	writeEBJSON(w, requestID, map[string]any{})
}

func (h *ebHandler) listEventBuses(ctx context.Context, w http.ResponseWriter, requestID string) {
	buses, err := h.store.listBuses(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(buses))
	for _, b := range buses {
		out = append(out, map[string]any{"Name": b.Name, "Arn": b.Arn})
	}
	writeEBJSON(w, requestID, map[string]any{"EventBuses": out})
}

// --- rules ---

func (h *ebHandler) putRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := strFromBody(body, "Name")
	if name == "" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "PutRule requires a Name.")
		return
	}
	bus := busOf(body)
	if ok, err := h.store.busExists(ctx, bus); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeEBError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Event bus "+bus+" does not exist.")
		return
	}
	schedExpr := strFromBody(body, "ScheduleExpression")
	pattern := strFromBody(body, "EventPattern")
	if schedExpr != "" && pattern != "" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"A rule has either a ScheduleExpression or an EventPattern, not both.")
		return
	}
	if schedExpr == "" && pattern == "" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"PutRule requires a ScheduleExpression or an EventPattern.")
		return
	}
	state := strFromBody(body, "State")
	if state == "" {
		state = "ENABLED"
	}
	if state != "ENABLED" && state != "DISABLED" {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "State must be ENABLED or DISABLED.")
		return
	}
	r := ebRule{
		Bus: bus, Name: name, Arn: h.ruleARN(bus, name),
		ScheduleExpr: schedExpr, EventPattern: pattern, State: state,
		Description: strFromBody(body, "Description"), Creator: principalFromCtx(ctx),
	}
	// Validate + (for schedules) compute the first fire — refuse anything we cannot faithfully evaluate.
	if schedExpr != "" {
		sched, err := parseSchedule(schedExpr)
		if err != nil {
			writeEBError(w, http.StatusBadRequest, "ValidationException", requestID, "ScheduleExpression: "+err.Error())
			return
		}
		if state == "ENABLED" {
			next, err := sched.nextFire(time.Now())
			if err != nil {
				writeEBError(w, http.StatusBadRequest, "ValidationException", requestID, "ScheduleExpression: "+err.Error())
				return
			}
			r.NextFireAt = sql.NullTime{Time: next, Valid: true}
		}
	} else {
		var p map[string]any
		if err := json.Unmarshal([]byte(pattern), &p); err != nil {
			writeEBError(w, http.StatusBadRequest, "InvalidEventPatternException", requestID, "EventPattern is not valid JSON.")
			return
		}
		if err := validatePattern(p); err != nil {
			writeEBError(w, http.StatusBadRequest, "InvalidEventPatternException", requestID, err.Error())
			return
		}
	}
	if err := h.store.putRule(ctx, r); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutRule", name, "bus", bus)
	writeEBJSON(w, requestID, map[string]any{"RuleArn": r.Arn})
}

func (h *ebHandler) deleteRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, bus := strFromBody(body, "Name"), busOf(body)
	ok, err := h.store.deleteRule(ctx, bus, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeEBError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Rule "+name+" does not exist.")
		return
	}
	h.audit(ctx, "DeleteRule", name, "bus", bus)
	writeEBJSON(w, requestID, map[string]any{})
}

func (h *ebHandler) describeRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, bus := strFromBody(body, "Name"), busOf(body)
	r, ok, err := h.store.getRule(ctx, bus, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeEBError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Rule "+name+" does not exist.")
		return
	}
	writeEBJSON(w, requestID, h.ruleJSON(r))
}

func (h *ebHandler) listRules(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	bus := busOf(body)
	rules, err := h.store.listRules(ctx, bus, strFromBody(body, "NamePrefix"))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, h.ruleJSON(r))
	}
	writeEBJSON(w, requestID, map[string]any{"Rules": out})
}

func (h *ebHandler) setRuleState(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, state string) {
	name, bus := strFromBody(body, "Name"), busOf(body)
	r, ok, err := h.store.getRule(ctx, bus, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeEBError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Rule "+name+" does not exist.")
		return
	}
	var next sql.NullTime
	if state == "ENABLED" && r.ScheduleExpr != "" {
		// Re-arm the schedule from now (so a re-enable does not fire a backlog of missed slots).
		if sched, err := parseSchedule(r.ScheduleExpr); err == nil {
			if nf, err := sched.nextFire(time.Now()); err == nil {
				next = sql.NullTime{Time: nf, Valid: true}
			}
		}
	}
	if _, err := h.store.setState(ctx, bus, name, state, next); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, map[string]string{"ENABLED": "EnableRule", "DISABLED": "DisableRule"}[state], name, "bus", bus)
	writeEBJSON(w, requestID, map[string]any{})
}

// --- targets ---

func (h *ebHandler) putTargets(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, claims iam.Claims) {
	name, bus := strFromBody(body, "Rule"), busOf(body)
	rule, ok, err := h.store.getRule(ctx, bus, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeEBError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Rule "+name+" does not exist.")
		return
	}
	targets := sliceOf(body["Targets"])
	if len(targets) == 0 {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "PutTargets requires at least one target.")
		return
	}
	existing, _ := h.store.countTargets(ctx, bus, name)
	if existing+len(targets) > 5 {
		writeEBError(w, http.StatusBadRequest, "LimitExceededException", requestID, "A rule can have at most 5 targets.")
		return
	}
	for _, tv := range targets {
		tm, _ := tv.(map[string]any)
		id, _ := tm["Id"].(string)
		arn, _ := tm["Arn"].(string)
		if id == "" || arn == "" {
			writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "each target needs an Id and an Arn.")
			return
		}
		if _, has := tm["RoleArn"]; has {
			writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
				"RoleArn on a target is not supported; the triggered invocation runs under the rule creator's authority.")
			return
		}
		if _, has := tm["InputPath"]; has {
			writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "InputPath is not supported; use Input (a constant) or omit it.")
			return
		}
		if _, has := tm["InputTransformer"]; has {
			writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "InputTransformer is not supported; use Input (a constant) or omit it.")
			return
		}
		ttype, ok := targetType(arn)
		if !ok {
			writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
				"unsupported target type for "+arn+"; the open-infra shim supports Lambda and SQS targets.")
			return
		}
		// Escalation fence: the caller must be able to invoke/send to this target themselves. A rule is
		// then not a way to reach something you could not reach directly.
		if reason, authorized := h.authorizeTarget(ctx, r, claims, ttype, arn); !authorized {
			writeEBError(w, http.StatusForbidden, "AccessDeniedException", requestID,
				"not authorized to invoke the target "+arn+" (a rule cannot target what its creator cannot invoke): "+reason)
			return
		}
		input := ""
		if iv, ok := tm["Input"].(string); ok {
			input = iv
		}
		if err := h.store.putTarget(ctx, bus, name, ebTarget{ID: id, Arn: arn, Type: ttype, Input: input}); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	_ = rule
	h.audit(ctx, "PutTargets", name, "bus", bus, "count", len(targets))
	writeEBJSON(w, requestID, map[string]any{"FailedEntryCount": 0, "FailedEntries": []any{}})
}

func (h *ebHandler) removeTargets(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, bus := strFromBody(body, "Rule"), busOf(body)
	ids := stringSlice(body["Ids"])
	for _, id := range ids {
		if _, err := h.store.removeTarget(ctx, bus, name, id); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "RemoveTargets", name, "bus", bus)
	writeEBJSON(w, requestID, map[string]any{"FailedEntryCount": 0, "FailedEntries": []any{}})
}

func (h *ebHandler) listTargetsByRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, bus := strFromBody(body, "Rule"), busOf(body)
	targets, err := h.store.listTargets(ctx, bus, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(targets))
	for _, t := range targets {
		e := map[string]any{"Id": t.ID, "Arn": t.Arn}
		if t.Input != "" {
			e["Input"] = t.Input
		}
		out = append(out, e)
	}
	writeEBJSON(w, requestID, map[string]any{"Targets": out})
}

// --- events ---

func (h *ebHandler) putEvents(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	entries := sliceOf(body["Entries"])
	if len(entries) == 0 || len(entries) > 10 {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "PutEvents takes 1..10 entries.")
		return
	}
	resultEntries := make([]any, 0, len(entries))
	failed := 0
	for _, ev := range entries {
		em, _ := ev.(map[string]any)
		bus := "default"
		if b, _ := em["EventBusName"].(string); b != "" {
			bus = b
		}
		detail, _ := em["Detail"].(string)
		if len(detail) > 256*1024 {
			failed++
			resultEntries = append(resultEntries, map[string]any{"ErrorCode": "InternalFailure", "ErrorMessage": "Detail exceeds 256 KB."})
			continue
		}
		envelope, id := h.buildEnvelope(em, bus)
		if err := h.routeEvent(ctx, bus, envelope); err != nil {
			failed++
			resultEntries = append(resultEntries, map[string]any{"ErrorCode": "InternalFailure", "ErrorMessage": "routing failed"})
			continue
		}
		resultEntries = append(resultEntries, map[string]any{"EventId": id})
	}
	writeEBJSON(w, requestID, map[string]any{"FailedEntryCount": failed, "Entries": resultEntries})
}

func (h *ebHandler) testEventPattern(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	patternStr := strFromBody(body, "EventPattern")
	eventStr := strFromBody(body, "Event")
	var pattern, event map[string]any
	if err := json.Unmarshal([]byte(patternStr), &pattern); err != nil {
		writeEBError(w, http.StatusBadRequest, "InvalidEventPatternException", requestID, "EventPattern is not valid JSON.")
		return
	}
	if err := validatePattern(pattern); err != nil {
		writeEBError(w, http.StatusBadRequest, "InvalidEventPatternException", requestID, err.Error())
		return
	}
	if err := json.Unmarshal([]byte(eventStr), &event); err != nil {
		writeEBError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "Event is not valid JSON.")
		return
	}
	writeEBJSON(w, requestID, map[string]any{"Result": matchPattern(pattern, event)})
}

// --- routing + delivery ---

// routeEvent matches an event against enabled pattern rules on the bus and delivers to their targets.
func (h *ebHandler) routeEvent(ctx context.Context, bus string, envelope map[string]any) error {
	rules, err := h.store.enabledPatternRules(ctx, bus)
	if err != nil {
		return err
	}
	for _, r := range rules {
		var p map[string]any
		if json.Unmarshal([]byte(r.EventPattern), &p) != nil {
			continue
		}
		if matchPattern(p, envelope) {
			h.fireRuleTargets(ctx, r, envelope, "pattern")
		}
	}
	return nil
}

// fireRuleTargets delivers an event to all of a rule's targets on the durable path. A missed/failed
// delivery is logged and metered — never silently dropped.
func (h *ebHandler) fireRuleTargets(ctx context.Context, r ebRule, envelope map[string]any, trigger string) {
	targets, err := h.store.listTargets(ctx, r.Bus, r.Name)
	if err != nil {
		h.logger.Error("eventbridge: could not load targets", "rule", r.Name, "error", err.Error())
		return
	}
	for _, t := range targets {
		payload := []byte(t.Input)
		if t.Input == "" {
			payload, _ = json.Marshal(envelope)
		}
		if err := h.deliver(ctx, t, payload); err != nil {
			h.logger.Warn("eventbridge: target delivery FAILED (missed execution)",
				"rule", r.Name, "target", t.Arn, "trigger", trigger, "error", err.Error())
			h.audit(ctx, "TargetDeliveryFailed", r.Name, "target", t.Arn, "creator", r.Creator, "error", err.Error())
			continue
		}
		h.audit(ctx, "TargetDelivered", r.Name, "target", t.Arn, "trigger", trigger, "creator", r.Creator)
	}
}

func (h *ebHandler) deliver(ctx context.Context, t ebTarget, payload []byte) error {
	switch t.Type {
	case "lambda":
		if h.async == nil {
			return errNoAsync
		}
		return h.async.publish(lambdaNameFromArn(t.Arn), "application/json", payload, "")
	case "sqs":
		if h.sqs == nil {
			return errNoSQS
		}
		qname := arnLast(t.Arn)
		url, ok, err := h.sqs.queueURLByName(ctx, qname)
		if err != nil {
			return err
		}
		if !ok {
			return errNoQueue
		}
		bodyStr := string(payload)
		_, err = h.sqs.sendMessage(ctx, url, bodyStr, md5Hex(bodyStr), "", nil, 0)
		return err
	}
	return errUnsupportedTarget
}

// --- scheduler ---

// runScheduler is the in-process cron/rate driver. Rules are persisted, so a restart reloads them; a fire
// that a restart straddles is not caught up (documented divergence) but is observable. Exits with ctx.
func (h *ebHandler) runScheduler(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	h.logger.Info("eventbridge scheduler started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.tickSchedule(ctx)
		}
	}
}

func (h *ebHandler) tickSchedule(ctx context.Context) {
	h.schedMu.Lock()
	defer h.schedMu.Unlock()
	now := time.Now()
	due, err := h.store.dueScheduled(ctx, now)
	if err != nil {
		h.logger.Warn("eventbridge scheduler: due query failed", "error", err.Error())
		return
	}
	for _, r := range due {
		// Compute and persist the NEXT fire first, so a slow delivery cannot cause a double-fire on the
		// next tick.
		sched, err := parseSchedule(r.ScheduleExpr)
		if err != nil {
			h.logger.Error("eventbridge scheduler: unparseable schedule on a stored rule", "rule", r.Name, "error", err.Error())
			continue
		}
		next, err := sched.nextFire(now)
		if err != nil {
			continue
		}
		if err := h.store.setNextFire(ctx, r.Bus, r.Name, next); err != nil {
			h.logger.Warn("eventbridge scheduler: could not advance next fire", "rule", r.Name, "error", err.Error())
			continue
		}
		h.fireRuleTargets(ctx, r, h.scheduledEnvelope(r), "schedule")
	}
}

// --- helpers ---

func (h *ebHandler) buildEnvelope(entry map[string]any, bus string) (map[string]any, string) {
	id := uuidLike()
	var detail any = map[string]any{}
	if d, _ := entry["Detail"].(string); d != "" {
		var parsed any
		if json.Unmarshal([]byte(d), &parsed) == nil {
			detail = parsed
		}
	}
	return map[string]any{
		"version":     "0",
		"id":          id,
		"detail-type": strFromBody(entry, "DetailType"),
		"source":      strFromBody(entry, "Source"),
		"account":     h.account,
		"time":        time.Now().UTC().Format(time.RFC3339),
		"region":      h.region,
		"resources":   entry["Resources"],
		"detail":      detail,
	}, id
}

func (h *ebHandler) scheduledEnvelope(r ebRule) map[string]any {
	return map[string]any{
		"version":     "0",
		"id":          uuidLike(),
		"detail-type": "Scheduled Event",
		"source":      "aws.events",
		"account":     h.account,
		"time":        time.Now().UTC().Format(time.RFC3339),
		"region":      h.region,
		"resources":   []any{r.Arn},
		"detail":      map[string]any{},
	}
}

// authorizeTarget verifies the caller may invoke/send to the target — the escalation fence.
func (h *ebHandler) authorizeTarget(ctx context.Context, r *http.Request, claims iam.Claims, ttype, arn string) (string, bool) {
	switch ttype {
	case "lambda":
		fn := lambdaNameFromArn(arn)
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "lambda:InvokeFunction", "Function", fn, r); denied {
			return reason, false
		}
		if allowed, reason := iam.CanDo(ctx, h.cs, claims, "create", "openinfra.dev", "functions", h.fnNS, fn); !allowed {
			return reason, false
		}
		return "", true
	case "sqs":
		q := arnLast(arn)
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "sqs:SendMessage", "Queue", q, r); denied {
			return reason, false
		}
		if allowed, reason := iam.CanDo(ctx, h.cs, claims, "create", "openinfra.dev", "applications", h.authzNS, q); !allowed {
			return reason, false
		}
		return "", true
	}
	return "unsupported target", false
}

func (h *ebHandler) ruleJSON(r ebRule) map[string]any {
	out := map[string]any{"Name": r.Name, "Arn": r.Arn, "State": r.State, "EventBusName": r.Bus, "Description": r.Description}
	if r.ScheduleExpr != "" {
		out["ScheduleExpression"] = r.ScheduleExpr
	}
	if r.EventPattern != "" {
		out["EventPattern"] = r.EventPattern
	}
	return out
}

func (h *ebHandler) ruleARN(bus, name string) string {
	if bus == "default" {
		return "arn:aws:events:" + h.region + ":" + h.account + ":rule/" + name
	}
	return "arn:aws:events:" + h.region + ":" + h.account + ":rule/" + bus + "/" + name
}

func (h *ebHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("eventbridge backend error", "error", err.Error())
	writeEBError(w, http.StatusInternalServerError, "InternalException", requestID, "An internal error occurred.")
}

func (h *ebHandler) audit(ctx context.Context, op, rule string, kv ...any) {
	args := []any{"service", "events", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if rule != "" {
		args = append(args, "rule", rule)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "eventbridge audit", args...)
}

func (h *ebHandler) auditDeny(ctx context.Context, op, rule, reason string) {
	args := []any{"service", "events", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if rule != "" {
		args = append(args, "rule", rule)
	}
	h.logger.InfoContext(ctx, "eventbridge audit", args...)
}

// --- pure helpers ---

// targetType classifies a target ARN into a supported delivery type, or ok=false to refuse it.
func targetType(arn string) (string, bool) {
	switch {
	case strings.Contains(arn, ":lambda:") && strings.Contains(arn, ":function:"):
		return "lambda", true
	case strings.Contains(arn, ":sqs:"):
		return "sqs", true
	}
	return "", false
}

// lambdaNameFromArn extracts the function name from arn:aws:lambda:region:acct:function:NAME[:qualifier].
func lambdaNameFromArn(arn string) string {
	i := strings.Index(arn, ":function:")
	if i < 0 {
		return arnLast(arn)
	}
	name := arn[i+len(":function:"):]
	if j := strings.Index(name, ":"); j >= 0 {
		name = name[:j] // strip a version/alias qualifier
	}
	return name
}

func arnLast(arn string) string {
	if i := strings.LastIndex(arn, ":"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

type ebErr string

func (e ebErr) Error() string { return string(e) }

const (
	errNoAsync           = ebErr("Lambda target delivery requires the async event bus (NATS_URL) on the shim")
	errNoSQS             = ebErr("SQS target delivery requires the SQS data layer on the shim")
	errNoQueue           = ebErr("the target SQS queue does not exist")
	errUnsupportedTarget = ebErr("unsupported target type")
)
