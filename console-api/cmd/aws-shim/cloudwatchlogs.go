// CloudWatch Logs front door for the aws-shim.
//
// Recognizes CloudWatch Logs requests in the AWS JSON protocol (X-Amz-Target: Logs_20140328.<Op>),
// authenticates them through the shared SigV4 path, authorizes them with the one policy world (coarse
// SubjectAccessReview + fine-grained Cedar logs:* at LOG-GROUP granularity — where write is separable from
// read and a principal scoped to group A cannot read group B), and stores/serves events from Postgres.
//
// This is the AWS-shaped log SINK for applications and SDKs (which write here by default). It is distinct
// from the cluster's Loki stack, which remains the sink for pod logs and the shim's own audit lines; this
// store gives the CloudWatch Logs API its exact contract — ordered byte-identical read-back with original
// millisecond timestamps, terminating pagination, and GENUINE per-group retention (a reaper enforces it,
// so DescribeLogGroups' retentionInDays is the truth, not a claim).
//
// Deliberate carve-outs, refused honestly: Logs Insights (StartQuery/GetQueryResults/StopQuery) and filter
// patterns beyond term/phrase matching (JSON-selector and metric-filter syntaxes) — refused, never
// silently returning unfiltered data. Sequence tokens: accepted with or without, always echoed back, never
// rejected on mismatch (AWS's current relaxed behavior). See docs/aws-shim.md.
//
// Accounts: the door keeps each account's log groups apart, as on AWS. The management account's groups are
// where they always were; a member account's are stored under its account key ("<account>:<group>",
// accountKey — a log group name has no ":"), their streams and events with them, and carry its account in
// their ARNs. A member account's service groups (/aws/lambda/<fn> …) are its own workloads', in its home
// namespace.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type cwlHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *cwlStore // nil => data layer not configured (honest 501)
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger
	// derived serves the groups AWS keeps a service's own logs in (/aws/lambda/<fn> …) from the platform's
	// log store (cloudwatchlogs_loki.go); nil => none.
	derived *cwlDerived
}

// CloudWatch Logs keeps each account's log groups apart.
func init() { accountScopedServices["logs"] = true }

func newCWLHandler(cs kubernetes.Interface, authzNS, account, region string, store *cwlStore, logger *slog.Logger) *cwlHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &cwlHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, logger: logger}
}

// allowedRetentionDays is AWS's fixed set of retention values.
var allowedRetentionDays = map[int]bool{
	1: true, 3: true, 5: true, 7: true, 14: true, 30: true, 60: true, 90: true, 120: true, 150: true,
	180: true, 365: true, 400: true, 545: true, 731: true, 1096: true, 1827: true, 2192: true,
	2557: true, 2922: true, 3288: true, 3653: true,
}

func writeCWLError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeCWLJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *cwlHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeCWLError(w, http.StatusForbidden, authCode(r, "SignatureDoesNotMatch"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."))
}

func verbForCWLOp(op string) (string, bool) {
	switch op {
	case "DescribeLogGroups", "DescribeLogStreams", "GetLogEvents", "FilterLogEvents":
		return "get", true
	case "CreateLogGroup", "CreateLogStream", "PutLogEvents", "PutRetentionPolicy", "TagLogGroup", "DeleteRetentionPolicy":
		return "create", true
	case "DeleteLogGroup", "DeleteLogStream":
		return "delete", true
	}
	return "", false
}

func (h *cwlHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"No operation named in the X-Amz-Target header (expected Logs_20140328.<Op>).")
		return
	}
	// Logs Insights — refused honestly (a query language that returns approximate results is worse than absent).
	switch op {
	case "StartQuery", "GetQueryResults", "StopQuery", "DescribeQueries":
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"CloudWatch Logs Insights is not supported by the open-infra shim; use GetLogEvents/FilterLogEvents.")
		return
	}
	verb, known := verbForCWLOp(op)
	if !known {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"CloudWatch Logs "+op+" is not implemented by the open-infra shim.")
		return
	}
	body := readJSONBody(r)
	group, _ := body["logGroupName"].(string)
	if memberKeyRe.MatchString(group) {
		// An account key's form, which no log group name has (AWS's have no ":"): never another account's group.
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"1 validation error detected: Value '"+group+"' at 'logGroupName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+")
		return
	}

	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	// logs:<Op> on the log group (decide): in legacy the coarse SubjectAccessReview, then the data-plane
	// refinement per log group (an assumed role is checked on every op, DescribeLogGroups on LogGroup::*).
	if ok, reason := decide(ctx, r, h.authz, claims, "logs:"+op, "LogGroup", group,
		coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "openinfra.dev", "applications", h.authzNS, group,
			"logs:"+op, "LogGroup", group)); !ok {
		h.audit(ctx, op, group, "deny", reason)
		writeCWLError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	acct := claims.Account
	if acct == "" {
		acct = h.account
	}
	ctx = context.WithValue(ctx, cwlAccountKey{}, acct)
	if h.derived != nil {
		if op == "DescribeLogGroups" {
			h.describeLogGroups(ctx, w, requestID, body, claims)
			return
		}
		// A service's own group (/aws/lambda/<fn> …): read from the log store, and read-only.
		if g, ok := h.derived.resolve(ctx, claims, group); ok {
			switch op {
			case "DescribeLogStreams":
				h.derivedDescribeStreams(ctx, w, requestID, g, body)
			case "GetLogEvents":
				h.derivedGetEvents(ctx, w, requestID, g, body)
			case "FilterLogEvents":
				h.derivedFilterEvents(ctx, w, requestID, g, body)
			case "CreateLogGroup":
				writeCWLError(w, http.StatusBadRequest, "ResourceAlreadyExistsException", requestID, "The specified log group already exists.")
			default:
				writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
					"log group "+group+" holds the logs its "+derivedOwner(g)+" writes, read from the platform's log store: it is read-only here, and its retention is the log store's ("+strconv.Itoa(h.derived.retention)+" days).")
			}
			h.audit(ctx, op, group, "allow", "log store")
			return
		}
	}
	if h.store == nil {
		writeCWLError(w, http.StatusNotImplemented, "ServiceUnavailableException", requestID,
			"the CloudWatch Logs data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}

	switch op {
	case "CreateLogGroup":
		h.createLogGroup(ctx, w, requestID, body)
	case "CreateLogStream":
		h.createLogStream(ctx, w, requestID, body)
	case "PutLogEvents":
		h.putLogEvents(ctx, w, requestID, body)
	case "DescribeLogGroups":
		h.describeLogGroups(ctx, w, requestID, body, claims)
	case "DescribeLogStreams":
		h.describeLogStreams(ctx, w, requestID, body)
	case "PutRetentionPolicy":
		h.putRetentionPolicy(ctx, w, requestID, body)
	case "DeleteRetentionPolicy":
		h.deleteRetentionPolicy(ctx, w, requestID, body)
	case "DeleteLogGroup":
		h.deleteLogGroup(ctx, w, requestID, body)
	case "DeleteLogStream":
		h.deleteLogStream(ctx, w, requestID, body)
	case "TagLogGroup":
		h.tagLogGroup(ctx, w, requestID, body)
	case "GetLogEvents":
		h.getLogEvents(ctx, w, requestID, body)
	case "FilterLogEvents":
		h.filterLogEvents(ctx, w, requestID, body)
	default:
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"CloudWatch Logs "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- groups / streams ---

func (h *cwlHandler) createLogGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["logGroupName"].(string)
	if name == "" {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "logGroupName is required.")
		return
	}
	created, err := h.store.createGroup(ctx, accountKey(ctx, name), h.groupARN(ctx, name), stringMap(body["tags"]))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !created {
		writeCWLError(w, http.StatusBadRequest, "ResourceAlreadyExistsException", requestID, "The specified log group already exists.")
		return
	}
	h.audit(ctx, "CreateLogGroup", name, "allow", "")
	writeCWLJSON(w, requestID, map[string]any{})
}

func (h *cwlHandler) createLogStream(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	stream, _ := body["logStreamName"].(string)
	created, groupExists, err := h.store.createStream(ctx, accountKey(ctx, group), stream)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !groupExists {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log group does not exist.")
		return
	}
	if !created {
		writeCWLError(w, http.StatusBadRequest, "ResourceAlreadyExistsException", requestID, "The specified log stream already exists.")
		return
	}
	h.audit(ctx, "CreateLogStream", group, "allow", stream)
	writeCWLJSON(w, requestID, map[string]any{})
}

func (h *cwlHandler) putLogEvents(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	stream, _ := body["logStreamName"].(string)
	raw := sliceOf(body["logEvents"])
	if len(raw) == 0 {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "logEvents must not be empty.")
		return
	}
	if len(raw) > 10000 {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "A single PutLogEvents call cannot contain more than 10000 events.")
		return
	}
	groupK := accountKey(ctx, group)
	if ok, err := h.store.streamExists(ctx, groupK, stream); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log stream does not exist.")
		return
	}
	// Retention window for the "expired" rejection.
	g, _, _ := h.store.getGroup(ctx, groupK)
	nowMs := time.Now().UnixMilli()
	futureLimit := nowMs + 2*60*60*1000 // 2 hours ahead
	var expiredCutoff int64 = -1
	if g.RetentionDays.Valid {
		expiredCutoff = nowMs - g.RetentionDays.Int64*86400000
	}

	total := 0
	var lastTs int64 = -1
	accepted := make([]putEvent, 0, len(raw))
	rejected := map[string]int{}
	for i, ev := range raw {
		em, _ := ev.(map[string]any)
		ts := toInt64(em["timestamp"])
		msg, _ := em["message"].(string)
		// per-event size (message bytes + 26 overhead, as AWS counts).
		if len(msg)+26 > 256*1024 {
			writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "Log event too large: max 256 KB per event.")
			return
		}
		total += len(msg) + 26
		if total > 1024*1024 {
			writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "The batch exceeds the 1 MB limit.")
			return
		}
		// Chronological order is a hard contract.
		if ts < lastTs {
			writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
				"Log events in a single PutLogEvents request must be in chronological order by timestamp.")
			return
		}
		lastTs = ts
		switch {
		case ts > futureLimit:
			rejected["tooNewLogEventStartIndex"] = i // first too-new index (kept as last-seen start)
		case expiredCutoff >= 0 && ts < expiredCutoff:
			rejected["expiredLogEventEndIndex"] = i
		default:
			accepted = append(accepted, putEvent{TsMs: ts, Message: msg})
		}
	}
	if len(accepted) > 0 {
		if err := h.store.putEvents(ctx, groupK, stream, accepted, nowMs); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "PutLogEvents", group, "allow", stream)
	out := map[string]any{"nextSequenceToken": "seq-" + strconv.FormatInt(nowMs, 10)}
	if len(rejected) > 0 {
		out["rejectedLogEventsInfo"] = rejected
	}
	writeCWLJSON(w, requestID, out)
}

// describeLogGroups lists the caller's account's groups SDKs created (the store) and the services' own groups
// (the log store), by name, as AWS does; a service's group shadows a stored group of the same name.
func (h *cwlHandler) describeLogGroups(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, claims iam.Claims) {
	prefix, _ := body["logGroupNamePrefix"].(string)
	entries := map[string]map[string]any{}
	if h.store != nil {
		groups, err := h.store.listGroups(ctx, accountKey(ctx, prefix))
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		for _, g := range groups {
			name, mine := nameOfAccountKey(ctx, g.Name)
			if !mine {
				continue // another account's group
			}
			e := map[string]any{
				"logGroupName": name, "arn": g.Arn,
				"creationTime": g.Created.UnixMilli(), "storedBytes": 0,
			}
			if g.RetentionDays.Valid {
				e["retentionInDays"] = g.RetentionDays.Int64
			}
			entries[name] = e
		}
	}
	if h.derived != nil {
		acct := h.accountOf(ctx)
		for _, g := range h.derived.groups(ctx, claims, prefix) {
			entries[g.Name] = map[string]any{
				"logGroupName": g.Name, "arn": h.groupARNIn(acct, g.Name), "creationTime": g.Created.UnixMilli(),
				"storedBytes": 0, "retentionInDays": h.derived.retention, "logGroupClass": "STANDARD",
			}
		}
	}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, entries[n])
	}
	writeCWLJSON(w, requestID, map[string]any{"logGroups": out})
}

// derivedOwner names what writes a service's group.
func derivedOwner(g derivedGroup) string {
	switch g.Kind {
	case "lambda":
		return "function"
	case "training":
		return "training jobs"
	case "processing":
		return "processing jobs"
	}
	return "application"
}

func (h *cwlHandler) describeLogStreams(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	if ok, err := h.groupMustExist(ctx, w, requestID, group); err != nil || !ok {
		return
	}
	streams, err := h.store.listStreams(ctx, accountKey(ctx, group), strFromBody(body, "logStreamNamePrefix"))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(streams))
	for _, st := range streams {
		e := map[string]any{
			"logStreamName": st.Name, "creationTime": st.Created.UnixMilli(),
			"arn": h.streamARN(ctx, group, st.Name),
		}
		if st.FirstEvent.Valid {
			e["firstEventTimestamp"] = st.FirstEvent.Int64
		}
		if st.LastEvent.Valid {
			e["lastEventTimestamp"] = st.LastEvent.Int64
		}
		if st.LastIngest.Valid {
			e["lastIngestionTime"] = st.LastIngest.Int64
		}
		out = append(out, e)
	}
	writeCWLJSON(w, requestID, map[string]any{"logStreams": out})
}

func (h *cwlHandler) putRetentionPolicy(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	days := toInt(body["retentionInDays"])
	if !allowedRetentionDays[days] {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"retentionInDays must be one of the AWS-allowed values (1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1096,1827,2192,2557,2922,3288,3653).")
		return
	}
	ok, err := h.store.setRetention(ctx, accountKey(ctx, group), days)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log group does not exist.")
		return
	}
	h.audit(ctx, "PutRetentionPolicy", group, "allow", strconv.Itoa(days)+"d")
	writeCWLJSON(w, requestID, map[string]any{})
}

// deleteRetentionPolicy makes the group keep its events forever again (AWS's default).
func (h *cwlHandler) deleteRetentionPolicy(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	ok, err := h.store.clearRetention(ctx, accountKey(ctx, group))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log group does not exist.")
		return
	}
	h.audit(ctx, "DeleteRetentionPolicy", group, "allow", "")
	writeCWLJSON(w, requestID, map[string]any{})
}

func (h *cwlHandler) deleteLogGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	ok, err := h.store.deleteGroup(ctx, accountKey(ctx, group))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log group does not exist.")
		return
	}
	// AU-9: deleting a log group is an audit-integrity event — recorded distinctly.
	h.audit(ctx, "DeleteLogGroup", group, "allow", "AUDIT-INTEGRITY: log group deleted")
	writeCWLJSON(w, requestID, map[string]any{})
}

func (h *cwlHandler) deleteLogStream(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	stream, _ := body["logStreamName"].(string)
	ok, err := h.store.deleteStream(ctx, accountKey(ctx, group), stream)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log stream does not exist.")
		return
	}
	h.audit(ctx, "DeleteLogStream", group, "allow", stream)
	writeCWLJSON(w, requestID, map[string]any{})
}

func (h *cwlHandler) tagLogGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	groupK := accountKey(ctx, group)
	g, ok, err := h.store.getGroup(ctx, groupK)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log group does not exist.")
		return
	}
	tags := g.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	for k, v := range stringMap(body["tags"]) {
		tags[k] = v
	}
	if err := h.store.setTags(ctx, groupK, tags); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeCWLJSON(w, requestID, map[string]any{})
}

// --- reads ---

func (h *cwlHandler) getLogEvents(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	stream, _ := body["logStreamName"].(string)
	groupK := accountKey(ctx, group)
	if ok, err := h.store.streamExists(ctx, groupK, stream); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log stream does not exist.")
		return
	}
	startFromHead, _ := body["startFromHead"].(bool)
	limit := toInt(body["limit"])
	afterID := parseCursor(strFromBody(body, "nextToken"))
	events, minID, maxID, err := h.store.getEvents(ctx, groupK, stream, startFromHead, limit, afterID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{"timestamp": e.TsMs, "message": e.Message, "ingestionTime": e.IngestMs})
	}
	// Forward token advances past the max id seen; when nothing new is returned it equals the input cursor,
	// so a client loop terminates. Backward token points before the min id seen.
	fwd := afterID
	if maxID > fwd {
		fwd = maxID
	}
	bwd := afterID
	if minID > 0 {
		bwd = minID
	}
	writeCWLJSON(w, requestID, map[string]any{
		"events":            out,
		"nextForwardToken":  "f/" + strconv.FormatInt(fwd, 10),
		"nextBackwardToken": "b/" + strconv.FormatInt(bwd, 10),
	})
}

func (h *cwlHandler) filterLogEvents(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group, _ := body["logGroupName"].(string)
	if ok, err := h.groupMustExist(ctx, w, requestID, group); err != nil || !ok {
		return
	}
	terms, err := parseFilterPattern(strFromBody(body, "filterPattern"))
	if err != nil {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, err.Error())
		return
	}
	startMs := toInt64(body["startTime"])
	endMs := toInt64(body["endTime"])
	limit := toInt(body["limit"])
	afterID := parseCursor(strFromBody(body, "nextToken"))
	events, maxID, err := h.store.filterEvents(ctx, accountKey(ctx, group), startMs, endMs, terms, limit, afterID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"logStreamName": e.Stream, "timestamp": e.TsMs, "message": e.Message,
			"ingestionTime": e.IngestMs, "eventId": strconv.FormatInt(e.ID, 10),
		})
	}
	resp := map[string]any{"events": out}
	// Only return a nextToken when the page was full (more may remain); omitting it terminates the loop.
	if limit > 0 && len(events) >= limit && maxID > 0 {
		resp["nextToken"] = strconv.FormatInt(maxID, 10)
	}
	writeCWLJSON(w, requestID, resp)
}

// --- helpers ---

// groupMustExist reports whether the caller's account has the group (answering the request when it does not).
func (h *cwlHandler) groupMustExist(ctx context.Context, w http.ResponseWriter, requestID, group string) (bool, error) {
	_, ok, err := h.store.getGroup(ctx, accountKey(ctx, group))
	if err != nil {
		h.internal(w, requestID, err)
		return false, err
	}
	if !ok {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log group does not exist.")
		return false, nil
	}
	return true, nil
}

// groupARN is the ARN of the caller's account's group name.
func (h *cwlHandler) groupARN(ctx context.Context, name string) string {
	return h.groupARNIn(h.accountOf(ctx), name)
}

// streamARN is the ARN of a stream of the caller's account's group.
func (h *cwlHandler) streamARN(ctx context.Context, group, stream string) string {
	return h.streamARNIn(h.accountOf(ctx), group, stream)
}

func (h *cwlHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("cloudwatchlogs backend error", "error", err.Error())
	writeCWLError(w, http.StatusInternalServerError, "ServiceUnavailableException", requestID, "The service cannot complete the request.")
}

func (h *cwlHandler) audit(ctx context.Context, op, group, decision, detail string) {
	args := []any{"service", "logs", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if group != "" {
		args = append(args, "logGroup", group)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "cloudwatchlogs audit", args...)
}

// --- pure helpers ---

// parseCursor extracts the numeric id from a GetLogEvents/FilterLogEvents token ("f/123", "b/123", "123").
func parseCursor(token string) int64 {
	if token == "" {
		return 0
	}
	if i := strings.IndexByte(token, '/'); i >= 0 {
		token = token[i+1:]
	}
	n, _ := strconv.ParseInt(token, 10, 64)
	return n
}

// parseFilterPattern turns a CloudWatch filter pattern into AND-matched substring terms, or errors on a
// syntax we do not implement (JSON-selector {...}, metric-filter [...], and the ?/- operators). An empty
// pattern matches everything. Quoted "phrases" are single terms.
func parseFilterPattern(pattern string) ([]string, error) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return nil, nil
	}
	if strings.HasPrefix(p, "{") || strings.HasPrefix(p, "[") {
		return nil, &patternError{"CloudWatch Logs JSON-selector and metric-filter patterns are not supported; use plain terms or quoted phrases."}
	}
	var terms []string
	i := 0
	for i < len(p) {
		for i < len(p) && p[i] == ' ' {
			i++
		}
		if i >= len(p) {
			break
		}
		if p[i] == '"' {
			j := i + 1
			for j < len(p) && p[j] != '"' {
				j++
			}
			if j >= len(p) {
				return nil, &patternError{"unterminated quoted phrase in filter pattern"}
			}
			terms = append(terms, p[i+1:j])
			i = j + 1
			continue
		}
		j := i
		for j < len(p) && p[j] != ' ' {
			j++
		}
		term := p[i:j]
		i = j
		if strings.HasPrefix(term, "?") || strings.HasPrefix(term, "-") || strings.HasPrefix(term, "$") {
			return nil, &patternError{"filter operators ?, -, and $ are not supported; use plain terms or quoted phrases."}
		}
		terms = append(terms, term)
	}
	return terms, nil
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}
