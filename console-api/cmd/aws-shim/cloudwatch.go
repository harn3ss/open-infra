// CloudWatch metrics + alarms front door for the aws-shim (polyhedron#170) — the other half of CloudWatch
// (Logs shipped in #164). Speaks the AWS QUERY protocol (form request, XML response), the SNS/RDS family.
//
// The crux (issue item 3): alarms must ACTUALLY EVALUATE. An in-process evaluator (like the EventBridge
// scheduler) aggregates each alarm's metric over its EvaluationPeriods and transitions OK/ALARM/
// INSUFFICIENT_DATA per the ComparisonOperator + DatapointsToAlarm + TreatMissingData, and FIRES its SNS
// AlarmActions on entering ALARM — reusing the shipped SNS doorway (#159) for durable delivery. An alarm
// that is created but never evaluates is worse than absent (the operator believes they have coverage they
// do not), so an action target that is not an SNS topic is REFUSED at PutMetricAlarm rather than accepted.
//
// Authorization is the one policy world, at NAMESPACE granularity: a tenant cannot write into or READ
// another tenant's namespace (cross-tenant GetMetricData is a data-exposure hole, same shape as #164).
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

const cwXMLNamespace = "http://monitoring.amazonaws.com/doc/2010-08-01/"

// snsPublisher is the slice of SNS the alarm evaluator needs — implemented by *snsHandler.
type snsPublisher interface {
	publishMessage(ctx context.Context, topicArn, subject, message string) (string, error)
}

type cwHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *cwStore
	authz   *dataplaneauthz.Checker
	sns     snsPublisher
	logger  *slog.Logger
}

func newCWHandler(cs kubernetes.Interface, authzNS, account, region string, store *cwStore, sns snsPublisher, logger *slog.Logger) *cwHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &cwHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, sns: sns, logger: logger}
}

func (h *cwHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeCWError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", cwXMLNamespace)
}

func verbForCWOp(op string) (string, bool) {
	switch op {
	case "GetMetricData", "GetMetricStatistics", "ListMetrics", "DescribeAlarms":
		return "get", true
	case "PutMetricData", "PutMetricAlarm", "SetAlarmState":
		return "create", true
	case "DeleteAlarms":
		return "delete", true
	}
	return "", false
}

func (h *cwHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	// The modern AWS SDK/CLI sends CloudWatch in JSON "query mode" (X-Amz-Target:
	// GraniteServiceVersion20100801.<Op>, a JSON body, header x-amzn-query-mode: true) and expects the
	// classic XML query RESPONSE — NOT the form-encoded request the older query protocol used (confirmed
	// empirically; the issue's "form-encoded request" assumption is stale). We normalize the JSON body into
	// the AWS query `.member.N` form shape so the shared member-index parsers below work unchanged, and keep
	// emitting XML responses (which botocore parses in query mode). A legacy form-encoded client still works.
	op := ""
	if tgt := r.Header.Get("X-Amz-Target"); tgt != "" {
		op = opFromTarget(tgt)
		vals := url.Values{}
		for k, v := range readJSONBody(r) {
			flattenQuery(k, v, vals)
		}
		r.PostForm = vals
		r.Form = vals
	} else {
		op = r.PostFormValue("Action")
	}
	if op == "" {
		writeCWError(w, http.StatusBadRequest, "InvalidAction", requestID, "no Action or X-Amz-Target in the request.", cwXMLNamespace)
		return
	}
	verb, known := verbForCWOp(op)
	if !known {
		writeCWError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"CloudWatch "+op+" is not implemented by the open-infra shim.", cwXMLNamespace)
		return
	}
	if h.store == nil {
		writeCWError(w, http.StatusInternalServerError, "InternalFailure", requestID,
			"the CloudWatch data layer is not configured on this shim (set SQS_PG_URI)", cwXMLNamespace)
		return
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	ns := r.PostFormValue("Namespace")

	// Coarse SAR (namespace as the resource name). Alarm-list ops carry no namespace; they gate per-alarm.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, ns); !allowed {
		h.auditDeny(ctx, op, ns, reason)
		writeCWError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cwXMLNamespace)
		return
	}
	// Fine-grained Cedar at namespace granularity (the cross-tenant read/write fence). Ops with a namespace
	// are gated here; namespace-less ops (DescribeAlarms/DeleteAlarms) gate per-alarm inside the op.
	if ns != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "cloudwatch:"+op, "Namespace", ns, r); denied {
			h.auditDeny(ctx, op, ns, reason)
			writeCWError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cwXMLNamespace)
			return
		}
	}

	switch op {
	case "PutMetricData":
		h.putMetricData(ctx, w, r, requestID, ns)
	case "GetMetricStatistics":
		h.getMetricStatistics(ctx, w, r, requestID, ns)
	case "GetMetricData":
		h.getMetricData(ctx, w, r, requestID, claims)
	case "ListMetrics":
		h.listMetrics(ctx, w, r, requestID, ns)
	case "PutMetricAlarm":
		h.putMetricAlarm(ctx, w, r, requestID, ns)
	case "DescribeAlarms":
		h.describeAlarms(ctx, w, r, requestID, claims)
	case "DeleteAlarms":
		h.deleteAlarms(ctx, w, r, requestID, claims)
	case "SetAlarmState":
		h.setAlarmState(ctx, w, r, requestID, claims)
	default:
		writeCWError(w, http.StatusBadRequest, "InvalidAction", requestID, "unimplemented op "+op, cwXMLNamespace)
	}
}

// --- PutMetricData ---

func (h *cwHandler) putMetricData(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, ns string) {
	if ns == "" {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "PutMetricData requires a Namespace.", cwXMLNamespace)
		return
	}
	data := parseMetricData(r.PostForm)
	if len(data) == 0 {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "PutMetricData requires MetricData.", cwXMLNamespace)
		return
	}
	for _, d := range data {
		if d.MetricName == "" {
			writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "each MetricData member requires a MetricName.", cwXMLNamespace)
			return
		}
		if err := h.store.putDatum(ctx, ns, d.MetricName, dimsHash(d.Dims), d.Dims, d.TsMs, d.Value, d.Sum, d.Min, d.Max, d.Count, d.Unit, d.Resolution); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "PutMetricData", ns, "metrics", len(data))
	writeCWJSON(w, requestID, map[string]any{})
}

// --- GetMetricStatistics ---

func (h *cwHandler) getMetricStatistics(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, ns string) {
	name := r.PostFormValue("MetricName")
	if ns == "" || name == "" {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "GetMetricStatistics requires Namespace and MetricName.", cwXMLNamespace)
		return
	}
	dims := parseDims(r.PostForm, "Dimensions")
	period := atoiDefault(r.PostFormValue("Period"), 60)
	start := parseAWSTime(r.PostFormValue("StartTime"), time.Now().Add(-1*time.Hour))
	end := parseAWSTime(r.PostFormValue("EndTime"), time.Now())
	stats := memberLeaves(r.PostForm, "Statistics")
	exts := memberLeaves(r.PostForm, "ExtendedStatistics")
	if len(stats) == 0 && len(exts) == 0 {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "GetMetricStatistics requires Statistics or ExtendedStatistics.", cwXMLNamespace)
		return
	}
	unit := r.PostFormValue("Unit")

	dps, err := h.store.queryDatapoints(ctx, ns, name, dimsHash(dims), start.UnixMilli(), end.UnixMilli())
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	buckets := bucketize(dps, period, start.UnixMilli(), end.UnixMilli())

	datapoints := make([]any, 0, len(buckets))
	for _, bk := range buckets {
		dp := map[string]any{"Timestamp": epochSeconds(bk.StartMs)}
		for _, s := range stats {
			if v, ok := statOf(bk, s); ok {
				dp[s] = v
			}
		}
		if len(exts) > 0 {
			ext := map[string]any{}
			for _, e := range exts {
				if v, ok := extStatOf(bk, e); ok {
					ext[e] = v
				}
			}
			dp["ExtendedStatistics"] = ext
		}
		if unit != "" {
			dp["Unit"] = unit
		}
		datapoints = append(datapoints, dp)
	}
	h.audit(ctx, "GetMetricStatistics", ns, "metric", name, "datapoints", len(buckets))
	writeCWJSON(w, requestID, map[string]any{"Label": name, "Datapoints": datapoints})
}

// --- GetMetricData (MetricStat queries; metric-math Expression refused) ---

func (h *cwHandler) getMetricData(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	start := parseAWSTime(r.PostFormValue("StartTime"), time.Now().Add(-1*time.Hour))
	end := parseAWSTime(r.PostFormValue("EndTime"), time.Now())
	idxs := memberIndices(r.PostForm, "MetricDataQueries")
	if len(idxs) == 0 {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "GetMetricData requires MetricDataQueries.", cwXMLNamespace)
		return
	}
	type result struct {
		id     string
		label  string
		ts     []int64
		values []float64
	}
	var results []result
	for _, i := range idxs {
		p := "MetricDataQueries.member." + strconv.Itoa(i)
		id := r.PostFormValue(p + ".Id")
		if expr := r.PostFormValue(p + ".Expression"); expr != "" {
			writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
				"metric math expressions are not supported by the open-infra shim; use a MetricStat query. (A dashboard computing wrong math is worse than one that errors.)", cwXMLNamespace)
			return
		}
		ns := r.PostFormValue(p + ".MetricStat.Metric.Namespace")
		name := r.PostFormValue(p + ".MetricStat.Metric.MetricName")
		dims := parseDims(r.PostForm, p+".MetricStat.Metric.Dimensions")
		period := atoiDefault(r.PostFormValue(p+".MetricStat.Period"), 60)
		stat := r.PostFormValue(p + ".MetricStat.Stat")
		if ns == "" || name == "" || stat == "" {
			writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "each MetricStat query requires Metric.Namespace, Metric.MetricName and Stat.", cwXMLNamespace)
			return
		}
		// per-query cross-tenant fence
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "cloudwatch:GetMetricData", "Namespace", ns, r); denied {
			writeCWError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cwXMLNamespace)
			return
		}
		dps, err := h.store.queryDatapoints(ctx, ns, name, dimsHash(dims), start.UnixMilli(), end.UnixMilli())
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		buckets := bucketize(dps, period, start.UnixMilli(), end.UnixMilli())
		res := result{id: id, label: name}
		for _, bk := range buckets {
			if v, ok := statValue(bk, stat); ok {
				res.ts = append(res.ts, bk.StartMs)
				res.values = append(res.values, v)
			}
		}
		results = append(results, res)
	}
	out := make([]any, 0, len(results))
	for _, res := range results {
		ts := make([]any, 0, len(res.ts))
		for _, t := range res.ts {
			ts = append(ts, epochSeconds(t))
		}
		vals := make([]any, 0, len(res.values))
		for _, v := range res.values {
			vals = append(vals, v)
		}
		out = append(out, map[string]any{"Id": res.id, "Label": res.label, "StatusCode": "Complete", "Timestamps": ts, "Values": vals})
	}
	writeCWJSON(w, requestID, map[string]any{"MetricDataResults": out})
}

// --- ListMetrics ---

func (h *cwHandler) listMetrics(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, ns string) {
	name := r.PostFormValue("MetricName")
	metrics, err := h.store.listMetrics(ctx, ns, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]any, 0, len(metrics))
	for _, m := range metrics {
		items = append(items, map[string]any{"Namespace": m.Namespace, "MetricName": m.MetricName, "Dimensions": dimsJSON(m.Dims)})
	}
	writeCWJSON(w, requestID, map[string]any{"Metrics": items})
}

// --- PutMetricAlarm ---

func (h *cwHandler) putMetricAlarm(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, ns string) {
	name := r.PostFormValue("AlarmName")
	metric := r.PostFormValue("MetricName")
	if name == "" || ns == "" || metric == "" {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "PutMetricAlarm requires AlarmName, Namespace and MetricName.", cwXMLNamespace)
		return
	}
	op := r.PostFormValue("ComparisonOperator")
	if !validComparison(op) {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "ComparisonOperator must be one of GreaterThanThreshold, GreaterThanOrEqualToThreshold, LessThanThreshold, LessThanOrEqualToThreshold.", cwXMLNamespace)
		return
	}
	stat := r.PostFormValue("Statistic")
	ext := r.PostFormValue("ExtendedStatistic")
	if stat == "" && ext == "" {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "PutMetricAlarm requires Statistic or ExtendedStatistic.", cwXMLNamespace)
		return
	}
	if ext != "" {
		if _, ok := parsePercentile(ext); !ok {
			writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "ExtendedStatistic must be a percentile (pNN).", cwXMLNamespace)
			return
		}
	}
	thresholdStr := r.PostFormValue("Threshold")
	threshold, terr := strconv.ParseFloat(thresholdStr, 64)
	if terr != nil {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Threshold must be a number.", cwXMLNamespace)
		return
	}
	treat := r.PostFormValue("TreatMissingData")
	if treat == "" {
		treat = "missing"
	}
	switch treat {
	case "missing", "notBreaching", "breaching", "ignore":
	default:
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "TreatMissingData must be one of missing, notBreaching, breaching, ignore.", cwXMLNamespace)
		return
	}
	actions := memberLeaves(r.PostForm, "AlarmActions")
	for _, a := range actions {
		if !strings.HasPrefix(a, "arn:aws:sns:") {
			writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
				"the open-infra shim fires only SNS AlarmActions (arn:aws:sns:...); other action targets are refused rather than accepted as an action that never fires. Offending action: "+a, cwXMLNamespace)
			return
		}
	}
	alarm := cwAlarm{
		Name: name, Namespace: ns, MetricName: metric, Dims: parseDims(r.PostForm, "Dimensions"),
		Statistic: stat, ExtendedStatistic: ext,
		Period:            atoiDefault(r.PostFormValue("Period"), 60),
		EvaluationPeriods: atoiDefault(r.PostFormValue("EvaluationPeriods"), 1),
		DatapointsToAlarm: atoiDefault(r.PostFormValue("DatapointsToAlarm"), 0),
		Threshold:         threshold, ComparisonOperator: op, TreatMissingData: treat, AlarmActions: actions,
		Principal: principalFromCtx(ctx),
	}
	alarm.DimsHash = dimsHash(alarm.Dims)
	if alarm.DatapointsToAlarm == 0 {
		alarm.DatapointsToAlarm = alarm.EvaluationPeriods
	}
	if err := h.store.putAlarm(ctx, alarm); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutMetricAlarm", ns, "alarm", name)
	writeCWJSON(w, requestID, map[string]any{})
}

// --- DescribeAlarms (per-alarm namespace fence) ---

func (h *cwHandler) describeAlarms(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	names := memberLeaves(r.PostForm, "AlarmNames")
	stateFilter := r.PostFormValue("StateValue")
	alarms, err := h.store.listAlarms(ctx, names, stateFilter)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]any, 0, len(alarms))
	for _, a := range alarms {
		// cross-tenant fence: only alarms whose namespace the principal may read
		if denied, _ := deniedByDataPlane(ctx, h.authz, claims, "cloudwatch:DescribeAlarms", "Namespace", a.Namespace, r); denied {
			continue
		}
		items = append(items, h.alarmJSON(a))
	}
	writeCWJSON(w, requestID, map[string]any{"MetricAlarms": items})
}

func (h *cwHandler) alarmJSON(a cwAlarm) map[string]any {
	m := map[string]any{
		"AlarmName":          a.Name,
		"Namespace":          a.Namespace,
		"MetricName":         a.MetricName,
		"Period":             a.Period,
		"EvaluationPeriods":  a.EvaluationPeriods,
		"DatapointsToAlarm":  a.DatapointsToAlarm,
		"Threshold":          a.Threshold,
		"ComparisonOperator": a.ComparisonOperator,
		"TreatMissingData":   a.TreatMissingData,
		"StateValue":         a.State,
		"StateReason":        a.StateReason,
		"Dimensions":         dimsJSON(a.Dims),
		"AlarmActions":       a.AlarmActions,
	}
	if a.Statistic != "" {
		m["Statistic"] = a.Statistic
	}
	if a.ExtendedStatistic != "" {
		m["ExtendedStatistic"] = a.ExtendedStatistic
	}
	return m
}

// --- DeleteAlarms ---

func (h *cwHandler) deleteAlarms(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	names := memberLeaves(r.PostForm, "AlarmNames")
	if len(names) == 0 {
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "DeleteAlarms requires AlarmNames.", cwXMLNamespace)
		return
	}
	// per-alarm namespace fence
	for _, n := range names {
		a, ok, err := h.store.getAlarm(ctx, n)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if ok {
			if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "cloudwatch:DeleteAlarms", "Namespace", a.Namespace, r); denied {
				writeCWError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cwXMLNamespace)
				return
			}
		}
	}
	if _, err := h.store.deleteAlarms(ctx, names); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteAlarms", "", "count", len(names))
	writeCWJSON(w, requestID, map[string]any{})
}

// --- SetAlarmState (fires actions immediately, as AWS does) ---

func (h *cwHandler) setAlarmState(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name := r.PostFormValue("AlarmName")
	state := r.PostFormValue("StateValue")
	reason := r.PostFormValue("StateReason")
	switch state {
	case "OK", "ALARM", "INSUFFICIENT_DATA":
	default:
		writeCWError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "StateValue must be OK, ALARM or INSUFFICIENT_DATA.", cwXMLNamespace)
		return
	}
	a, ok, err := h.store.getAlarm(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCWError(w, http.StatusNotFound, "ResourceNotFound", requestID, "alarm "+name+" not found", cwXMLNamespace)
		return
	}
	if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "cloudwatch:SetAlarmState", "Namespace", a.Namespace, r); denied {
		writeCWError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cwXMLNamespace)
		return
	}
	prev := a.State
	if _, err := h.store.setAlarmStateDB(ctx, name, state, reason); err != nil {
		h.internal(w, requestID, err)
		return
	}
	if state == "ALARM" && prev != "ALARM" {
		a.State = state
		a.StateReason = reason
		h.fireActions(ctx, a)
	}
	h.audit(ctx, "SetAlarmState", a.Namespace, "alarm", name, "state", state)
	writeCWJSON(w, requestID, map[string]any{})
}

// --- the in-process alarm evaluator ---

// startEvaluator periodically evaluates every alarm and transitions its state, firing SNS actions on entry
// to ALARM. No-op if the data layer is unset.
func (h *cwHandler) startEvaluator(ctx context.Context, interval time.Duration) {
	if h.store == nil {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.evaluateAll(ctx)
			}
		}
	}()
}

func (h *cwHandler) evaluateAll(ctx context.Context) {
	alarms, err := h.store.allAlarms(ctx)
	if err != nil {
		h.logger.Warn("cloudwatch evaluator: list alarms failed", "error", err.Error())
		return
	}
	for _, a := range alarms {
		newState, reason := h.evaluateAlarm(ctx, a)
		if newState == a.State {
			continue
		}
		if _, err := h.store.setAlarmStateDB(ctx, a.Name, newState, reason); err != nil {
			h.logger.Warn("cloudwatch evaluator: set state failed", "alarm", a.Name, "error", err.Error())
			continue
		}
		h.logger.InfoContext(ctx, "cloudwatch alarm transition", "alarm", a.Name, "from", a.State, "to", newState, "reason", reason)
		if newState == "ALARM" {
			a.State = newState
			a.StateReason = reason
			h.fireActions(ctx, a)
		}
	}
}

// evaluateAlarm computes the alarm's next state from the last EvaluationPeriods periods.
func (h *cwHandler) evaluateAlarm(ctx context.Context, a cwAlarm) (string, string) {
	stat := a.Statistic
	if stat == "" {
		stat = a.ExtendedStatistic
	}
	periodMs := int64(a.Period) * 1000
	if periodMs <= 0 {
		periodMs = 60000
	}
	now := time.Now().UnixMilli()
	startMs := now - int64(a.EvaluationPeriods)*periodMs
	dps, err := h.store.queryDatapoints(ctx, a.Namespace, a.MetricName, a.DimsHash, startMs, now)
	if err != nil {
		return a.State, a.State // keep last state on a transient error
	}
	buckets := bucketize(dps, a.Period, startMs, now)
	valByStart := map[int64]float64{}
	for _, bk := range buckets {
		if v, ok := statValue(bk, stat); ok {
			valByStart[bk.StartMs] = v
		}
	}
	breaching, considered, missing := 0, 0, 0
	for i := 0; i < a.EvaluationPeriods; i++ {
		slot := startMs + int64(i)*periodMs
		if v, present := valByStart[slot]; present {
			considered++
			if breaches(v, a.ComparisonOperator, a.Threshold) {
				breaching++
			}
			continue
		}
		missing++
		switch a.TreatMissingData {
		case "breaching":
			considered++
			breaching++
		case "notBreaching":
			considered++
		case "ignore", "missing":
			// not counted
		}
	}
	if considered == 0 {
		if missing > 0 && a.TreatMissingData == "ignore" {
			return a.State, "retaining state; all datapoints missing and TreatMissingData=ignore"
		}
		return "INSUFFICIENT_DATA", "no datapoints in the evaluation window"
	}
	if breaching >= a.DatapointsToAlarm {
		return "ALARM", "threshold breached in " + strconv.Itoa(breaching) + " of " + strconv.Itoa(a.EvaluationPeriods) + " datapoints"
	}
	return "OK", "within threshold"
}

// fireActions publishes the alarm-state notification to each SNS AlarmAction.
func (h *cwHandler) fireActions(ctx context.Context, a cwAlarm) {
	if h.sns == nil {
		return
	}
	notif := map[string]any{
		"AlarmName":       a.Name,
		"AWSAccountId":    h.account,
		"NewStateValue":   a.State,
		"NewStateReason":  a.StateReason,
		"StateChangeTime": time.Now().UTC().Format(time.RFC3339),
		"Region":          h.region,
		"Trigger": map[string]any{
			"MetricName":         a.MetricName,
			"Namespace":          a.Namespace,
			"Statistic":          a.Statistic,
			"Period":             a.Period,
			"Threshold":          a.Threshold,
			"ComparisonOperator": a.ComparisonOperator,
		},
	}
	msg, _ := json.Marshal(notif)
	for _, action := range a.AlarmActions {
		if !strings.HasPrefix(action, "arn:aws:sns:") {
			continue
		}
		if _, err := h.sns.publishMessage(ctx, action, "ALARM: \""+a.Name+"\"", string(msg)); err != nil {
			h.logger.Warn("cloudwatch: alarm action publish failed", "alarm", a.Name, "action", action, "error", err.Error())
		}
	}
}

// --- helpers ---

// CloudWatch uses the JSON "query mode" (awsQueryCompatible) protocol: JSON request AND JSON RESPONSE
// (application/x-amz-json-1.0), the same family as this shim's SQS/KMS doorways — NOT the XML query
// response the legacy query protocol used.

func writeCWError(w http.ResponseWriter, status int, code, requestID, message, _ string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	// query-compatible error code header, for a client running in query mode.
	w.Header().Set("x-amzn-query-error", code+";Sender")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeCWJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *cwHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("cloudwatch backend error", "error", err.Error())
	writeCWError(w, http.StatusInternalServerError, "InternalFailure", requestID, "An error occurred on the server side.", cwXMLNamespace)
}

// epochSeconds renders a ms timestamp as a JSON-protocol unix-seconds number.
func epochSeconds(ms int64) float64 { return float64(ms) / 1000.0 }

// dimsJSON renders a dimension map as the JSON [{Name,Value}] list, name-sorted for stability.
func dimsJSON(dims map[string]string) []any {
	names := make([]string, 0, len(dims))
	for k := range dims {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]any, 0, len(names))
	for _, k := range names {
		out = append(out, map[string]any{"Name": k, "Value": dims[k]})
	}
	return out
}

func (h *cwHandler) audit(ctx context.Context, op, ns string, kv ...any) {
	args := []any{"service", "cloudwatch", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if ns != "" {
		args = append(args, "namespace", ns)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "cloudwatch audit", args...)
}

func (h *cwHandler) auditDeny(ctx context.Context, op, ns, reason string) {
	args := []any{"service", "cloudwatch", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if ns != "" {
		args = append(args, "namespace", ns)
	}
	h.logger.InfoContext(ctx, "cloudwatch audit", args...)
}

// --- query-protocol form parsing ---

type metricDatum struct {
	MetricName string
	Dims       map[string]string
	TsMs       int64
	Value      float64
	Sum        float64
	Min        float64
	Max        float64
	Count      float64
	Unit       string
	Resolution int
}

// parseMetricData extracts the MetricData.member.N.* list from the form.
func parseMetricData(form url.Values) []metricDatum {
	var out []metricDatum
	for _, i := range memberIndices(form, "MetricData") {
		p := "MetricData.member." + strconv.Itoa(i)
		d := metricDatum{
			MetricName: form.Get(p + ".MetricName"),
			Dims:       parseDims(form, p+".Dimensions"),
			Unit:       form.Get(p + ".Unit"),
			Resolution: atoiDefault(form.Get(p+".StorageResolution"), 60),
		}
		d.TsMs = parseAWSTime(form.Get(p+".Timestamp"), time.Now()).UnixMilli()
		// StatisticValues take precedence when present; else the single Value.
		if sv := form.Get(p + ".StatisticValues.Sum"); sv != "" {
			d.Sum = parseFloatDefault(form.Get(p+".StatisticValues.Sum"), 0)
			d.Min = parseFloatDefault(form.Get(p+".StatisticValues.Minimum"), 0)
			d.Max = parseFloatDefault(form.Get(p+".StatisticValues.Maximum"), 0)
			d.Count = parseFloatDefault(form.Get(p+".StatisticValues.SampleCount"), 1)
			if d.Count > 0 {
				d.Value = d.Sum / d.Count
			}
		} else {
			v := parseFloatDefault(form.Get(p+".Value"), 0)
			d.Value, d.Sum, d.Min, d.Max, d.Count = v, v, v, v, 1
		}
		out = append(out, d)
	}
	return out
}

// parseDims extracts a Dimensions.member.N.{Name,Value} list under the given prefix.
func parseDims(form url.Values, prefix string) map[string]string {
	dims := map[string]string{}
	for _, i := range memberIndices(form, prefix) {
		p := prefix + ".member." + strconv.Itoa(i)
		name := form.Get(p + ".Name")
		val := form.Get(p + ".Value")
		if name != "" {
			dims[name] = val
		}
	}
	return dims
}

// memberIndices returns the sorted set of N present under "<prefix>.member.N[.*]".
func memberIndices(form url.Values, prefix string) []int {
	p := prefix + ".member."
	seen := map[int]bool{}
	for k := range form {
		if !strings.HasPrefix(k, p) {
			continue
		}
		rest := k[len(p):]
		numStr := rest
		if i := strings.IndexByte(rest, '.'); i >= 0 {
			numStr = rest[:i]
		}
		if n, err := strconv.Atoi(numStr); err == nil {
			seen[n] = true
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// memberLeaves returns the values of a leaf list "<prefix>.member.N" (e.g. Statistics, AlarmActions).
func memberLeaves(form url.Values, prefix string) []string {
	var out []string
	for _, i := range memberIndices(form, prefix) {
		if v := form.Get(prefix + ".member." + strconv.Itoa(i)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseAWSTime(s string, def time.Time) time.Time {
	if s == "" {
		return def
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02T15:04:05.000Z", s); err == nil {
		return t
	}
	if epoch, err := strconv.ParseFloat(s, 64); err == nil {
		// Accept epoch seconds (the common query/JSON serialization) or milliseconds, by magnitude:
		// anything >= 1e12 is already milliseconds.
		if epoch >= 1e12 {
			return time.UnixMilli(int64(epoch))
		}
		return time.UnixMilli(int64(epoch * 1000))
	}
	return def
}

// flattenQuery serializes a decoded JSON value into AWS query form params: lists become <prefix>.member.N,
// structs become <prefix>.<Field>, scalars become <prefix>. This is exactly the AWS query wire shape the
// member-index parsers consume, so a JSON query-mode request and a legacy form request converge.
func flattenQuery(prefix string, v any, out url.Values) {
	switch t := v.(type) {
	case string:
		out.Set(prefix, t)
	case bool:
		out.Set(prefix, strconv.FormatBool(t))
	case float64:
		out.Set(prefix, strconv.FormatFloat(t, 'f', -1, 64))
	case []any:
		for i, e := range t {
			flattenQuery(prefix+".member."+strconv.Itoa(i+1), e, out)
		}
	case map[string]any:
		for k, e := range t {
			flattenQuery(prefix+"."+k, e, out)
		}
	}
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func parseFloatDefault(s string, def float64) float64 {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return def
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
