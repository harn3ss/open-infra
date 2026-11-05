// CloudWatch Logs: the log groups AWS creates for a service's own logs, read from the platform's log
// store (Loki).
//
// On AWS a Lambda function writes to /aws/lambda/<function>, a SageMaker training or processing job to
// /aws/sagemaker/TrainingJobs or /aws/sagemaker/ProcessingJobs, and an ECS task (awslogs) to its group, so
// `aws logs tail /aws/lambda/<fn>` shows what the function printed. Here those workloads are pods whose
// output the platform already collects in Loki. These groups are views of it:
//
//   - /aws/lambda/<function>        a kind: Function's user container, one stream per execution environment
//     (pod), named as Lambda names them: YYYY/MM/DD/[$LATEST]<id>
//   - /aws/sagemaker/TrainingJobs   every kind: TrainingJob's pods, stream <job>/algo-1-<start epoch>
//   - /aws/sagemaker/ProcessingJobs every kind: ProcessingJob's pods, stream <job>/algo-1-<start epoch>
//   - /ecs/<application>            a kind: Application's pods, stream ecs/<container>/<task id>
//
// They exist while the resource does, in the namespaces the Lambda API serves (the functions namespace and
// the stack namespace) of the caller's account. They are read-only: the workload writes them, retention is
// the log store's (retentionInDays says so), and DescribeLogGroups, DescribeLogStreams, GetLogEvents and
// FilterLogEvents answer for them as for any group. A group an SDK creates (CreateLogGroup/PutLogEvents)
// is the front door's own store (cloudwatchlogs.go), as before.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	cwlLambdaPrefix     = "/aws/lambda/"
	cwlTrainingGroup    = "/aws/sagemaker/TrainingJobs"
	cwlProcessingGroup  = "/aws/sagemaker/ProcessingJobs"
	cwlECSPrefix        = "/ecs/"
	cwlDerivedPageLimit = 10000 // GetLogEvents / FilterLogEvents: AWS's maximum page
)

var (
	trainingJobGVR   = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "trainingjobs"}
	processingJobGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "processingjobs"}
	applicationGVR   = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "applications"}
)

// derivedGroup is one AWS-named log group over the log store.
type derivedGroup struct {
	Name    string
	Kind    string // lambda | training | processing | ecs
	Created time.Time
	// sources are the log store selectors whose lines are the group's events, each with how a pod's stream
	// is named.
	sources []derivedSource
}

type derivedSource struct {
	selector string // a LogQL stream selector
	job      string // training/processing: the job a stream belongs to
}

// derivedStream is one stream: a pod (an ECS task's container).
type derivedStream struct {
	Name        string
	pod, ns     string
	sel         string // the stream's own lines
	First, Last int64  // event timestamps, ms
}

// streamSelector is the log store selector of one stream: a pod's lines, of the user container for a
// function (its queue-proxy sidecar is the platform's, not the function's), of one container for an ECS task.
func streamSelector(g derivedGroup, labels map[string]string) string {
	ns, pod := labels["namespace"], labels["pod"]
	switch g.Kind {
	case "lambda":
		return fmt.Sprintf(`{namespace=%q,pod=%q,container="user-container"}`, ns, pod)
	case "ecs":
		return fmt.Sprintf(`{namespace=%q,pod=%q,container=%q}`, ns, pod, labels["container"])
	}
	return fmt.Sprintf(`{namespace=%q,pod=%q}`, ns, pod)
}

// lokiEntry is one log line from the store.
type lokiEntry struct {
	TsNs   int64
	Line   string
	Labels map[string]string
}

// cwlDerived reads the derived groups. A nil *cwlDerived serves none.
type cwlDerived struct {
	loki      *lokiClient
	dyn       dynamic.Interface
	cs        kubernetes.Interface
	fns       *fnLocator
	dir       *accounts.Directory
	retention int // days the log store keeps lines (Loki's retention_period)
	now       func() time.Time

	mu    sync.Mutex
	first map[string]int64 // a stream's selector -> its earliest line (ns): its name and creation time
}

func newCWLDerived(lokiURL string, dyn dynamic.Interface, cs kubernetes.Interface, fns *fnLocator, management string, retentionDays int) *cwlDerived {
	if lokiURL == "" || dyn == nil || fns == nil {
		return nil
	}
	if retentionDays <= 0 {
		retentionDays = 7
	}
	return &cwlDerived{
		loki: &lokiClient{base: strings.TrimRight(lokiURL, "/"), http: &http.Client{Timeout: 20 * time.Second}},
		dyn:  dyn, cs: cs, fns: fns, dir: accounts.NewDirectory(management), retention: retentionDays,
		now: time.Now, first: map[string]int64{},
	}
}

// isDerivedName reports whether a group name is one of the derived forms (whether or not it exists).
func isDerivedName(name string) bool {
	return strings.HasPrefix(name, cwlLambdaPrefix) || name == cwlTrainingGroup || name == cwlProcessingGroup ||
		strings.HasPrefix(name, cwlECSPrefix)
}

// namespaces are the namespaces whose resources the caller's account owns, of those the front door serves.
func (d *cwlDerived) namespaces(ctx context.Context, claims iam.Claims) []string {
	acct := claims.Account
	if acct == "" {
		acct = d.dir.Management()
	}
	var out []string
	for _, ns := range d.fns.namespaces {
		if d.cs != nil {
			if obj, err := d.cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
				d.dir.Observe(obj)
			}
		}
		if d.dir.AccountOf(ns) == acct {
			out = append(out, ns)
		}
	}
	return out
}

// groups lists the derived groups of the caller's account whose names start with prefix.
func (d *cwlDerived) groups(ctx context.Context, claims iam.Claims, prefix string) []derivedGroup {
	var out []derivedGroup
	add := func(g derivedGroup) {
		if strings.HasPrefix(g.Name, prefix) {
			out = append(out, g)
		}
	}
	jobs := map[string]*derivedGroup{}
	for _, ns := range d.namespaces(ctx, claims) {
		for _, fn := range d.list(ctx, functionClaimGVR, ns) {
			add(lambdaGroup(ns, fn.GetName(), fn.GetCreationTimestamp().Time))
		}
		for _, app := range d.list(ctx, applicationGVR, ns) {
			add(ecsGroup(ns, app.GetName(), app.GetCreationTimestamp().Time))
		}
		for kind, gvr := range map[string]schema.GroupVersionResource{"training": trainingJobGVR, "processing": processingJobGVR} {
			for _, job := range d.list(ctx, gvr, ns) {
				g := jobs[kind]
				if g == nil {
					name := cwlTrainingGroup
					if kind == "processing" {
						name = cwlProcessingGroup
					}
					g = &derivedGroup{Name: name, Kind: kind, Created: job.GetCreationTimestamp().Time}
					jobs[kind] = g
				}
				if t := job.GetCreationTimestamp().Time; t.Before(g.Created) {
					g.Created = t
				}
				g.sources = append(g.sources, jobSource(kind, ns, job.GetName()))
			}
		}
	}
	for _, kind := range []string{"training", "processing"} {
		if g := jobs[kind]; g != nil {
			add(*g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return dedupGroups(out)
}

// resolve is the derived group of that name in the caller's account.
func (d *cwlDerived) resolve(ctx context.Context, claims iam.Claims, name string) (derivedGroup, bool) {
	if d == nil || !isDerivedName(name) {
		return derivedGroup{}, false
	}
	for _, g := range d.groups(ctx, claims, name) {
		if g.Name == name {
			return g, true
		}
	}
	return derivedGroup{}, false
}

// dedupGroups merges groups of one name (a function of that name in two namespaces of the account).
func dedupGroups(gs []derivedGroup) []derivedGroup {
	var out []derivedGroup
	for _, g := range gs {
		if n := len(out); n > 0 && out[n-1].Name == g.Name {
			out[n-1].sources = append(out[n-1].sources, g.sources...)
			if g.Created.Before(out[n-1].Created) {
				out[n-1].Created = g.Created
			}
			continue
		}
		out = append(out, g)
	}
	return out
}

func (d *cwlDerived) list(ctx context.Context, gvr schema.GroupVersionResource, ns string) []unstructured.Unstructured {
	l, err := d.dyn.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil // a kind this shim may not read here: no groups of it
	}
	return l.Items
}

// The selectors: a Function's revisions are its Knative Service's (<name>-NNNNN) user container; a job's pods
// are <job>-train-/-proc- pods (app = its name); an Application's are its Deployment's.
func lambdaGroup(ns, fn string, created time.Time) derivedGroup {
	return derivedGroup{Name: cwlLambdaPrefix + fn, Kind: "lambda", Created: created, sources: []derivedSource{{
		selector: fmt.Sprintf(`{namespace=%q,container="user-container",app=~%q}`, ns, regexp.QuoteMeta(fn)+`-[0-9]+`)}}}
}

func ecsGroup(ns, app string, created time.Time) derivedGroup {
	return derivedGroup{Name: cwlECSPrefix + app, Kind: "ecs", Created: created, sources: []derivedSource{{
		selector: fmt.Sprintf(`{namespace=%q,app=%q,pod=~%q}`, ns, app, regexp.QuoteMeta(app)+`-[a-z0-9]+-[a-z0-9]+`)}}}
}

func jobSource(kind, ns, job string) derivedSource {
	suffix := "-train"
	if kind == "processing" {
		suffix = "-proc"
	}
	return derivedSource{job: job, selector: fmt.Sprintf(`{namespace=%q,app=%q,pod=~%q}`, ns, job, regexp.QuoteMeta(job+suffix)+`-[a-z0-9]+`)}
}

// window is the time range the log store can hold.
func (d *cwlDerived) window() (int64, int64) {
	end := d.now()
	return end.Add(-time.Duration(d.retention) * 24 * time.Hour).UnixNano(), end.UnixNano()
}

// streams are a group's streams: one per pod the log store has lines from.
func (d *cwlDerived) streams(ctx context.Context, g derivedGroup) ([]derivedStream, error) {
	start, end := d.window()
	var out []derivedStream
	seen := map[string]bool{}
	for _, src := range g.sources {
		series, err := d.loki.series(ctx, src.selector, start, end)
		if err != nil {
			return nil, err
		}
		for _, s := range series {
			ns, pod := s["namespace"], s["pod"]
			sel := streamSelector(g, s)
			if pod == "" || seen[sel] {
				continue
			}
			seen[sel] = true
			first, last, err := d.bounds(ctx, sel, start, end)
			if err != nil {
				return nil, err
			}
			if first == 0 {
				continue
			}
			out = append(out, derivedStream{Name: streamName(g, src, s, first), ns: ns, pod: pod, sel: sel, First: first / 1e6, Last: last / 1e6})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// bounds are a stream's earliest and latest line (ns) in the window.
func (d *cwlDerived) bounds(ctx context.Context, sel string, start, end int64) (int64, int64, error) {
	first := d.firstOf(sel)
	if first == 0 {
		es, err := d.loki.queryRange(ctx, sel, start, end, 1, true)
		if err != nil || len(es) == 0 {
			return 0, 0, err
		}
		first = es[0].TsNs
		d.mu.Lock()
		d.first[sel] = first
		d.mu.Unlock()
	}
	es, err := d.loki.queryRange(ctx, sel, start, end, 1, false)
	if err != nil || len(es) == 0 {
		return first, first, err
	}
	return first, es[0].TsNs, nil
}

func (d *cwlDerived) firstOf(sel string) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.first[sel]
}

// streamName names a pod's stream as the service names it.
func streamName(g derivedGroup, src derivedSource, labels map[string]string, firstNs int64) string {
	id := podID(labels["namespace"], labels["pod"])
	switch g.Kind {
	case "lambda":
		return time.Unix(0, firstNs).UTC().Format("2006/01/02") + "/[$LATEST]" + id
	case "training", "processing":
		return src.job + "/algo-1-" + strconv.FormatInt(firstNs/1e9, 10)
	default: // ecs (awslogs): <prefix>/<container>/<task id>
		c := labels["container"]
		if c == "" {
			c = "app"
		}
		return "ecs/" + c + "/" + id
	}
}

// podID is a pod's stable 32-hex id (a Lambda execution environment's / an ECS task's).
func podID(ns, pod string) string {
	sum := sha256.Sum256([]byte(ns + "/" + pod))
	return hex.EncodeToString(sum[:16])
}

// eventID is an event's stable id, numeric as AWS's are (the CLI's `logs tail --follow` de-duplicates on it).
func eventID(ns, pod string, tsNs int64, line string) string {
	sum := sha256.Sum256([]byte(ns + "/" + pod + "/" + strconv.FormatInt(tsNs, 10) + "/" + line))
	return new(big.Int).SetBytes(sum[:20]).String()
}

// selectorFor narrows a group's sources to the streams asked for (nil = all of them).
func (d *cwlDerived) selectorsFor(ctx context.Context, g derivedGroup, streamNames []string, prefix string) ([]string, map[string]string, error) {
	if len(streamNames) == 0 && prefix == "" {
		sels := make([]string, 0, len(g.sources))
		for _, s := range g.sources {
			sels = append(sels, s.selector)
		}
		return sels, nil, nil
	}
	sts, err := d.streams(ctx, g)
	if err != nil {
		return nil, nil, err
	}
	want := map[string]bool{}
	for _, n := range streamNames {
		want[n] = true
	}
	var sels []string
	names := map[string]string{}
	for _, s := range sts {
		if (len(want) > 0 && !want[s.Name]) || (prefix != "" && !strings.HasPrefix(s.Name, prefix)) {
			continue
		}
		sels = append(sels, s.sel)
		names[s.sel] = s.Name
	}
	return sels, names, nil
}

// --- the operations, for a derived group ---

func (h *cwlHandler) derivedDescribeStreams(ctx context.Context, w http.ResponseWriter, requestID string, g derivedGroup, body map[string]any) {
	sts, err := h.derived.streams(ctx, g)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	prefix := strFromBody(body, "logStreamNamePrefix")
	orderBy := strFromBody(body, "orderBy")
	if prefix != "" && orderBy == "LastEventTime" {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"Cannot order by LastEventTime with a logStreamNamePrefix.")
		return
	}
	var keep []derivedStream
	for _, s := range sts {
		if strings.HasPrefix(s.Name, prefix) {
			keep = append(keep, s)
		}
	}
	if orderBy == "LastEventTime" {
		sort.SliceStable(keep, func(i, j int) bool { return keep[i].Last < keep[j].Last })
	}
	if desc, _ := body["descending"].(bool); desc {
		for i, j := 0, len(keep)-1; i < j; i, j = i+1, j-1 {
			keep[i], keep[j] = keep[j], keep[i]
		}
	}
	limit := toInt(body["limit"])
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	off := 0
	if tok := strFromBody(body, "nextToken"); tok != "" {
		off, _ = strconv.Atoi(strings.TrimPrefix(tok, "o/"))
	}
	if off > len(keep) {
		off = len(keep)
	}
	page := keep[off:]
	resp := map[string]any{}
	if len(page) > limit {
		page = page[:limit]
		resp["nextToken"] = "o/" + strconv.Itoa(off+limit)
	}
	out := make([]any, 0, len(page))
	for _, s := range page {
		out = append(out, map[string]any{
			"logStreamName": s.Name, "creationTime": s.First, "firstEventTimestamp": s.First,
			"lastEventTimestamp": s.Last, "lastIngestionTime": s.Last, "storedBytes": 0,
			"arn": h.streamARNIn(h.accountOf(ctx), g.Name, s.Name),
		})
	}
	resp["logStreams"] = out
	writeCWLJSON(w, requestID, resp)
}

func (h *cwlHandler) derivedGetEvents(ctx context.Context, w http.ResponseWriter, requestID string, g derivedGroup, body map[string]any) {
	stream := strFromBody(body, "logStreamName")
	sels, names, err := h.derived.selectorsFor(ctx, g, []string{stream}, "")
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if len(names) == 0 {
		writeCWLError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The specified log stream does not exist.")
		return
	}
	start, end := h.derived.window()
	if t := toInt64(body["startTime"]); t > 0 {
		start = t * 1e6
	}
	if t := toInt64(body["endTime"]); t > 0 {
		end = t * 1e6
	}
	limit := toInt(body["limit"])
	if limit <= 0 || limit > cwlDerivedPageLimit {
		limit = cwlDerivedPageLimit
	}
	fromHead, _ := body["startFromHead"].(bool)
	token := strFromBody(body, "nextToken")
	forward := fromHead
	switch {
	case strings.HasPrefix(token, "f/"):
		forward = true
		if t, err := strconv.ParseInt(token[2:], 10, 64); err == nil {
			start = t + 1
		}
	case strings.HasPrefix(token, "b/"):
		forward = false
		if t, err := strconv.ParseInt(token[2:], 10, 64); err == nil {
			end = t
		}
	}
	events, err := h.derived.loki.queryAll(ctx, sels, start, end, limit, forward)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TsNs < events[j].TsNs })
	out := make([]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{"timestamp": e.TsNs / 1e6, "message": e.Line, "ingestionTime": e.TsNs / 1e6})
	}
	// At the end of the stream a token comes back unchanged, so a client reading forward stops.
	fwd, bwd := token, token
	if len(events) > 0 {
		fwd = "f/" + strconv.FormatInt(events[len(events)-1].TsNs, 10)
		bwd = "b/" + strconv.FormatInt(events[0].TsNs, 10)
	}
	if fwd == "" || !strings.HasPrefix(fwd, "f/") {
		fwd = "f/" + strconv.FormatInt(start-1, 10)
	}
	if bwd == "" || !strings.HasPrefix(bwd, "b/") {
		bwd = "b/" + strconv.FormatInt(end, 10)
	}
	writeCWLJSON(w, requestID, map[string]any{"events": out, "nextForwardToken": fwd, "nextBackwardToken": bwd})
}

// filterToken is a FilterLogEvents nextToken: where the next page starts (ns), and how many events at that
// exact instant were already returned.
type filterToken struct {
	T int64 `json:"t"`
	N int   `json:"n"`
}

func (h *cwlHandler) derivedFilterEvents(ctx context.Context, w http.ResponseWriter, requestID string, g derivedGroup, body map[string]any) {
	terms, err := parseFilterPattern(strFromBody(body, "filterPattern"))
	if err != nil {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, err.Error())
		return
	}
	var names []string
	for _, n := range sliceOf(body["logStreamNames"]) {
		if s, ok := n.(string); ok {
			names = append(names, s)
		}
	}
	prefix := strFromBody(body, "logStreamNamePrefix")
	if len(names) > 0 && prefix != "" {
		writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"logStreamNames and logStreamNamePrefix are mutually exclusive.")
		return
	}
	sels, streamNames, err := h.derived.selectorsFor(ctx, g, names, prefix)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	start, end := h.derived.window()
	if t := toInt64(body["startTime"]); t > 0 {
		start = t * 1e6
	}
	if t := toInt64(body["endTime"]); t > 0 {
		end = t*1e6 + 1e6 // endTime is inclusive, in ms
	}
	skip := 0
	if tok := strFromBody(body, "nextToken"); tok != "" {
		var ft filterToken
		if b, err := base64.RawURLEncoding.DecodeString(tok); err != nil || json.Unmarshal(b, &ft) != nil {
			writeCWLError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "The nextToken is invalid.")
			return
		}
		start, skip = ft.T, ft.N
	}
	limit := toInt(body["limit"])
	if limit <= 0 || limit > cwlDerivedPageLimit {
		limit = cwlDerivedPageLimit
	}
	var events []lokiEntry
	if len(sels) > 0 {
		filtered := make([]string, len(sels))
		for i, s := range sels {
			filtered[i] = s + lineFilters(terms)
		}
		events, err = h.derived.loki.queryAll(ctx, filtered, start, end, limit+skip+1, true)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TsNs < events[j].TsNs })
	// Drop what an earlier page returned at the instant it ended.
	if skip > 0 {
		n := 0
		for n < len(events) && n < skip && events[n].TsNs == start {
			n++
		}
		events = events[n:]
	}
	resp := map[string]any{}
	if len(events) > limit {
		events = events[:limit]
		last := events[len(events)-1].TsNs
		same := 0
		for i := len(events) - 1; i >= 0 && events[i].TsNs == last; i-- {
			same++
		}
		if last == start {
			same += skip
		}
		b, _ := json.Marshal(filterToken{T: last, N: same})
		resp["nextToken"] = base64.RawURLEncoding.EncodeToString(b)
	}
	out := make([]any, 0, len(events))
	for _, e := range events {
		ns, pod := e.Labels["namespace"], e.Labels["pod"]
		name := streamNames[streamSelector(g, e.Labels)]
		if name == "" {
			name = h.derived.nameFor(g, e.Labels)
		}
		out = append(out, map[string]any{
			"logStreamName": name, "timestamp": e.TsNs / 1e6, "message": e.Line,
			"ingestionTime": e.TsNs / 1e6, "eventId": eventID(ns, pod, e.TsNs, e.Line),
		})
	}
	resp["events"] = out
	resp["searchedLogStreams"] = []any{}
	writeCWLJSON(w, requestID, resp)
}

// nameFor names an event's stream from its labels (the stream's earliest line names a Lambda stream's date).
func (d *cwlDerived) nameFor(g derivedGroup, labels map[string]string) string {
	pod := labels["pod"]
	sel := streamSelector(g, labels)
	first := d.firstOf(sel)
	if first == 0 {
		start, end := d.window()
		if es, err := d.loki.queryRange(context.Background(), sel, start, end, 1, true); err == nil && len(es) > 0 {
			first = es[0].TsNs
			d.mu.Lock()
			d.first[sel] = first
			d.mu.Unlock()
		}
	}
	src := derivedSource{}
	for _, s := range g.sources {
		if s.job != "" && strings.HasPrefix(pod, s.job+"-") {
			src = s
		}
	}
	return streamName(g, src, labels, first)
}

// lineFilters is a filter pattern's terms as log store line filters: every term must appear (CloudWatch's
// term and quoted-phrase matching is a case-sensitive substring match).
func lineFilters(terms []string) string {
	var b strings.Builder
	for _, t := range terms {
		b.WriteString(" |= ")
		b.WriteString(strconv.Quote(t))
	}
	return b.String()
}

// accountOf is the caller's account, for ARNs (the management account until requests carry one).
func (h *cwlHandler) accountOf(ctx context.Context) string {
	if a, ok := ctx.Value(cwlAccountKey{}).(string); ok && a != "" {
		return a
	}
	return h.account
}

type cwlAccountKey struct{}

func (h *cwlHandler) streamARNIn(account, group, stream string) string {
	return "arn:aws:logs:" + h.region + ":" + account + ":log-group:" + group + ":log-stream:" + stream
}

func (h *cwlHandler) groupARNIn(account, name string) string {
	return "arn:aws:logs:" + h.region + ":" + account + ":log-group:" + name + ":*"
}

// --- the log store's HTTP API ---

type lokiClient struct {
	base string
	http *http.Client
}

// queryRange is the store's lines for a selector (a LogQL query), at most limit, oldest first when forward.
func (c *lokiClient) queryRange(ctx context.Context, query string, start, end int64, limit int, forward bool) ([]lokiEntry, error) {
	dir := "backward"
	if forward {
		dir = "forward"
	}
	q := url.Values{"query": {query}, "start": {strconv.FormatInt(start, 10)}, "end": {strconv.FormatInt(end, 10)},
		"limit": {strconv.Itoa(limit)}, "direction": {dir}}
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/loki/api/v1/query_range", q, &resp); err != nil {
		return nil, err
	}
	var out []lokiEntry
	for _, r := range resp.Data.Result {
		for _, v := range r.Values {
			ts, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			out = append(out, lokiEntry{TsNs: ts, Line: v[1], Labels: r.Stream})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if forward {
			return out[i].TsNs < out[j].TsNs
		}
		return out[i].TsNs > out[j].TsNs
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// queryAll runs queryRange for each selector and keeps the limit nearest the direction's start.
func (c *lokiClient) queryAll(ctx context.Context, queries []string, start, end int64, limit int, forward bool) ([]lokiEntry, error) {
	var all []lokiEntry
	for _, q := range queries {
		es, err := c.queryRange(ctx, q, start, end, limit, forward)
		if err != nil {
			return nil, err
		}
		all = append(all, es...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if forward {
			return all[i].TsNs < all[j].TsNs
		}
		return all[i].TsNs > all[j].TsNs
	})
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// series are the label sets of the store's streams matching a selector in the range.
func (c *lokiClient) series(ctx context.Context, selector string, start, end int64) ([]map[string]string, error) {
	q := url.Values{"match[]": {selector}, "start": {strconv.FormatInt(start, 10)}, "end": {strconv.FormatInt(end, 10)}}
	var resp struct {
		Data []map[string]string `json:"data"`
	}
	if err := c.get(ctx, "/loki/api/v1/series", q, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *lokiClient) get(ctx context.Context, path string, q url.Values, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("log store: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("log store: %s %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}
