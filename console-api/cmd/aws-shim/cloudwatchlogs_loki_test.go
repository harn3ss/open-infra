package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// fakeLoki is the log store's HTTP API over an in-memory set of lines: stream selectors (=, =~) and |=
// line filters, start/end/limit/direction, and the series API.
type fakeLoki struct {
	lines   []fakeLine
	queries []string
}

type fakeLine struct {
	labels map[string]string
	ts     int64
	line   string
}

var (
	fakeMatcherRE = regexp.MustCompile(`(\w+)(=~|=)("(?:[^"\\]|\\.)*")`)
	fakeFilterRE  = regexp.MustCompile(`\|= ("(?:[^"\\]|\\.)*")`)
)

func (f *fakeLoki) match(selector string, l fakeLine) bool {
	sel := selector
	if i := strings.Index(sel, "}"); i >= 0 {
		sel = sel[:i+1]
	}
	for _, m := range fakeMatcherRE.FindAllStringSubmatch(sel, -1) {
		v, _ := strconv.Unquote(m[3])
		got := l.labels[m[1]]
		if m[2] == "=" && got != v {
			return false
		}
		if m[2] == "=~" && !regexp.MustCompile("^(?:"+v+")$").MatchString(got) {
			return false
		}
	}
	for _, m := range fakeFilterRE.FindAllStringSubmatch(selector, -1) {
		v, _ := strconv.Unquote(m[1])
		if !strings.Contains(l.line, v) {
			return false
		}
	}
	return true
}

func (f *fakeLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
	end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
	switch r.URL.Path {
	case "/loki/api/v1/series":
		seen := map[string]bool{}
		var out []map[string]string
		for _, l := range f.lines {
			key := l.labels["namespace"] + "/" + l.labels["pod"] + "/" + l.labels["container"]
			if l.ts >= start && l.ts < end && f.match(q.Get("match[]"), l) && !seen[key] {
				seen[key] = true
				out = append(out, l.labels)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": out})
	case "/loki/api/v1/query_range":
		f.queries = append(f.queries, q.Get("query"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		var hits []fakeLine
		for _, l := range f.lines {
			if l.ts >= start && l.ts < end && f.match(q.Get("query"), l) {
				hits = append(hits, l)
			}
		}
		fwd := q.Get("direction") == "forward"
		sort.SliceStable(hits, func(i, j int) bool {
			if fwd {
				return hits[i].ts < hits[j].ts
			}
			return hits[i].ts > hits[j].ts
		})
		if len(hits) > limit {
			hits = hits[:limit]
		}
		byStream := map[string]map[string]any{}
		var order []string
		for _, h := range hits {
			b, _ := json.Marshal(h.labels)
			k := string(b)
			if byStream[k] == nil {
				byStream[k] = map[string]any{"stream": h.labels, "values": [][2]string{}}
				order = append(order, k)
			}
			byStream[k]["values"] = append(byStream[k]["values"].([][2]string), [2]string{strconv.FormatInt(h.ts, 10), h.line})
		}
		res := []any{}
		for _, k := range order {
			res = append(res, byStream[k])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": res}})
	default:
		http.NotFound(w, r)
	}
}

var cwlNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) int64 { return cwlNow.Add(-d).UnixNano() }

func claimOf(kind, ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": ns, "creationTimestamp": cwlNow.Add(-48 * time.Hour).Format(time.RFC3339)},
	}}
}

func logLine(ns, pod, container, app string, ts int64, line string) fakeLine {
	return fakeLine{labels: map[string]string{"namespace": ns, "pod": pod, "container": container, "app": app}, ts: ts, line: line}
}

// cwlDerivedFixture: a function "hello" (two pods, one gone), an application "web", a training job "tj", and
// a function in a namespace of another account.
func cwlDerivedFixture(t *testing.T, allow bool) (*cwlHandler, *fakeLoki) {
	t.Helper()
	loki := &fakeLoki{lines: []fakeLine{
		logLine("default", "hello-00001-deployment-aaa-1", "user-container", "hello-00001", at(3*time.Hour), "START RequestId: 1"),
		logLine("default", "hello-00001-deployment-aaa-1", "user-container", "hello-00001", at(3*time.Hour)+1e6, "marker-alpha first"),
		logLine("default", "hello-00001-deployment-aaa-1", "queue-proxy", "hello-00001", at(3*time.Hour)+2e6, "proxy noise marker-alpha"),
		logLine("default", "hello-00002-deployment-bbb-2", "user-container", "hello-00002", at(time.Hour), "connection refused once"),
		logLine("default", "hello-00002-deployment-bbb-2", "user-container", "hello-00002", at(time.Hour)+1e6, "marker-alpha second"),
		logLine("default", "hello-00002-deployment-bbb-2", "user-container", "hello-00002", at(time.Hour)+1e6, "same instant, another line"),
		logLine("default", "helloworld-00001-deployment-ccc-3", "user-container", "helloworld-00001", at(time.Hour), "another function"),
		logLine("default", "web-7d9f-xk2p1", "app", "web", at(2*time.Hour), "GET / 200"),
		logLine("default", "tj-train-q8x2z", "trainer", "tj", at(5*time.Hour), "epoch 1 loss 0.4"),
		logLine(testCFNNamespace, "stackfn-00001-deployment-ddd-4", "user-container", "stackfn-00001", at(time.Hour), "member account line"),
		logLine("default", "old-00001-deployment-eee-5", "user-container", "old-00001", at(10*24*time.Hour), "older than retention"),
	}}
	srv := httptest.NewServer(loki)
	t.Cleanup(srv.Close)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		functionClaimGVR: "FunctionList", applicationGVR: "ApplicationList",
		trainingJobGVR: "TrainingJobList", processingJobGVR: "ProcessingJobList",
	}, claimOf("Function", "default", "hello"), claimOf("Function", "default", "helloworld"),
		claimOf("Application", "default", "web"), claimOf("TrainingJob", "default", "tj"),
		claimOf("Function", testCFNNamespace, "stackfn"))
	cs := csWithSAR(allow)
	_, _ = cs.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, metav1.CreateOptions{})
	_, _ = cs.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testCFNNamespace,
		Labels: map[string]string{"openinfra.dev/account-id": "912345678901"}}}, metav1.CreateOptions{})
	fns := newFnLocator(dyn, discardLogger(), "default", testCFNNamespace)
	h := newCWLHandler(cs, "default", "000000000000", "us-east-1", nil, discardLogger())
	h.derived = newCWLDerived(srv.URL, dyn, cs, fns, "000000000000", 7)
	h.derived.now = func() time.Time { return cwlNow }
	return h, loki
}

func cwlCall(t *testing.T, h *cwlHandler, claims iam.Claims, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	r.Header.Set("X-Amz-Target", "Logs_20140328."+op)
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func groupNames(out map[string]any) []string {
	var names []string
	for _, g := range sliceOf(out["logGroups"]) {
		names = append(names, g.(map[string]any)["logGroupName"].(string))
	}
	return names
}

func TestCWLDerived_DescribeLogGroupsListsTheAccountsServiceGroups(t *testing.T) {
	h, _ := cwlDerivedFixture(t, true)
	code, out := cwlCall(t, h, testUser, "DescribeLogGroups", map[string]any{})
	if code != 200 {
		t.Fatalf("DescribeLogGroups: %d %v", code, out)
	}
	got := groupNames(out)
	want := []string{"/aws/lambda/hello", "/aws/lambda/helloworld", "/aws/sagemaker/TrainingJobs", "/ecs/web"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("groups %v, want %v (another account's function is not listed)", got, want)
	}
	g := sliceOf(out["logGroups"])[0].(map[string]any)
	if g["arn"] != "arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/hello:*" || toInt(g["retentionInDays"]) != 7 {
		t.Errorf("group fields %v", g)
	}
	_, out = cwlCall(t, h, testUser, "DescribeLogGroups", map[string]any{"logGroupNamePrefix": "/aws/lambda/hellow"})
	if got := groupNames(out); len(got) != 1 || got[0] != "/aws/lambda/helloworld" {
		t.Errorf("prefix: %v", got)
	}
	// A caller of the member account: its account's groups are its own function's only (the scoping) …
	member := testUser
	member.Account = "912345678901"
	scoped := h.derived.groups(t.Context(), member, "")
	if len(scoped) != 1 || scoped[0].Name != "/aws/lambda/stackfn" {
		t.Errorf("member account groups %v", scoped)
	}
	// … and through the API a member principal is judged by IAM policy alone: with none attached it sees
	// nothing, as an AWS user with no policy does.
	_, out = cwlCall(t, h, member, "DescribeLogGroups", map[string]any{})
	if got := groupNames(out); len(got) != 0 {
		t.Errorf("a member principal with no policy listed %v", got)
	}
}

func TestCWLDerived_LambdaStreamsAreNamedAsLambdaNamesThem(t *testing.T) {
	h, _ := cwlDerivedFixture(t, true)
	code, out := cwlCall(t, h, testUser, "DescribeLogStreams", map[string]any{"logGroupName": "/aws/lambda/hello", "orderBy": "LastEventTime", "descending": true})
	if code != 200 {
		t.Fatalf("DescribeLogStreams: %d %v", code, out)
	}
	sts := sliceOf(out["logStreams"])
	if len(sts) != 2 {
		t.Fatalf("streams %v (one per execution environment; another function's pods are not its)", sts)
	}
	re := regexp.MustCompile(`^2026/11/05/\[\$LATEST\][0-9a-f]{32}$`)
	newest := sts[0].(map[string]any)
	if !re.MatchString(newest["logStreamName"].(string)) {
		t.Errorf("stream name %q, want Lambda's YYYY/MM/DD/[$LATEST]<id>", newest["logStreamName"])
	}
	if toInt64(newest["lastEventTimestamp"]) != at(time.Hour)/1e6+1 || toInt64(newest["firstEventTimestamp"]) != at(time.Hour)/1e6 {
		t.Errorf("stream timestamps %v", newest)
	}
	if toInt64(sts[1].(map[string]any)["lastEventTimestamp"]) >= toInt64(newest["lastEventTimestamp"]) {
		t.Error("orderBy LastEventTime descending: newest first")
	}
	// Training jobs: <job>/algo-1-<start>.
	_, out = cwlCall(t, h, testUser, "DescribeLogStreams", map[string]any{"logGroupName": "/aws/sagemaker/TrainingJobs"})
	if s := sliceOf(out["logStreams"]); len(s) != 1 || !strings.HasPrefix(s[0].(map[string]any)["logStreamName"].(string), "tj/algo-1-") {
		t.Errorf("training streams %v", s)
	}
	// ECS (awslogs): ecs/<container>/<task id>.
	_, out = cwlCall(t, h, testUser, "DescribeLogStreams", map[string]any{"logGroupName": "/ecs/web"})
	if s := sliceOf(out["logStreams"]); len(s) != 1 || !regexp.MustCompile(`^ecs/app/[0-9a-f]{32}$`).MatchString(s[0].(map[string]any)["logStreamName"].(string)) {
		t.Errorf("ecs streams %v", s)
	}
}

func TestCWLDerived_GetLogEventsPagesAndTerminates(t *testing.T) {
	h, _ := cwlDerivedFixture(t, true)
	_, out := cwlCall(t, h, testUser, "DescribeLogStreams", map[string]any{"logGroupName": "/aws/lambda/hello", "orderBy": "LastEventTime"})
	stream := sliceOf(out["logStreams"])[0].(map[string]any)["logStreamName"].(string) // the older pod
	code, out := cwlCall(t, h, testUser, "GetLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "logStreamName": stream, "startFromHead": true, "limit": 1})
	if code != 200 {
		t.Fatalf("GetLogEvents: %d %v", code, out)
	}
	evs := sliceOf(out["events"])
	if len(evs) != 1 || evs[0].(map[string]any)["message"] != "START RequestId: 1" {
		t.Fatalf("first page %v", evs)
	}
	tok := out["nextForwardToken"].(string)
	_, out = cwlCall(t, h, testUser, "GetLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "logStreamName": stream, "nextToken": tok})
	evs = sliceOf(out["events"])
	if len(evs) != 1 || evs[0].(map[string]any)["message"] != "marker-alpha first" {
		t.Fatalf("second page %v (the user container only: no queue-proxy line)", evs)
	}
	tok = out["nextForwardToken"].(string)
	_, out = cwlCall(t, h, testUser, "GetLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "logStreamName": stream, "nextToken": tok})
	if len(sliceOf(out["events"])) != 0 || out["nextForwardToken"] != tok {
		t.Errorf("at the end the forward token comes back unchanged, so a reader stops: %v", out)
	}
	code, out = cwlCall(t, h, testUser, "GetLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "logStreamName": "2026/11/05/[$LATEST]nope"})
	if code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Errorf("an unknown stream: %d %v", code, out)
	}
}

func TestCWLDerived_FilterLogEvents(t *testing.T) {
	h, _ := cwlDerivedFixture(t, true)
	code, out := cwlCall(t, h, testUser, "FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "filterPattern": "marker-alpha"})
	if code != 200 {
		t.Fatalf("FilterLogEvents: %d %v", code, out)
	}
	evs := sliceOf(out["events"])
	if len(evs) != 2 || evs[0].(map[string]any)["message"] != "marker-alpha first" || evs[1].(map[string]any)["message"] != "marker-alpha second" {
		t.Fatalf("events %v (oldest first; another function's and the proxy's lines excluded)", evs)
	}
	e := evs[0].(map[string]any)
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(e["eventId"].(string)) || !strings.Contains(e["logStreamName"].(string), "[$LATEST]") {
		t.Errorf("event fields %v", e)
	}
	_, again := cwlCall(t, h, testUser, "FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "filterPattern": "marker-alpha"})
	if sliceOf(again["events"])[0].(map[string]any)["eventId"] != e["eventId"] {
		t.Error("an event's id is stable (logs tail --follow de-duplicates on it)")
	}
	// A quoted phrase.
	_, out = cwlCall(t, h, testUser, "FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "filterPattern": `"connection refused"`})
	if n := len(sliceOf(out["events"])); n != 1 {
		t.Errorf("phrase: %d events", n)
	}
	// JSON selectors are refused, never answered unfiltered.
	code, out = cwlCall(t, h, testUser, "FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "filterPattern": `{ $.level = "ERROR" }`})
	if code != 400 || out["__type"] != "InvalidParameterException" {
		t.Errorf("a JSON pattern: %d %v", code, out)
	}
	// Pages: limit 1, through events that share an instant, with no event lost or repeated.
	var msgs []string
	var tok any
	for i := 0; i < 10; i++ {
		body := map[string]any{"logGroupName": "/aws/lambda/hello", "limit": 1}
		if tok != nil {
			body["nextToken"] = tok
		}
		_, out = cwlCall(t, h, testUser, "FilterLogEvents", body)
		for _, ev := range sliceOf(out["events"]) {
			msgs = append(msgs, ev.(map[string]any)["message"].(string))
		}
		if tok = out["nextToken"]; tok == nil {
			break
		}
	}
	want := []string{"START RequestId: 1", "marker-alpha first", "connection refused once", "marker-alpha second", "same instant, another line"}
	sort.Strings(msgs)
	sort.Strings(want)
	if strings.Join(msgs, "|") != strings.Join(want, "|") {
		t.Errorf("paged events %v, want %v", msgs, want)
	}
}

func TestCWLDerived_ReadOnlyAndDenied(t *testing.T) {
	h, _ := cwlDerivedFixture(t, true)
	code, out := cwlCall(t, h, testUser, "PutLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello", "logStreamName": "s",
		"logEvents": []any{map[string]any{"timestamp": cwlNow.UnixMilli(), "message": "x"}}})
	if code != 400 || out["__type"] != "InvalidParameterException" || !strings.Contains(out["message"].(string), "read-only") {
		t.Errorf("writing a function's group: %d %v", code, out)
	}
	code, out = cwlCall(t, h, testUser, "CreateLogGroup", map[string]any{"logGroupName": "/aws/lambda/hello"})
	if code != 400 || out["__type"] != "ResourceAlreadyExistsException" {
		t.Errorf("creating a function's group: %d %v", code, out)
	}
	// Without the right, nothing is read.
	denied, _ := cwlDerivedFixture(t, false)
	code, out = cwlCall(t, denied, testUser, "FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello"})
	if code != 403 || out["__type"] != "AccessDeniedException" {
		t.Errorf("a caller without the right: %d %v", code, out)
	}
}

func TestCWLDerived_RetentionWindowBoundsTheStore(t *testing.T) {
	h, loki := cwlDerivedFixture(t, true)
	_, _ = cwlCall(t, h, testUser, "FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/hello"})
	for _, q := range loki.queries {
		if !strings.Contains(q, `container="user-container"`) && strings.Contains(q, "app=~") {
			t.Errorf("a function's query is its user container's: %s", q)
		}
	}
	if _, ok := h.derived.resolve(t.Context(), testUser, "/aws/lambda/old"); ok {
		t.Error("a function with no claim has no group, even if old lines remain")
	}
}

// A query never asks the store for more lines than its per-query limit (Loki answers 400 above it);
// a caller asking for CloudWatch's larger page still gets its events, paged on.
func TestCWLDerived_StoreQueryLimitIsCapped(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("limit"))
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer srv.Close()
	c := &lokiClient{base: srv.URL, http: srv.Client()}
	if _, err := c.queryRange(t.Context(), `{namespace="default"}`, 0, 1, 10000, true); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != strconv.Itoa(lokiMaxEntries) {
		t.Fatalf("asked the store for limit %v, want at most %d", asked, lokiMaxEntries)
	}
}
