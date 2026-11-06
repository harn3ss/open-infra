package main

// CloudWatch Logs keeps each account's log groups apart (account-scoped): the store-backed groups against
// a real Postgres (OPENINFRA_TEST_PG_URI; skipped without it), and a member account's service groups from
// its home namespace.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func cwlFixture(t *testing.T) *cwlHandler {
	t.Helper()
	db := freshPGDB(t)
	st := &cwlStore{db: db}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newCWLHandler(csWithSAR(true), "authz", testMgmt, "us-east-1", st, discardLogger())
	h.authz = acctAuthz(t)
	return h
}

func cwlCallAs(t *testing.T, h *cwlHandler, c iam.Claims, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return callAs(t, h.serve, c, "Logs_20140328."+op, body)
}

func eventMessages(out map[string]any) string {
	var m []string
	for _, e := range sliceOf(out["events"]) {
		m = append(m, e.(map[string]any)["message"].(string))
	}
	return strings.Join(m, ",")
}

func TestServicesPG_CloudWatchLogsAccounts_GroupsAreEachAccountsOwn(t *testing.T) {
	h := cwlFixture(t)
	now := time.Now().UnixMilli()
	for _, c := range []iam.Claims{acctMgmt, acctMember} {
		who := "mgmt"
		if c.Account != "" {
			who = "member"
		}
		if code, out := cwlCallAs(t, h, c, "CreateLogGroup", map[string]any{"logGroupName": "/app/web"}); code != 200 {
			t.Fatalf("%s CreateLogGroup (the same name in each account): %d %v", who, code, out)
		}
		if code, out := cwlCallAs(t, h, c, "CreateLogStream", map[string]any{"logGroupName": "/app/web", "logStreamName": "s"}); code != 200 {
			t.Fatalf("%s CreateLogStream: %d %v", who, code, out)
		}
		if code, out := cwlCallAs(t, h, c, "PutLogEvents", map[string]any{"logGroupName": "/app/web", "logStreamName": "s",
			"logEvents": []any{map[string]any{"timestamp": now, "message": who + " line"}}}); code != 200 {
			t.Fatalf("%s PutLogEvents: %d %v", who, code, out)
		}
	}
	if code, out := cwlCallAs(t, h, acctMember, "CreateLogGroup", map[string]any{"logGroupName": "/only/member"}); code != 200 {
		t.Fatalf("member CreateLogGroup: %d %v", code, out)
	}
	if code, out := cwlCallAs(t, h, acctMember, "CreateLogGroup", map[string]any{"logGroupName": "/app/web"}); code != 400 || out["__type"] != "ResourceAlreadyExistsException" {
		t.Fatalf("a second member CreateLogGroup: %d %v", code, out)
	}

	// Each account reads its own group's events.
	read := func(c iam.Claims, op string) string {
		body := map[string]any{"logGroupName": "/app/web", "startFromHead": true}
		if op == "GetLogEvents" {
			body["logStreamName"] = "s"
		}
		code, out := cwlCallAs(t, h, c, op, body)
		if code != 200 {
			t.Fatalf("%s: %d %v", op, code, out)
		}
		return eventMessages(out)
	}
	for _, op := range []string{"GetLogEvents", "FilterLogEvents"} {
		if got := read(acctMember, op); got != "member line" {
			t.Errorf("member %s = %q, want its own line only", op, got)
		}
		if got := read(acctMgmt, op); got != "mgmt line" {
			t.Errorf("management %s = %q, want its own line only", op, got)
		}
	}

	// Each account lists its own groups, with its account in their ARNs.
	list := func(c iam.Claims) (names, arns []string) {
		_, out := cwlCallAs(t, h, c, "DescribeLogGroups", map[string]any{})
		return namesAndARNs(sliceOf(out["logGroups"]), "logGroupName", "arn")
	}
	names, arns := list(acctMember)
	if strings.Join(names, ",") != "/app/web,/only/member" ||
		arns[0] != "arn:aws:logs:us-east-1:"+testMember+":log-group:/app/web:*" {
		t.Fatalf("member groups %v %v", names, arns)
	}
	names, arns = list(acctMgmt)
	if strings.Join(names, ",") != "/app/web" || arns[0] != "arn:aws:logs:us-east-1:"+testMgmt+":log-group:/app/web:*" {
		t.Fatalf("management groups %v %v (the member's must not be listed)", names, arns)
	}
	_, out := cwlCallAs(t, h, acctMember, "DescribeLogStreams", map[string]any{"logGroupName": "/app/web"})
	if st := sliceOf(out["logStreams"]); len(st) != 1 || st[0].(map[string]any)["arn"] != "arn:aws:logs:us-east-1:"+testMember+":log-group:/app/web:log-stream:s" {
		t.Fatalf("member DescribeLogStreams = %v", out)
	}
	if code, out := cwlCallAs(t, h, acctMgmt, "DescribeLogStreams", map[string]any{"logGroupName": "/only/member"}); code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Fatalf("the management account reached the member's group: %d %v", code, out)
	}

	// An account key's form never names another account's group.
	for _, c := range []iam.Claims{acctMgmt, acctMember} {
		if code, out := cwlCallAs(t, h, c, "GetLogEvents", map[string]any{"logGroupName": testMember + ":/app/web", "logStreamName": "s"}); code != 400 || out["__type"] != "InvalidParameterException" {
			t.Errorf("a group named as an account key: %d %v", code, out)
		}
	}

	// Retention and deletion act on the caller's account's group only.
	if code, _ := cwlCallAs(t, h, acctMember, "PutRetentionPolicy", map[string]any{"logGroupName": "/app/web", "retentionInDays": 7}); code != 200 {
		t.Fatal("member PutRetentionPolicy")
	}
	_, out = cwlCallAs(t, h, acctMgmt, "DescribeLogGroups", map[string]any{})
	if g := sliceOf(out["logGroups"])[0].(map[string]any); g["retentionInDays"] != nil {
		t.Errorf("the member's retention reached the management account's group: %v", g)
	}
	if code, _ := cwlCallAs(t, h, acctMember, "DeleteLogGroup", map[string]any{"logGroupName": "/app/web"}); code != 200 {
		t.Fatal("member DeleteLogGroup")
	}
	if got := read(acctMgmt, "GetLogEvents"); got != "mgmt line" {
		t.Fatalf("the member's DeleteLogGroup took the management account's events: %q", got)
	}
}

// A member account's service groups are its own workloads': a function in its home namespace has its
// /aws/lambda group, listed (with the member's account) to the member and not to the management account.
func TestCloudWatchLogsAccounts_MemberServiceGroupsFromItsHome(t *testing.T) {
	h, loki := cwlDerivedFixture(t, true)
	h.authz = acctAuthz(t)
	if _, err := h.derived.dyn.Resource(functionClaimGVR).Namespace(memberHome).Create(context.Background(),
		claimOf("Function", memberHome, "mfn"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	loki.lines = append(loki.lines, logLine(memberHome, "mfn-00001-deployment-fff-6", "user-container", "mfn-00001", at(time.Hour), "member function line"))

	names := func(c iam.Claims) []string {
		_, out := callAs(t, h.serve, c, "Logs_20140328.DescribeLogGroups", map[string]any{})
		return groupNames(out)
	}
	if got := names(acctMember); !containsStr(got, "/aws/lambda/mfn") || containsStr(got, "/aws/lambda/hello") {
		t.Fatalf("member groups %v: want its home's function, not the management account's", got)
	}
	if got := names(acctMgmt); containsStr(got, "/aws/lambda/mfn") || !containsStr(got, "/aws/lambda/hello") {
		t.Fatalf("management groups %v: want its own functions, not the member's", got)
	}
	_, out := callAs(t, h.serve, acctMember, "Logs_20140328.DescribeLogGroups", map[string]any{"logGroupNamePrefix": "/aws/lambda/mfn"})
	if g := sliceOf(out["logGroups"]); len(g) != 1 || g[0].(map[string]any)["arn"] != "arn:aws:logs:us-east-1:"+testMember+":log-group:/aws/lambda/mfn:*" {
		t.Fatalf("member group %v", out)
	}
	code, out := callAs(t, h.serve, acctMember, "Logs_20140328.FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/mfn"})
	if code != 200 || eventMessages(out) != "member function line" {
		t.Fatalf("member FilterLogEvents: %d %v", code, out)
	}
	if code, out := callAs(t, h.serve, acctMgmt, "Logs_20140328.FilterLogEvents", map[string]any{"logGroupName": "/aws/lambda/mfn"}); code == 200 && eventMessages(out) != "" {
		t.Fatalf("the management account read the member's function's logs: %v", out)
	}
}
