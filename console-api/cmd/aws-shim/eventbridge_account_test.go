package main

// EventBridge keeps each account's buses, rules and targets apart (account-scoped): against a real
// Postgres store (OPENINFRA_TEST_PG_URI; skipped without it), the management account's bob and a member
// account's bob — both allowed everything by their own account's IAM policy — each see only their own.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

var (
	acctMgmt   = iam.Claims{Sub: "bob"}
	acctMember = iam.Claims{Sub: "bob", Account: testMember}
)

// acctAuthz allows the management account's bob and the member account's bob everything, each by a
// policy of its own account (enforce).
func acctAuthz(t *testing.T) *dataplaneauthz.Checker {
	t.Helper()
	return checkerInMode(t, "enforce", dataplaneauthz.PolicyDoc{Name: "all",
		AppliesTo: []string{"User::bob", "User::" + memberHome + "/bob"}, Statements: []policyengine.Statement{dpAllow([]string{"*"}, "*")}})
}

// asAccount is the context the router gives a request of claims to an account-scoped door.
func asAccount(c iam.Claims) context.Context {
	if c.Account == "" {
		return inAccountScope(context.Background())
	}
	return inAccountScope(memberCtx())
}

// callAs serves one JSON-protocol request of claims (in their account) and decodes the answer.
func callAs(t *testing.T, serve func(http.ResponseWriter, *http.Request, iam.Claims, string), c iam.Claims, target string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)).WithContext(asAccount(c))
	r.Header.Set("X-Amz-Target", target)
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	serve(w, r, c, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func ebFixture(t *testing.T) (*ebHandler, *sql.DB) {
	t.Helper()
	db := freshPGDB(t)
	eb, sq := &ebStore{db: db}, &sqsStore{db: db}
	for _, ensure := range []func(context.Context) error{eb.ensureSchema, sq.ensureSchema} {
		if err := ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	h := newEBHandler(csWithSAR(true), "authz", "fns", testMgmt, "us-east-1", eb, nil, sq, discardLogger())
	h.authz = acctAuthz(t)
	h.homeOf = testDirectory().HomeOf
	return h, db
}

func ebCall(t *testing.T, h *ebHandler, c iam.Claims, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return callAs(t, h.serve, c, "AWSEvents."+op, body)
}

func namesAndARNs(list []any, nameKey, arnKey string) (names, arns []string) {
	for _, e := range list {
		m := e.(map[string]any)
		names = append(names, m[nameKey].(string))
		arns = append(arns, m[arnKey].(string))
	}
	return names, arns
}

func TestServicesPG_EventBridgeAccounts_BusesAndRulesAreEachAccountsOwn(t *testing.T) {
	h, _ := ebFixture(t)
	// The same bus name in both accounts, independently.
	if code, out := ebCall(t, h, acctMgmt, "CreateEventBus", map[string]any{"Name": "orders"}); code != 200 ||
		out["EventBusArn"] != "arn:aws:events:us-east-1:"+testMgmt+":event-bus/orders" {
		t.Fatalf("management CreateEventBus: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "CreateEventBus", map[string]any{"Name": "orders"}); code != 200 ||
		out["EventBusArn"] != "arn:aws:events:us-east-1:"+testMember+":event-bus/orders" {
		t.Fatalf("member CreateEventBus: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "CreateEventBus", map[string]any{"Name": "orders"}); code != 400 || out["__type"] != "ResourceAlreadyExistsException" {
		t.Fatalf("a second member CreateEventBus: %d %v", code, out)
	}
	if code, _ := ebCall(t, h, acctMember, "CreateEventBus", map[string]any{"Name": "audit"}); code != 200 {
		t.Fatal("member CreateEventBus audit")
	}
	// Each account lists its own buses — the member's default bus is its own, with its account.
	_, out := ebCall(t, h, acctMember, "ListEventBuses", map[string]any{})
	names, arns := namesAndARNs(sliceOf(out["EventBuses"]), "Name", "Arn")
	if strings.Join(names, ",") != "audit,default,orders" {
		t.Fatalf("member buses %v", names)
	}
	for _, a := range arns {
		if !strings.Contains(a, ":"+testMember+":event-bus/") {
			t.Errorf("member bus ARN %q does not carry the member account", a)
		}
	}
	_, out = ebCall(t, h, acctMgmt, "ListEventBuses", map[string]any{})
	if names, arns := namesAndARNs(sliceOf(out["EventBuses"]), "Name", "Arn"); strings.Join(names, ",") != "default,orders" ||
		arns[0] != "arn:aws:events:::event-bus/default" || arns[1] != "arn:aws:events:us-east-1:"+testMgmt+":event-bus/orders" {
		t.Fatalf("management buses %v %v (the member's must not be listed; the management account's unchanged)", names, arns)
	}

	// The same rule name on each account's default bus, independently.
	mp := `{"source":["member.app"]}`
	if code, out := ebCall(t, h, acctMember, "PutRule", map[string]any{"Name": "on-order", "EventPattern": mp}); code != 200 ||
		out["RuleArn"] != "arn:aws:events:us-east-1:"+testMember+":rule/on-order" {
		t.Fatalf("member PutRule: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMgmt, "PutRule", map[string]any{"Name": "on-order", "EventPattern": `{"source":["mgmt.app"]}`}); code != 200 ||
		out["RuleArn"] != "arn:aws:events:us-east-1:"+testMgmt+":rule/on-order" {
		t.Fatalf("management PutRule: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "PutRule", map[string]any{"Name": "nightly", "EventBusName": "orders", "ScheduleExpression": "rate(1 hour)"}); code != 200 ||
		out["RuleArn"] != "arn:aws:events:us-east-1:"+testMember+":rule/orders/nightly" {
		t.Fatalf("member PutRule on its bus: %d %v", code, out)
	}
	_, d := ebCall(t, h, acctMember, "DescribeRule", map[string]any{"Name": "on-order"})
	if d["EventPattern"] != mp || d["EventBusName"] != "default" || d["Arn"] != "arn:aws:events:us-east-1:"+testMember+":rule/on-order" {
		t.Fatalf("member DescribeRule = %v", d)
	}
	_, d = ebCall(t, h, acctMgmt, "DescribeRule", map[string]any{"Name": "on-order"})
	if d["EventPattern"] != `{"source":["mgmt.app"]}` || d["EventBusName"] != "default" {
		t.Fatalf("management DescribeRule = %v", d)
	}
	_, d = ebCall(t, h, acctMember, "ListRules", map[string]any{"EventBusName": "orders"})
	if rs := sliceOf(d["Rules"]); len(rs) != 1 || rs[0].(map[string]any)["Name"] != "nightly" || rs[0].(map[string]any)["EventBusName"] != "orders" {
		t.Fatalf("member ListRules on orders = %v", d)
	}
	if _, d = ebCall(t, h, acctMgmt, "ListRules", map[string]any{"EventBusName": "orders"}); len(sliceOf(d["Rules"])) != 0 {
		t.Fatalf("the management account listed the member's rule: %v", d)
	}

	// Another account's bus is never reached: not by its ARN, not by an account key's form.
	for _, ref := range []string{"arn:aws:events:us-east-1:" + testMgmt + ":event-bus/orders", testMgmt + ":orders", testMember + ":default"} {
		if code, out := ebCall(t, h, acctMember, "ListRules", map[string]any{"EventBusName": ref}); code != 400 || out["__type"] != "ResourceNotFoundException" {
			t.Errorf("member ListRules on %s: %d %v, want ResourceNotFoundException", ref, code, out)
		}
	}
	for _, ref := range []string{"arn:aws:events:us-east-1:" + testMember + ":event-bus/orders", testMember + ":orders"} {
		if code, out := ebCall(t, h, acctMgmt, "PutRule", map[string]any{"Name": "x", "EventBusName": ref, "ScheduleExpression": "rate(1 hour)"}); code != 400 || out["__type"] != "ResourceNotFoundException" {
			t.Errorf("management PutRule on %s: %d %v, want ResourceNotFoundException", ref, code, out)
		}
	}
	if code, out := ebCall(t, h, acctMgmt, "CreateEventBus", map[string]any{"Name": testMember + ":evil"}); code != 400 || out["__type"] != "ValidationException" {
		t.Errorf("a bus named as an account key: %d %v", code, out)
	}

	// Deleting the member's rule and bus leaves the management account's.
	if code, _ := ebCall(t, h, acctMember, "DeleteRule", map[string]any{"Name": "on-order"}); code != 200 {
		t.Fatal("member DeleteRule")
	}
	if code, _ := ebCall(t, h, acctMgmt, "DescribeRule", map[string]any{"Name": "on-order"}); code != 200 {
		t.Fatal("the member's DeleteRule removed the management account's rule")
	}
	if code, _ := ebCall(t, h, acctMember, "DeleteEventBus", map[string]any{"Name": "audit"}); code != 200 {
		t.Fatal("member DeleteEventBus")
	}
	if code, out := ebCall(t, h, acctMember, "DeleteEventBus", map[string]any{"Name": "audit"}); code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Fatalf("member DeleteEventBus twice: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMgmt, "DeleteEventBus", map[string]any{"Name": "nosuch"}); code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Fatalf("management DeleteEventBus nosuch: %d %v", code, out)
	}
}

// queueIn makes a queue of an account in the SQS store under its account key, as the account-scoped SQS
// front door keeps it.
func queueIn(t *testing.T, db *sql.DB, acct, name string, attrs map[string]string) string {
	t.Helper()
	url := "http://shim.test:4566/" + acct + "/" + name
	if _, err := (&sqsStore{db: db}).createQueue(context.Background(), accountKeyFor(acct, name), url, attrs); err != nil {
		t.Fatal(err)
	}
	return url
}

func queueBodies(t *testing.T, db *sql.DB, url string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT body FROM sqs_messages WHERE queue_url=$1 ORDER BY id`, url)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b string
		_ = rows.Scan(&b)
		out = append(out, b)
	}
	return out
}

// A rule delivers to the queue of the account its target's ARN names, and its events carry its account;
// another account's queue takes them only when its policy allows the rule.
func TestServicesPG_EventBridgeAccounts_DeliveryIsInTheTargetsAccount(t *testing.T) {
	h, db := ebFixture(t)
	mgmtQ := queueIn(t, db, testMgmt, "jobs", nil)
	memberQ := queueIn(t, db, testMember, "jobs", nil)
	pattern := `{"source":["app"]}`
	for _, c := range []iam.Claims{acctMgmt, acctMember} {
		acct := testMgmt
		if c.Account != "" {
			acct = testMember
		}
		if code, out := ebCall(t, h, c, "PutRule", map[string]any{"Name": "to-jobs", "EventPattern": pattern}); code != 200 {
			t.Fatalf("PutRule (%s): %d %v", acct, code, out)
		}
		if code, out := ebCall(t, h, c, "PutTargets", map[string]any{"Rule": "to-jobs", "Targets": []any{
			map[string]any{"Id": "q", "Arn": "arn:aws:sqs:us-east-1:" + acct + ":jobs"}}}); code != 200 {
			t.Fatalf("PutTargets (%s): %d %v", acct, code, out)
		}
	}
	if code, out := ebCall(t, h, acctMember, "PutEvents", map[string]any{"Entries": []any{map[string]any{"Source": "app", "DetailType": "t", "Detail": `{"from":"member"}`}}}); code != 200 || toInt(out["FailedEntryCount"]) != 0 {
		t.Fatalf("member PutEvents: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMgmt, "PutEvents", map[string]any{"Entries": []any{map[string]any{"Source": "app", "DetailType": "t", "Detail": `{"from":"mgmt"}`}}}); code != 200 || toInt(out["FailedEntryCount"]) != 0 {
		t.Fatalf("management PutEvents: %d %v", code, out)
	}
	mb, gb := queueBodies(t, db, memberQ), queueBodies(t, db, mgmtQ)
	if len(mb) != 1 || !strings.Contains(mb[0], `"from":"member"`) || !strings.Contains(mb[0], `"account":"`+testMember+`"`) {
		t.Fatalf("the member's queue got %v, want its own event in its account", mb)
	}
	if len(gb) != 1 || !strings.Contains(gb[0], `"from":"mgmt"`) || !strings.Contains(gb[0], `"account":"`+testMgmt+`"`) {
		t.Fatalf("the management queue got %v, want its own event only", gb)
	}

	// The member's rule targeting the management account's queue: cross-account, so the queue's policy
	// must allow it — none does, so nothing arrives.
	if code, out := ebCall(t, h, acctMember, "PutRule", map[string]any{"Name": "to-mgmt", "EventPattern": `{"source":["cross"]}`}); code != 200 {
		t.Fatalf("PutRule to-mgmt: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "PutTargets", map[string]any{"Rule": "to-mgmt", "Targets": []any{
		map[string]any{"Id": "q", "Arn": "arn:aws:sqs:us-east-1:" + testMgmt + ":jobs"}}}); code != 200 {
		t.Fatalf("PutTargets cross-account: %d %v", code, out)
	}
	rule, _, _ := h.store.getRule(context.Background(), accountKeyFor(testMember, "default"), "to-mgmt")
	tgt := ebTarget{Type: "sqs", Arn: "arn:aws:sqs:us-east-1:" + testMgmt + ":jobs"}
	if err := h.deliver(memberCtx(), rule, tgt, []byte(`{"n":1}`)); err != errQueuePolicy {
		t.Fatalf("a cross-account delivery to a queue with no policy: %v, want the queue policy refusal", err)
	}
	// Its policy allowing the member's rule lets it in.
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"*","Condition":{"ArnEquals":{"aws:SourceArn":"` + rule.Arn + `"}}}]}`
	if _, err := db.Exec(`UPDATE sqs_queues SET attributes = jsonb_build_object('Policy', $1::text) WHERE url=$2`, doc, mgmtQ); err != nil {
		t.Fatal(err)
	}
	if err := h.deliver(memberCtx(), rule, tgt, []byte(`{"n":2}`)); err != nil {
		t.Fatalf("a cross-account delivery the queue's policy allows: %v", err)
	}
	if gb := queueBodies(t, db, mgmtQ); len(gb) != 2 || gb[1] != `{"n":2}` {
		t.Fatalf("the management queue got %v", gb)
	}
}

// An ARN names its account's resource: a target or bus of the rule's own account, of another of the
// organization's accounts, or — for the management account, which always read an ARN by name — an account
// outside the organization, still its own.
func TestEventBridgeAccounts_ARNsNameTheirAccount(t *testing.T) {
	h := newEBHandler(nil, "authz", "fns", testMgmt, "us-east-1", nil, nil, nil, discardLogger())
	h.homeOf = testDirectory().HomeOf
	for _, c := range []struct{ acct, arn, want string }{
		{testMgmt, "arn:aws:sqs:us-east-1:" + testMgmt + ":jobs", testMgmt},
		{testMgmt, "arn:aws:sqs:us-east-1:" + testMember + ":jobs", testMember},
		{testMgmt, "arn:aws:sqs:us-east-1:111122223333:jobs", testMgmt},
		{testMgmt, "arn:aws:sqs:us-east-1:open-infra:jobs", testMgmt},
		{testMember, "arn:aws:sqs:us-east-1:" + testMember + ":jobs", testMember},
		{testMember, "arn:aws:sqs:us-east-1::jobs", testMember},
		{testMember, "arn:aws:sqs:us-east-1:" + testMgmt + ":jobs", testMgmt},
		{testMember, "arn:aws:sqs:us-east-1:111122223333:jobs", "111122223333"},
	} {
		if got := h.ownerOfARN(c.acct, c.arn); got != c.want {
			t.Errorf("ownerOfARN(%s, %s) = %s, want %s", c.acct, c.arn, got, c.want)
		}
	}
	mgmt, member := context.Background(), memberCtx()
	for _, c := range []struct {
		ctx      context.Context
		ref, key string
		ok       bool
	}{
		{mgmt, "default", "default", true},
		{mgmt, "arn:aws:events:::event-bus/default", "default", true},
		{mgmt, "arn:aws:events:us-east-1:" + testMgmt + ":event-bus/orders", "orders", true},
		{mgmt, "arn:aws:events:us-east-1:" + testMember + ":event-bus/orders", "", false},
		{mgmt, testMember + ":orders", "", false},
		{member, "default", testMember + ":default", true},
		{member, "arn:aws:events:us-east-1:" + testMember + ":event-bus/orders", testMember + ":orders", true},
		{member, "arn:aws:events:us-east-1:" + testMgmt + ":event-bus/orders", "", false},
		{member, testMember + ":orders", "", false},
	} {
		if key, _, ok := h.busKey(c.ctx, c.ref); ok != c.ok || key != c.key {
			t.Errorf("busKey(%s) = %q %v, want %q %v", c.ref, key, ok, c.key, c.ok)
		}
	}
	if got := h.ruleARN(testMember, "orders", "r"); got != "arn:aws:events:us-east-1:"+testMember+":rule/orders/r" {
		t.Errorf("a member rule's ARN %s", got)
	}
	if got := h.ruleARN(testMgmt, "default", "r"); got != "arn:aws:events:us-east-1:"+testMgmt+":rule/r" {
		t.Errorf("a management rule's ARN %s", got)
	}
}

// A member account's Lambda target is a function of its own account, in its home namespace; another
// account's function is refused.
func TestServicesPG_EventBridgeAccounts_LambdaTargetsAreTheRulesAccounts(t *testing.T) {
	h, _ := ebFixture(t)
	if code, out := ebCall(t, h, acctMember, "PutRule", map[string]any{"Name": "fn", "EventPattern": `{"source":["app"]}`}); code != 200 {
		t.Fatalf("PutRule: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "PutTargets", map[string]any{"Rule": "fn", "Targets": []any{
		map[string]any{"Id": "f", "Arn": "arn:aws:lambda:us-east-1:" + testMember + ":function:hello"}}}); code != 200 {
		t.Fatalf("PutTargets own function: %d %v", code, out)
	}
	ts, err := h.store.listTargets(context.Background(), accountKeyFor(testMember, "default"), "fn")
	if err != nil || len(ts) != 1 || ts[0].NS != memberHome {
		t.Fatalf("the member's function target %v (%v), want it in the member's home %s", ts, err, memberHome)
	}
	if code, out := ebCall(t, h, acctMember, "PutTargets", map[string]any{"Rule": "fn", "Targets": []any{
		map[string]any{"Id": "g", "Arn": "arn:aws:lambda:us-east-1:" + testMgmt + ":function:hello"}}}); code != 400 || out["__type"] != "InvalidParameterException" {
		t.Fatalf("PutTargets another account's function: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "ListTargetsByRule", map[string]any{"Rule": "fn"}); code != 200 || len(sliceOf(out["Targets"])) != 1 {
		t.Fatalf("member ListTargetsByRule: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMgmt, "ListTargetsByRule", map[string]any{"Rule": "fn"}); code != 200 || len(sliceOf(out["Targets"])) != 0 {
		t.Fatalf("the management account listed the member's rule's targets: %d %v", code, out)
	}
}

// The scheduler fires a member account's rule in that account: its event names the account and reaches the
// account's own queue.
func TestServicesPG_EventBridgeAccounts_SchedulerFiresInTheRulesAccount(t *testing.T) {
	h, db := ebFixture(t)
	mgmtQ := queueIn(t, db, testMgmt, "ticks", nil)
	memberQ := queueIn(t, db, testMember, "ticks", nil)
	if code, out := ebCall(t, h, acctMember, "PutRule", map[string]any{"Name": "tick", "ScheduleExpression": "rate(1 minute)"}); code != 200 {
		t.Fatalf("PutRule: %d %v", code, out)
	}
	if code, out := ebCall(t, h, acctMember, "PutTargets", map[string]any{"Rule": "tick", "Targets": []any{
		map[string]any{"Id": "q", "Arn": "arn:aws:sqs:us-east-1:" + testMember + ":ticks"}}}); code != 200 {
		t.Fatalf("PutTargets: %d %v", code, out)
	}
	if _, err := db.Exec(`UPDATE eb_rules SET next_fire_at=$1`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	h.tickSchedule(context.Background())
	mb := queueBodies(t, db, memberQ)
	if len(mb) != 1 || !strings.Contains(mb[0], `"account":"`+testMember+`"`) || !strings.Contains(mb[0], `arn:aws:events:us-east-1:`+testMember+`:rule/tick`) {
		t.Fatalf("the member's queue got %v, want its rule's Scheduled Event in its account", mb)
	}
	if gb := queueBodies(t, db, mgmtQ); len(gb) != 0 {
		t.Fatalf("the management account's queue of the same name got %v", gb)
	}
}

// A member account's PutEvents on another account's bus fails the entry, never landing on a bus of its own.
func TestServicesPG_EventBridgeAccounts_PutEventsOnAnotherAccountsBus(t *testing.T) {
	h, _ := ebFixture(t)
	_, out := ebCall(t, h, acctMember, "PutEvents", map[string]any{"Entries": []any{
		map[string]any{"Source": "app", "EventBusName": "arn:aws:events:us-east-1:" + testMgmt + ":event-bus/default"},
		map[string]any{"Source": "app"}}})
	es := sliceOf(out["Entries"])
	if toInt(out["FailedEntryCount"]) != 1 || len(es) != 2 || es[0].(map[string]any)["ErrorCode"] != "AccessDeniedException" || es[1].(map[string]any)["EventId"] == nil {
		t.Fatalf("PutEvents = %v", out)
	}
}
