package main

// SQS keeps each account's queues apart (real Postgres stores, OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): a member account's queues are its own — under its own store keys, with URLs
// and ARNs naming its account, listed only for it — beside the management account's of the same names,
// which it never sees, reads, overwrites or lists, by URL or by name. Another account's queue is reached
// only across accounts, as on AWS: its own policy must let the caller in.

import (
	"context"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

// withAccountPolicies gives both doors the organization (testDirectory: the member account team-a) and a
// policy world in mode: the management account's alice (mgmtDoorCaller) allowed — in legacy by RBAC, as
// before — and the member account's bob (memberDoorCaller) by his identity policy: every SQS, SNS and
// Lambda action on any resource, so a refusal here is the doors keeping accounts apart (another account's
// resource still needs its own policy).
func (f *svcFixture) withAccountPolicies(t *testing.T, mode string) {
	t.Helper()
	f.sqs.accounts = testDirectory()
	all := []policyengine.Statement{dpAllow([]string{"sqs:*", "sns:*", "lambda:*"}, "*")}
	a := checkerInMode(t, mode,
		dataplaneauthz.PolicyDoc{Name: "alice-all", AppliesTo: []string{"User::alice"}, Statements: all},
		dataplaneauthz.PolicyDoc{Name: "bob-all", AppliesTo: []string{"User::" + memberHome + "/bob"}, Statements: all})
	f.sqs.authz, f.sns.authz = a, a
}

func (f *svcFixture) sqsAs(t *testing.T, c doorCaller, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return c.call(t, f.sqs.serve, "AmazonSQS."+op, body)
}

func (f *svcFixture) createQueueAs(t *testing.T, c doorCaller, name string, attrs map[string]any) string {
	t.Helper()
	body := map[string]any{"QueueName": name}
	if attrs != nil {
		body["Attributes"] = attrs
	}
	code, out := f.sqsAs(t, c, "CreateQueue", body)
	u, _ := out["QueueUrl"].(string)
	if code != 200 || u == "" {
		t.Fatalf("CreateQueue %s = %d %v", name, code, out)
	}
	return u
}

// drain receives (and deletes) what queueURL holds, as c.
func (f *svcFixture) drain(t *testing.T, c doorCaller, queueURL string) []string {
	t.Helper()
	code, out := f.sqsAs(t, c, "ReceiveMessage", map[string]any{"QueueUrl": queueURL, "MaxNumberOfMessages": 10, "VisibilityTimeout": 0})
	if code != 200 {
		t.Fatalf("ReceiveMessage %s = %d %v", queueURL, code, out)
	}
	var bodies []string
	msgs, _ := out["Messages"].([]any)
	for _, m := range msgs {
		mm := m.(map[string]any)
		bodies = append(bodies, mm["Body"].(string))
		f.sqsAs(t, c, "DeleteMessage", map[string]any{"QueueUrl": queueURL, "ReceiptHandle": mm["ReceiptHandle"]})
	}
	return bodies
}

func queueURLList(out map[string]any) []string {
	var urls []string
	l, _ := out["QueueUrls"].([]any)
	for _, u := range l {
		urls = append(urls, u.(string))
	}
	return urls
}

func TestServicesPG_SQSKeepsEachAccountsQueuesApart(t *testing.T) {
	f := newSvcFixture(t)
	f.withAccountPolicies(t, "legacy")
	ctx := context.Background()
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()

	mgmtJobs := f.createQueueAs(t, mgmt, "jobs", nil)
	if mgmtJobs != "http://shim.local:4566/"+testAcct+"/jobs" {
		t.Fatalf("the management account's queue URL changed: %s", mgmtJobs)
	}
	memberJobs := f.createQueueAs(t, member, "jobs", map[string]any{"VisibilityTimeout": "7"})
	if memberJobs != "http://shim.local:4566/"+testMember+"/jobs" {
		t.Fatalf("a member account's queue URL must carry its account: %s", memberJobs)
	}
	f.createQueueAs(t, mgmt, "mgmt-only", nil)

	// Each is stored under its own account's key; the management account's exactly as before.
	if key, ok, _ := f.sqs.store.queueKeyByURL(ctx, mgmtJobs); !ok || key != "jobs" {
		t.Errorf("the management account's queue key = %q %v, want the bare name", key, ok)
	}
	if key, ok, _ := f.sqs.store.queueKeyByURL(ctx, memberJobs); !ok || key != testMember+":jobs" {
		t.Errorf("the member account's queue key = %q %v", key, ok)
	}
	// The same name, a different configuration: the member's create neither failed (QueueNameExists)
	// nor touched the management account's queue.
	if attrs, _, _, _ := f.sqs.store.queueAttrs(ctx, mgmtJobs); attrs["VisibilityTimeout"] != "" {
		t.Errorf("the member's create changed the management account's queue: %v", attrs)
	}

	// GetQueueUrl and GetQueueAttributes answer in the caller's account.
	if _, out := f.sqsAs(t, member, "GetQueueUrl", map[string]any{"QueueName": "jobs"}); out["QueueUrl"] != memberJobs {
		t.Errorf("member GetQueueUrl = %v", out)
	}
	if _, out := f.sqsAs(t, mgmt, "GetQueueUrl", map[string]any{"QueueName": "jobs"}); out["QueueUrl"] != mgmtJobs {
		t.Errorf("management GetQueueUrl = %v", out)
	}
	if code, out := f.sqsAs(t, member, "GetQueueUrl", map[string]any{"QueueName": "mgmt-only"}); code != 400 || !strings.Contains(toStr(out["__type"]), "QueueDoesNotExist") {
		t.Errorf("a member's GetQueueUrl found the management account's queue: %d %v", code, out)
	}
	_, out := f.sqsAs(t, member, "GetQueueAttributes", map[string]any{"QueueUrl": memberJobs, "AttributeNames": []any{"All"}})
	if attrs, _ := out["Attributes"].(map[string]any); attrs["QueueArn"] != "arn:aws:sqs:us-east-1:"+testMember+":jobs" || attrs["VisibilityTimeout"] != "7" {
		t.Errorf("member GetQueueAttributes = %v", out)
	}
	_, out = f.sqsAs(t, mgmt, "GetQueueAttributes", map[string]any{"QueueUrl": mgmtJobs, "AttributeNames": []any{"QueueArn"}})
	if attrs, _ := out["Attributes"].(map[string]any); attrs["QueueArn"] != "arn:aws:sqs:us-east-1:"+testAcct+":jobs" {
		t.Errorf("management GetQueueAttributes = %v", out)
	}

	// ListQueues lists the caller's account's queues alone.
	if _, out := f.sqsAs(t, member, "ListQueues", map[string]any{}); strings.Join(queueURLList(out), ",") != memberJobs {
		t.Errorf("member ListQueues = %v", queueURLList(out))
	}
	if _, out := f.sqsAs(t, mgmt, "ListQueues", map[string]any{}); len(queueURLList(out)) != 2 || strings.Contains(strings.Join(queueURLList(out), ","), testMember) {
		t.Errorf("management ListQueues = %v, want its two queues and not the member's", queueURLList(out))
	}
	if _, out := f.sqsAs(t, member, "ListQueues", map[string]any{"QueueNamePrefix": "mgmt"}); len(queueURLList(out)) != 0 {
		t.Errorf("member ListQueues by prefix = %v", queueURLList(out))
	}

	// Messages stay in their account's queue.
	if code, out := f.sqsAs(t, member, "SendMessage", map[string]any{"QueueUrl": memberJobs, "MessageBody": "member-1"}); code != 200 {
		t.Fatalf("member SendMessage = %d %v", code, out)
	}
	if got := f.drain(t, mgmt, mgmtJobs); len(got) != 0 {
		t.Errorf("the member's message reached the management account's queue: %v", got)
	}
	if got := f.drain(t, member, memberJobs); strings.Join(got, ",") != "member-1" {
		t.Errorf("member receive = %v", got)
	}

	// A queue is its name — within the account the URL names: a member's URL from another endpoint is its
	// own queue, and a member's URL never resolves to the management account's queue of that name.
	if code, out := f.sqsAs(t, member, "SendMessage", map[string]any{"QueueUrl": "https://sqs.us-east-1.amazonaws.com/" + testMember + "/jobs", "MessageBody": "member-2"}); code != 200 {
		t.Fatalf("member SendMessage by another endpoint's URL = %d %v", code, out)
	}
	if got := f.drain(t, member, memberJobs); strings.Join(got, ",") != "member-2" {
		t.Errorf("member receive = %v", got)
	}
	if code, out := f.sqsAs(t, member, "SendMessage", map[string]any{"QueueUrl": "http://shim.local:4566/" + testMember + "/mgmt-only", "MessageBody": "leak"}); code != 400 || !strings.Contains(toStr(out["__type"]), "QueueDoesNotExist") {
		t.Errorf("a member's URL reached the management account's queue of that name: %d %v", code, out)
	}
	if code, out := f.sqsAs(t, member, "DeleteQueue", map[string]any{"QueueUrl": "http://shim.local:4566/" + testMember + "/mgmt-only"}); code != 400 {
		t.Errorf("a member deleted by name what only the management account has: %d %v", code, out)
	}
	// The management account's URL fallback keeps working as before — for any account id but a member
	// account's: a URL naming a member account means that account's queue, which it does not have.
	if code, out := f.sqsAs(t, mgmt, "SendMessage", map[string]any{"QueueUrl": "https://elsewhere.example/" + testAcct + "/mgmt-only", "MessageBody": "mgmt-1"}); code != 200 {
		t.Fatalf("management SendMessage by another endpoint's URL = %d %v", code, out)
	}
	if code, out := f.sqsAs(t, mgmt, "SendMessage", map[string]any{"QueueUrl": "https://elsewhere.example/555555555555/mgmt-only", "MessageBody": "mgmt-2"}); code != 200 {
		t.Fatalf("management SendMessage by a URL minted with another account id = %d %v", code, out)
	}
	if code, out := f.sqsAs(t, mgmt, "SendMessage", map[string]any{"QueueUrl": "https://elsewhere.example/" + testMember + "/mgmt-only", "MessageBody": "member-named"}); code == 200 {
		t.Errorf("a URL naming a member account reached the management account's queue of that name: %v", out)
	}
	if got := f.drain(t, mgmt, "http://shim.local:4566/"+testAcct+"/mgmt-only"); strings.Join(got, ",") != "mgmt-1,mgmt-2" {
		t.Errorf("management receive = %v", got)
	}

	// Another account's queue, named by its URL, is reached across accounts: denied both ways without its
	// policy — the management account's caller included (the legacy check knows no accounts).
	if code, out := f.sqsAs(t, member, "SendMessage", map[string]any{"QueueUrl": mgmtJobs, "MessageBody": "x"}); code != 403 {
		t.Errorf("a member sent to the management account's queue without its policy: %d %v", code, out)
	}
	if code, out := f.sqsAs(t, mgmt, "SendMessage", map[string]any{"QueueUrl": memberJobs, "MessageBody": "x"}); code != 403 {
		t.Errorf("the management account sent to a member's queue without its policy: %d %v", code, out)
	}
	if code, out := f.sqsAs(t, mgmt, "DeleteQueue", map[string]any{"QueueUrl": memberJobs}); code != 403 {
		t.Errorf("the management account deleted a member's queue: %d %v", code, out)
	}
	if code, out := f.sqsAs(t, member, "GetQueueUrl", map[string]any{"QueueName": "jobs", "QueueOwnerAWSAccountId": testAcct}); code != 403 {
		t.Errorf("a member read the management account's queue URL without its policy: %d %v", code, out)
	}
	// The queue's own policy letting the member account in: the member's identity grant then reaches it
	// for what the policy allows, and nothing more. (Its Resource names the management account as the IAM
	// policy world does, the install's identity — the fixture's handlers report another id in URLs.)
	grant := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + testMember + `:root"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:` + testMgmt + `:jobs"}]}`
	if code, out := f.sqsAs(t, mgmt, "SetQueueAttributes", map[string]any{"QueueUrl": mgmtJobs, "Attributes": map[string]any{"Policy": grant}}); code != 200 {
		t.Fatalf("SetQueueAttributes Policy = %d %v", code, out)
	}
	f.withAccountPolicies(t, "enforce") // a resource policy is read when IAM policy decides
	if code, out := f.sqsAs(t, member, "SendMessage", map[string]any{"QueueUrl": mgmtJobs, "MessageBody": "across"}); code != 200 {
		t.Fatalf("a member's send the management account's queue policy allows = %d %v", code, out)
	}
	if code, out := f.sqsAs(t, member, "PurgeQueue", map[string]any{"QueueUrl": mgmtJobs}); code != 403 {
		t.Errorf("a member purged the management account's queue (its policy allows SendMessage only): %d %v", code, out)
	}
	if got := f.drain(t, mgmt, mgmtJobs); strings.Join(got, ",") != "across" {
		t.Errorf("management receive = %v, want the member's cross-account message", got)
	}

	// The member deleting its queue leaves the management account's of the same name.
	if code, out := f.sqsAs(t, member, "DeleteQueue", map[string]any{"QueueUrl": memberJobs}); code != 200 {
		t.Fatalf("member DeleteQueue = %d %v", code, out)
	}
	if _, _, ok, _ := f.sqs.store.queueAttrs(ctx, mgmtJobs); !ok {
		t.Error("deleting the member's queue deleted the management account's")
	}
}

// A queue's dead-letter queue is its own account's: a member's redrive moves its messages into its own
// dead-letter queue, never the management account's of that name, and a RedrivePolicy naming another
// account's queue is refused.
func TestServicesPG_SQSRedriveStaysInTheQueuesAccount(t *testing.T) {
	f := newSvcFixture(t)
	f.withAccountPolicies(t, "legacy")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtDLQ := f.createQueueAs(t, mgmt, "dlq", nil)
	memberDLQ := f.createQueueAs(t, member, "dlq", nil)

	across := `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:` + testAcct + `:dlq","maxReceiveCount":"1"}`
	if code, out := f.sqsAs(t, member, "CreateQueue", map[string]any{"QueueName": "work", "Attributes": map[string]any{"RedrivePolicy": across}}); code != 400 {
		t.Errorf("a member's RedrivePolicy naming the management account's queue = %d %v, want refused", code, out)
	}
	own := `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:` + testMember + `:dlq","maxReceiveCount":"1"}`
	work := f.createQueueAs(t, member, "work", map[string]any{"RedrivePolicy": own})
	if code, out := f.sqsAs(t, member, "SendMessage", map[string]any{"QueueUrl": work, "MessageBody": "poison"}); code != 200 {
		t.Fatalf("SendMessage = %d %v", code, out)
	}
	for i := 0; i < 2; i++ { // the second receive exceeds maxReceiveCount 1: the message is dead-lettered
		f.sqsAs(t, member, "ReceiveMessage", map[string]any{"QueueUrl": work, "VisibilityTimeout": 0})
	}
	if got := f.drain(t, mgmt, mgmtDLQ); len(got) != 0 {
		t.Errorf("a member's message was dead-lettered into the management account's queue: %v", got)
	}
	if got := f.drain(t, member, memberDLQ); strings.Join(got, ",") != "poison" {
		t.Errorf("the member's dead-letter queue = %v, want the poison message", got)
	}
}
