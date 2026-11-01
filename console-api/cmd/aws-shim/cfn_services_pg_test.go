package main

// Integration tests of a stack's service resources (cfn_services.go) against REAL Postgres stores and
// the real front-door handlers: a queue/topic/parameter/key the CloudFormation applier provisions is
// used through the SQS/SNS/SSM/KMS APIs by the names and ARNs a stack reports. Vault Transit and a
// Function are faked over HTTP. Run with OPENINFRA_TEST_PG_URI=postgres://…/postgres?sslmode=disable
// (a throwaway server: each test creates and drops its own database); skipped without it.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"
)

func freshPGDB(t *testing.T) *sql.DB {
	t.Helper()
	uri := os.Getenv("OPENINFRA_TEST_PG_URI")
	if uri == "" {
		t.Skip("OPENINFRA_TEST_PG_URI not set (a throwaway Postgres for the store-backed tests)")
	}
	admin, err := sql.Open("postgres", uri)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("svc_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(uri)
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.Exec("DROP DATABASE " + name)
		_ = admin.Close()
	})
	return db
}

// fakeVault serves the Transit calls the shim makes: login, key create/read/rotate/delete, and an
// encrypt/decrypt that binds the key name and AAD (a mismatched decrypt fails, as AES-GCM would).
func fakeVault(t *testing.T) *vaultTransit {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		p := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case p == "auth/kubernetes/login":
			_, _ = io.WriteString(w, `{"auth":{"client_token":"tok","lease_duration":3600}}`)
		case strings.HasPrefix(p, "transit/encrypt/"):
			key := strings.TrimPrefix(p, "transit/encrypt/")
			blob := base64.StdEncoding.EncodeToString([]byte(key + "|" + in["associated_data"] + "|" + in["plaintext"]))
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + blob}})
		case strings.HasPrefix(p, "transit/decrypt/"):
			key := strings.TrimPrefix(p, "transit/decrypt/")
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(in["ciphertext"], "vault:v1:"))
			parts := strings.SplitN(string(raw), "|", 3)
			if len(parts) != 3 || parts[0] != key || parts[1] != in["associated_data"] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"errors":["cipher: message authentication failed"]}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": parts[2]}})
		case r.Method == http.MethodGet && strings.HasPrefix(p, "transit/keys/"):
			_, _ = io.WriteString(w, `{"data":{"latest_version":1}}`)
		default: // key create / rotate / config / delete
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("jwt"), 0o600)
	return &vaultTransit{addr: srv.URL, role: "r", tokenPath: tok, hc: srv.Client()}
}

// fnCalls records what a faked Function was invoked with; every request to any Function host lands here.
type fnCalls struct {
	mu     sync.Mutex
	hosts  []string
	bodies [][]byte
	direct []string
}

func (f *fnCalls) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.hosts, f.bodies, f.direct = append(f.hosts, r.URL.Host), append(f.bodies, b), append(f.direct, r.Header.Get("X-Openinfra-Invoke"))
	f.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("null")), Request: r}, nil
}

func (f *fnCalls) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		got := len(f.bodies)
		f.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Function was invoked %d times, want %d", got, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type svcFixture struct {
	ap     *impersonatingApplier
	sqs    *sqsHandler
	sns    *snsHandler
	ssm    *ssmHandler
	kms    *kmsHandler
	fn     *fnCalls
	allow  *bool
	claims iam.Claims
}

func newSvcFixture(t *testing.T) *svcFixture {
	t.Helper()
	db := freshPGDB(t)
	ctx := context.Background()
	sqsSt, snsSt, ssmSt, kmsSt, owners := &sqsStore{db: db}, &snsStore{db: db}, &ssmStore{db: db}, &kmsStore{db: db}, &cfnServiceOwners{db: db}
	for _, f := range []func(context.Context) error{sqsSt.ensureSchema, snsSt.ensureSchema, ssmSt.ensureSchema, kmsSt.ensureSchema, owners.ensureSchema} {
		if err := f(ctx); err != nil {
			t.Fatal(err)
		}
	}
	allow := true
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		sar.Status.Allowed = allow
		return true, sar, nil
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vault := fakeVault(t)
	const acct, region = "123456789012", "us-east-1"
	fn := &fnCalls{}
	sqsH := newSQSHandler(cs, "authz", acct, region, sqsSt, logger)
	snsH := newSNSHandler(cs, "authz", acct, region, snsSt, sqsSt, logger)
	snsH.lambdaNS, snsH.svcSuffix, snsH.invoker = "default", "svc.test", &http.Client{Transport: fn}
	ssmH := newSSMHandler(cs, "authz", acct, region, vault, ssmSt, logger)
	kmsH := newKMSHandler(cs, nil, "policies", "authz", acct, region, vault, kmsSt, logger)
	door := &cfnDoorway{cs: cs, authzNS: "authz", ns: "open-infra-cfn", logger: logger}
	door.services = &cfnServices{sqs: sqsH, sns: snsH, ssm: ssmH, kms: kmsH, owners: owners}
	ap := &impersonatingApplier{ns: "open-infra-cfn", user: "openinfra:alice", groups: []string{"openinfra:admins"}, svc: door.services, door: door}
	return &svcFixture{ap: ap, sqs: sqsH, sns: snsH, ssm: ssmH, kms: kmsH, fn: fn, allow: &allow,
		claims: iam.Claims{Sub: "alice", Groups: []string{"openinfra:admins"}}}
}

// manifest renders a service-kind object as the cfn engine applies it.
func svcManifest(kind, name, stack string, spec map[string]any) []byte {
	b, _ := yaml.Marshal(map[string]any{
		"apiVersion": cfn.ServiceAPIVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": "open-infra-cfn", "labels": map[string]any{"cfn.openinfra.dev/stack": stack, "app.kubernetes.io/managed-by": "cfn"}},
		"spec":     spec,
	})
	return b
}

func (f *svcFixture) callJSON(t *testing.T, serve func(http.ResponseWriter, *http.Request, iam.Claims, string), target string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://shim.local:4566/", strings.NewReader(string(b)))
	r.Header.Set("X-Amz-Target", target)
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	w := httptest.NewRecorder()
	serve(w, r, f.claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *svcFixture) callQuery(t *testing.T, form url.Values) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://shim.local:4566/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.sns.serve(w, r, f.claims, "req-1")
	return w.Code, w.Body.String()
}

// A stack queue is a queue the SQS API serves: under any URL naming it, with the stack's attributes, and
// owned by its stack (a second create-only apply does nothing; deleting it removes it).
func TestServicesPG_SQSQueue(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	stackURL := "http://shim.test:4566/000000000000/st-q"
	y := svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": stackURL, "attributes": map[string]any{"VisibilityTimeout": "1"}})
	if created, err := f.ap.Create(ctx, y); err != nil || !created {
		t.Fatalf("create = %v, %v", created, err)
	}
	if created, err := f.ap.Create(ctx, y); err != nil || created {
		t.Fatalf("a second create-only apply = %v, %v (want false: it exists)", created, err)
	}
	if l, found, _ := f.ap.GetLabels(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueue, "st-q"); !found || l["cfn.openinfra.dev/stack"] != "st" {
		t.Fatalf("labels = %v (found %v)", l, found)
	}
	code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.GetQueueUrl", map[string]any{"QueueName": "st-q"})
	if code != 200 || out["QueueUrl"] != stackURL {
		t.Fatalf("GetQueueUrl = %d %v", code, out)
	}
	// Any host/account in the URL names the same queue.
	code, out = f.callJSON(t, f.sqs.serve, "AmazonSQS.SendMessage", map[string]any{"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/st-q", "MessageBody": "hello"})
	if code != 200 || out["MessageId"] == nil {
		t.Fatalf("SendMessage = %d %v", code, out)
	}
	code, out = f.callJSON(t, f.sqs.serve, "AmazonSQS.ReceiveMessage", map[string]any{"QueueUrl": stackURL})
	msgs, _ := out["Messages"].([]any)
	if code != 200 || len(msgs) != 1 || msgs[0].(map[string]any)["Body"] != "hello" {
		t.Fatalf("ReceiveMessage = %d %v", code, out)
	}
	// An update sets exactly the template's attributes: VisibilityTimeout dropped -> back to the default.
	y2 := svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": stackURL, "attributes": map[string]any{"DelaySeconds": "2"}})
	if err := f.ap.Apply(ctx, y2); err != nil {
		t.Fatal(err)
	}
	_, out = f.callJSON(t, f.sqs.serve, "AmazonSQS.GetQueueAttributes", map[string]any{"QueueUrl": stackURL, "AttributeNames": []any{"All"}})
	attrs, _ := out["Attributes"].(map[string]any)
	if attrs["VisibilityTimeout"] != "30" || attrs["DelaySeconds"] != "2" {
		t.Errorf("after the update, attributes = %v", attrs)
	}
	if spec, found, _ := f.ap.GetSpec(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueue, "st-q"); !found || spec["attributes"].(map[string]any)["DelaySeconds"] != "2" {
		t.Errorf("live spec = %v", spec)
	}
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueue, "st-q"); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.callJSON(t, f.sqs.serve, "AmazonSQS.GetQueueUrl", map[string]any{"QueueName": "st-q"}); code == 200 {
		t.Errorf("the queue survived its delete")
	}
	if err := f.ap.WaitGone(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueue, "st-q", time.Second); err != nil {
		t.Error(err)
	}
}

// A queue created through the API (no stack) carries no stack label, so the engine refuses to take it
// over; a caller who may not create the queue gets nothing.
func TestServicesPG_OwnershipAndAuthorization(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	if code, _ := f.callJSON(t, f.sqs.serve, "AmazonSQS.CreateQueue", map[string]any{"QueueName": "theirs"}); code != 200 {
		t.Fatalf("CreateQueue = %d", code)
	}
	l, found, err := f.ap.GetLabels(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueue, "theirs")
	if err != nil || !found || l["cfn.openinfra.dev/stack"] != "" {
		t.Fatalf("an API-made queue's labels = %v (found %v, %v)", l, found, err)
	}
	*f.allow = false
	_, err = f.ap.Create(ctx, svcManifest(cfn.KindSQSQueue, "denied-q", "st", map[string]any{"queueName": "denied-q", "url": "http://x/0/denied-q", "attributes": map[string]any{}}))
	if !cfn.IsUnauthorized(err) {
		t.Fatalf("a caller without sqs:CreateQueue: %v, want Unauthorized", err)
	}
	if ok, _ := f.ap.svcExists(ctx, cfn.KindSQSQueue, "denied-q"); ok {
		t.Error("the denied queue was created")
	}
}

// A stack topic publishes, through the SNS API under the stack's ARN (another account/region than the
// shim's own), to its sqs subscription (a stack queue) and its lambda subscription (a stack Function).
func TestServicesPG_SNSTopicDeliversToQueueAndFunction(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	stackTopic := "arn:aws:sns:openinfra:000000000000:st-t"
	must := func(y []byte) {
		t.Helper()
		if _, err := f.ap.Create(ctx, y); err != nil {
			t.Fatal(err)
		}
	}
	must(svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": "http://shim.test:4566/000000000000/st-q", "attributes": map[string]any{}}))
	must(svcManifest(cfn.KindSNSTopic, "st-t", "st", map[string]any{"topicName": "st-t", "topicArn": stackTopic, "attributes": map[string]any{"DisplayName": "Orders"}}))
	must(svcManifest(cfn.KindSNSSubscription, "sub-q", "st", map[string]any{"protocol": "sqs", "endpoint": "arn:aws:sqs:openinfra:000000000000:st-q", "topicArn": stackTopic, "subscriptionArn": stackTopic + ":sub-q"}))
	must(svcManifest(cfn.KindSNSSubscription, "sub-fn", "st", map[string]any{"protocol": "lambda", "endpoint": "arn:aws:lambda:openinfra:000000000000:function:st-fn", "function": "st-fn", "inStack": true, "topicArn": stackTopic, "subscriptionArn": stackTopic + ":sub-fn"}))

	code, body := f.callQuery(t, url.Values{"Action": {"Publish"}, "TopicArn": {stackTopic}, "Message": {"order-1"}, "Subject": {"new"}})
	if code != 200 || !strings.Contains(body, "MessageId") {
		t.Fatalf("Publish = %d %s", code, body)
	}
	_, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.ReceiveMessage", map[string]any{"QueueUrl": "http://shim.test:4566/000000000000/st-q"})
	msgs, _ := out["Messages"].([]any)
	if len(msgs) != 1 || !strings.Contains(msgs[0].(map[string]any)["Body"].(string), `"Message":"order-1"`) {
		t.Fatalf("the queue got %v", out)
	}
	f.fn.waitFor(t, 1)
	if f.fn.hosts[0] != "st-fn.open-infra-cfn.svc.test" || f.fn.direct[0] != "direct" {
		t.Errorf("invoked %s (direct=%q), want the stack's Function in its namespace, direct", f.fn.hosts[0], f.fn.direct[0])
	}
	var ev struct {
		Records []struct {
			EventSource string
			Sns         struct{ Message, Subject, TopicArn string }
		}
	}
	_ = json.Unmarshal(f.fn.bodies[0], &ev)
	if len(ev.Records) != 1 || ev.Records[0].EventSource != "aws:sns" || ev.Records[0].Sns.Message != "order-1" || ev.Records[0].Sns.Subject != "new" {
		t.Errorf("the Function got %s", f.fn.bodies[0])
	}
	// Deleting the topic removes it (and its subscriptions).
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindSNSTopic, "st-t"); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.callQuery(t, url.Values{"Action": {"Publish"}, "TopicArn": {stackTopic}, "Message": {"x"}}); code == 200 {
		t.Error("publish to a deleted topic succeeded")
	}
}

// A lambda Subscribe through the SNS front door needs the caller to be able to invoke the Function.
func TestServicesPG_SNSLambdaSubscribeFence(t *testing.T) {
	f := newSvcFixture(t)
	if code, body := f.callQuery(t, url.Values{"Action": {"CreateTopic"}, "Name": {"api-t"}}); code != 200 {
		t.Fatalf("CreateTopic = %d %s", code, body)
	}
	topic := "arn:aws:sns:us-east-1:123456789012:api-t"
	sub := url.Values{"Action": {"Subscribe"}, "TopicArn": {topic}, "Protocol": {"lambda"}, "Endpoint": {"arn:aws:lambda:us-east-1:123456789012:function:fn1"}}
	if code, body := f.callQuery(t, sub); code != 200 || !strings.Contains(body, "SubscriptionArn") {
		t.Fatalf("Subscribe lambda = %d %s", code, body)
	}
	if code, _ := f.callQuery(t, url.Values{"Action": {"Publish"}, "TopicArn": {topic}, "Message": {"m"}}); code != 200 {
		t.Fatal("publish failed")
	}
	f.fn.waitFor(t, 1)
	if f.fn.hosts[0] != "fn1.default.svc.test" {
		t.Errorf("invoked %s, want the Lambda API's namespace", f.fn.hosts[0])
	}
	*f.allow = false
	if code, _ := f.callQuery(t, sub); code == 200 {
		t.Error("a caller who may not invoke the Function subscribed it")
	}
}

// A lambda subscription to a function by name — through the SNS front door, or a stack's subscription to
// a function outside that stack — delivers where the function is: here, another stack's.
func TestServicesPG_SNSLambdaFindsAStackFunction(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	f.sns.fns = newFnLocator(fnDyn(fnClaim("open-infra-cfn", "other-fn")), discardLogger(), "default", "open-infra-cfn")
	if code, body := f.callQuery(t, url.Values{"Action": {"CreateTopic"}, "Name": {"api-t"}}); code != 200 {
		t.Fatalf("CreateTopic = %d %s", code, body)
	}
	topic := "arn:aws:sns:us-east-1:123456789012:api-t"
	sub := url.Values{"Action": {"Subscribe"}, "TopicArn": {topic}, "Protocol": {"lambda"}, "Endpoint": {"arn:aws:lambda:us-east-1:123456789012:function:other-fn"}}
	if code, body := f.callQuery(t, sub); code != 200 {
		t.Fatalf("Subscribe lambda = %d %s", code, body)
	}
	stackTopic := "arn:aws:sns:us-east-1:123456789012:st-t"
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSNSTopic, "st-t", "st", map[string]any{"topicName": "st-t", "topicArn": stackTopic, "attributes": map[string]any{}})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSNSSubscription, "sub-fn", "st", map[string]any{"protocol": "lambda", "endpoint": "arn:aws:lambda:us-east-1:123456789012:function:other-fn", "function": "other-fn", "topicArn": stackTopic, "subscriptionArn": stackTopic + ":sub-fn"})); err != nil {
		t.Fatal(err)
	}
	for _, tp := range []string{topic, stackTopic} {
		if code, _ := f.callQuery(t, url.Values{"Action": {"Publish"}, "TopicArn": {tp}, "Message": {"m"}}); code != 200 {
			t.Fatalf("publish to %s failed", tp)
		}
	}
	f.fn.waitFor(t, 2)
	for _, h := range f.fn.hosts {
		if h != "other-fn.open-infra-cfn.svc.test" {
			t.Errorf("invoked %s, want the function where it is", h)
		}
	}
}

// A stack parameter is a parameter the SSM API serves; a SecureString is stored encrypted and decrypts
// for a caller who may.
func TestServicesPG_SSMParameter(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSSMParameter, "st-P-ABC", "st", map[string]any{"name": "st-P-ABC", "type": "String", "value": "v1"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSSMParameter, "/app/secret", "st", map[string]any{"name": "/app/secret", "type": "SecureString", "value": "s3cr3t"})); err != nil {
		t.Fatal(err)
	}
	code, out := f.callJSON(t, f.ssm.serve, "AmazonSSM.GetParameter", map[string]any{"Name": "st-P-ABC"})
	if code != 200 || out["Parameter"].(map[string]any)["Value"] != "v1" {
		t.Fatalf("GetParameter = %d %v", code, out)
	}
	code, out = f.callJSON(t, f.ssm.serve, "AmazonSSM.GetParameter", map[string]any{"Name": "/app/secret", "WithDecryption": true})
	if code != 200 || out["Parameter"].(map[string]any)["Value"] != "s3cr3t" {
		t.Fatalf("GetParameter (decrypt) = %d %v", code, out)
	}
	if err := f.ap.Apply(ctx, svcManifest(cfn.KindSSMParameter, "st-P-ABC", "st", map[string]any{"name": "st-P-ABC", "type": "String", "value": "v2"})); err != nil {
		t.Fatal(err)
	}
	_, out = f.callJSON(t, f.ssm.serve, "AmazonSSM.GetParameter", map[string]any{"Name": "st-P-ABC"})
	if p := out["Parameter"].(map[string]any); p["Value"] != "v2" || p["Version"] != float64(2) {
		t.Errorf("after the update: %v", p)
	}
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindSSMParameter, "st-P-ABC"); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.callJSON(t, f.ssm.serve, "AmazonSSM.GetParameter", map[string]any{"Name": "st-P-ABC"}); code == 200 {
		t.Error("the parameter survived its delete")
	}
}

// A stack key is a key the KMS API serves: listed, usable by id and by the stack's alias, and scheduled
// for deletion (with the stack's pending window) when the stack deletes it.
func TestServicesPG_KMSKeyAndAlias(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	keyID := "11111111-2222-4333-8444-555555555555"
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindKMSKey, keyID, "st", map[string]any{"keyId": keyID, "arn": "arn:aws:kms:openinfra:000000000000:key/" + keyID, "description": "app key", "pendingWindowInDays": 7})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindKMSAlias, "alias/app", "st", map[string]any{"aliasName": "alias/app", "targetKeyId": keyID})); err != nil {
		t.Fatal(err)
	}
	code, out := f.callJSON(t, f.kms.serve, "TrentService.ListKeys", map[string]any{})
	if code != 200 || !strings.Contains(fmt.Sprint(out["Keys"]), keyID) {
		t.Fatalf("ListKeys = %d %v", code, out)
	}
	code, out = f.callJSON(t, f.kms.serve, "TrentService.Encrypt", map[string]any{"KeyId": "alias/app", "Plaintext": base64.StdEncoding.EncodeToString([]byte("hi"))})
	if code != 200 || out["CiphertextBlob"] == nil {
		t.Fatalf("Encrypt via the alias = %d %v", code, out)
	}
	code, out = f.callJSON(t, f.kms.serve, "TrentService.Decrypt", map[string]any{"CiphertextBlob": out["CiphertextBlob"]})
	if pt, _ := base64.StdEncoding.DecodeString(fmt.Sprint(out["Plaintext"])); code != 200 || string(pt) != "hi" {
		t.Fatalf("Decrypt = %d %v", code, out)
	}
	// An update changes the description (as UpdateKeyDescription).
	if err := f.ap.Apply(ctx, svcManifest(cfn.KindKMSKey, keyID, "st", map[string]any{"keyId": keyID, "description": "renamed", "pendingWindowInDays": 7})); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := f.kms.store.getKey(ctx, keyID); m.Description != "renamed" {
		t.Errorf("description = %q", m.Description)
	}
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindKMSAlias, "alias/app"); err != nil {
		t.Fatal(err)
	}
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindKMSKey, keyID); err != nil {
		t.Fatal(err)
	}
	m, _, _ := f.kms.store.getKey(ctx, keyID)
	if m.State != "PendingDeletion" || !m.DeletionDate.Valid || m.DeletionDate.Time.Sub(time.Now()) > 8*24*time.Hour {
		t.Errorf("after the stack's delete: state %s, deletion %v", m.State, m.DeletionDate)
	}
	if ok, _ := f.ap.svcExists(ctx, cfn.KindKMSKey, keyID); ok {
		t.Error("a key pending deletion still counts as the stack's")
	}
}

// The applier's view of a service object is what the engine reads: Get* for a missing one is not found.
func TestServicesPG_MissingIsNotFound(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	for _, k := range []string{cfn.KindSQSQueue, cfn.KindSNSTopic, cfn.KindSNSSubscription, cfn.KindSSMParameter, cfn.KindKMSKey, cfn.KindKMSAlias} {
		if _, found, err := f.ap.GetSpec(ctx, cfn.ServiceAPIVersion, k, "nope"); err != nil || found {
			t.Errorf("%s: GetSpec found=%v err=%v", k, found, err)
		}
		if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, k, "nope"); err != nil {
			t.Errorf("%s: deleting a missing one: %v", k, err)
		}
	}
}
