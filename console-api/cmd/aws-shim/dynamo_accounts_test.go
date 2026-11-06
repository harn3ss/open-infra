package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ddbMember is a member account's request context as the router builds it for the DynamoDB door: the
// member's identity and home, marked account-scoped.
func ddbMember() context.Context { return inAccountScope(memberCtx()) }

// ddbBob is the member account's bob; ddbMgmtBob the management account's.
var (
	ddbBob     = iam.Claims{Sub: "bob", Account: testMember}
	ddbMgmtBob = iam.Claims{Sub: "bob"}
)

// ddbAllowAll is a policy world in which both accounts' bob may do anything with DynamoDB.
func ddbAllowAll(t *testing.T) *dataplaneauthz.Checker {
	t.Helper()
	return checkerInMode(t, "enforce", dataplaneauthz.PolicyDoc{Name: "ddb",
		AppliesTo:  []string{"User::bob", "User::" + memberHome + "/bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"dynamodb:*"}, "*")}})
}

func ddbServe(h *dynamoHandler, ctx context.Context, claims iam.Claims, op, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDB_20120810."+op, body).WithContext(ctx), claims, "r")
	return w
}

// The DynamoDB door and its Streams twin keep each account's tables apart, so they are account-scoped.
func TestDynamoAccounts_DoorsAreAccountScoped(t *testing.T) {
	if !accountScopedServices["dynamodb"] || !accountScopedServices["dynamodbstreams"] {
		t.Fatalf("dynamodb / dynamodbstreams must be account-scoped: %v", accountScopedServices)
	}
}

// Every table name a member account's request carries becomes its account's key; the management account's
// request is left exactly as it came.
func TestDynamoAccounts_RequestNamesBecomeTheAccountsKeys(t *testing.T) {
	requests := map[string]string{
		"GetItem":                   `{"TableName":"orders","Key":{"id":{"S":"1"}}}`,
		"BatchGetItem":              `{"RequestItems":{"orders":{"Keys":[{"id":{"S":"1"}}]},"users":{"Keys":[{"id":{"S":"2"}}]}}}`,
		"BatchWriteItem":            `{"RequestItems":{"orders":[{"PutRequest":{"Item":{"id":{"S":"1"}}}}]}}`,
		"TransactWriteItems":        `{"TransactItems":[{"Put":{"TableName":"orders","Item":{"id":{"S":"1"}}}},{"ConditionCheck":{"TableName":"users","Key":{"id":{"S":"2"}},"ConditionExpression":"attribute_exists(id)"}},{"Delete":{"TableName":"orders","Key":{"id":{"S":"3"}}}},{"Update":{"TableName":"users","Key":{"id":{"S":"4"}},"UpdateExpression":"SET a = :a"}}]}`,
		"TransactGetItems":          `{"TransactItems":[{"Get":{"TableName":"orders","Key":{"id":{"S":"1"}}}}]}`,
		"RestoreTableToPointInTime": `{"SourceTableName":"orders","TargetTableName":"orders-restored","UseLatestRestorableTime":true}`,
	}
	parse := func(s string) map[string]any {
		m := map[string]any{}
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for op, raw := range requests {
		table, _ := parse(raw)["TableName"].(string)

		mgmt := parse(raw)
		key, refusal := scopeDynamoRequest(context.Background(), op, table, mgmt)
		if refusal != "" || key != table || !reflect.DeepEqual(mgmt, parse(raw)) {
			t.Errorf("%s: the management account's request changed: key %q refusal %q body %v", op, key, refusal, mgmt)
		}

		member := parse(raw)
		key, refusal = scopeDynamoRequest(ddbMember(), op, table, member)
		if refusal != "" {
			t.Fatalf("%s: %s", op, refusal)
		}
		if table != "" && (key != testMember+":"+table || member["TableName"] != key) {
			t.Errorf("%s: the table is %q (body %v), want the member account's key", op, key, member["TableName"])
		}
		b, _ := json.Marshal(member)
		for _, name := range []string{"orders", "users", "orders-restored"} {
			if strings.Contains(raw, `"`+name+`"`) && (strings.Contains(string(b), `"`+name+`"`) || !strings.Contains(string(b), `"`+testMember+":"+name+`"`)) {
				t.Errorf("%s: %q is not the member account's key everywhere: %s", op, name, b)
			}
		}
	}
}

// A name with ":" is no table's (AWS: [a-zA-Z0-9_.-]+) and could be one account's key in another's: it is
// refused, for the management account (whose bare names are its keys) as for a member, before anything is
// authorized — a caller with no grant at all is told so.
func TestDynamoAccounts_ColonNameIsRefused(t *testing.T) {
	h := newDynamoHandler(csWithSAR(false), "default", nil, nil, "", discardLogger())
	h.authz = checkerInMode(t, "enforce")
	cases := []struct {
		ctx    context.Context
		claims iam.Claims
		op     string
		body   string
	}{
		{context.Background(), ddbMgmtBob, "GetItem", `{"TableName":"` + testMember + `:orders","Key":{"id":{"S":"1"}}}`},
		{context.Background(), ddbMgmtBob, "DescribeTable", `{"TableName":"` + testMember + `:orders"}`},
		{context.Background(), ddbMgmtBob, "BatchGetItem", `{"RequestItems":{"` + testMember + `:orders":{"Keys":[{"id":{"S":"1"}}]}}}`},
		{context.Background(), ddbMgmtBob, "TransactGetItems", `{"TransactItems":[{"Get":{"TableName":"` + testMember + `:orders","Key":{"id":{"S":"1"}}}}]}`},
		{context.Background(), ddbMgmtBob, "RestoreTableToPointInTime", `{"SourceTableName":"orders","TargetTableName":"` + testMember + `:orders"}`},
		{context.Background(), ddbMgmtBob, "ListTables", `{"ExclusiveStartTableName":"` + testMember + `:a"}`},
		{ddbMember(), ddbBob, "PutItem", `{"TableName":"000000000000:orders","Item":{"id":{"S":"1"}}}`},
	}
	for _, c := range cases {
		w := ddbServe(h, c.ctx, c.claims, c.op, c.body)
		if w.Code != http.StatusBadRequest || !strings.HasSuffix(decodeDynamoErr(t, w)["__type"], "#ValidationException") ||
			!strings.Contains(w.Body.String(), "regular expression pattern") {
			t.Errorf("%s %s: %d %s, want AWS's ValidationException", c.op, c.body, w.Code, w.Body.String())
		}
	}
	// A valid name still reaches authorization.
	if w := ddbServe(h, context.Background(), ddbMgmtBob, "GetItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`); w.Code != http.StatusForbidden {
		t.Errorf("a valid name must reach authorization: %d %s", w.Code, w.Body.String())
	}
}

// A member account's principal is decided on its own account's tables (a same-account request): its
// identity policy alone admits it, and without a grant it is refused.
func TestDynamoAccounts_MemberIsDecidedInItsOwnAccount(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "", discardLogger())
	h.authz = ddbAllowAll(t)
	if w := ddbServe(h, ddbMember(), ddbBob, "GetItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`); w.Code != http.StatusNotImplemented {
		t.Errorf("the member account's bob allowed dynamodb:* must reach its own table (here: no data layer, 501): %d %s", w.Code, w.Body.String())
	}
	h.authz = checkerInMode(t, "enforce")
	if w := ddbServe(h, ddbMember(), ddbBob, "GetItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`); w.Code != http.StatusForbidden {
		t.Errorf("a member account's principal without a grant must be refused: %d %s", w.Code, w.Body.String())
	}
}

// A key reads back as the caller's name for it, and a table's ARNs carry the account it belongs to: the
// member account's for its tables, the install's own (exactly as before) for the management account's.
func TestDynamoAccounts_NamesAndARNs(t *testing.T) {
	member := ddbMember()
	if n := tableName(member, accountKey(member, "orders")); n != "orders" {
		t.Errorf("tableName(member key) = %q", n)
	}
	if n := tableName(context.Background(), "orders"); n != "orders" {
		t.Errorf("tableName(management key) = %q", n)
	}
	h := &dynamoHandler{account: testMgmt, region: "us-east-1"}
	if got, want := dynamoTableARN(h.region, h.arnAccount(member), "orders"), "arn:aws:dynamodb:us-east-1:"+testMember+":table/orders"; got != want {
		t.Errorf("member TableArn = %q, want %q", got, want)
	}
	if got, want := dynamoStreamARN(h.region, h.arnAccount(context.Background()), "orders"), "arn:aws:dynamodb:us-east-1:"+testMgmt+":table/orders/stream/orders"; got != want {
		t.Errorf("management stream ARN = %q, want %q", got, want)
	}
	s := &ddbStreamsHandler{account: testMgmt, region: "us-east-1"}
	if got := s.streamARN(member, "orders"); got != "arn:aws:dynamodb:us-east-1:"+testMember+":table/orders/stream/orders" {
		t.Errorf("member stream ARN = %q", got)
	}
}

// ListTables reads a member account's keys' range alone; the management account's listing reads every key
// and keeps those that are its own.
func TestDynamoAccounts_ListTablesRange(t *testing.T) {
	member := ddbMember()
	if f := tableKeyIDFilter(member, ""); f["$gt"] != testMember+":" || f["$lt"] != testMember+";" {
		t.Errorf("member range from the start = %v", f)
	}
	if f := tableKeyIDFilter(member, "m"); f["$gt"] != testMember+":m" || f["$lt"] != testMember+";" {
		t.Errorf("member range after m = %v", f)
	}
	if f := tableKeyIDFilter(context.Background(), ""); len(f) != 0 {
		t.Errorf("management range from the start = %v, want none", f)
	}
	if f := tableKeyIDFilter(context.Background(), "m"); len(f) != 1 || f["$gt"] != "m" {
		t.Errorf("management range after m = %v", f)
	}
	for _, key := range []string{testMember + ":orders", "912345678902:orders"} {
		if _, ok := nameOfAccountKey(context.Background(), key); ok {
			t.Errorf("the management account's listing keeps a member account's key %q", key)
		}
	}
}

// A declared table belongs to the account of its claim's namespace: a namespace labelled with a member
// account is that account's; an unlabelled one, a platform namespace or one labelled with the management
// account is the management account's; a label that is no account id places it in none.
func TestDynamoAccounts_DeclaredTableAccounts(t *testing.T) {
	ns := func(name, id string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{accounts.LabelAccountID: id}}}
	}
	h := &dynamoHandler{cs: fake.NewSimpleClientset(ns(memberHome, testMember), ns("team-a-dev", testMember),
		ns("legacy", testMgmt), ns("open-infra-aws-shim", testMember), ns("odd", "not-an-id"),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}})}
	ta, err := h.declaredTableAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{memberHome: testMember, "team-a-dev": testMember, "legacy": testMgmt,
		"open-infra-aws-shim": testMgmt, "plain": testMgmt, "": testMgmt}
	for n, acct := range want {
		if got, ok := ta.of(n); !ok || got != acct {
			t.Errorf("namespace %q: account %q (%v), want %q", n, got, ok, acct)
		}
	}
	if _, ok := ta.of("odd"); ok {
		t.Error("a namespace whose label is no account id must place its tables in no account")
	}
}

// A stack's table hooks act in the stack's account: a member account's declaration is not the management
// account's (whose stack would otherwise wait on it, and then drop its own table of that name), and is the
// member account's.
func TestDynamoAccounts_StackTableDeclarationIsTheAccounts(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "openinfra-dynamo-table-" + memberHome + "-orders", Namespace: shimNS,
			Labels: map[string]string{tableConfigLabel: "orders", tableNamespaceLabel: memberHome}},
		Data: map[string]string{"tableName": "orders", "keyAttrs": `["id"]`},
	}
	home := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: memberHome, Labels: map[string]string{accounts.LabelAccountID: testMember}}}
	h := &dynamoHandler{cs: fake.NewSimpleClientset(cm, home), tableNS: shimNS, logger: discardLogger()}
	if declared, err := h.tableDeclared(context.Background(), "orders"); err != nil || declared {
		t.Errorf("the management account sees the member account's declaration as its own: %v %v", declared, err)
	}
	if declared, err := h.tableDeclared(memberCtx(), "orders"); err != nil || !declared {
		t.Errorf("the member account must see its own declaration: %v %v", declared, err)
	}
}

// A member account's restore labels its recovery cluster with the table's name and account (":" is no
// label value's); the management account's label is as it always was.
func TestDynamoAccounts_RestoreClusterLabels(t *testing.T) {
	labelsOf := func(src string) map[string]string {
		c := buildDynamoRecoveryCluster("ns", "dynamo-docdb", "store", "dynamo-restore-x", "", src, dynamoClusterSpec{})
		return c["metadata"].(map[string]any)["labels"].(map[string]string)
	}
	if l := labelsOf(testMember + ":orders"); l["openinfra.dev/dynamo-restore-of"] != "orders" || l["openinfra.dev/dynamo-restore-account"] != testMember {
		t.Errorf("member restore labels = %v", l)
	}
	if l := labelsOf("orders"); l["openinfra.dev/dynamo-restore-of"] != "orders" || l["openinfra.dev/dynamo-restore-account"] != "" {
		t.Errorf("management restore labels = %v", l)
	}
}

func ddbStreamsServe(h *ddbStreamsHandler, ctx context.Context, claims iam.Claims, op, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDBStreams_20120810."+op, body).WithContext(ctx), claims, "r")
	return w
}

// A member account's stream ARN names its own account; one naming another account (the management
// account's stream of a table of the same name) is cross-account, refused as AWS refuses it without a
// resource policy. A name with ":" — in a TableName, an ARN or a hand-written iterator — is refused for
// every account, so no account reaches another's stream by spelling its key.
func TestDynamoAccounts_StreamsStayInTheAccount(t *testing.T) {
	h := newDDBStreamsHandler(csWithSAR(true), "default", testMgmt, "us-east-1", nil, nil, discardLogger())
	h.authz = ddbAllowAll(t)
	mgmtARN := "arn:aws:dynamodb:us-east-1:" + testMgmt + ":table/orders/stream/orders"
	ownARN := "arn:aws:dynamodb:us-east-1:" + testMember + ":table/orders/stream/orders"

	w := ddbStreamsServe(h, ddbMember(), ddbBob, "DescribeStream", `{"StreamArn":"`+mgmtARN+`"}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDeniedException") {
		t.Errorf("a member account reading the management account's stream: %d %s", w.Code, w.Body.String())
	}
	// Its own ARN is decided and served (here: no store, 501).
	if w := ddbStreamsServe(h, ddbMember(), ddbBob, "DescribeStream", `{"StreamArn":"`+ownARN+`"}`); w.Code != http.StatusNotImplemented {
		t.Errorf("a member account's own stream must be served: %d %s", w.Code, w.Body.String())
	}
	colon := []struct {
		ctx    context.Context
		claims iam.Claims
		op     string
		body   string
	}{
		{context.Background(), ddbMgmtBob, "ListStreams", `{"TableName":"` + testMember + `:orders"}`},
		{context.Background(), ddbMgmtBob, "DescribeStream", `{"StreamArn":"arn:aws:dynamodb:us-east-1:` + testMgmt + `:table/` + testMember + `:orders/stream/x"}`},
		{context.Background(), ddbMgmtBob, "GetRecords", `{"ShardIterator":"` + encodeIterator(shardIterator{Stream: testMember + ":orders", Shard: ddbStreamShard, NextSeq: 1}) + `"}`},
		{ddbMember(), ddbBob, "GetRecords", `{"ShardIterator":"` + encodeIterator(shardIterator{Stream: testMgmt + ":orders", Shard: ddbStreamShard, NextSeq: 1}) + `"}`},
	}
	for _, c := range colon {
		if w := ddbStreamsServe(h, c.ctx, c.claims, c.op, c.body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "ValidationException") {
			t.Errorf("%s %s: %d %s, want a ValidationException", c.op, c.body, w.Code, w.Body.String())
		}
	}
}
