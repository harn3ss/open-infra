package main

// A member account's stack provisions its queues, topics, parameters, keys and aliases into its own
// account's space (real Postgres stores, OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go): each is
// stored under the account's key and recorded as its stack's in its account, the same names live in the
// management account independently, and neither account's stack reaches the other's.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"sigs.k8s.io/yaml"
)

// memberSvcManifest renders a service-kind object as the engine applies one of a member account's stack:
// in its home.
func memberSvcManifest(kind, name, stack string, spec map[string]any) []byte {
	b, _ := yaml.Marshal(map[string]any{
		"apiVersion": cfn.ServiceAPIVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": memberHome, "labels": map[string]any{"cfn.openinfra.dev/stack": stack, "app.kubernetes.io/managed-by": "cfn"}},
		"spec":     spec,
	})
	return b
}

// memberApplier is the fixture's applier for the member account's bob (an operation of a member account's
// stack, in its home), with every door deciding by IAM policy (doorAccountsAuthz).
func (f *svcFixture) memberApplier(t *testing.T) (*impersonatingApplier, context.Context) {
	t.Helper()
	authz := doorAccountsAuthz(t)
	f.ap.door.authz, f.sqs.authz, f.sns.authz, f.ssm.authz, f.kms.authz = authz, authz, authz, authz, authz
	claims := bobClaims
	ap := &impersonatingApplier{ns: memberHome, user: "openinfra:" + testMember + ":bob", svc: f.ap.svc, door: f.ap.door,
		claims: &claims, account: testMember, home: memberHome}
	return ap, ap.accountCtx(context.Background())
}

func TestServicesPG_MemberStackProvisionsInItsAccount(t *testing.T) {
	f := newSvcFixture(t)
	mem, mctx := f.memberApplier(t)
	ctx := context.Background()
	const mgmtKey, memberKey = "22222222-2222-4222-8222-222222222222", "11111111-1111-4111-8111-111111111111"
	mgmtTopic, memberTopic := "arn:aws:sns:us-east-1:123456789012:st-t", "arn:aws:sns:us-east-1:"+testMember+":st-t"
	mgmtQueue, memberQueue := "http://shim.test:4566/123456789012/st-q", "http://shim.test:4566/"+testMember+"/st-q"
	create := func(ap *impersonatingApplier, c context.Context, y []byte) {
		t.Helper()
		if created, err := ap.Create(c, y); err != nil || !created {
			t.Fatalf("create = %v, %v", created, err)
		}
	}
	// The management account's stack, then a member account's of the same names.
	create(f.ap, ctx, svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": mgmtQueue, "attributes": map[string]any{}}))
	create(f.ap, ctx, svcManifest(cfn.KindSNSTopic, "st-t", "st", map[string]any{"topicName": "st-t", "topicArn": mgmtTopic, "attributes": map[string]any{}}))
	create(f.ap, ctx, svcManifest(cfn.KindSSMParameter, "/st/p", "st", map[string]any{"name": "/st/p", "type": "String", "value": "mgmt"}))
	create(f.ap, ctx, svcManifest(cfn.KindKMSKey, mgmtKey, "st", map[string]any{"keyId": mgmtKey, "arn": "arn:aws:kms:us-east-1:123456789012:key/" + mgmtKey}))
	create(f.ap, ctx, svcManifest(cfn.KindKMSAlias, "alias/st", "st", map[string]any{"aliasName": "alias/st", "targetKeyId": mgmtKey}))

	create(mem, mctx, memberSvcManifest(cfn.KindSQSQueue, "st-q", "mst", map[string]any{"queueName": "st-q", "url": memberQueue, "attributes": map[string]any{}}))
	create(mem, mctx, memberSvcManifest(cfn.KindSNSTopic, "st-t", "mst", map[string]any{"topicName": "st-t", "topicArn": memberTopic, "attributes": map[string]any{}}))
	create(mem, mctx, memberSvcManifest(cfn.KindSSMParameter, "/st/p", "mst", map[string]any{"name": "/st/p", "type": "String", "value": "member"}))
	create(mem, mctx, memberSvcManifest(cfn.KindKMSKey, memberKey, "mst", map[string]any{"keyId": memberKey, "arn": "arn:aws:kms:us-east-1:" + testMember + ":key/" + memberKey}))
	create(mem, mctx, memberSvcManifest(cfn.KindKMSAlias, "alias/st", "mst", map[string]any{"aliasName": "alias/st", "targetKeyId": memberKey}))

	// Each is stored under its account's key: the management account's exactly where it always was.
	if u, ok, _ := f.sqs.store.queueURLByName(ctx, "st-q"); !ok || u != mgmtQueue {
		t.Errorf("the management account's queue: %s %v", u, ok)
	}
	if u, ok, _ := f.sqs.store.queueURLByName(ctx, testMember+":st-q"); !ok || u != memberQueue {
		t.Errorf("the member account's queue, under its key: %s %v", u, ok)
	}
	if a, ok, _ := f.sns.store.topicARNByName(ctx, "st-t"); !ok || a != mgmtTopic {
		t.Errorf("the management account's topic: %s %v", a, ok)
	}
	if a, ok, _ := f.sns.store.topicARNByName(ctx, testMember+":st-t"); !ok || a != memberTopic {
		t.Errorf("the member account's topic, under its key: %s %v", a, ok)
	}
	for key, want := range map[string]string{"/st/p": "mgmt", testMember + ":/st/p": "member"} {
		p, ok, _ := f.ssm.store.getParam(ctx, key)
		v, _, _ := f.ssm.store.getVersion(ctx, key, p.CurrentVer)
		if !ok || v != want {
			t.Errorf("parameter %s = %q %v, want %q", key, v, ok, want)
		}
	}
	for key, want := range map[string]string{"alias/st": mgmtKey, testMember + ":alias/st": memberKey} {
		if k, ok, _ := f.kms.store.aliasTarget(ctx, key); !ok || k != want {
			t.Errorf("alias %s -> %s %v, want %s", key, k, ok, want)
		}
	}
	// Each is its own account's stack's, and each account's stack sees its own.
	for _, c := range []struct {
		ap    *impersonatingApplier
		ctx   context.Context
		stack string
	}{{f.ap, ctx, "st"}, {mem, mctx, "mst"}} {
		for kind, name := range map[string]string{cfn.KindSQSQueue: "st-q", cfn.KindSNSTopic: "st-t", cfn.KindSSMParameter: "/st/p", cfn.KindKMSAlias: "alias/st"} {
			if l, found, err := c.ap.GetLabels(c.ctx, cfn.ServiceAPIVersion, kind, name); err != nil || !found || l["cfn.openinfra.dev/stack"] != c.stack {
				t.Errorf("%s %s of stack %s: %v %v %v", kind, name, c.stack, l, found, err)
			}
		}
	}
	if spec, found, _ := mem.GetSpec(mctx, cfn.ServiceAPIVersion, cfn.KindSSMParameter, "/st/p"); !found || spec["value"] != "member" {
		t.Errorf("the member account's parameter, as its stack reads it: %v", spec)
	}
	// The member account's API reaches its own.
	if code, out := memberDoorCaller().call(t, f.sqs.serve, "AmazonSQS.GetQueueUrl", map[string]any{"QueueName": "st-q"}); code != 200 || out["QueueUrl"] != memberQueue {
		t.Errorf("member GetQueueUrl: %d %v", code, out)
	}
	// A member account's stack never reaches the management account's key, by id or by alias.
	if ok, _ := mem.svcExists(mctx, cfn.KindKMSKey, mgmtKey); ok {
		t.Error("the management account's key exists for a member account's stack")
	}
	if _, err := mem.Create(mctx, memberSvcManifest(cfn.KindKMSAlias, "alias/borrow", "mst", map[string]any{"aliasName": "alias/borrow", "targetKeyId": mgmtKey})); err == nil {
		t.Error("a member account's alias pointed at the management account's key")
	}
	// Ownership rows carry their account.
	rows := map[string]string{}
	r, err := f.ap.svc.owners.(*cfnServiceOwners).db.QueryContext(ctx, `SELECT account, stack FROM cfn_service_resources WHERE kind=$1 AND name=$2`, cfn.KindSQSQueue, "st-q")
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var a, s string
		_ = r.Scan(&a, &s)
		rows[a] = s
	}
	r.Close()
	if len(rows) != 2 || rows[""] != "st" || rows[testMember] != "mst" {
		t.Errorf("ownership rows of st-q: %v", rows)
	}

	// The member account's stack deletes its own; the management account's stay.
	for kind, name := range map[string]string{cfn.KindKMSAlias: "alias/st", cfn.KindSQSQueue: "st-q", cfn.KindSNSTopic: "st-t", cfn.KindSSMParameter: "/st/p"} {
		if err := mem.Delete(mctx, cfn.ServiceAPIVersion, kind, name); err != nil {
			t.Fatalf("member delete %s: %v", kind, err)
		}
		if ok, _ := mem.svcExists(mctx, kind, name); ok {
			t.Errorf("the member account's %s survived its delete", kind)
		}
		if ok, _ := f.ap.svcExists(ctx, kind, name); !ok {
			t.Errorf("a member account's delete removed the management account's %s", kind)
		}
		if _, _, found, _ := f.ap.svc.owners.get(ctx, kind, name); !found {
			t.Errorf("a member account's delete removed the management account's ownership of %s", kind)
		}
	}
}

// A member account's stack subscribes its topic to its own queue; to another account's queue only when that
// queue's policy lets the topic send to it, as the SNS front door decides a Subscribe.
func TestServicesPG_MemberSubscriptionDeliversInItsAccount(t *testing.T) {
	f := newSvcFixture(t)
	mem, mctx := f.memberApplier(t)
	ctx := context.Background()
	memberTopic := "arn:aws:sns:us-east-1:" + testMember + ":st-t"
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSQSQueue, "theirs", "st", map[string]any{"queueName": "theirs",
		"url": "http://shim.test:4566/123456789012/theirs", "attributes": map[string]any{}})); err != nil {
		t.Fatal(err)
	}
	for _, y := range [][]byte{
		memberSvcManifest(cfn.KindSQSQueue, "st-q", "mst", map[string]any{"queueName": "st-q", "url": "http://shim.test:4566/" + testMember + "/st-q", "attributes": map[string]any{}}),
		memberSvcManifest(cfn.KindSNSTopic, "st-t", "mst", map[string]any{"topicName": "st-t", "topicArn": memberTopic, "attributes": map[string]any{}}),
	} {
		if _, err := mem.Create(mctx, y); err != nil {
			t.Fatal(err)
		}
	}
	own := memberSvcManifest(cfn.KindSNSSubscription, "sub-own", "mst", map[string]any{"protocol": "sqs",
		"endpoint": "arn:aws:sqs:us-east-1:" + testMember + ":st-q", "topicArn": memberTopic, "subscriptionArn": memberTopic + ":sub-own"})
	if _, err := mem.Create(mctx, own); err != nil {
		t.Fatalf("a member account's topic subscribes its own queue: %v", err)
	}
	foreign := memberSvcManifest(cfn.KindSNSSubscription, "sub-theirs", "mst", map[string]any{"protocol": "sqs",
		"endpoint": "arn:aws:sqs:us-east-1:123456789012:theirs", "topicArn": memberTopic, "subscriptionArn": memberTopic + ":sub-theirs"})
	if _, err := mem.Create(mctx, foreign); !cfn.IsUnauthorized(err) {
		t.Fatalf("a member account's topic subscribed another account's queue its policy does not open: %v", err)
	}
	if _, ok, _ := f.sns.store.subByArn(ctx, memberTopic+":sub-theirs"); ok {
		t.Error("the refused subscription was stored")
	}
}

// The ownership table becomes account-keyed once: every earlier row is the management account's, and the
// same resource name may then be recorded in each account.
func TestServicesPG_ServiceOwnersAccountMigration(t *testing.T) {
	db := freshPGDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
CREATE TABLE cfn_service_resources (
  kind text NOT NULL, name text NOT NULL, stack text NOT NULL, namespace text NOT NULL,
  spec jsonb NOT NULL DEFAULT '{}', updated timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (kind, name));
INSERT INTO cfn_service_resources (kind, name, stack, namespace) VALUES ('SQSQueue', 'q', 'old', 'open-infra-cfn');`); err != nil {
		t.Fatal(err)
	}
	o := &cfnServiceOwners{db: db}
	for i := 0; i < 2; i++ { // idempotent
		if err := o.ensureSchema(ctx); err != nil {
			t.Fatalf("ensureSchema pass %d: %v", i+1, err)
		}
	}
	if stack, _, found, err := o.get(ctx, "SQSQueue", "q"); err != nil || !found || stack != "old" {
		t.Fatalf("an earlier row is the management account's: %s %v %v", stack, found, err)
	}
	mctx := inAccountScope(memberCtx())
	if _, _, found, _ := o.get(mctx, "SQSQueue", "q"); found {
		t.Fatal("a member account sees the management account's row")
	}
	if err := o.put(mctx, "SQSQueue", "q", "new", memberHome, nil); err != nil {
		t.Fatalf("the same name in a member account: %v", err)
	}
	if stack, _, _, _ := o.get(ctx, "SQSQueue", "q"); stack != "old" {
		t.Fatalf("a member account's row replaced the management account's: %s", stack)
	}
	var cols string
	if err := db.QueryRowContext(ctx, `SELECT string_agg(a.attname, ',' ORDER BY k.ord) FROM pg_constraint c
  CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
 WHERE c.conrelid = 'cfn_service_resources'::regclass AND c.contype = 'p'`).Scan(&cols); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if cols != "account,kind,name" {
		t.Fatalf("primary key = %q", cols)
	}
	if err := o.del(mctx, "SQSQueue", "q"); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := o.get(ctx, "SQSQueue", "q"); !found {
		t.Fatal("a member account's delete removed the management account's row")
	}
}
