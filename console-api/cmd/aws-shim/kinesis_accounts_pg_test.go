package main

// Each account's streams are its own (real Postgres store, OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): the same stream name in both accounts, each with its own ARN, shards and
// records; a shard iterator reads only the account's stream it was issued for, and neither account
// describes, lists, reads or deletes the other's.

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestKinesisPG_EachAccountKeepsItsOwnStreams(t *testing.T) {
	ctx := context.Background()
	st := &kinesisStore{db: freshPGDB(t)}
	if err := st.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	h := newKinesisHandler(csWithSAR(true), "authz", testMgmt, "us-east-1", st, discardLogger())
	h.authz = doorAccountsAuthz(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	kin := func(c doorCaller, op string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return c.call(t, h.serve, "Kinesis_20131202."+op, body)
	}
	data := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	const shard = "shardId-000000000000"

	for _, c := range []struct {
		who  doorCaller
		word string
	}{{mgmt, "mgmt-record"}, {member, "member-record"}} {
		if code, out := kin(c.who, "CreateStream", map[string]any{"StreamName": "orders", "ShardCount": 1}); code != 200 {
			t.Fatalf("CreateStream = %d %v", code, out)
		}
		if code, out := kin(c.who, "PutRecord", map[string]any{"StreamName": "orders", "PartitionKey": "k", "Data": data(c.word)}); code != 200 {
			t.Fatalf("PutRecord = %d %v", code, out)
		}
	}
	if code, out := kin(member, "CreateStream", map[string]any{"StreamName": "member-only", "ShardCount": 1}); code != 200 {
		t.Fatalf("CreateStream = %d %v", code, out)
	}
	if _, ok, _ := st.getStream(ctx, "orders"); !ok {
		t.Error("the management account's stream is stored as it always was")
	}
	if _, ok, _ := st.getStream(ctx, testMember+":orders"); !ok {
		t.Error("the member account's stream is stored under its account's key")
	}

	// Each describes its own, with its own ARN, and reads its own records through its own iterator.
	iterators := map[string]string{}
	for _, c := range []struct {
		who        doorCaller
		acct, word string
	}{{mgmt, testMgmt, "mgmt-record"}, {member, testMember, "member-record"}} {
		_, out := kin(c.who, "DescribeStreamSummary", map[string]any{"StreamName": "orders"})
		d, _ := out["StreamDescriptionSummary"].(map[string]any)
		if d["StreamName"] != "orders" || d["StreamARN"] != "arn:aws:kinesis:us-east-1:"+c.acct+":stream/orders" {
			t.Errorf("DescribeStreamSummary (%s) = %v", c.acct, out)
		}
		_, out = kin(c.who, "GetShardIterator", map[string]any{"StreamName": "orders", "ShardId": shard, "ShardIteratorType": "TRIM_HORIZON"})
		it, _ := out["ShardIterator"].(string)
		iterators[c.acct] = it
		code, out := kin(c.who, "GetRecords", map[string]any{"ShardIterator": it})
		recs := sliceOf(out["Records"])
		if code != 200 || len(recs) != 1 || recs[0].(map[string]any)["Data"] != data(c.word) {
			t.Errorf("GetRecords (%s) = %d %v", c.acct, code, out)
		}
		if next, _ := out["NextShardIterator"].(string); next == "" {
			t.Errorf("GetRecords (%s) gave no NextShardIterator", c.acct)
		} else if code, _ := kin(c.who, "GetRecords", map[string]any{"ShardIterator": next}); code != 200 {
			t.Errorf("GetRecords (%s) with its NextShardIterator = %d", c.acct, code)
		}
	}
	// An iterator reads only the account's stream it was issued for.
	if code, out := kin(mgmt, "GetRecords", map[string]any{"ShardIterator": iterators[testMember]}); code != 400 || len(sliceOf(out["Records"])) != 0 {
		t.Errorf("the management account read the member account's stream through its iterator: %d %v", code, out)
	}
	if code, out := kin(member, "GetRecords", map[string]any{"ShardIterator": iterators[testMgmt]}); code != 400 || len(sliceOf(out["Records"])) != 0 {
		t.Errorf("the member account read the management account's stream through its iterator: %d %v", code, out)
	}
	forged := encodeIterator(shardIterator{Stream: testMember + ":orders", Shard: shard, NextSeq: 1})
	if code, _ := kin(mgmt, "GetRecords", map[string]any{"ShardIterator": forged}); code != 400 {
		t.Errorf("the management account read the member account's stream through a forged iterator: %d", code)
	}

	// Listings: each account's own streams alone.
	_, out := kin(member, "ListStreams", map[string]any{})
	if ns := sliceOf(out["StreamNames"]); len(ns) != 2 || ns[0] != "member-only" || ns[1] != "orders" {
		t.Errorf("the member account's ListStreams = %v", out)
	}
	_, out = kin(mgmt, "ListStreams", map[string]any{})
	if ns := sliceOf(out["StreamNames"]); len(ns) != 1 || ns[0] != "orders" {
		t.Errorf("the management account's ListStreams = %v", out)
	}

	// The management account never reaches the member account's stream by its store key, nor makes one.
	for _, op := range []string{"DescribeStream", "PutRecord", "DeleteStream"} {
		if code, out := kin(mgmt, op, map[string]any{"StreamName": testMember + ":member-only", "PartitionKey": "k", "Data": data("x")}); code != 400 || jsonErrType(out) != "ResourceNotFoundException" {
			t.Errorf("the management account's %s on the member account's store key = %d %v", op, code, out)
		}
	}
	if code, out := kin(mgmt, "CreateStream", map[string]any{"StreamName": testMember + ":planted"}); code != 400 || jsonErrType(out) != "ValidationException" {
		t.Errorf("the management account created a stream under a member account's key: %d %v", code, out)
	}
	if code, _ := kin(member, "DescribeStream", map[string]any{"StreamName": "planted"}); code != 400 {
		t.Errorf("a planted stream appeared in the member account: %d", code)
	}

	// Deleting the member account's stream leaves the management account's of the same name.
	if code, out := kin(member, "DeleteStream", map[string]any{"StreamName": "orders"}); code != 200 {
		t.Fatalf("DeleteStream = %d %v", code, out)
	}
	if code, out := kin(mgmt, "GetRecords", map[string]any{"ShardIterator": iterators[testMgmt]}); code != 200 || len(sliceOf(out["Records"])) != 1 {
		t.Errorf("the management account's stream after the member account deleted its own: %d %v", code, out)
	}
	// The retention reaper trims every account's records by its own stream's retention, and keeps the rest.
	if _, err := st.reap(ctx); err != nil {
		t.Fatal(err)
	}
	if code, out := kin(mgmt, "GetRecords", map[string]any{"ShardIterator": iterators[testMgmt]}); code != 200 || len(sliceOf(out["Records"])) != 1 {
		t.Errorf("the reaper trimmed a record inside its retention: %d %v", code, out)
	}
}

// Kinesis keeps each account's streams apart, so the router decides a member account's principal there on
// its own account's streams.
func TestKinesis_IsAccountScoped(t *testing.T) {
	if !accountScopedServices["kinesis"] {
		t.Error("kinesis is not listed as account-scoped")
	}
}
