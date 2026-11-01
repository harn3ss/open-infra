package main

// FIFO queues against a real Postgres store (OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go): group
// order, one batch of a group in flight at a time, five-minute deduplication, sequence numbers, and the
// refusals.

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
)

func (f *svcFixture) sqsCall(t *testing.T, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return f.callJSON(t, f.sqs.serve, "AmazonSQS."+op, body)
}

// receiveFIFO receives up to max messages, returning their bodies and receipt handles in order.
func (f *svcFixture) receiveFIFO(t *testing.T, q string, max int) (bodies, handles []string) {
	t.Helper()
	code, out := f.sqsCall(t, "ReceiveMessage", map[string]any{"QueueUrl": q, "MaxNumberOfMessages": max, "MessageSystemAttributeNames": []any{"All"}})
	if code != 200 {
		t.Fatalf("ReceiveMessage = %d %v", code, out)
	}
	msgs, _ := out["Messages"].([]any)
	for _, m := range msgs {
		mm := m.(map[string]any)
		bodies = append(bodies, mm["Body"].(string))
		handles = append(handles, mm["ReceiptHandle"].(string))
	}
	return bodies, handles
}

func TestServicesPG_SQSFIFO(t *testing.T) {
	f := newSvcFixture(t)
	for _, c := range []struct {
		name  string
		attrs map[string]any
	}{
		{"orders", map[string]any{"FifoQueue": "true"}},
		{"orders.fifo", map[string]any{}},
		{"plain", map[string]any{"ContentBasedDeduplication": "true"}},
	} {
		if code, out := f.sqsCall(t, "CreateQueue", map[string]any{"QueueName": c.name, "Attributes": c.attrs}); code != 400 {
			t.Errorf("CreateQueue %s %v = %d %v, want a refusal", c.name, c.attrs, code, out)
		}
	}
	code, out := f.sqsCall(t, "CreateQueue", map[string]any{"QueueName": "orders.fifo", "Attributes": map[string]any{"FifoQueue": "true"}})
	if code != 200 {
		t.Fatalf("CreateQueue FIFO = %d %v", code, out)
	}
	q := out["QueueUrl"].(string)
	_, out = f.sqsCall(t, "GetQueueAttributes", map[string]any{"QueueUrl": q, "AttributeNames": []any{"All"}})
	attrs := out["Attributes"].(map[string]any)
	if attrs["FifoQueue"] != "true" || attrs["ContentBasedDeduplication"] != "false" || attrs["DeduplicationScope"] != "queue" {
		t.Errorf("attributes = %v", attrs)
	}
	if code, _ := f.sqsCall(t, "SetQueueAttributes", map[string]any{"QueueUrl": q, "Attributes": map[string]any{"FifoQueue": "false"}}); code != 400 {
		t.Error("FifoQueue was changed after create")
	}

	send := func(body, group, dedup string) (string, string) {
		t.Helper()
		code, out := f.sqsCall(t, "SendMessage", map[string]any{"QueueUrl": q, "MessageBody": body, "MessageGroupId": group, "MessageDeduplicationId": dedup})
		if code != 200 {
			t.Fatalf("SendMessage %s = %d %v", body, code, out)
		}
		return out["MessageId"].(string), out["SequenceNumber"].(string)
	}
	for _, bad := range []map[string]any{
		{"QueueUrl": q, "MessageBody": "x", "MessageDeduplicationId": "d"},                                           // no group
		{"QueueUrl": q, "MessageBody": "x", "MessageGroupId": "g"},                                                   // no dedup, no CBD
		{"QueueUrl": q, "MessageBody": "x", "MessageGroupId": "g", "MessageDeduplicationId": "d", "DelaySeconds": 1}, // per-message delay
	} {
		if code, _ := f.sqsCall(t, "SendMessage", bad); code != 400 {
			t.Errorf("SendMessage %v = %d, want a refusal", bad, code)
		}
	}
	idA, seqA := send("a", "g1", "1")
	_, seqB := send("b", "g1", "2")
	send("c", "g1", "3")
	send("x", "g2", "4")
	if !(seqA < seqB) || len(seqA) != 20 {
		t.Errorf("sequence numbers %s, %s", seqA, seqB)
	}
	// A duplicate within the window is accepted and not enqueued: the same MessageId and SequenceNumber.
	if id, seq := send("a-again", "g1", "1"); id != idA || seq != seqA {
		t.Errorf("duplicate send = %s/%s, want %s/%s", id, seq, idA, seqA)
	}

	// One message of g1 in flight blocks the rest of g1; g2 is independent.
	b1, h1 := f.receiveFIFO(t, q, 1)
	if strings.Join(b1, ",") != "a" {
		t.Fatalf("first receive = %v, want a", b1)
	}
	b2, h2 := f.receiveFIFO(t, q, 10)
	if strings.Join(b2, ",") != "x" {
		t.Fatalf("with a in flight, receive = %v, want only g2's x", b2)
	}
	f.sqsCall(t, "DeleteMessage", map[string]any{"QueueUrl": q, "ReceiptHandle": h1[0]})
	f.sqsCall(t, "DeleteMessage", map[string]any{"QueueUrl": q, "ReceiptHandle": h2[0]})
	b3, h3 := f.receiveFIFO(t, q, 10)
	if strings.Join(b3, ",") != "b,c" {
		t.Fatalf("after a is deleted, receive = %v, want b,c in order (and no a-again)", b3)
	}
	send("d", "g1", "5")
	if b, _ := f.receiveFIFO(t, q, 10); len(b) != 0 {
		t.Errorf("with b,c in flight, g1's d was received: %v", b)
	}
	for _, h := range h3 {
		f.sqsCall(t, "DeleteMessage", map[string]any{"QueueUrl": q, "ReceiptHandle": h})
	}
	if b, _ := f.receiveFIFO(t, q, 10); strings.Join(b, ",") != "d" {
		t.Errorf("then receive = %v, want d", b)
	}

	// ContentBasedDeduplication: the body's SHA-256 is the deduplication id.
	f.sqsCall(t, "SetQueueAttributes", map[string]any{"QueueUrl": q, "Attributes": map[string]any{"ContentBasedDeduplication": "true"}})
	c1, _ := f.sqsCall(t, "SendMessage", map[string]any{"QueueUrl": q, "MessageBody": "same", "MessageGroupId": "g3"})
	_, o1 := f.sqsCall(t, "SendMessage", map[string]any{"QueueUrl": q, "MessageBody": "same", "MessageGroupId": "g3"})
	_, o2 := f.sqsCall(t, "SendMessage", map[string]any{"QueueUrl": q, "MessageBody": "same", "MessageGroupId": "g3"})
	if c1 != 200 || o1["MessageId"] != o2["MessageId"] {
		t.Errorf("content-based duplicates got different ids: %v %v", o1, o2)
	}
	// DeduplicationScope messageGroup: the same id in two groups is two messages.
	f.sqsCall(t, "SetQueueAttributes", map[string]any{"QueueUrl": q, "Attributes": map[string]any{"DeduplicationScope": "messageGroup"}})
	_, s1 := send("p", "g4", "shared")
	_, s2 := send("p", "g5", "shared")
	if s1 == s2 {
		t.Error("per-group deduplication merged two groups' messages")
	}

	// Batch: a group's entries keep the batch's order; a bad entry fails alone.
	code, out = f.sqsCall(t, "SendMessageBatch", map[string]any{"QueueUrl": q, "Entries": []any{
		map[string]any{"Id": "1", "MessageBody": "e1", "MessageGroupId": "g6", "MessageDeduplicationId": "e1"},
		map[string]any{"Id": "2", "MessageBody": "e2", "MessageGroupId": "g6", "MessageDeduplicationId": "e2"},
		map[string]any{"Id": "3", "MessageBody": "e3", "MessageDeduplicationId": "e3"},
	}})
	if ok, _ := out["Successful"].([]any); code != 200 || len(ok) != 2 {
		t.Fatalf("SendMessageBatch = %d %v", code, out)
	}
	if failed, _ := out["Failed"].([]any); len(failed) != 1 || failed[0].(map[string]any)["Code"] != "MissingParameter" {
		t.Errorf("the entry with no group: %v", out["Failed"])
	}

	// A standard queue refuses a MessageDeduplicationId; FIFO refusals elsewhere.
	_, sout := f.sqsCall(t, "CreateQueue", map[string]any{"QueueName": "std"})
	if code, _ := f.sqsCall(t, "SendMessage", map[string]any{"QueueUrl": sout["QueueUrl"], "MessageBody": "x", "MessageDeduplicationId": "d"}); code != 400 {
		t.Error("a standard queue took a MessageDeduplicationId")
	}
	if code, _ := f.sqsCall(t, "ReceiveMessage", map[string]any{"QueueUrl": q, "ReceiveRequestAttemptId": "r1"}); code != 400 {
		t.Error("ReceiveRequestAttemptId was accepted and ignored")
	}
	if code, _ := f.sqsCall(t, "SetQueueAttributes", map[string]any{"QueueUrl": q, "Attributes": map[string]any{
		"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:std","maxReceiveCount":2}`}}); code != 400 {
		t.Error("a FIFO queue took a standard dead-letter queue")
	}
	if code, body := f.callQuery(t, url.Values{"Action": {"CreateTopic"}, "Name": {"t"}}); code != 200 {
		t.Fatalf("CreateTopic = %d %s", code, body)
	}
	if code, _ := f.callQuery(t, url.Values{"Action": {"Subscribe"}, "TopicArn": {"arn:aws:sns:us-east-1:123456789012:t"}, "Protocol": {"sqs"},
		"Endpoint": {"arn:aws:sqs:us-east-1:123456789012:orders.fifo"}}); code == 200 {
		t.Error("a FIFO queue subscribed to a standard topic")
	}
	eb := newEBHandler(nil, "authz", "default", "123456789012", "us-east-1", nil, nil, f.sqs.store, discardLogger())
	if err := eb.deliver(context.Background(), ebRule{Bus: "default", Name: "r"}, ebTarget{Type: "sqs", Arn: "arn:aws:sqs:us-east-1:123456789012:orders.fifo"}, []byte("{}")); err != errFIFOTarget {
		t.Errorf("an EventBridge delivery to a FIFO queue: %v", err)
	}
}

// Concurrent consumers of one group still receive it strictly in order, one message at a time.
func TestServicesPG_SQSFIFOConcurrentConsumersKeepOrder(t *testing.T) {
	f := newSvcFixture(t)
	_, out := f.sqsCall(t, "CreateQueue", map[string]any{"QueueName": "c.fifo", "Attributes": map[string]any{"FifoQueue": "true", "ContentBasedDeduplication": "true"}})
	q := out["QueueUrl"].(string)
	const n = 12
	for i := 0; i < n; i++ {
		if code, out := f.sqsCall(t, "SendMessage", map[string]any{"QueueUrl": q, "MessageBody": string(rune('a' + i)), "MessageGroupId": "g"}); code != 200 {
			t.Fatalf("send %d = %v", i, out)
		}
	}
	var mu sync.Mutex
	var got []string
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tries := 0; tries < 200; tries++ {
				mu.Lock()
				done := len(got) >= n
				mu.Unlock()
				if done {
					return
				}
				msgs, err := f.sqs.store.receive(context.Background(), q, 1, 30e9, 0, "", true)
				if err != nil {
					t.Error(err)
					return
				}
				for _, m := range msgs {
					mu.Lock()
					got = append(got, m.Body)
					mu.Unlock()
					if _, err := f.sqs.store.deleteByHandle(context.Background(), q, m.ReceiptHandle); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()
	if len(got) != n || !sort.StringsAreSorted(got) {
		t.Errorf("received %v, want all %d in send order", got, n)
	}
}
