// SQS front door for the aws-shim.
//
// Recognizes SQS requests in the AWS JSON protocol (the operation named in X-Amz-Target:
// AmazonSQS.<Op>, which is what current SDKs and the aws CLI v2 speak), authenticates them through
// the shared SigV4 path, authorizes them with the same one-policy-world checks every other front door
// uses (coarse SubjectAccessReview + fine-grained Cedar dataPlane at QUEUE granularity), executes them
// against a Postgres-backed store, and speaks SQS's dialect.
//
// Faithful semantics: a per-receive opaque ReceiptHandle a stale handle can never
// reuse; visibility timeout with per-message ChangeMessageVisibility (0 = immediate redeliver);
// at-least-once, unordered standard queues; maxReceiveCount → DLQ with an observable
// ApproximateReceiveCount; long polling that returns an empty success; and MD5OfMessageBody /
// MD5OfMessageAttributes computed exactly as AWS does so SDK verification passes.
//
// A queue's Policy decides the deliveries the shim itself makes to it (an SNS topic's, an EventBridge
// rule's; resource_policy.go); a policy outside what that honors is refused where it is set.
//
// FIFO queues (.fifo) keep SQS's contract — group ordering, five-minute deduplication, sequence numbers
// (sqs_fifo.go).
//
// Deliberate carve-outs, refused honestly rather than faked (never a silent divergence):
//   - the legacy AWS query protocol — current SDKs use JSON; a query-only client is refused.
//
// See docs/aws-shim.md for the full divergence list.
package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type sqsHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *sqsStore // nil => data layer not configured (honest 501)
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger
	// urlBase is the shim's own queue URL base (SQS_QUEUE_URL_BASE): the URL a queue is recorded under
	// when its creator called by an AWS name (queueURLs).
	urlBase string
}

// defaultQueueURLBase is the shim's in-cluster queue URL base, unless SQS_QUEUE_URL_BASE names another.
const defaultQueueURLBase = "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566"

func newSQSHandler(cs kubernetes.Interface, authzNS, account, region string, store *sqsStore, logger *slog.Logger) *sqsHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &sqsHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, logger: logger}
}

// --- error dialect (AWS JSON) ---

func writeSQSError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "com.amazonaws.sqs#" + code, "message": message})
}

func writeSQSJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *sqsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeSQSError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForSQSOp maps an SQS operation to the coarse RBAC verb its SubjectAccessReview checks. Note
// ReceiveMessage is a "get" (the consume read) while DeleteMessage is a "delete": a principal with
// read-but-not-delete is a real, deliberate SQS configuration (a consumer that can read but not ack),
// and this mapping honors it — the fine-grained Cedar action (sqs:ReceiveMessage vs sqs:DeleteMessage)
// enforces it precisely at queue granularity.
func verbForSQSOp(op string) (string, bool) {
	switch op {
	case "GetQueueUrl", "GetQueueAttributes", "ListQueues", "ReceiveMessage":
		return "get", true
	case "CreateQueue", "SetQueueAttributes", "SendMessage", "SendMessageBatch",
		"ChangeMessageVisibility", "ChangeMessageVisibilityBatch":
		return "create", true
	case "DeleteQueue", "DeleteMessage", "DeleteMessageBatch", "PurgeQueue":
		return "delete", true
	}
	return "", false
}

func (h *sqsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		// No X-Amz-Target: either a legacy query-protocol call (Action=... form) or malformed. Current
		// SDKs use the JSON protocol; refuse the legacy form honestly rather than half-answering it.
		if r.PostFormValue("Action") != "" {
			writeSQSError(w, http.StatusBadRequest, "InvalidAction", requestID,
				"the open-infra shim implements the SQS JSON protocol (X-Amz-Target); the legacy query protocol is not supported")
			return
		}
		writeSQSError(w, http.StatusBadRequest, "MissingAction", requestID, "No operation named in the X-Amz-Target header.")
		return
	}
	verb, known := verbForSQSOp(op)
	if !known {
		writeSQSError(w, http.StatusBadRequest, "InvalidAction", requestID, "Unrecognized SQS operation "+op+".")
		return
	}
	body := readJSONBody(r)

	queueName := sqsAuthzQueue(op, body)

	// One policy world: the coarse impersonated SubjectAccessReview (table-agnostic, as S3/DynamoDB in v1).
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, queueName); !allowed {
		writeSQSError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only tighten. Scoped to the queue when we have one;
	// this is where sqs:ReceiveMessage is separable from sqs:DeleteMessage. An assumed role is checked on
	// every op — ListQueues on Queue::* (dataPlaneDenied).
	if denied, reason := dataPlaneDenied(r.Context(), h.authz, claims, "sqs:"+op, "Queue", queueName, r); denied {
		writeSQSError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
		return
	}
	if h.store == nil {
		writeSQSError(w, http.StatusNotImplemented, "InternalFailure", requestID,
			"the SQS data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}

	ctx := r.Context()
	h.resolveLegacyQueueURL(ctx, body) // a queue made before the account changed answers to either URL (identity_compat.go)
	// A queue is its name: a QueueUrl naming another host or account (the URL a stack reported, one
	// minted for another endpoint of this shim) means the queue of that name.
	if u, _ := body["QueueUrl"].(string); u != "" {
		if stored, found, err := h.canonicalURL(ctx, u); err == nil && found {
			body["QueueUrl"] = stored
		}
	}
	switch op {
	case "CreateQueue":
		h.createQueue(ctx, w, r, requestID, body)
	case "GetQueueUrl":
		h.getQueueURL(ctx, w, r, requestID, body)
	case "GetQueueAttributes":
		h.getQueueAttributes(ctx, w, requestID, body)
	case "SetQueueAttributes":
		h.setQueueAttributes(ctx, w, requestID, body)
	case "DeleteQueue":
		h.deleteQueue(ctx, w, requestID, body)
	case "ListQueues":
		h.listQueues(ctx, w, r, requestID, body)
	case "SendMessage":
		h.sendMessage(ctx, w, requestID, body)
	case "SendMessageBatch":
		h.sendMessageBatch(ctx, w, requestID, body)
	case "ReceiveMessage":
		h.receiveMessage(ctx, w, requestID, body)
	case "DeleteMessage":
		h.deleteMessage(ctx, w, requestID, body)
	case "DeleteMessageBatch":
		h.deleteMessageBatch(ctx, w, requestID, body)
	case "ChangeMessageVisibility":
		h.changeMessageVisibility(ctx, w, requestID, body)
	case "PurgeQueue":
		h.purgeQueue(ctx, w, requestID, body)
	default:
		writeSQSError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"SQS "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- queue operations ---

func (h *sqsHandler) createQueue(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any) {
	name, _ := body["QueueName"].(string)
	if name == "" {
		writeSQSError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "CreateQueue requires a QueueName.")
		return
	}
	attrs := stringMap(body["Attributes"])
	if e := checkQueueType(name, attrs, nil, true); e != nil {
		writeSQSError(w, http.StatusBadRequest, e.code, requestID, e.msg)
		return
	}
	if err := checkResourcePolicy(attrs[policyAttr], h.queueARN(name)); err != nil {
		writeSQSError(w, http.StatusBadRequest, "InvalidAttributeValue", requestID, "Invalid value for the parameter Policy: "+err.Error())
		return
	}
	if v, ok := attrs[policyAttr]; ok && strings.TrimSpace(v) == "" {
		delete(attrs, policyAttr)
	}
	url, answer := h.queueURLs(r, name)
	existed, err := h.store.createQueue(ctx, name, url, attrs)
	if err == errQueueExistsDiff {
		writeSQSError(w, http.StatusBadRequest, "QueueNameExists", requestID,
			"A queue already exists with the same name and a different configuration.")
		return
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	_ = existed // idempotent same-config create returns the URL as AWS does
	writeSQSJSON(w, requestID, map[string]any{"QueueUrl": answer})
}

func (h *sqsHandler) getQueueURL(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any) {
	name, _ := body["QueueName"].(string)
	url, ok, err := h.store.queueURLByName(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	writeSQSJSON(w, requestID, map[string]any{"QueueUrl": h.answerURL(r, url)})
}

func (h *sqsHandler) getQueueAttributes(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	attrs, created, ok, err := h.store.queueAttrs(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	avail, inflight, err := h.store.counts(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	// Merge stored attributes with AWS defaults + the computed/read-only ones.
	out := map[string]string{
		"VisibilityTimeout":             "30",
		"MessageRetentionPeriod":        "345600",
		"DelaySeconds":                  "0",
		"ReceiveMessageWaitTimeSeconds": "0",
		"MaximumMessageSize":            "262144",
	}
	if isFIFO(attrs) {
		for k, v := range fifoQueueDefaults {
			out[k] = v
		}
	}
	for k, v := range attrs {
		out[k] = v
	}
	out["ApproximateNumberOfMessages"] = strconv.Itoa(avail)
	out["ApproximateNumberOfMessagesNotVisible"] = strconv.Itoa(inflight)
	out["QueueArn"] = h.queueARN(queueNameFromURL(url))
	out["CreatedTimestamp"] = strconv.FormatInt(created.Unix(), 10)

	// Honor a requested AttributeNames filter (All / specific names); default is All.
	names := stringSlice(body["AttributeNames"])
	if len(names) > 0 && !containsStr(names, "All") {
		filtered := map[string]string{}
		for _, n := range names {
			if v, ok := out[n]; ok {
				filtered[n] = v
			}
		}
		out = filtered
	}
	writeSQSJSON(w, requestID, map[string]any{"Attributes": out})
}

func (h *sqsHandler) setQueueAttributes(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	attrs := stringMap(body["Attributes"])
	have, _, found, err := h.store.queueAttrs(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	if e := checkQueueType(queueNameFromURL(url), attrs, have, false); e != nil {
		writeSQSError(w, http.StatusBadRequest, e.code, requestID, e.msg)
		return
	}
	if doc, set := attrs[policyAttr]; set {
		// A queue policy decides the deliveries the shim makes to the queue (resource_policy.go); one it
		// cannot honor is refused rather than kept and ignored. An empty Policy removes it, as on AWS.
		if err := checkResourcePolicy(doc, h.queueARN(queueNameFromURL(url))); err != nil {
			writeSQSError(w, http.StatusBadRequest, "InvalidAttributeValue", requestID, "Invalid value for the parameter Policy: "+err.Error())
			return
		}
	}
	ok, err := h.store.setQueueAttrs(ctx, url, attrs)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	writeSQSJSON(w, requestID, map[string]any{})
}

func (h *sqsHandler) deleteQueue(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	ok, err := h.store.deleteQueue(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	writeSQSJSON(w, requestID, map[string]any{})
}

func (h *sqsHandler) listQueues(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any) {
	prefix, _ := body["QueueNamePrefix"].(string)
	urls, err := h.store.listQueues(ctx, prefix, 1000)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	for i, u := range urls {
		urls[i] = h.answerURL(r, u)
	}
	writeSQSJSON(w, requestID, map[string]any{"QueueUrls": urls})
}

// --- message operations ---

const maxMessageSize = 262144 // 256 KiB

func (h *sqsHandler) sendMessage(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	msgBody, _ := body["MessageBody"].(string)
	if msgBody == "" {
		writeSQSError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "The message body must not be empty.")
		return
	}
	attrs := mapOf(body["MessageAttributes"])
	if len(msgBody)+messageAttributesSize(attrs) > maxMessageSize {
		writeSQSError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"One or more parameters are invalid. Reason: Message must be shorter than 262144 bytes.")
		return
	}
	qattrs, _, ok, err := h.store.queueAttrs(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	md5Body := md5Hex(msgBody)
	md5Attrs := md5OfMessageAttributes(attrs)
	out := map[string]any{"MD5OfMessageBody": md5Body}
	if isFIFO(qattrs) {
		p, e := fifoParams(qattrs, body, msgBody)
		if e != nil {
			writeSQSError(w, http.StatusBadRequest, e.code, requestID, e.msg)
			return
		}
		id, seq, _, err := h.store.sendFIFO(ctx, url, msgBody, md5Body, md5Attrs, attrs, h.delayFor(ctx, url, map[string]any{}), p.group, p.dedup, p.scope)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		out["MessageId"], out["SequenceNumber"] = id, fifoSeq(seq)
	} else {
		if e := standardOnly(body); e != nil {
			writeSQSError(w, http.StatusBadRequest, e.code, requestID, e.msg)
			return
		}
		id, err := h.store.sendMessage(ctx, url, msgBody, md5Body, md5Attrs, attrs, h.delayFor(ctx, url, body))
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		out["MessageId"] = id
	}
	if md5Attrs != "" {
		out["MD5OfMessageAttributes"] = md5Attrs
	}
	writeSQSJSON(w, requestID, out)
}

func (h *sqsHandler) sendMessageBatch(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	entries := sliceOf(body["Entries"])
	if len(entries) == 0 || len(entries) > 10 {
		writeSQSError(w, http.StatusBadRequest, "TooManyEntriesInBatchRequest", requestID,
			"The batch request contains more entries than permissible (1..10).")
		return
	}
	qattrs, _, ok, err := h.store.queueAttrs(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	fifo := isFIFO(qattrs)
	delay := time.Duration(-1) // resolve per-queue lazily below
	successful := []any{}
	failed := []any{}
	seen := map[string]bool{}
	for _, e := range entries {
		em, _ := e.(map[string]any)
		id, _ := em["Id"].(string)
		if id == "" || seen[id] {
			failed = append(failed, map[string]any{"Id": id, "SenderFault": true, "Code": "BatchEntryIdsNotDistinct", "Message": "duplicate or missing entry Id"})
			continue
		}
		seen[id] = true
		mb, _ := em["MessageBody"].(string)
		attrs := mapOf(em["MessageAttributes"])
		if mb == "" || len(mb)+messageAttributesSize(attrs) > maxMessageSize {
			failed = append(failed, map[string]any{"Id": id, "SenderFault": true, "Code": "InvalidParameterValue", "Message": "empty or oversized message"})
			continue
		}
		if delay < 0 {
			delay = h.delayFor(ctx, url, map[string]any{})
		}
		md5Body := md5Hex(mb)
		md5Attrs := md5OfMessageAttributes(attrs)
		s := map[string]any{"Id": id, "MD5OfMessageBody": md5Body}
		if fifo {
			// A batch's entries are sent in order, so a group's messages keep the order of the batch.
			p, e := fifoParams(qattrs, em, mb)
			if e != nil {
				failed = append(failed, map[string]any{"Id": id, "SenderFault": true, "Code": e.code, "Message": e.msg})
				continue
			}
			mid, seq, _, err := h.store.sendFIFO(ctx, url, mb, md5Body, md5Attrs, attrs, delay, p.group, p.dedup, p.scope)
			if err != nil {
				failed = append(failed, map[string]any{"Id": id, "SenderFault": false, "Code": "InternalError", "Message": "send failed"})
				continue
			}
			s["MessageId"], s["SequenceNumber"] = mid, fifoSeq(seq)
		} else {
			if e := standardOnly(em); e != nil {
				failed = append(failed, map[string]any{"Id": id, "SenderFault": true, "Code": e.code, "Message": e.msg})
				continue
			}
			d := delay
			if ds, ok := em["DelaySeconds"]; ok {
				d = time.Duration(toInt(ds)) * time.Second
			}
			mid, err := h.store.sendMessage(ctx, url, mb, md5Body, md5Attrs, attrs, d)
			if err != nil {
				failed = append(failed, map[string]any{"Id": id, "SenderFault": false, "Code": "InternalError", "Message": "send failed"})
				continue
			}
			s["MessageId"] = mid
		}
		if md5Attrs != "" {
			s["MD5OfMessageAttributes"] = md5Attrs
		}
		successful = append(successful, s)
	}
	writeSQSJSON(w, requestID, map[string]any{"Successful": successful, "Failed": failed})
}

func (h *sqsHandler) receiveMessage(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	qattrs, _, ok, err := h.store.queueAttrs(ctx, url)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	max := 1
	if v, ok := body["MaxNumberOfMessages"]; ok {
		max = toInt(v)
	}
	if max < 1 || max > 10 {
		writeSQSError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"Value for parameter MaxNumberOfMessages is invalid. Reason: must be between 1 and 10.")
		return
	}
	visibility := time.Duration(attrInt(qattrs, "VisibilityTimeout", 30)) * time.Second
	if v, ok := body["VisibilityTimeout"]; ok {
		visibility = time.Duration(toInt(v)) * time.Second
	}
	wait := time.Duration(attrInt(qattrs, "ReceiveMessageWaitTimeSeconds", 0)) * time.Second
	if v, ok := body["WaitTimeSeconds"]; ok {
		wait = time.Duration(toInt(v)) * time.Second
	}
	if wait > 20*time.Second {
		wait = 20 * time.Second
	}
	maxReceive, dlqURL := h.redrive(ctx, qattrs)
	fifo := isFIFO(qattrs)
	if v, _ := body["ReceiveRequestAttemptId"].(string); v != "" && fifo {
		writeSQSError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"ReceiveRequestAttemptId (receive-retry deduplication) is not supported by this shim; retry the receive without it (the messages of a group stay in flight until their visibility timeout).")
		return
	}

	// Long polling: block up to `wait`, returning as soon as a message is available. An expiry with no
	// message is an empty SUCCESS, never an error — SDK consumer loops depend on that.
	deadline := time.Now().Add(wait)
	for {
		msgs, err := h.store.receive(ctx, url, max, visibility, maxReceive, dlqURL, fifo)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if len(msgs) > 0 {
			h.writeMessages(w, requestID, msgs, body)
			return
		}
		if time.Now().After(deadline) || wait == 0 {
			writeSQSJSON(w, requestID, map[string]any{}) // empty success
			return
		}
		select {
		case <-ctx.Done():
			writeSQSJSON(w, requestID, map[string]any{})
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (h *sqsHandler) writeMessages(w http.ResponseWriter, requestID string, msgs []storedMessage, body map[string]any) {
	// System attributes (ApproximateReceiveCount, ...), asked for as AttributeNames or (current SDKs)
	// MessageSystemAttributeNames.
	wantSys := append(stringSlice(body["AttributeNames"]), stringSlice(body["MessageSystemAttributeNames"])...)
	wantMsgAttrs := stringSlice(body["MessageAttributeNames"])
	out := make([]any, 0, len(msgs))
	for _, m := range msgs {
		msg := map[string]any{
			"MessageId":     m.MessageID,
			"ReceiptHandle": m.ReceiptHandle,
			"MD5OfBody":     m.MD5Body,
			"Body":          m.Body,
		}
		if m.MD5Attrs != "" && wantsAny(wantMsgAttrs) {
			msg["MD5OfMessageAttributes"] = m.MD5Attrs
			msg["MessageAttributes"] = filterMessageAttributes(m.Attrs, wantMsgAttrs)
		}
		if wantsAttr(wantSys) {
			sys := map[string]string{
				"ApproximateReceiveCount":          strconv.Itoa(m.ReceiveCount),
				"SentTimestamp":                    strconv.FormatInt(m.SentAt.UnixMilli(), 10),
				"ApproximateFirstReceiveTimestamp": strconv.FormatInt(m.FirstReceived.UnixMilli(), 10),
			}
			if m.GroupID != "" {
				sys["MessageGroupId"], sys["MessageDeduplicationId"], sys["SequenceNumber"] = m.GroupID, m.DedupID, fifoSeq(m.Seq)
			}
			msg["Attributes"] = filterSystemAttributes(sys, wantSys)
		}
		out = append(out, msg)
	}
	writeSQSJSON(w, requestID, map[string]any{"Messages": out})
}

func (h *sqsHandler) deleteMessage(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	handle, _ := body["ReceiptHandle"].(string)
	ok, err := h.store.deleteByHandle(ctx, url, handle)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "ReceiptHandleIsInvalid", requestID,
			"The receipt handle is not valid — it is stale, already used, or for a message that has since been redelivered.")
		return
	}
	writeSQSJSON(w, requestID, map[string]any{})
}

func (h *sqsHandler) deleteMessageBatch(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	entries := sliceOf(body["Entries"])
	if len(entries) == 0 || len(entries) > 10 {
		writeSQSError(w, http.StatusBadRequest, "TooManyEntriesInBatchRequest", requestID,
			"The batch request contains more entries than permissible (1..10).")
		return
	}
	successful := []any{}
	failed := []any{}
	for _, e := range entries {
		em, _ := e.(map[string]any)
		id, _ := em["Id"].(string)
		handle, _ := em["ReceiptHandle"].(string)
		ok, err := h.store.deleteByHandle(ctx, url, handle)
		switch {
		case err != nil:
			failed = append(failed, map[string]any{"Id": id, "SenderFault": false, "Code": "InternalError", "Message": "delete failed"})
		case !ok:
			failed = append(failed, map[string]any{"Id": id, "SenderFault": true, "Code": "ReceiptHandleIsInvalid", "Message": "stale or invalid receipt handle"})
		default:
			successful = append(successful, map[string]any{"Id": id})
		}
	}
	writeSQSJSON(w, requestID, map[string]any{"Successful": successful, "Failed": failed})
}

func (h *sqsHandler) changeMessageVisibility(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	handle, _ := body["ReceiptHandle"].(string)
	vis := time.Duration(toInt(body["VisibilityTimeout"])) * time.Second
	ok, err := h.store.changeVisibility(ctx, url, handle, vis)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSQSError(w, http.StatusBadRequest, "MessageNotInflight", requestID,
			"The message referred to is not in flight (the receipt handle is stale, or the message was deleted/redelivered).")
		return
	}
	writeSQSJSON(w, requestID, map[string]any{})
}

func (h *sqsHandler) purgeQueue(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	url, _ := body["QueueUrl"].(string)
	if _, _, ok, err := h.store.queueAttrs(ctx, url); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeSQSError(w, http.StatusBadRequest, "QueueDoesNotExist", requestID, "The specified queue does not exist.")
		return
	}
	if err := h.store.purge(ctx, url); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeSQSJSON(w, requestID, map[string]any{})
}

// --- helpers ---

func (h *sqsHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("sqs backend error", "error", err.Error())
	writeSQSError(w, http.StatusInternalServerError, "InternalFailure", requestID, "The server encountered an internal error.")
}

func (h *sqsHandler) queueURL(r *http.Request, name string) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/" + h.account + "/" + name
}

// queueURLs is the URL a new queue is recorded under, and the one its creator is answered with. Both are
// the caller's own endpoint, except when the caller came in by an AWS name (a VM guest whose resolver
// sends sqs.<region>.amazonaws.com here): that caller is answered in AWS's shape, but the queue is
// recorded under the shim's own URL. A recorded amazonaws.com URL would be handed to every later caller
// (GetQueueUrl, ListQueues, a stack's outputs), and an SDK that sends to the QueueUrl's host — the
// JavaScript SDK v3 does — would send that caller's credentials and messages to AWS.
func (h *sqsHandler) queueURLs(r *http.Request, name string) (stored, answer string) {
	answer = h.queueURL(r, name)
	if !awsSQSHost(r) {
		return answer, answer
	}
	base := h.urlBase
	if base == "" {
		base = defaultQueueURLBase
	}
	return strings.TrimRight(base, "/") + "/" + h.account + "/" + name, answer
}

// answerURL is the URL a queue recorded under stored is reported to this caller with: the recorded URL,
// or, for a caller that came in by an AWS name, the queue's URL at that name (queueURLs).
func (h *sqsHandler) answerURL(r *http.Request, stored string) string {
	if !awsSQSHost(r) {
		return stored
	}
	return h.queueURL(r, queueNameFromURL(stored))
}

// canonicalURL is the stored URL of the queue a QueueUrl addresses: the URL itself when a queue has it,
// else the queue named by its last path segment (queue names are unique in this store).
func (h *sqsHandler) canonicalURL(ctx context.Context, u string) (string, bool, error) {
	if _, _, ok, err := h.store.queueAttrs(ctx, u); err != nil || ok {
		return u, ok, err
	}
	return h.store.queueURLByName(ctx, queueNameFromURL(u))
}

func (h *sqsHandler) queueARN(name string) string {
	return "arn:aws:sqs:" + h.region + ":" + h.account + ":" + name
}

// delayFor resolves the effective DelaySeconds for a send: the per-message value if present, else the
// queue's DelaySeconds attribute, else 0.
func (h *sqsHandler) delayFor(ctx context.Context, url string, body map[string]any) time.Duration {
	if v, ok := body["DelaySeconds"]; ok {
		return time.Duration(toInt(v)) * time.Second
	}
	if attrs, _, ok, _ := h.store.queueAttrs(ctx, url); ok {
		return time.Duration(attrInt(attrs, "DelaySeconds", 0)) * time.Second
	}
	return 0
}

// redrive parses a queue's RedrivePolicy attribute into (maxReceiveCount, dlqURL). Returns (0,"") when
// there is no redrive or the DLQ cannot be resolved (in which case messages are not dead-lettered).
func (h *sqsHandler) redrive(ctx context.Context, qattrs map[string]string) (int, string) {
	raw := qattrs["RedrivePolicy"]
	if raw == "" {
		return 0, ""
	}
	var rp struct {
		DeadLetterTargetArn string `json:"deadLetterTargetArn"`
		MaxReceiveCount     any    `json:"maxReceiveCount"`
	}
	if json.Unmarshal([]byte(raw), &rp) != nil {
		return 0, ""
	}
	maxRecv := toInt(rp.MaxReceiveCount)
	if maxRecv <= 0 || rp.DeadLetterTargetArn == "" {
		return 0, ""
	}
	// arn:aws:sqs:region:account:name -> name -> url
	dlqName := rp.DeadLetterTargetArn[strings.LastIndex(rp.DeadLetterTargetArn, ":")+1:]
	url, ok, err := h.store.queueURLByName(ctx, dlqName)
	if err != nil || !ok {
		return 0, ""
	}
	return maxRecv, url
}

// --- AWS message-attribute MD5 (SDKs verify MD5OfMessageAttributes; the encoding is exact) ---

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// md5OfMessageAttributes computes the MD5 AWS defines over a message's attributes: attributes sorted by
// name, and for each the length-prefixed name, length-prefixed data type, a 1-byte transport type
// (1=String/Number value, 2=Binary), and the length-prefixed value. Empty attributes → "".
func md5OfMessageAttributes(attrs map[string]any) string {
	if len(attrs) == 0 {
		return ""
	}
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	h := md5.New()
	for _, name := range names {
		a, _ := attrs[name].(map[string]any)
		if a == nil {
			continue
		}
		dataType, _ := a["DataType"].(string)
		writeLenPrefixed(h, []byte(name))
		writeLenPrefixed(h, []byte(dataType))
		if bv, ok := a["BinaryValue"].(string); ok && bv != "" {
			raw, _ := base64.StdEncoding.DecodeString(bv)
			h.Write([]byte{2})
			writeLenPrefixed(h, raw)
		} else {
			sv, _ := a["StringValue"].(string)
			h.Write([]byte{1})
			writeLenPrefixed(h, []byte(sv))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

// messageAttributesSize is a conservative size estimate of the attributes for the 256 KiB limit check.
func messageAttributesSize(attrs map[string]any) int {
	n := 0
	for name, v := range attrs {
		n += len(name)
		if a, ok := v.(map[string]any); ok {
			if s, ok := a["StringValue"].(string); ok {
				n += len(s)
			}
			if s, ok := a["BinaryValue"].(string); ok {
				n += len(s)
			}
			if s, ok := a["DataType"].(string); ok {
				n += len(s)
			}
		}
	}
	return n
}

// --- small JSON-wire coercions ---

// sqsAuthzQueue is the queue an op is authorized against: the same field the op acts on. CreateQueue and
// GetQueueUrl name a queue by QueueName; every other op acts on QueueUrl, so a QueueName sent alongside
// it is ignored here exactly as the op ignores it. ListQueues names none.
func sqsAuthzQueue(op string, body map[string]any) string {
	switch op {
	case "CreateQueue", "GetQueueUrl":
		n, _ := body["QueueName"].(string)
		return n
	case "ListQueues":
		return ""
	}
	if u, _ := body["QueueUrl"].(string); u != "" {
		return queueNameFromURL(u)
	}
	return ""
}

func queueNameFromURL(u string) string {
	u = strings.TrimRight(u, "/")
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		} else if val != nil {
			out[k] = toStr(val)
		}
	}
	return out
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sliceOf(v any) []any {
	s, _ := v.([]any)
	return s
}

func stringSlice(v any) []string {
	s, _ := v.([]any)
	out := make([]string, 0, len(s))
	for _, e := range s {
		if str, ok := e.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		// Kubernetes unstructured reads (unstructured.NestedMap) surface JSON integers as int64,
		// so any value read back from a live object's spec lands here — not float64.
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func toStr(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(s)
	}
	return ""
}

func attrInt(attrs map[string]string, key string, def int) int {
	if v, ok := attrs[key]; ok {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// wantsAttr reports whether system attributes were requested (default when unspecified is none in the
// JSON protocol, but AWS returns them when "All" or a specific name is asked).
func wantsAttr(names []string) bool { return len(names) > 0 }
func wantsAny(names []string) bool  { return len(names) > 0 }

func filterSystemAttributes(sys map[string]string, want []string) map[string]string {
	if containsStr(want, "All") {
		return sys
	}
	out := map[string]string{}
	for _, n := range want {
		if v, ok := sys[n]; ok {
			out[n] = v
		}
	}
	return out
}

func filterMessageAttributes(attrs map[string]any, want []string) map[string]any {
	if containsStr(want, "All") || len(want) == 0 {
		return attrs
	}
	out := map[string]any{}
	for _, n := range want {
		if v, ok := attrs[n]; ok {
			out[n] = v
		}
	}
	return out
}
