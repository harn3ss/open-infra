// FIFO queues for the SQS front door.
//
// A FIFO queue (name ending .fifo, FifoQueue=true) is SQS's, in its store (sqs_store.go): every message
// names a MessageGroupId; within a group messages are received in the order they were sent, one batch at a
// time (no message of a group is handed out while another of it is in flight); a message whose
// deduplication id — MessageDeduplicationId, or with ContentBasedDeduplication the SHA-256 of its body —
// was sent in the last five minutes is accepted and not enqueued again (DeduplicationScope queue, or
// messageGroup: per group); each message gets a SequenceNumber. FifoThroughputLimit is accepted (it is a
// throughput mode, not a semantic). A queue's dead-letter queue is of its own type, as on AWS.
//
// Not served, and refused rather than ignored: a per-message DelaySeconds (SQS refuses it on FIFO too),
// ReceiveRequestAttemptId (the receive-retry deduplication), an SNS subscription of a FIFO queue to the
// (standard) topics SNS serves here, and an EventBridge FIFO-queue target (it needs SqsParameters).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// fifoIDRe is what a MessageGroupId or MessageDeduplicationId may hold: up to 128 alphanumerics and
// punctuation.
var fifoIDRe = regexp.MustCompile("^[A-Za-z0-9!\"#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_`{|}~]{1,128}$")

var sqsBaseNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func isFIFO(qattrs map[string]string) bool { return qattrs["FifoQueue"] == "true" }

// sqsAttrError is a refused queue attribute: the SQS error code and message.
type sqsAttrError struct{ code, msg string }

func (e *sqsAttrError) Error() string { return e.msg }

// checkQueueType validates the FIFO side of a queue's attributes. creating: a CreateQueue of name with
// attrs (FifoQueue is set only there, and must agree with the name); else a SetQueueAttributes of attrs on
// a queue whose attributes are have. A FifoQueue "false" is dropped from attrs (a standard queue).
func checkQueueType(name string, attrs, have map[string]string, creating bool) *sqsAttrError {
	fifo := isFIFO(have)
	if creating {
		switch attrs["FifoQueue"] {
		case "true":
			fifo = true
		case "", "false":
			delete(attrs, "FifoQueue")
		default:
			return &sqsAttrError{"InvalidAttributeValue", "Invalid value for the parameter FifoQueue."}
		}
		base, isFifoName := strings.CutSuffix(name, ".fifo")
		if fifo != isFifoName || len(name) > 80 || !sqsBaseNameRe.MatchString(base) {
			return &sqsAttrError{"InvalidParameterValue", "The name of a FIFO queue can only include alphanumeric characters, hyphens, or underscores, must end with .fifo suffix and be 1 to 80 in length; a queue named .fifo is a FIFO queue (FifoQueue=true) and only it."}
		}
	} else if _, set := attrs["FifoQueue"]; set {
		return &sqsAttrError{"InvalidAttributeName", "FifoQueue cannot be changed after the queue is created."}
	}
	for _, a := range []string{"ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit"} {
		if _, set := attrs[a]; set && !fifo {
			return &sqsAttrError{"InvalidAttributeName", "Unknown Attribute " + a + " (it applies only to a FIFO queue)."}
		}
	}
	allowed := map[string][]string{
		"ContentBasedDeduplication": {"true", "false"},
		"DeduplicationScope":        {"queue", "messageGroup"},
		"FifoThroughputLimit":       {"perQueue", "perMessageGroupId"},
	}
	for a, vals := range allowed {
		if v, set := attrs[a]; set && !containsStr(vals, v) {
			return &sqsAttrError{"InvalidAttributeValue", fmt.Sprintf("Invalid value for the parameter %s.", a)}
		}
	}
	merged := map[string]string{}
	for k, v := range have {
		merged[k] = v
	}
	for k, v := range attrs {
		merged[k] = v
	}
	if merged["FifoThroughputLimit"] == "perMessageGroupId" && merged["DeduplicationScope"] != "messageGroup" {
		return &sqsAttrError{"InvalidAttributeValue", "FifoThroughputLimit perMessageGroupId requires DeduplicationScope messageGroup."}
	}
	if rp, set := attrs["RedrivePolicy"]; set && rp != "" {
		var r struct {
			DeadLetterTargetArn string `json:"deadLetterTargetArn"`
		}
		if json.Unmarshal([]byte(rp), &r) == nil && r.DeadLetterTargetArn != "" && strings.HasSuffix(r.DeadLetterTargetArn, ".fifo") != fifo {
			return &sqsAttrError{"InvalidParameterValue", "Value for parameter RedrivePolicy is invalid. Reason: the dead-letter queue of a FIFO queue must also be a FIFO queue, and that of a standard queue a standard queue."}
		}
	}
	return nil
}

// fifoQueueDefaults are a FIFO queue's attributes GetQueueAttributes reports when unset.
var fifoQueueDefaults = map[string]string{
	"ContentBasedDeduplication": "false",
	"DeduplicationScope":        "queue",
	"FifoThroughputLimit":       "perQueue",
}

// fifoSend is what a send to a FIFO queue needs: its group, deduplication id and dedup scope.
type fifoSend struct{ group, dedup, scope string }

// fifoParams reads a send (or batch entry) m to the FIFO queue with attributes qattrs. It returns the
// SQS error to answer when the send is not valid for the queue.
func fifoParams(qattrs map[string]string, m map[string]any, body string) (fifoSend, *sqsAttrError) {
	var p fifoSend
	if _, set := m["DelaySeconds"]; set {
		return p, &sqsAttrError{"InvalidParameterValue", "Value for parameter DelaySeconds is invalid. Reason: The request include parameter that is not valid for this queue type."}
	}
	p.group, _ = m["MessageGroupId"].(string)
	if p.group == "" {
		return p, &sqsAttrError{"MissingParameter", "The request must contain the parameter MessageGroupId."}
	}
	if !fifoIDRe.MatchString(p.group) {
		return p, &sqsAttrError{"InvalidParameterValue", "Value for parameter MessageGroupId is invalid (up to 128 alphanumeric or punctuation characters)."}
	}
	p.dedup, _ = m["MessageDeduplicationId"].(string)
	switch {
	case p.dedup != "" && !fifoIDRe.MatchString(p.dedup):
		return p, &sqsAttrError{"InvalidParameterValue", "Value for parameter MessageDeduplicationId is invalid (up to 128 alphanumeric or punctuation characters)."}
	case p.dedup == "" && qattrs["ContentBasedDeduplication"] == "true":
		sum := sha256.Sum256([]byte(body))
		p.dedup = hex.EncodeToString(sum[:])
	case p.dedup == "":
		return p, &sqsAttrError{"InvalidParameterValue", "The queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly"}
	}
	if qattrs["DeduplicationScope"] == "messageGroup" {
		p.scope = p.group
	}
	return p, nil
}

// standardOnly refuses the FIFO-only send parameters on a standard queue (SQS refuses a
// MessageDeduplicationId there; a MessageGroupId is a fair-queue hint SQS accepts on a standard queue).
func standardOnly(m map[string]any) *sqsAttrError {
	if v, _ := m["MessageDeduplicationId"].(string); v != "" {
		return &sqsAttrError{"InvalidParameterValue", "Value for parameter MessageDeduplicationId is invalid. Reason: The request include parameter that is not valid for this queue type."}
	}
	return nil
}

// fifoSeq renders a sequence number as SQS does: a decimal string, here 20 digits.
func fifoSeq(n int64) string { return fmt.Sprintf("%020d", n) }
