// SNS lambda subscriptions: a topic delivers each Publish to a kind: Function, as SNS invokes a Lambda.
//
// The Function is invoked at its cluster-local address in its namespace (the Lambda API's for a
// Subscribe through this front door; a stack's own for a stack's subscription), with the direct-invoke
// header so its handler receives the SNS event itself ({"Records":[{"EventSource":"aws:sns",…}]}), not an
// API-Gateway mapping of it. Delivery is asynchronous, as SNS's: Publish returns once every sqs delivery
// is persisted, and each lambda delivery is attempted (with retries) after. It is not durable across a
// shim restart — a delivery still retrying when the shim stops is lost (documented in docs/aws-shim.md).
//
// Subscribe is an escalation point (it points the platform's delivery at a Function), so a lambda
// Subscribe needs the caller to be able to invoke that Function themselves — the same fence EventBridge
// applies to a Lambda target.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// canonicalTopicArn is the stored ARN of the topic an ARN addresses: the ARN itself when a topic has it,
// else the topic named by its last segment (topic names are unique in this store).
func (h *snsHandler) canonicalTopicArn(ctx context.Context, arn string) (string, bool, error) {
	if ok, err := h.store.topicExists(ctx, arn); err != nil || ok {
		return arn, ok, err
	}
	return h.store.topicARNByName(ctx, nameFromArn(arn))
}

// subscribeLambda is Subscribe for the lambda protocol: the endpoint is a function ARN, the caller must
// be able to invoke it, and the subscription records the Function's namespace — where a Function of
// that name is (the Lambda API's namespace or a stack's), else the Lambda API's — so delivery goes
// where the caller's right to invoke was checked.
func (h *snsHandler) subscribeLambda(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, topicArn, endpoint string) {
	if h.invoker == nil || h.lambdaNS == "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"lambda delivery is not configured on this shim; the subscription is refused rather than accepted and never delivered.", snsXMLNamespace)
		return
	}
	if !strings.Contains(endpoint, ":function:") {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "a lambda subscription's Endpoint must be a function ARN.", snsXMLNamespace)
		return
	}
	attrs := parseQueryMap(r, "Attributes")
	if _, ok := attrs["FilterPolicy"]; ok {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"message FilterPolicy is not yet implemented by this shim; it is refused rather than accepted and ignored (which would deliver filtered-out messages).", snsXMLNamespace)
		return
	}
	fn := lambdaNameFromArn(endpoint)
	ns := h.fns.namespaceOf(ctx, fn, h.lambdaNS)
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, "create", "openinfra.dev", "functions", ns, fn); !allowed {
		writeQueryError(w, http.StatusForbidden, "AuthorizationError", requestID,
			"not authorized to subscribe the function "+endpoint+" (a subscription cannot invoke what its creator cannot): "+reason, snsXMLNamespace)
		return
	}
	if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "lambda:InvokeFunction", "Function", fn, r); denied {
		writeQueryError(w, http.StatusForbidden, "AuthorizationError", requestID,
			"not authorized to subscribe the function "+endpoint+" (a subscription cannot invoke what its creator cannot): "+reason, snsXMLNamespace)
		return
	}
	raw := strings.EqualFold(attrs["RawMessageDelivery"], "true")
	subArn := topicArn + ":" + randHex(8)
	if err := h.store.subscribeWith(ctx, subArn, topicArn, "lambda", endpoint, raw, map[string]string{snsFnNamespaceAttr: ns}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "Subscribe", map[string]string{"SubscriptionArn": subArn})
}

// snsLambdaEvent is the event SNS invokes a Lambda with.
func snsLambdaEvent(subArn, msgID, topicArn, subject, message string, now time.Time) []byte {
	sns := map[string]any{
		"Type":              "Notification",
		"MessageId":         msgID,
		"TopicArn":          topicArn,
		"Subject":           nil,
		"Message":           message,
		"Timestamp":         now.UTC().Format("2006-01-02T15:04:05.000Z"),
		"SignatureVersion":  "1",
		"Signature":         "", // not signed: subscribers cannot verify, and we say so (see the file header of sns.go)
		"SigningCertUrl":    "",
		"UnsubscribeUrl":    "",
		"MessageAttributes": map[string]any{},
	}
	if subject != "" {
		sns["Subject"] = subject
	}
	b, _ := json.Marshal(map[string]any{"Records": []any{map[string]any{
		"EventSource":          "aws:sns",
		"EventVersion":         "1.0",
		"EventSubscriptionArn": subArn,
		"Sns":                  sns,
	}}})
	return b
}

// snsLambdaAttempts / snsLambdaBackoff: SNS retries a Lambda delivery; so does this (3 tries, backing off).
var (
	snsLambdaAttempts = 3
	snsLambdaBackoff  = 2 * time.Second
)

// deliverLambda invokes a lambda subscription's Function with the SNS event, asynchronously, retrying a
// failed invoke (a transport error, a 5xx, or a handler error) a few times. The outcome is logged.
func (h *snsHandler) deliverLambda(sub snsSubscription, msgID, topicArn, subject, message string) {
	if h.invoker == nil {
		h.logger.Warn("sns: lambda delivery not configured, skipping", "subscription", sub.Arn)
		return
	}
	ns := sub.FnNamespace
	if ns == "" {
		ns = h.lambdaNS
	}
	fn := lambdaNameFromArn(sub.Endpoint)
	event := snsLambdaEvent(sub.Arn, msgID, topicArn, subject, message, time.Now())
	target := "http://" + fn + "." + ns + "." + h.svcSuffix + "/"
	go func() {
		backoff := snsLambdaBackoff
		for attempt := 1; attempt <= snsLambdaAttempts; attempt++ {
			err := h.invokeOnce(target, event)
			if err == nil {
				return
			}
			if attempt == snsLambdaAttempts {
				h.logger.Warn("sns: lambda delivery failed", "subscription", sub.Arn, "function", fn, "namespace", ns, "error", err.Error())
				return
			}
			time.Sleep(backoff)
			backoff *= 2
		}
	}()
}

type snsDeliveryError string

func (e snsDeliveryError) Error() string { return string(e) }

func (h *snsHandler) invokeOnce(target string, event []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(event))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Openinfra-Invoke", "direct") // the handler gets the SNS event, AWS Invoke semantics
	req.Header.Set("X-Amz-Invocation-Type", "Event")
	resp, err := h.invoker.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= http.StatusInternalServerError {
		return snsDeliveryError("HTTP " + resp.Status)
	}
	if fe := resp.Header.Get("X-Amz-Function-Error"); fe != "" {
		return snsDeliveryError("function error: " + fe)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return snsDeliveryError("HTTP " + resp.Status)
	}
	return nil
}
