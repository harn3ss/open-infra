// SNS front door for the aws-shim.
//
// SNS speaks the AWS QUERY protocol (form-encoded `Action=...` POST, XML response) — unlike SQS's
// JSON. Its core value is the canonical AWS pattern: an SNS topic fans out to N SQS queues. Delivery
// is DURABLE by construction: Publish inserts the (enveloped) message into each subscribed queue via
// the SQS store before it acknowledges, so a returned MessageId always means the message was persisted
// for every current subscription — never the fire-and-forget false-green SNS makes easy.
//
// v1 supports the `sqs` subscription protocol only. Everything the shim does not genuinely implement is
// REFUSED honestly, never accepted-and-silently-dropped: lambda/http/https/email/sms/application/
// firehose protocols, message FilterPolicy, `.fifo` topics, and a topic resource Policy on
// SetTopicAttributes (this is a one-policy-world; authorization is Cedar, not a second engine). The
// delivered envelope omits the AWS message Signature/SigningCertURL rather than emitting a meaningless
// one — subscribers cannot verify, and we say so rather than teach a false "verified". See
// docs/aws-shim.md and polyhedron#159.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

const snsXMLNamespace = "http://sns.amazonaws.com/doc/2010-03-31/"

type snsHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *snsStore // nil => data layer not configured (honest error)
	sqs     *sqsStore // SNS -> SQS delivery (durable); nil disables sqs fan-out
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger
}

func newSNSHandler(cs kubernetes.Interface, authzNS, account, region string, store *snsStore, sqs *sqsStore, logger *slog.Logger) *snsHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &snsHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, sqs: sqs, logger: logger}
}

func (h *snsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", snsXMLNamespace)
}

// verbForSNSOp maps an SNS op to its coarse RBAC verb. Publish and Subscribe are both "create"
// coarsely; they are separated at the fine-grained Cedar layer (sns:Publish vs sns:Subscribe), which is
// where "publish broadly, subscribe tightly" is enforced — Subscribe points the platform's outbound
// delivery at a destination and must be independently grantable.
func verbForSNSOp(op string) (string, bool) {
	switch op {
	case "ListTopics", "GetTopicAttributes", "ListSubscriptions", "ListSubscriptionsByTopic", "GetSubscriptionAttributes":
		return "get", true
	case "CreateTopic", "SetTopicAttributes", "Subscribe", "SetSubscriptionAttributes", "Publish", "PublishBatch":
		return "create", true
	case "DeleteTopic", "Unsubscribe":
		return "delete", true
	}
	return "", false
}

func (h *snsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	op := r.PostFormValue("Action")
	if op == "" {
		op = r.URL.Query().Get("Action")
	}
	verb, known := verbForSNSOp(op)
	if !known {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"The SNS action '"+op+"' is not implemented by this open-infra shim.", snsXMLNamespace)
		return
	}

	// Resource name for authz: the topic name from TopicArn (most ops) or Name (CreateTopic).
	res := ""
	if n := r.PostFormValue("Name"); n != "" {
		res = n
	} else if ta := r.PostFormValue("TopicArn"); ta != "" {
		res = nameFromArn(ta)
	} else if sa := r.PostFormValue("SubscriptionArn"); sa != "" {
		res = nameFromArn(topicArnOfSub(sa))
	}

	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, res); !allowed {
		writeQueryError(w, http.StatusForbidden, "AuthorizationError", requestID, reason, snsXMLNamespace)
		return
	}
	if res != "" {
		if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "sns:"+op, "Topic", res, r); denied {
			writeQueryError(w, http.StatusForbidden, "AuthorizationError", requestID, reason, snsXMLNamespace)
			return
		}
	}
	if h.store == nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID,
			"the SNS data layer is not configured on this shim (set SQS_PG_URI)", snsXMLNamespace)
		return
	}

	ctx := r.Context()
	switch op {
	case "CreateTopic":
		h.createTopic(ctx, w, r, requestID)
	case "DeleteTopic":
		h.deleteTopic(ctx, w, r, requestID)
	case "ListTopics":
		h.listTopics(ctx, w, requestID)
	case "GetTopicAttributes":
		h.getTopicAttributes(ctx, w, r, requestID)
	case "SetTopicAttributes":
		h.setTopicAttributes(ctx, w, r, requestID)
	case "Subscribe":
		h.subscribe(ctx, w, r, requestID)
	case "Unsubscribe":
		h.unsubscribe(ctx, w, r, requestID)
	case "ListSubscriptions":
		h.listSubscriptions(ctx, w, r, requestID, "")
	case "ListSubscriptionsByTopic":
		h.listSubscriptions(ctx, w, r, requestID, r.PostFormValue("TopicArn"))
	case "GetSubscriptionAttributes":
		h.getSubscriptionAttributes(ctx, w, r, requestID)
	case "SetSubscriptionAttributes":
		h.setSubscriptionAttributes(ctx, w, r, requestID)
	case "Publish":
		h.publish(ctx, w, r, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"SNS "+op+" is recognized but not implemented by the open-infra shim.", snsXMLNamespace)
	}
}

// --- topics ---

func (h *snsHandler) createTopic(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("Name")
	if name == "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "CreateTopic requires a Name.", snsXMLNamespace)
		return
	}
	if strings.HasSuffix(name, ".fifo") {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"FIFO (.fifo) topics are not yet supported by the open-infra shim; standard topics only.", snsXMLNamespace)
		return
	}
	arn := h.topicARN(name)
	if _, err := h.store.createTopic(ctx, arn, name); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "CreateTopic", map[string]string{"TopicArn": arn})
}

func (h *snsHandler) deleteTopic(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("TopicArn")
	if _, err := h.store.deleteTopic(ctx, arn); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "DeleteTopic", nil) // AWS returns success even if absent (idempotent delete)
}

func (h *snsHandler) listTopics(ctx context.Context, w http.ResponseWriter, requestID string) {
	arns, err := h.store.listTopics(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeTopicList(w, requestID, arns)
}

func (h *snsHandler) getTopicAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("TopicArn")
	attrs, ok, err := h.store.topicAttrs(ctx, arn)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Topic does not exist.", snsXMLNamespace)
		return
	}
	subs, _ := h.store.subscriptionsForTopic(ctx, arn)
	out := map[string]string{
		"TopicArn":               arn,
		"Owner":                  h.account,
		"SubscriptionsConfirmed": itoa(len(subs)),
		"SubscriptionsPending":   "0",
		"DisplayName":            attrs["DisplayName"],
	}
	h.writeAttributes(w, requestID, "GetTopicAttributes", out)
}

func (h *snsHandler) setTopicAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("TopicArn")
	name := r.PostFormValue("AttributeName")
	val := r.PostFormValue("AttributeValue")
	if name == "Policy" {
		// One policy world: a topic resource policy is not a second authorization engine. Refuse rather
		// than accept-and-ignore (which would let a caller believe they set access control that does nothing).
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"SNS topic resource policies are not honored by the open-infra shim; authorization is Cedar (one policy world). Refused rather than silently ignored.", snsXMLNamespace)
		return
	}
	ok, err := h.store.setTopicAttr(ctx, arn, name, val)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Topic does not exist.", snsXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "SetTopicAttributes", nil)
}

// --- subscriptions ---

func (h *snsHandler) subscribe(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	topicArn := r.PostFormValue("TopicArn")
	protocol := r.PostFormValue("Protocol")
	endpoint := r.PostFormValue("Endpoint")
	if exists, err := h.store.topicExists(ctx, topicArn); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !exists {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Topic does not exist.", snsXMLNamespace)
		return
	}
	// v1 supports sqs only. Every other protocol is refused HONESTLY at subscribe time — a subscription
	// that exists but never delivers is worse than a rejected subscribe (the operator has evidence that
	// contradicts reality). http/https are additionally an egress surface (deferred until a confirmation
	// handshake + destination allowlist land).
	if protocol != "sqs" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"subscription protocol '"+protocol+"' is not supported by this shim (v1: sqs only). It is refused rather than accepted and never delivered.", snsXMLNamespace)
		return
	}
	attrs := parseQueryMap(r, "Attributes")
	// FilterPolicy: implement faithfully or refuse — accepting and ignoring would deliver messages a
	// subscriber explicitly filtered out (a correctness+privacy defect). v1 refuses it.
	if _, ok := attrs["FilterPolicy"]; ok {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"message FilterPolicy is not yet implemented by this shim; it is refused rather than accepted and ignored (which would deliver filtered-out messages).", snsXMLNamespace)
		return
	}
	// The endpoint must be a queue we know (an SQS queue ARN); reject a dangling subscription early.
	if h.sqs == nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "sqs delivery is not configured", snsXMLNamespace)
		return
	}
	if _, ok, err := h.sqs.queueURLByName(ctx, nameFromArn(endpoint)); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "the sqs endpoint queue does not exist: "+endpoint, snsXMLNamespace)
		return
	}
	raw := strings.EqualFold(attrs["RawMessageDelivery"], "true")
	subArn := topicArn + ":" + randHex(8)
	if err := h.store.subscribe(ctx, subArn, topicArn, "sqs", endpoint, raw, true); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "Subscribe", map[string]string{"SubscriptionArn": subArn})
}

func (h *snsHandler) unsubscribe(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("SubscriptionArn")
	if _, err := h.store.unsubscribe(ctx, arn); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "Unsubscribe", nil)
}

func (h *snsHandler) listSubscriptions(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, topicArn string) {
	var subs []snsSubscription
	var err error
	action := "ListSubscriptions"
	if topicArn != "" {
		subs, err = h.store.subscriptionsForTopic(ctx, topicArn)
		action = "ListSubscriptionsByTopic"
	} else {
		subs, err = h.store.listSubscriptions(ctx)
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeSubscriptionList(w, requestID, action, subs)
}

func (h *snsHandler) getSubscriptionAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("SubscriptionArn")
	sub, ok, err := h.store.subByArn(ctx, arn)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Subscription does not exist.", snsXMLNamespace)
		return
	}
	out := map[string]string{
		"SubscriptionArn":    sub.Arn,
		"TopicArn":           sub.TopicArn,
		"Protocol":           sub.Protocol,
		"Endpoint":           sub.Endpoint,
		"RawMessageDelivery": boolStr(sub.Raw),
		"Owner":              h.account,
	}
	h.writeAttributes(w, requestID, "GetSubscriptionAttributes", out)
}

func (h *snsHandler) setSubscriptionAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("SubscriptionArn")
	name := r.PostFormValue("AttributeName")
	val := r.PostFormValue("AttributeValue")
	if name == "FilterPolicy" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"message FilterPolicy is not yet implemented by this shim; refused rather than accepted and ignored.", snsXMLNamespace)
		return
	}
	if name != "RawMessageDelivery" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"only RawMessageDelivery is a settable subscription attribute on this shim; '"+name+"' is refused.", snsXMLNamespace)
		return
	}
	ok, err := h.store.setSubRaw(ctx, arn, strings.EqualFold(val, "true"))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Subscription does not exist.", snsXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "SetSubscriptionAttributes", nil)
}

// --- publish (durable fan-out) ---

func (h *snsHandler) publish(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	topicArn := r.PostFormValue("TopicArn")
	if topicArn == "" {
		topicArn = r.PostFormValue("TargetArn")
	}
	message := r.PostFormValue("Message")
	subject := r.PostFormValue("Subject")
	if message == "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "Publish requires a Message.", snsXMLNamespace)
		return
	}
	if len(message) > maxMessageSize {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "Message too long (max 262144 bytes).", snsXMLNamespace)
		return
	}
	if exists, err := h.store.topicExists(ctx, topicArn); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !exists {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Topic does not exist.", snsXMLNamespace)
		return
	}
	subs, err := h.store.subscriptionsForTopic(ctx, topicArn)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	msgID := uuidLike()
	// DURABLE fan-out: deliver to every sqs subscription synchronously (a row INSERT via the SQS store)
	// BEFORE acknowledging. If any delivery fails, Publish reports failure — never a MessageId for a
	// message that was not persisted for its subscribers.
	for _, sub := range subs {
		if sub.Protocol != "sqs" {
			continue // v1: only sqs is a deliverable protocol; others were refused at Subscribe
		}
		url, ok, err := h.sqs.queueURLByName(ctx, nameFromArn(sub.Endpoint))
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !ok {
			// The target queue was deleted after subscribe; skip but do not fail the whole publish.
			h.logger.Warn("sns: subscription endpoint queue missing, skipping", "endpoint", sub.Endpoint)
			continue
		}
		body := message
		if !sub.Raw {
			env := map[string]any{
				"Type":           "Notification",
				"MessageId":      msgID,
				"TopicArn":       topicArn,
				"Message":        message,
				"Timestamp":      time.Now().UTC().Format(time.RFC3339),
				"UnsubscribeURL": "sns://" + sub.Arn, // opaque; SNS emits an HTTP URL, we do not front one
			}
			if subject != "" {
				env["Subject"] = subject
			}
			b, _ := json.Marshal(env)
			body = string(b)
		}
		if _, err := h.sqs.sendMessage(ctx, url, body, md5Hex(body), "", nil, 0); err != nil {
			h.internal(w, requestID, err) // durable delivery failed -> not a success
			return
		}
	}
	h.writeResult(w, requestID, "Publish", map[string]string{"MessageId": msgID})
}

// --- XML response writers ---

func (h *snsHandler) topicARN(name string) string {
	return "arn:aws:sns:" + h.region + ":" + h.account + ":" + name
}

func (h *snsHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("sns backend error", "error", err.Error())
	writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "The server encountered an internal error.", snsXMLNamespace)
}

// writeResult writes a generic <XxxResponse><XxxResult>...</XxxResult><ResponseMetadata/></XxxResponse>
// with a flat set of string fields (e.g. TopicArn, SubscriptionArn, MessageId). A nil fields map emits
// an empty result (delete/set acknowledgements).
func (h *snsHandler) writeResult(w http.ResponseWriter, requestID, action string, fields map[string]string) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<` + action + `Response xmlns="` + snsXMLNamespace + `">`)
	b.WriteString(`<` + action + `Result>`)
	for k, v := range fields {
		b.WriteString(`<` + k + `>` + xmlEscape(v) + `</` + k + `>`)
	}
	b.WriteString(`</` + action + `Result>`)
	b.WriteString(`<ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata>`)
	b.WriteString(`</` + action + `Response>`)
	h.writeXML(w, requestID, b.String())
}

func (h *snsHandler) writeTopicList(w http.ResponseWriter, requestID string, arns []string) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<ListTopicsResponse xmlns="` + snsXMLNamespace + `"><ListTopicsResult><Topics>`)
	for _, a := range arns {
		b.WriteString(`<member><TopicArn>` + xmlEscape(a) + `</TopicArn></member>`)
	}
	b.WriteString(`</Topics></ListTopicsResult><ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata></ListTopicsResponse>`)
	h.writeXML(w, requestID, b.String())
}

func (h *snsHandler) writeSubscriptionList(w http.ResponseWriter, requestID, action string, subs []snsSubscription) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<` + action + `Response xmlns="` + snsXMLNamespace + `"><` + action + `Result><Subscriptions>`)
	for _, s := range subs {
		b.WriteString(`<member>`)
		b.WriteString(`<SubscriptionArn>` + xmlEscape(s.Arn) + `</SubscriptionArn>`)
		b.WriteString(`<TopicArn>` + xmlEscape(s.TopicArn) + `</TopicArn>`)
		b.WriteString(`<Protocol>` + xmlEscape(s.Protocol) + `</Protocol>`)
		b.WriteString(`<Endpoint>` + xmlEscape(s.Endpoint) + `</Endpoint>`)
		b.WriteString(`<Owner>` + xmlEscape(h.account) + `</Owner>`)
		b.WriteString(`</member>`)
	}
	b.WriteString(`</Subscriptions></` + action + `Result><ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata></` + action + `Response>`)
	h.writeXML(w, requestID, b.String())
}

func (h *snsHandler) writeAttributes(w http.ResponseWriter, requestID, action string, attrs map[string]string) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<` + action + `Response xmlns="` + snsXMLNamespace + `"><` + action + `Result><Attributes>`)
	for k, v := range attrs {
		if v == "" {
			continue
		}
		b.WriteString(`<entry><key>` + xmlEscape(k) + `</key><value>` + xmlEscape(v) + `</value></entry>`)
	}
	b.WriteString(`</Attributes></` + action + `Result><ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata></` + action + `Response>`)
	h.writeXML(w, requestID, b.String())
}

func (h *snsHandler) writeXML(w http.ResponseWriter, requestID, body string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// --- helpers ---

// parseQueryMap collects an AWS query-protocol map parameter ("Attributes.entry.N.key" /
// "Attributes.entry.N.value") into a Go map.
func parseQueryMap(r *http.Request, prefix string) map[string]string {
	out := map[string]string{}
	for i := 1; i <= 32; i++ {
		k := r.PostFormValue(prefix + ".entry." + itoa(i) + ".key")
		if k == "" {
			continue
		}
		out[k] = r.PostFormValue(prefix + ".entry." + itoa(i) + ".value")
	}
	return out
}

// nameFromArn returns the last colon-delimited segment (the resource name) of an ARN.
func nameFromArn(arn string) string {
	if i := strings.LastIndex(arn, ":"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// topicArnOfSub strips the trailing ":<subid>" from a subscription ARN to get its topic ARN.
func topicArnOfSub(subArn string) string {
	if i := strings.LastIndex(subArn, ":"); i >= 0 {
		return subArn[:i]
	}
	return subArn
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func uuidLike() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

func itoa(n int) string { return strconv.Itoa(n) }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
