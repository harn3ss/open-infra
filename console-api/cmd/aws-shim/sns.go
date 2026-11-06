// SNS front door for the aws-shim.
//
// SNS speaks the AWS QUERY protocol (form-encoded `Action=...` POST, XML response) — unlike SQS's
// JSON. Its core value is the canonical AWS pattern: an SNS topic fans out to N SQS queues. Delivery
// is DURABLE by construction: Publish inserts the (enveloped) message into each subscribed queue via
// the SQS store before it acknowledges, so a returned MessageId always means the message was persisted
// for every current subscription — never the fire-and-forget false-green SNS makes easy.
//
// The `sqs` and `lambda` subscription protocols are delivered (lambda: sns_lambda.go). Everything the
// shim does not genuinely implement is REFUSED honestly, never accepted-and-silently-dropped:
// http/https/email/sms/application/firehose protocols, `.fifo` topics, and a topic
// Policy beyond grants to services (callers are authorized by IAM, one policy world; a topic's or a
// queue's Policy decides only the deliveries the shim itself makes — resource_policy.go). The
// delivered envelope omits the AWS message Signature/SigningCertURL rather than emitting a meaningless
// one — subscribers cannot verify, and we say so rather than teach a false "verified". See
// docs/aws-shim.md and.
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

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
	"github.com/harn3ss/open-infra/cfn/snsfilter"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
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
	// lambda delivery (sns_lambda.go): a lambda subscription's Function is invoked at its cluster-local
	// address in its namespace, recorded when it is subscribed: where fns finds a Function of that name
	// (the Lambda API's namespace, lambdaNS, or a stack's), else lambdaNS. nil invoker = lambda
	// subscriptions refused.
	lambdaNS  string
	fns       *fnLocator
	svcSuffix string
	invoker   *http.Client
	// accounts tells a member account from any other account id an ARN may carry (topicIn,
	// endpointQueue); nil knows none.
	accounts accountHomes
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

	res := snsAuthzTopic(op, r)
	ctx := r.Context()

	// The topic the request addresses, in the account it belongs to (topicTarget): the caller's own, or —
	// named by an ARN — another account's, which is then reached across accounts.
	t, byTopicArn := topicRef{account: h.acct(ctx), name: res}, false
	if h.store != nil {
		if !isMemberRequest(ctx) {
			// A management-account topic made before the account changed answers to either ARN
			// (identity_compat.go). Only the management account ever had the legacy id.
			h.resolveLegacyARNs(ctx, r)
		}
		var err error
		if t, byTopicArn, err = h.topicTarget(ctx, op, r); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}

	// sns:<Op> on the topic (decide): in legacy the coarse SubjectAccessReview, then the data-plane
	// refinement per topic (an assumed role is checked on every op, ListTopics/ListSubscriptions on
	// Topic::*); in enforce IAM policy alone, with the topic's own policy. A topic of another account is
	// decided across accounts.
	opts, legacy := h.accountAuthz(ctx, t.account, coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "openinfra.dev", "applications", h.authzNS, res,
		"sns:"+op, "Topic", res))
	if ok, reason := decide(ctx, r, h.authz, claims, "sns:"+op, "Topic", res, legacy,
		append(h.topicPolicyOpt(ctx, t), opts...)...); !ok {
		writeQueryError(w, http.StatusForbidden, "AuthorizationError", requestID, reason, snsXMLNamespace)
		return
	}
	if h.store == nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID,
			"the SNS data layer is not configured on this shim (set SQS_PG_URI)", snsXMLNamespace)
		return
	}

	// A topic is its name: a TopicArn naming another region (the ARN a stack reported) means the topic of
	// that name in the account the ARN names (topicTarget).
	if a := r.FormValue("TopicArn"); a != "" && byTopicArn && t.arn != "" && t.arn != a {
		r.Form.Set("TopicArn", t.arn)
		if r.PostForm != nil {
			r.PostForm.Set("TopicArn", t.arn)
		}
	}
	switch op {
	case "CreateTopic":
		h.createTopic(ctx, w, r, requestID)
	case "DeleteTopic":
		h.deleteTopic(ctx, w, r, requestID)
	case "ListTopics":
		h.listTopics(ctx, w, requestID)
	case "GetTopicAttributes":
		h.getTopicAttributes(ctx, w, r, requestID, t)
	case "SetTopicAttributes":
		h.setTopicAttributes(ctx, w, r, requestID)
	case "Subscribe":
		h.subscribe(ctx, w, r, requestID, claims, t)
	case "Unsubscribe":
		h.unsubscribe(ctx, w, r, requestID)
	case "ListSubscriptions":
		h.listSubscriptions(ctx, w, r, requestID, "", h.acct(ctx))
	case "ListSubscriptionsByTopic":
		h.listSubscriptions(ctx, w, r, requestID, r.PostFormValue("TopicArn"), t.account)
	case "GetSubscriptionAttributes":
		h.getSubscriptionAttributes(ctx, w, r, requestID, t)
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
	if memberKeyRe.MatchString(name) {
		// "<account>:<name>" is a member account's store key (accountKey), and no topic name AWS accepts
		// (letters, digits, hyphens and underscores): one account cannot make a topic in another's.
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "Invalid parameter: Topic Name", snsXMLNamespace)
		return
	}
	arn := h.topicARNIn(h.acct(ctx), name) // a topic is made in the caller's account
	if _, err := h.store.createTopic(ctx, arn, accountKey(ctx, name)); err != nil {
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

// listTopics lists the caller's account's topics — never another account's.
func (h *snsHandler) listTopics(ctx context.Context, w http.ResponseWriter, requestID string) {
	arns, err := h.store.listTopicsIn(ctx, callerAccount(ctx))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeTopicList(w, requestID, arns)
}

func (h *snsHandler) getTopicAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, t topicRef) {
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
		"Owner":                  t.account,
		"SubscriptionsConfirmed": itoa(len(subs)),
		"SubscriptionsPending":   "0",
		"DisplayName":            attrs["DisplayName"],
	}
	if p := attrs[policyAttr]; p != "" {
		out[policyAttr] = p
	}
	h.writeAttributes(w, requestID, "GetTopicAttributes", out)
}

func (h *snsHandler) setTopicAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("TopicArn")
	name := r.PostFormValue("AttributeName")
	val := r.PostFormValue("AttributeValue")
	if name == "Policy" {
		// A topic policy decides the publishes the shim itself makes to the topic (a CloudWatch alarm's;
		// resource_policy.go). Callers stay authorized by IAM (one policy world), so a grant to a user or
		// role — or anything else the shim cannot honor — is refused rather than kept and ignored.
		canonical, found, err := h.canonicalTopicArn(ctx, arn)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !found {
			writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Topic does not exist.", snsXMLNamespace)
			return
		}
		if err := checkResourcePolicy(val, canonical); err != nil {
			writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "Invalid parameter: Policy: "+err.Error(), snsXMLNamespace)
			return
		}
		arn = canonical
		if strings.TrimSpace(val) == "" {
			val = "" // removes the policy
		}
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

func (h *snsHandler) subscribe(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, t topicRef) {
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
	// sqs and lambda are delivered. Every other protocol is refused HONESTLY at subscribe time — a
	// subscription that exists but never delivers is worse than a rejected subscribe (the operator has
	// evidence that contradicts reality). http/https are additionally an egress surface (deferred until a
	// confirmation handshake + destination allowlist land).
	if protocol == "lambda" {
		h.subscribeLambda(ctx, w, r, requestID, claims, topicArn, endpoint)
		return
	}
	if protocol != "sqs" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"subscription protocol '"+protocol+"' is not supported by this shim (sqs and lambda are delivered). It is refused rather than accepted and never delivered.", snsXMLNamespace)
		return
	}
	attrs := parseQueryMap(r, "Attributes")
	filter, err := subscriptionFilter(attrs)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "Invalid parameter: FilterPolicy: "+err.Error(), snsXMLNamespace)
		return
	}
	// The endpoint must be a queue we know (an SQS queue ARN); reject a dangling subscription early.
	if h.sqs == nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "sqs delivery is not configured", snsXMLNamespace)
		return
	}
	queueURL, queueOwner, ok, err := h.endpointQueue(ctx, t.account, endpoint)
	if err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "the sqs endpoint queue does not exist: "+endpoint, snsXMLNamespace)
		return
	}
	if reason, ok, err := h.mayDeliverToQueue(ctx, r, claims, topicArn, t.account, queueURL, queueOwner); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeQueryError(w, http.StatusForbidden, "AuthorizationError", requestID,
			"not authorized to subscribe the queue "+endpoint+" (a subscription cannot send where its creator cannot): "+reason, snsXMLNamespace)
		return
	}
	if strings.HasSuffix(nameFromArn(endpoint), ".fifo") {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID,
			"Invalid parameter: Endpoint Reason: FIFO SQS Queues can not be subscribed to standard SNS topics", snsXMLNamespace)
		return
	}
	raw := strings.EqualFold(attrs["RawMessageDelivery"], "true")
	subArn := topicArn + ":" + randHex(8)
	if err := h.store.subscribeWith(ctx, subArn, topicArn, "sqs", endpoint, raw, filter); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "Subscribe", map[string]string{"SubscriptionArn": subArn})
}

// mayDeliverToQueue reports whether a subscription the caller makes to a topic of account topicOwner may
// deliver into the queue at queueURL, of account queueOwner: the caller may send to that queue itself
// (sqs:SendMessage, as the SQS front door checks it — across accounts for another account's queue, with
// the queue's own policy), or the queue's own policy lets this topic send to it — the queue owner's
// grant, as on AWS. The shim delivers to a queue with no policy from its own account's topics, so
// without this a subscription could write into any queue of the account.
func (h *snsHandler) mayDeliverToQueue(ctx context.Context, r *http.Request, claims iam.Claims, topicArn, topicOwner, queueURL, queueOwner string) (string, bool, error) {
	queue := queueNameFromURL(queueURL)
	verb, _ := verbForSQSOp("SendMessage")
	opts, legacy := h.accountAuthz(ctx, queueOwner, coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "openinfra.dev", "applications", h.authzNS, queue,
		"sqs:SendMessage", "Queue", queue))
	if h.normAccount(queueOwner) != h.acct(ctx) {
		opts = append(h.queuePolicyOpt(ctx, queueURL), opts...)
	}
	if ok, reason := decide(ctx, r, h.authz, claims, "sqs:SendMessage", "Queue", queue, legacy, opts...); ok {
		return "", true, nil
	} else {
		granted, err := h.queueGrantsTopicFrom(ctx, topicArn, topicOwner, queueURL, queueOwner)
		return reason, granted, err
	}
}

// queueGrantsTopic reports whether the queue's own policy (one is set) lets the topic send to it — each
// in the account it belongs to (its store key; a topic not yet stored, the account its ARN names).
func (h *snsHandler) queueGrantsTopic(ctx context.Context, topicArn, queueURL string) (bool, error) {
	if h.sqs == nil {
		return false, nil
	}
	topicOwner, err := h.topicOwner(ctx, topicArn)
	if err != nil {
		return false, err
	}
	queueOwner := h.account
	if key, ok, err := h.sqs.queueKeyByURL(ctx, queueURL); err != nil {
		return false, err
	} else if ok {
		queueOwner, _ = splitAccountKey(key)
	}
	return h.queueGrantsTopicFrom(ctx, topicArn, topicOwner, queueURL, h.normAccount(queueOwner))
}

// queueGrantsTopicFrom is queueGrantsTopic with the topic's and the queue's accounts known.
func (h *snsHandler) queueGrantsTopicFrom(ctx context.Context, topicArn, topicOwner, queueURL, queueOwner string) (bool, error) {
	if h.sqs == nil {
		return false, nil
	}
	attrs, _, found, err := h.sqs.queueAttrs(ctx, queueURL)
	if err != nil || !found || strings.TrimSpace(attrs[policyAttr]) == "" {
		return false, err
	}
	return queueAcceptsIn(ctx, h.sqs, h.region, h.normAccount(queueOwner), queueURL, resourcepolicy.Request{
		Service: "sns.amazonaws.com", Action: "sqs:SendMessage", SourceArn: topicArn, SourceAccount: h.normAccount(topicOwner)}, h.logger)
}

func (h *snsHandler) unsubscribe(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("SubscriptionArn")
	if _, err := h.store.unsubscribe(ctx, arn); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "Unsubscribe", nil)
}

// listSubscriptions lists the subscriptions to topicArn, or (topicArn "") to the caller's account's
// topics — never another account's; owner is the account they are reported as owned by.
func (h *snsHandler) listSubscriptions(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, topicArn, owner string) {
	var subs []snsSubscription
	var err error
	action := "ListSubscriptions"
	if topicArn != "" {
		subs, err = h.store.subscriptionsForTopic(ctx, topicArn)
		action = "ListSubscriptionsByTopic"
	} else {
		subs, err = h.store.listSubscriptionsIn(ctx, callerAccount(ctx))
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeSubscriptionList(w, requestID, action, subs, owner)
}

func (h *snsHandler) getSubscriptionAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, t topicRef) {
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
		"Owner":              t.account,
	}
	if sub.FilterPolicy != "" {
		out["FilterPolicy"] = sub.FilterPolicy
		out["FilterPolicyScope"] = filterScope(sub.FilterPolicyScope)
	}
	h.writeAttributes(w, requestID, "GetSubscriptionAttributes", out)
}

func (h *snsHandler) setSubscriptionAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	arn := r.PostFormValue("SubscriptionArn")
	name := r.PostFormValue("AttributeName")
	val := r.PostFormValue("AttributeValue")
	if name == "FilterPolicy" || name == "FilterPolicyScope" {
		h.setSubscriptionFilter(ctx, w, requestID, arn, name, val)
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
	attrs, err := publishAttributes(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ParameterValueInvalid", requestID, err.Error(), snsXMLNamespace)
		return
	}
	msgID, err := h.publishMessageAttrs(ctx, topicArn, subject, message, attrs)
	if err != nil {
		h.internal(w, requestID, err) // durable delivery failed -> not a success
		return
	}
	h.writeResult(w, requestID, "Publish", map[string]string{"MessageId": msgID})
}

// publishMessage fans a message out to a topic's sqs subscriptions durably (a row INSERT per subscriber
// BEFORE returning), returning the MessageId. It is the programmatic Publish path — used by the HTTP
// Publish handler above AND by the CloudWatch alarm evaluator firing an SNS AlarmAction.
// The caller must have already confirmed the topic exists. An error means at least one durable delivery
// failed, so the caller must not treat the publish as succeeded.
func (h *snsHandler) publishMessage(ctx context.Context, topicArn, subject, message string) (string, error) {
	return h.publishMessageAttrs(ctx, topicArn, subject, message, nil)
}

// publishMessageAttrs is publishMessage for a message with attributes: each subscription's filter policy
// decides whether it receives the message (sns_filter.go), and the attributes travel with it. Nothing is
// taken from ctx's account: the topic's account is the one it is stored in (topicOwner), so a publish
// without a request (an alarm's) delivers exactly as one through the API — each queue looked up in the
// account its ARN names, and decided by its policy for this topic's account.
func (h *snsHandler) publishMessageAttrs(ctx context.Context, topicArn, subject, message string, attrs map[string]snsfilter.Attr) (string, error) {
	subs, err := h.store.subscriptionsForTopic(ctx, topicArn)
	if err != nil {
		return "", err
	}
	owner := h.account
	if len(subs) > 0 {
		if owner, err = h.topicOwner(ctx, topicArn); err != nil {
			return "", err
		}
	}
	msgID := uuidLike()
	for _, sub := range subs {
		if !h.passesFilter(sub, message, attrs) {
			continue
		}
		if sub.Protocol == "lambda" {
			h.deliverLambda(sub, msgID, topicArn, subject, message, attrs)
			continue
		}
		if sub.Protocol != "sqs" {
			continue // only sqs and lambda are deliverable; others were refused at Subscribe
		}
		url, queueOwner, ok, err := h.endpointQueue(ctx, owner, sub.Endpoint)
		if err != nil {
			return "", err
		}
		if !ok {
			// The target queue was deleted after subscribe; skip but do not fail the whole publish.
			h.logger.Warn("sns: subscription endpoint queue missing, skipping", "endpoint", sub.Endpoint)
			continue
		}
		if strings.HasSuffix(url, ".fifo") {
			h.logger.Warn("sns: a FIFO queue cannot take a standard topic's delivery; skipping", "endpoint", sub.Endpoint)
			continue
		}
		// The queue's policy decides whether this topic may send to it (resource_policy.go) — a queue of
		// another account takes it only when its policy says so. A refused delivery fails as on AWS: the
		// publish succeeds, the queue gets nothing.
		accepts, err := queueAcceptsIn(ctx, h.sqs, h.region, queueOwner, url, resourcepolicy.Request{
			Service: "sns.amazonaws.com", Action: "sqs:SendMessage", SourceArn: topicArn, SourceAccount: owner}, h.logger)
		if err != nil {
			return "", err
		}
		if !accepts {
			h.logger.Warn("sns: the queue's policy does not let this topic send to it; not delivered", "topic", topicArn, "endpoint", sub.Endpoint)
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
			if len(attrs) > 0 {
				env["MessageAttributes"] = envelopeAttributes(attrs)
			}
			b, _ := json.Marshal(env)
			body = string(b)
		}
		var qattrs map[string]any
		md5Attrs := ""
		if sub.Raw && len(attrs) > 0 {
			// Raw delivery hands the message attributes to SQS as the message's own, as SNS does.
			qattrs = sqsAttributes(attrs)
			md5Attrs = md5OfMessageAttributes(qattrs)
		}
		if _, err := h.sqs.sendMessage(ctx, url, body, md5Hex(body), md5Attrs, qattrs, 0); err != nil {
			return "", err
		}
	}
	return msgID, nil
}

// --- XML response writers ---

// topicARNIn is the ARN of account's topic name.
func (h *snsHandler) topicARNIn(account, name string) string {
	return "arn:aws:sns:" + h.region + ":" + account + ":" + name
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

func (h *snsHandler) writeSubscriptionList(w http.ResponseWriter, requestID, action string, subs []snsSubscription, owner string) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<` + action + `Response xmlns="` + snsXMLNamespace + `"><` + action + `Result><Subscriptions>`)
	for _, s := range subs {
		b.WriteString(`<member>`)
		b.WriteString(`<SubscriptionArn>` + xmlEscape(s.Arn) + `</SubscriptionArn>`)
		b.WriteString(`<TopicArn>` + xmlEscape(s.TopicArn) + `</TopicArn>`)
		b.WriteString(`<Protocol>` + xmlEscape(s.Protocol) + `</Protocol>`)
		b.WriteString(`<Endpoint>` + xmlEscape(s.Endpoint) + `</Endpoint>`)
		b.WriteString(`<Owner>` + xmlEscape(owner) + `</Owner>`)
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
// snsAuthzTopic is the topic an op is authorized against: the one named by the field the op acts on.
// CreateTopic names it by Name; Publish by TopicArn, else TargetArn; the subscription ops by the topic of
// their SubscriptionArn; the other topic ops by TopicArn. Fields an op ignores are ignored here too, so a
// Name or TopicArn sent alongside cannot redirect the check. ListTopics/ListSubscriptions name none.
func snsAuthzTopic(op string, r *http.Request) string {
	switch op {
	case "CreateTopic":
		return r.PostFormValue("Name")
	case "Publish", "PublishBatch":
		if ta := r.PostFormValue("TopicArn"); ta != "" {
			return nameFromArn(ta)
		}
		if ta := r.PostFormValue("TargetArn"); ta != "" {
			return nameFromArn(ta)
		}
		return ""
	case "Unsubscribe", "GetSubscriptionAttributes", "SetSubscriptionAttributes":
		if sa := r.PostFormValue("SubscriptionArn"); sa != "" {
			return nameFromArn(topicArnOfSub(sa))
		}
		return ""
	case "ListTopics", "ListSubscriptions":
		return ""
	}
	if ta := r.PostFormValue("TopicArn"); ta != "" {
		return nameFromArn(ta)
	}
	return ""
}

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

// topicPolicyOpt carries topic t's Policy attribute (its resource policy) to the evaluator, read only
// when IAM policy decides (resourcePolicyOpt).
func (h *snsHandler) topicPolicyOpt(ctx context.Context, t topicRef) []iamauthz.RequestOption {
	if h.store == nil || t.arn == "" {
		return nil
	}
	return resourcePolicyOpt(h.authz, func() string {
		attrs, found, err := h.store.topicAttrs(ctx, t.arn)
		if err != nil || !found {
			return ""
		}
		return attrs["Policy"]
	})
}

// queuePolicyOpt carries the Policy attribute of the queue at url to the evaluator (sqsHandler's).
func (h *snsHandler) queuePolicyOpt(ctx context.Context, url string) []iamauthz.RequestOption {
	if h.sqs == nil || url == "" {
		return nil
	}
	return resourcePolicyOpt(h.authz, func() string {
		attrs, _, found, err := h.sqs.queueAttrs(ctx, url)
		if err != nil || !found {
			return ""
		}
		return attrs[policyAttr]
	})
}

// --- accounts ---

func init() { accountScopedServices["sns"] = true }

// topicRef is the topic a request addresses: the account it belongs to (h.account for the management
// account's), its name, its store key, and the ARN it is stored under ("" when that account has no such
// topic).
type topicRef struct {
	account, name, key, arn string
}

// acct is the account the caller acts in, as the topics it makes and lists name it: a member account's
// id, or the handler's own for the management account (every ARN exactly as before accounts).
func (h *snsHandler) acct(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// normAccount is account with the management account's id — however it is written — as h.account.
func (h *snsHandler) normAccount(account string) string { return normAccount(h.account, account) }

// keyFor is the store key of account's topic (or queue) name.
func (h *snsHandler) keyFor(account, name string) string {
	if a := h.normAccount(account); a != h.account {
		return a + ":" + name
	}
	return name
}

// accountAuthz is sqsHandler.accountAuthz for a topic (or, for a subscription's delivery, a queue).
func (h *snsHandler) accountAuthz(ctx context.Context, owner string, legacy func() (bool, string)) ([]iamauthz.RequestOption, func() (bool, string)) {
	return accountAuthzFor(ctx, h.acct(ctx), h.normAccount(owner), h.account, legacy)
}

// topicTarget is the topic op addresses, in the account it belongs to, and whether it was named by the
// request's TopicArn: CreateTopic's in the caller's account; Publish's by TopicArn (else TargetArn); a
// subscription op's by its subscription's topic; every other topic op's by TopicArn (topicByARN).
// ListTopics and ListSubscriptions name none (the caller's account).
func (h *snsHandler) topicTarget(ctx context.Context, op string, r *http.Request) (topicRef, bool, error) {
	switch op {
	case "ListTopics", "ListSubscriptions":
		return topicRef{account: h.acct(ctx)}, false, nil
	case "CreateTopic":
		t, err := h.topicIn(ctx, "", r.PostFormValue("Name"))
		return t, false, err
	case "Publish", "PublishBatch":
		if a := r.PostFormValue("TopicArn"); a != "" {
			t, err := h.topicByARN(ctx, a)
			return t, true, err
		}
		if a := r.PostFormValue("TargetArn"); a != "" {
			t, err := h.topicByARN(ctx, a)
			return t, false, err
		}
		return topicRef{account: h.acct(ctx)}, false, nil
	case "Unsubscribe", "GetSubscriptionAttributes", "SetSubscriptionAttributes":
		sa := r.PostFormValue("SubscriptionArn")
		if sa == "" {
			return topicRef{account: h.acct(ctx)}, false, nil
		}
		topic := topicArnOfSub(sa)
		if sub, ok, err := h.store.subByArn(ctx, sa); err != nil {
			return topicRef{}, false, err
		} else if ok {
			topic = sub.TopicArn // the topic it is a subscription to, whichever account's
		}
		t, err := h.topicByARN(ctx, topic)
		return t, false, err
	}
	a := r.PostFormValue("TopicArn")
	if a == "" {
		return topicRef{account: h.acct(ctx)}, false, nil
	}
	t, err := h.topicByARN(ctx, a)
	return t, true, err
}

// topicByARN is the topic a TopicArn addresses: the topic stored under that ARN, whichever account's it
// is; else the topic its last segment names in the account the ARN names (a topic is its name: the ARN a
// stack reported for another region) — never another account's for an ARN naming the caller's (topicIn).
func (h *snsHandler) topicByARN(ctx context.Context, arn string) (topicRef, error) {
	key, ok, err := h.store.topicKeyByARN(ctx, arn)
	if err != nil {
		return topicRef{}, err
	}
	if ok {
		account, name := splitAccountKey(key)
		return topicRef{account: h.normAccount(account), name: name, key: key, arn: arn}, nil
	}
	return h.topicIn(ctx, awsidentity.AccountOfARN(arn), nameFromArn(arn))
}

// topicIn is topic name of account named ("" = the caller's own), as sqsHandler.queueIn: a topic of
// another account than the caller's is that account's, reached across accounts; the management account
// keeps what it always had (a topic it names in an account id that is no member account's is its own of
// that name); a member account's name never falls back to another account's topic, nor another
// account's name to a member's own.
func (h *snsHandler) topicIn(ctx context.Context, named, name string) (topicRef, error) {
	caller := h.acct(ctx)
	if named != "" {
		if named = h.normAccount(named); named != caller {
			key := h.keyFor(named, name)
			arn, ok, err := h.store.topicARNByName(ctx, key)
			if err != nil || ok || isMemberRequest(ctx) || knownMember(h.accounts, named) {
				return topicRef{account: named, name: name, key: key, arn: arn}, err
			}
		}
	}
	key := accountKey(ctx, name)
	arn, _, err := h.store.topicARNByName(ctx, key)
	return topicRef{account: caller, name: name, key: key, arn: arn}, err
}

// topicOwner is the account of the topic stored under arn (its store key); a topic not stored is the
// account its ARN names. Work without a request (an alarm's publish) takes the account from here.
func (h *snsHandler) topicOwner(ctx context.Context, arn string) (string, error) {
	key, ok, err := h.store.topicKeyByARN(ctx, arn)
	if err != nil {
		return "", err
	}
	if !ok {
		return h.normAccount(awsidentity.AccountOfARN(arn)), nil
	}
	account, _ := splitAccountKey(key)
	return h.normAccount(account), nil
}

// endpointQueue is the queue an sqs subscription's endpoint (a queue ARN) names, for a topic of account
// topicOwner: the queue of that name in the account the ARN names (one naming none, or the legacy id:
// the topic's own account), and that account. A management-account topic keeps what it always had: an
// endpoint naming an account id that is no member account's means its own account's queue of that name.
func (h *snsHandler) endpointQueue(ctx context.Context, topicOwner, endpoint string) (url, owner string, ok bool, err error) {
	name := nameFromArn(endpoint)
	owner = h.normAccount(topicOwner)
	if a := awsidentity.AccountOfARN(endpoint); a != "" {
		owner = h.normAccount(a)
	}
	if url, ok, err = h.sqs.queueURLByName(ctx, h.keyFor(owner, name)); err != nil || ok ||
		owner == h.account || h.normAccount(topicOwner) != h.account || knownMember(h.accounts, owner) {
		return url, owner, ok, err
	}
	url, ok, err = h.sqs.queueURLByName(ctx, name)
	return url, h.account, ok, err
}
