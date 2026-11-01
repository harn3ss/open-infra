package main

import (
	"context"
	"net/http"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// Identity compatibility: earlier releases presented the account as "open-infra", so topics and queues
// created then are stored under ARNs and URLs that carry it (arn:aws:sns:<region>:open-infra:<name>,
// <scheme>://<host>/open-infra/<name>). SNS keys topics and subscriptions by their full ARN and SQS keys
// queues by their full URL, so a request naming a resource is matched against every form the same
// resource may be stored under: the form given, the current account's, and the legacy one. A client that
// kept an old ARN or URL keeps working, and so does one that builds the ARN from the current account
// (e.g. a template's ${AWS::AccountId}) for a topic made before the change. A form that matches nothing
// is replaced by the current account's, so an error names the resource as AWS would.

// resolveStored returns the first of the forms v may be stored under for which exists reports true, or
// the current account's form when none does. v is returned unchanged when it has only one form (a name,
// another account's ARN) or a lookup fails.
func resolveStored(ctx context.Context, id awsidentity.Identity, v string, exists func(context.Context, string) (bool, error)) string {
	forms := id.Equivalents(v)
	if v == "" || len(forms) == 1 {
		return v
	}
	for _, f := range forms {
		ok, err := exists(ctx, f)
		if err != nil {
			return v
		}
		if ok {
			return f
		}
	}
	return id.Canonical(v)
}

// resolveLegacyARNs rewrites the request's TopicArn, TargetArn and SubscriptionArn to the form the topic
// or subscription is stored under (see above), before the op reads them.
func (h *snsHandler) resolveLegacyARNs(ctx context.Context, r *http.Request) {
	id := awsidentity.Identity{AccountID: h.account, Region: h.region}
	topicExists := func(ctx context.Context, arn string) (bool, error) { return h.store.topicExists(ctx, arn) }
	subExists := func(ctx context.Context, arn string) (bool, error) {
		_, ok, err := h.store.subByArn(ctx, arn)
		return ok, err
	}
	for key, exists := range map[string]func(context.Context, string) (bool, error){
		"TopicArn": topicExists, "TargetArn": topicExists, "SubscriptionArn": subExists,
	} {
		v := r.PostFormValue(key)
		if v == "" {
			continue
		}
		if got := resolveStored(ctx, id, v, exists); got != v {
			r.PostForm.Set(key, got)
			r.Form.Set(key, got)
		}
	}
}

// resolveLegacyQueueURL rewrites the request's QueueUrl to the form the queue is stored under.
func (h *sqsHandler) resolveLegacyQueueURL(ctx context.Context, body map[string]any) {
	u, _ := body["QueueUrl"].(string)
	if u == "" {
		return
	}
	id := awsidentity.Identity{AccountID: h.account, Region: h.region}
	exists := func(ctx context.Context, url string) (bool, error) {
		_, _, ok, err := h.store.queueAttrs(ctx, url)
		return ok, err
	}
	if got := resolveStored(ctx, id, u, exists); got != u {
		body["QueueUrl"] = got
	}
}
