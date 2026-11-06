// Queue and topic policies: the deliveries the shim makes to a queue or topic, decided by its Policy.
//
// On AWS an SNS topic may send to a queue only when the queue's policy lets it (the SNS fan-out
// QueuePolicy), and likewise an EventBridge rule; a CloudWatch alarm publishes to a topic its policy lets
// it. Here the shim makes those deliveries itself, so it asks the queue's or topic's Policy attribute —
// set through SetQueueAttributes/SetTopicAttributes, or by a stack's AWS::SQS::QueuePolicy /
// AWS::SNS::TopicPolicy — in the part cfn/resourcepolicy honors (grants to services, narrowed by source),
// and refuses any other policy where it is set. A queue or topic with no policy takes every delivery, as
// before (on AWS a queue with no policy takes none from SNS; that divergence is documented).
//
// Callers of the SQS and SNS APIs are authorized by IAM (RBAC + kind: Policy), not by these policies.
package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
)

// policyAttr is the queue and topic attribute that holds the policy document.
const policyAttr = "Policy"

func sqsResourceARN(region, account, name string) string {
	return "arn:aws:sqs:" + region + ":" + account + ":" + name
}

// checkResourcePolicy validates a policy document about to be set on the queue or topic resourceARN
// ("" = removing the policy, always fine).
func checkResourcePolicy(doc, resourceARN string) error {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	_, err := resourcepolicy.Parse(doc, resourceARN)
	return err
}

// policyAccepts reports whether a resource with Policy doc takes the delivery req. No policy takes it. A
// stored policy that does not parse was set before policies were honored (the SQS API used to keep any
// Policy unread): it is not applied, as before, and that is logged.
func policyAccepts(doc, resourceARN string, req resourcepolicy.Request, logger *slog.Logger) bool {
	if strings.TrimSpace(doc) == "" {
		return true
	}
	p, err := resourcepolicy.Parse(doc, resourceARN)
	if err != nil {
		if logger != nil {
			logger.Warn("resource policy not applied: it is outside what this shim honors (set before policies were honored); delivering as before",
				"resource", resourceARN, "error", err.Error())
		}
		return true
	}
	return p.Allows(req)
}

// queueAccepts reports whether the queue at url takes the delivery req (false if it does not exist).
func queueAccepts(ctx context.Context, st *sqsStore, region, account, url string, req resourcepolicy.Request, logger *slog.Logger) (bool, error) {
	attrs, _, ok, err := st.queueAttrs(ctx, url)
	if err != nil || !ok {
		return false, err
	}
	return policyAccepts(attrs[policyAttr], sqsResourceARN(region, account, queueNameFromURL(url)), req, logger), nil
}

// policyAcceptsFrom is policyAccepts for a delivery from the resource's own account (sameAccount) or
// another's: another account's is made only when the resource's policy lets it in, as on AWS — no policy,
// or one this shim cannot read, takes deliveries from the resource's own account alone.
func policyAcceptsFrom(doc, resourceARN string, sameAccount bool, req resourcepolicy.Request, logger *slog.Logger) bool {
	if sameAccount {
		return policyAccepts(doc, resourceARN, req, logger)
	}
	if strings.TrimSpace(doc) == "" {
		return false
	}
	p, err := resourcepolicy.Parse(doc, resourceARN)
	return err == nil && p.Allows(req)
}

// queueAcceptsIn is queueAccepts for a queue of account owner (a member account's queue, or a delivery
// on behalf of another account): the queue's ARN names its account, and a delivery whose
// req.SourceAccount is another account needs the queue's policy to let it in (policyAcceptsFrom). owner
// and req.SourceAccount are written alike (one id for the management account).
func queueAcceptsIn(ctx context.Context, st *sqsStore, region, owner, url string, req resourcepolicy.Request, logger *slog.Logger) (bool, error) {
	attrs, _, ok, err := st.queueAttrs(ctx, url)
	if err != nil || !ok {
		return false, err
	}
	return policyAcceptsFrom(attrs[policyAttr], sqsResourceARN(region, owner, queueNameFromURL(url)), req.SourceAccount == owner, req, logger), nil
}

// topicAccepts reports whether the topic takes a publish by a service (a CloudWatch alarm's) — the topic
// of the account its ARN names; a publish on behalf of another account is taken only when the topic's
// policy lets it in.
func (h *snsHandler) topicAccepts(ctx context.Context, topicArn string, req resourcepolicy.Request) (bool, error) {
	t, err := h.topicByARN(ctx, topicArn)
	if err != nil || t.arn == "" {
		return false, err
	}
	attrs, ok, err := h.store.topicAttrs(ctx, t.arn)
	if err != nil || !ok {
		return false, err
	}
	return policyAcceptsFrom(attrs[policyAttr], t.arn, h.normAccount(req.SourceAccount) == t.account, req, h.logger), nil
}
