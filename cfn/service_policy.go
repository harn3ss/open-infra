package cfn

// AWS::SQS::QueuePolicy and AWS::SNS::TopicPolicy, through the aws-shim front door (Capabilities.SQSAPI
// / SNSAPI): the policy document becomes the queue's or topic's Policy attribute in the SQS or SNS API's
// store, where it decides the deliveries the shim makes to that queue or topic (an SNS topic's or an
// EventBridge rule's SendMessage to a queue; a CloudWatch alarm's Publish to a topic). The part of a
// policy that can be honored is resourcepolicy's: grants to services, narrowed by source; anything else
// refuses the resource, as the SQS and SNS front doors refuse it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
)

// The policy service kinds (name = the policy's physical id).
const (
	KindSQSQueuePolicy = "SQSQueuePolicy"
	KindSNSTopicPolicy = "SNSTopicPolicy"
)

// svcPolicyID is a queue or topic policy's physical id (what its Ref returns): fixed by the stack and
// logical id, so an update finds the same one.
func svcPolicyID(id string, ctx *stackCtx) string {
	sum := sha256.Sum256([]byte(ctx.stackName() + "/" + id))
	return ctx.stackName() + "-" + id + "-" + strings.ToUpper(hex.EncodeToString(sum[:])[:12])
}

// policyDocJSON renders a resolved PolicyDocument (an object, or a JSON string) as the JSON the store
// keeps, refusing one that still carries a value with no concrete result.
func policyDocJSON(id string, v any) (string, []Finding) {
	var doc string
	switch t := v.(type) {
	case nil:
		return "", []Finding{{"Resource " + id, "PolicyDocument is required"}}
	case map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return "", []Finding{{"Resource " + id, "PolicyDocument is not a JSON object"}}
		}
		doc = string(b)
	case string:
		var m map[string]any
		if err := json.Unmarshal([]byte(t), &m); err != nil {
			return "", []Finding{{"Resource " + id, "PolicyDocument is not a JSON object"}}
		}
		doc = t
	default:
		return "", []Finding{{"Resource " + id, "PolicyDocument must be an object"}}
	}
	if placeholderRe.MatchString(doc) {
		return "", []Finding{{"Resource " + id, "PolicyDocument references a value with no concrete result here — refusing rather than storing a placeholder"}}
	}
	return doc, nil
}

// translateSQSQueuePolicy maps an AWS::SQS::QueuePolicy to the Policy attribute of each queue it names,
// in the SQS API's store.
func translateSQSQueuePolicy(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	f := blockUnknownProps(id, props, map[string]bool{"PolicyDocument": true, "Queues": true})
	if !ctx.caps.SQSAPI {
		return nil, append(f, Finding{"Resource " + id, "an AWS::SQS::QueuePolicy is applied to queues in the SQS API, which this deploy path does not serve"})
	}
	doc, df := policyDocJSON(id, props["PolicyDocument"])
	f = append(f, df...)
	list, _ := props["Queues"].([]any)
	if len(list) == 0 {
		f = append(f, Finding{"Resource " + id, "Queues must list at least one queue URL (e.g. !Ref Queue)"})
	}
	var names []any
	seen := map[string]bool{}
	for _, u := range list {
		s, ok := concrete(u)
		name := s[strings.LastIndex(s, "/")+1:]
		if !ok || !strings.Contains(s, "/") || !sqsQueueNameRe.MatchString(name) {
			f = append(f, Finding{"Resource " + id, "each of Queues must resolve to an SQS queue URL (e.g. !Ref Queue)"})
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
		if doc != "" {
			if _, err := resourcepolicy.Parse(doc, svcQueueARN(name, ctx)); err != nil {
				f = append(f, Finding{"Resource " + id, "PolicyDocument (queue " + name + "): " + err.Error()})
			}
		}
	}
	if doc != "" {
		var arns []string
		for _, n := range names {
			arns = append(arns, svcQueueARN(fmt.Sprint(n), ctx))
		}
		f = append(f, foreignResources(id, doc, arns, "queue")...)
	}
	if len(f) > 0 {
		return nil, f
	}
	return serviceManifest(KindSQSQueuePolicy, svcPolicyID(id, ctx), map[string]any{"queues": names, "document": doc}), nil
}

// foreignResources refuses a policy statement's Resource that names a queue (or topic) the policy is not
// attached to: one policy may cover several of its own (each statement applies to the ones its Resource
// matches, as on AWS), but a grant for one it is not attached to would be applied nowhere.
func foreignResources(id, doc string, attached []string, what string) []Finding {
	var d struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(doc), &d) != nil {
		return nil // policyDocJSON / resourcepolicy.Parse report a malformed document
	}
	var stmts []map[string]any
	if json.Unmarshal(d.Statement, &stmts) != nil {
		var one map[string]any
		if json.Unmarshal(d.Statement, &one) != nil {
			return nil
		}
		stmts = []map[string]any{one}
	}
	svc := ""
	if len(attached) > 0 {
		if p := strings.SplitN(attached[0], ":", 6); len(p) == 6 {
			svc = p[2]
		}
	}
	var f []Finding
	for _, st := range stmts {
		var res []string
		switch r := st["Resource"].(type) {
		case string:
			res = []string{r}
		case []any:
			for _, e := range r {
				if s, ok := e.(string); ok {
					res = append(res, s)
				}
			}
		}
		for _, r := range res {
			p := strings.SplitN(r, ":", 6)
			if r == "*" || strings.ContainsAny(r, "*?") || len(p) != 6 || p[2] != svc {
				continue
			}
			mine := false
			for _, a := range attached {
				mine = mine || resourcepolicy.SameResource(r, a)
			}
			if !mine {
				f = append(f, Finding{"Resource " + id, "PolicyDocument names " + r + ", a " + what + " this policy is not attached to — list it in the policy's " + map[string]string{"queue": "Queues", "topic": "Topics"}[what] + ", or drop it"})
			}
		}
	}
	return f
}

// translateSNSTopicPolicy maps an AWS::SNS::TopicPolicy to the Policy attribute of each topic it names,
// in the SNS API's store.
func translateSNSTopicPolicy(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	f := blockUnknownProps(id, props, map[string]bool{"PolicyDocument": true, "Topics": true})
	if !ctx.caps.SNSAPI {
		return nil, append(f, Finding{"Resource " + id, "an AWS::SNS::TopicPolicy is applied to topics in the SNS API, which this deploy path does not serve"})
	}
	doc, df := policyDocJSON(id, props["PolicyDocument"])
	f = append(f, df...)
	list, _ := props["Topics"].([]any)
	if len(list) == 0 {
		f = append(f, Finding{"Resource " + id, "Topics must list at least one topic ARN (e.g. !Ref Topic)"})
	}
	var arns []any
	seen := map[string]bool{}
	for _, v := range list {
		arn, ok := concrete(v)
		if !ok || !strings.HasPrefix(arn, "arn:") || !strings.Contains(arn, ":sns:") || strings.ContainsAny(arn, "*?") {
			f = append(f, Finding{"Resource " + id, "each of Topics must resolve to an SNS topic ARN (e.g. !Ref Topic)"})
			continue
		}
		if seen[arn] {
			continue
		}
		seen[arn] = true
		arns = append(arns, arn)
		if doc != "" {
			if _, err := resourcepolicy.Parse(doc, arn); err != nil {
				f = append(f, Finding{"Resource " + id, "PolicyDocument (topic " + arn + "): " + err.Error()})
			}
		}
	}
	if doc != "" {
		var attached []string
		for _, a := range arns {
			attached = append(attached, fmt.Sprint(a))
		}
		f = append(f, foreignResources(id, doc, attached, "topic")...)
	}
	if len(f) > 0 {
		return nil, f
	}
	return serviceManifest(KindSNSTopicPolicy, svcPolicyID(id, ctx), map[string]any{"topics": arns, "document": doc}), nil
}
