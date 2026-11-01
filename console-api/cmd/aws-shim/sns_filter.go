// SNS subscription filter policies and message attributes.
//
// A subscription's FilterPolicy (Subscribe Attributes, SetSubscriptionAttributes, or a stack's
// AWS::SNS::Subscription) decides which published messages it receives — by the message's attributes
// (FilterPolicyScope MessageAttributes, the default) or by its JSON body (MessageBody) — as SNS decides it
// (cfn/snsfilter). A policy SNS's semantics cannot be kept for is refused where it is set, never kept and
// applied differently. Publish's MessageAttributes are what an attribute policy reads, and they travel with
// the message: in the delivered envelope, as the SQS message's attributes for a raw delivery, and in the
// Lambda event.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/cfn/snsfilter"
)

// subscriptionFilter reads a Subscribe's FilterPolicy / FilterPolicyScope attributes into the
// subscription attributes to keep (empty when there is no policy).
func subscriptionFilter(attrs map[string]string) (map[string]string, error) {
	out := map[string]string{}
	policy, scope := strings.TrimSpace(attrs["FilterPolicy"]), attrs["FilterPolicyScope"]
	if policy == "" || policy == "{}" {
		if scope != "" && scope != snsfilter.ScopeAttributes && scope != snsfilter.ScopeBody {
			return nil, fmt.Errorf("FilterPolicyScope must be %s or %s", snsfilter.ScopeAttributes, snsfilter.ScopeBody)
		}
		if scope != "" {
			out["FilterPolicyScope"] = scope
		}
		return out, nil
	}
	if _, err := snsfilter.Parse(policy, scope); err != nil {
		return nil, err
	}
	out["FilterPolicy"] = policy
	if scope != "" {
		out["FilterPolicyScope"] = scope
	}
	return out, nil
}

func filterScope(s string) string {
	if s == "" {
		return snsfilter.ScopeAttributes
	}
	return s
}

// setSubscriptionFilter is SetSubscriptionAttributes for FilterPolicy or FilterPolicyScope: the
// subscription's policy and scope together must be one SNS can apply. An empty (or {}) FilterPolicy
// removes it.
func (h *snsHandler) setSubscriptionFilter(ctx context.Context, w http.ResponseWriter, requestID, arn, name, val string) {
	sub, ok, err := h.store.subByArn(ctx, arn)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeQueryError(w, http.StatusNotFound, "NotFound", requestID, "Subscription does not exist.", snsXMLNamespace)
		return
	}
	policy, scope := sub.FilterPolicy, sub.FilterPolicyScope
	if name == "FilterPolicy" {
		policy = strings.TrimSpace(val)
		if policy == "{}" {
			policy = ""
		}
	} else {
		scope = val
	}
	if _, err := subscriptionFilter(map[string]string{"FilterPolicy": policy, "FilterPolicyScope": scope}); err != nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameter", requestID, "Invalid parameter: "+name+": "+err.Error(), snsXMLNamespace)
		return
	}
	stored := policy
	if name == "FilterPolicyScope" {
		stored = scope
	}
	if _, err := h.store.setSubAttr(ctx, arn, name, stored); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "SetSubscriptionAttributes", nil)
}

// passesFilter reports whether the subscription receives this message.
func (h *snsHandler) passesFilter(sub snsSubscription, message string, attrs map[string]snsfilter.Attr) bool {
	if sub.FilterPolicy == "" {
		return true
	}
	p, err := snsfilter.Parse(sub.FilterPolicy, sub.FilterPolicyScope)
	if err != nil {
		// Policies are checked where they are set, so this is a stored policy no longer understood: deliver
		// nothing to it rather than everything, and say so.
		h.logger.Warn("sns: a subscription's FilterPolicy cannot be applied; not delivered", "subscription", sub.Arn, "error", err.Error())
		return false
	}
	if p.Scope() == snsfilter.ScopeBody {
		return p.MatchBody(message)
	}
	return p.MatchAttributes(attrs)
}

// publishAttributes reads Publish's MessageAttributes.entry.N.{Name,Value.DataType,Value.StringValue,
// Value.BinaryValue}, refusing what SNS refuses.
func publishAttributes(r *http.Request) (map[string]snsfilter.Attr, error) {
	out := map[string]snsfilter.Attr{}
	for i := 1; i <= 100; i++ {
		pre := "MessageAttributes.entry." + itoa(i) + "."
		name := r.PostFormValue(pre + "Name")
		if name == "" {
			continue
		}
		if len(out) == 10 {
			return nil, fmt.Errorf("a message has at most 10 message attributes")
		}
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "aws.") || strings.HasPrefix(lower, "amazon.") || len(name) > 256 {
			return nil, fmt.Errorf("the message attribute name %q is reserved or too long", name)
		}
		dt := r.PostFormValue(pre + "Value.DataType")
		base := dt
		if !strings.HasPrefix(dt, "String.Array") {
			if j := strings.Index(dt, "."); j >= 0 {
				base = dt[:j]
			}
		} else {
			base = "String.Array"
		}
		sv, bv := r.PostFormValue(pre+"Value.StringValue"), r.PostFormValue(pre+"Value.BinaryValue")
		switch base {
		case "String", "Number":
			if sv == "" {
				return nil, fmt.Errorf("the message attribute %q must have a StringValue", name)
			}
		case "String.Array":
			var list []any
			if json.Unmarshal([]byte(sv), &list) != nil {
				return nil, fmt.Errorf("the message attribute %q (String.Array) must be a JSON array", name)
			}
		case "Binary":
			if bv == "" {
				return nil, fmt.Errorf("the message attribute %q must have a BinaryValue", name)
			}
			sv = bv
		default:
			return nil, fmt.Errorf("the message attribute %q has an invalid DataType %q (String, String.Array, Number or Binary)", name, dt)
		}
		out[name] = snsfilter.Attr{Type: dt, Value: sv}
	}
	return out, nil
}

// envelopeAttributes are the attributes as an SNS notification (and a Lambda event) carries them.
func envelopeAttributes(attrs map[string]snsfilter.Attr) map[string]any {
	out := map[string]any{}
	for k, a := range attrs {
		out[k] = map[string]any{"Type": a.Type, "Value": a.Value}
	}
	return out
}

// sqsAttributes are the attributes as SQS message attributes (a raw delivery).
func sqsAttributes(attrs map[string]snsfilter.Attr) map[string]any {
	out := map[string]any{}
	for k, a := range attrs {
		if strings.HasPrefix(a.Type, "Binary") {
			out[k] = map[string]any{"DataType": a.Type, "BinaryValue": a.Value}
		} else {
			out[k] = map[string]any{"DataType": a.Type, "StringValue": a.Value}
		}
	}
	return out
}
