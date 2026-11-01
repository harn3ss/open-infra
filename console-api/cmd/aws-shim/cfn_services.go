// A stack's queues, topics, subscriptions, parameters, keys and aliases, in the shim's own AWS API
// stores (#347 J).
//
// The cfn engine emits these as service kinds (cfn.IsServiceKind); this applier provisions each one in
// the store the matching front door serves — the SQS queue row ReceiveMessage reads, the SNS topic
// Publish delivers from, the SSM parameter GetParameter returns, the KMS key Encrypt uses — so the
// application uses them through the AWS APIs by the names and ARNs the stack reports. Every step runs
// only for a caller that may do it through that front door (the same coarse RBAC check and
// data-plane action), so a stack can create nothing its caller could not create directly.
//
// Ownership: cfn_service_resources records which stack made each one (the analog of a Kubernetes
// object's stack label, which a store row does not have), so the engine's ownership rules — refuse to
// take over a resource another stack (or no stack) created, never re-adopt a retained one — hold here
// too. It also keeps each resource's applied spec, for drift and for fields a store does not hold.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// cfnServices are the stores the CloudFormation front door provisions service kinds into. A nil handler
// (or store) means that front door is not served here; the doorway then does not vouch for it
// (cfnDoorway.capsFor), so the engine keeps its kind mapping and never asks for it.
type cfnServices struct {
	sqs    *sqsHandler
	sns    *snsHandler
	ssm    *ssmHandler
	kms    *kmsHandler
	owners *cfnServiceOwners
}

func (s *cfnServices) sqsOK() bool {
	return s != nil && s.owners != nil && s.sqs != nil && s.sqs.store != nil
}
func (s *cfnServices) snsOK() bool {
	return s != nil && s.owners != nil && s.sns != nil && s.sns.store != nil
}
func (s *cfnServices) ssmOK() bool {
	return s != nil && s.owners != nil && s.ssm != nil && s.ssm.store != nil
}
func (s *cfnServices) kmsOK() bool {
	return s != nil && s.owners != nil && s.kms != nil && s.kms.store != nil && s.kms.transit != nil
}

// cfnServiceOwners records the stack that created each service resource, and its applied spec.
type cfnServiceOwners struct{ db *sql.DB }

func (o *cfnServiceOwners) ensureSchema(ctx context.Context) error {
	_, err := o.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS cfn_service_resources (
  kind      text NOT NULL,
  name      text NOT NULL,
  stack     text NOT NULL,
  namespace text NOT NULL,
  spec      jsonb NOT NULL DEFAULT '{}',
  updated   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, name)
);`)
	return err
}

func (o *cfnServiceOwners) get(ctx context.Context, kind, name string) (stack string, spec map[string]any, found bool, err error) {
	var sj []byte
	err = o.db.QueryRowContext(ctx, `SELECT stack, spec::text FROM cfn_service_resources WHERE kind=$1 AND name=$2`, kind, name).Scan(&stack, &sj)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	spec = map[string]any{}
	_ = json.Unmarshal(sj, &spec)
	return stack, spec, true, nil
}

func (o *cfnServiceOwners) put(ctx context.Context, kind, name, stack, ns string, spec map[string]any) error {
	sj, _ := json.Marshal(spec)
	_, err := o.db.ExecContext(ctx, `
		INSERT INTO cfn_service_resources (kind, name, stack, namespace, spec, updated) VALUES ($1,$2,$3,$4,$5::jsonb,now())
		ON CONFLICT (kind, name) DO UPDATE SET stack=EXCLUDED.stack, namespace=EXCLUDED.namespace, spec=EXCLUDED.spec, updated=now()`,
		kind, name, stack, ns, string(sj))
	return err
}

func (o *cfnServiceOwners) del(ctx context.Context, kind, name string) error {
	_, err := o.db.ExecContext(ctx, `DELETE FROM cfn_service_resources WHERE kind=$1 AND name=$2`, kind, name)
	return err
}

// ---- the applier's service-kind operations ----

func (a *impersonatingApplier) svcFor(kind string) error {
	if a.svc == nil || a.door == nil {
		return fmt.Errorf("%s resources are served by this shim's AWS API stores, which this deploy path cannot reach", kind)
	}
	ok := false
	switch kind {
	case cfn.KindSQSQueue:
		ok = a.svc.sqsOK()
	case cfn.KindSNSTopic, cfn.KindSNSSubscription:
		ok = a.svc.snsOK()
	case cfn.KindSSMParameter:
		ok = a.svc.ssmOK()
	case cfn.KindKMSKey, cfn.KindKMSAlias:
		ok = a.svc.kmsOK()
	}
	if !ok {
		return fmt.Errorf("the %s front door is not configured on this shim", kind)
	}
	return nil
}

// svcStep is one front-door call a service operation makes, and the checks that front door makes for it.
type svcStep struct {
	verb, action, resType, resID string
}

// svcSteps are the front-door calls an operation on a service resource amounts to (op is create,
// update, delete or get), each checked as that front door checks it.
func svcSteps(kind, op, name string, spec map[string]any) []svcStep {
	str := func(k string) string { s, _ := spec[k].(string); return s }
	step := func(verbOp func(string) (string, bool), service, svcOp, resType, resID string) svcStep {
		verb, _ := verbOp(svcOp)
		return svcStep{verb: verb, action: service + ":" + svcOp, resType: resType, resID: resID}
	}
	pick := func(ops map[string]string) string { return ops[op] }
	switch kind {
	case cfn.KindSQSQueue:
		svcOp := pick(map[string]string{"create": "CreateQueue", "update": "SetQueueAttributes", "delete": "DeleteQueue", "get": "GetQueueAttributes"})
		return []svcStep{step(verbForSQSOp, "sqs", svcOp, "Queue", name)}
	case cfn.KindSNSTopic:
		svcOp := pick(map[string]string{"create": "CreateTopic", "update": "SetTopicAttributes", "delete": "DeleteTopic", "get": "GetTopicAttributes"})
		return []svcStep{step(verbForSNSOp, "sns", svcOp, "Topic", name)}
	case cfn.KindSNSSubscription:
		svcOp := pick(map[string]string{"create": "Subscribe", "update": "Subscribe", "delete": "Unsubscribe", "get": "GetSubscriptionAttributes"})
		return []svcStep{step(verbForSNSOp, "sns", svcOp, "Topic", nameFromArn(str("topicArn")))}
	case cfn.KindSSMParameter:
		svcOp := pick(map[string]string{"create": "PutParameter", "update": "PutParameter", "delete": "DeleteParameter", "get": "GetParameter"})
		return []svcStep{step(verbForSSMOp, "ssm", svcOp, "Parameter", ssmScopeName(svcOp, map[string]any{"Name": name}))}
	case cfn.KindKMSKey:
		switch op {
		case "create": // CreateKey is checked on Key::* — the key has no id until it exists (as the front door)
			return []svcStep{step(verbForKMSOp, "kms", "CreateKey", "Key", "")}
		case "update": // each change is checked as it is made (svcUpdateKey); reading the key comes first
			return []svcStep{step(verbForKMSOp, "kms", "DescribeKey", "Key", name)}
		case "delete":
			return []svcStep{step(verbForKMSOp, "kms", "ScheduleKeyDeletion", "Key", name)}
		}
		return []svcStep{step(verbForKMSOp, "kms", "DescribeKey", "Key", name)}
	case cfn.KindKMSAlias:
		svcOp := pick(map[string]string{"create": "CreateAlias", "update": "UpdateAlias", "delete": "DeleteAlias", "get": "ListAliases"})
		return []svcStep{step(verbForKMSOp, "kms", svcOp, "Key", str("targetKeyId"))}
	}
	return nil
}

// svcAuthorize checks that the caller may do every front-door call op on this resource amounts to.
func (a *impersonatingApplier) svcAuthorize(ctx context.Context, kind, op, name string, spec map[string]any) error {
	for _, s := range svcSteps(kind, op, name, spec) {
		if s.verb == "" {
			return cfn.Unauthorized(fmt.Sprintf("%s %s: no authorization mapping for %s", kind, name, s.action))
		}
		if ok, reason := a.door.callerCan(ctx, a, s.verb, "openinfra.dev", "applications", a.door.authzNS, s.resID); !ok {
			return cfn.Unauthorized(fmt.Sprintf("%s %s not %sd: %s", kind, name, op, reason))
		}
		if ok, reason := a.door.callerPolicyAllows(ctx, a, s.action, s.resType, s.resID); !ok {
			return cfn.Unauthorized(fmt.Sprintf("%s %s not %sd: %s", kind, name, op, reason))
		}
	}
	// A lambda subscription points the platform's delivery at a Function: the caller must be able to
	// invoke that Function themselves (as a lambda Subscribe through the SNS front door).
	if kind == cfn.KindSNSSubscription && (op == "create" || op == "update") {
		if p, _ := spec["protocol"].(string); p == "lambda" {
			fn, _ := spec["function"].(string)
			ns := a.svc.lambdaNamespace(spec, a.ns)
			if ok, reason := a.door.callerCan(ctx, a, "create", "openinfra.dev", "functions", ns, fn); !ok {
				return cfn.Unauthorized(fmt.Sprintf("subscription %s not created: not authorized to deliver to function %s: %s", name, fn, reason))
			}
			if ok, reason := a.door.callerPolicyAllows(ctx, a, "lambda:InvokeFunction", "Function", fn); !ok {
				return cfn.Unauthorized(fmt.Sprintf("subscription %s not created: not authorized to deliver to function %s: %s", name, fn, reason))
			}
		}
	}
	return nil
}

// lambdaNamespace is where a lambda subscription's Function lives: the stack's namespace for one of the
// stack's own Functions, else the Lambda API's.
func (s *cfnServices) lambdaNamespace(spec map[string]any, stackNS string) string {
	if in, _ := spec["inStack"].(bool); in {
		return stackNS
	}
	return s.sns.lambdaNS
}

// svcExists reports whether the service resource exists in its store (under any owner).
func (a *impersonatingApplier) svcExists(ctx context.Context, kind, name string) (bool, error) {
	switch kind {
	case cfn.KindSQSQueue:
		_, ok, err := a.svc.sqs.store.queueURLByName(ctx, name)
		return ok, err
	case cfn.KindSNSTopic:
		_, ok, err := a.svc.sns.store.topicARNByName(ctx, name)
		return ok, err
	case cfn.KindSNSSubscription:
		_, spec, found, err := a.svc.owners.get(ctx, kind, name)
		if err != nil || !found {
			return false, err
		}
		arn, _ := spec["subscriptionArn"].(string)
		_, ok, err := a.svc.sns.store.subByArn(ctx, arn)
		return ok, err
	case cfn.KindSSMParameter:
		_, ok, err := a.svc.ssm.store.getParam(ctx, name)
		return ok, err
	case cfn.KindKMSKey:
		m, ok, err := a.svc.kms.store.getKey(ctx, name)
		// A key pending deletion is gone as far as its stack is concerned: the stack's delete scheduled it.
		return ok && m.State != "PendingDeletion", err
	case cfn.KindKMSAlias:
		_, ok, err := a.svc.kms.store.aliasTarget(ctx, name)
		return ok, err
	}
	return false, fmt.Errorf("unknown service kind %s", kind)
}

// svcPut creates (createOnly: only if absent, reporting whether it did) or updates a service resource.
func (a *impersonatingApplier) svcPut(ctx context.Context, obj *unstructured.Unstructured, createOnly bool) (bool, error) {
	kind, name := obj.GetKind(), obj.GetName()
	if err := a.svcFor(kind); err != nil {
		return false, err
	}
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	if spec == nil {
		spec = map[string]any{}
	}
	stack := obj.GetLabels()["cfn.openinfra.dev/stack"]
	ns := obj.GetNamespace()
	if ns == "" {
		ns = a.ns
	}
	exists, err := a.svcExists(ctx, kind, name)
	if err != nil {
		return false, err
	}
	if exists && createOnly {
		return false, nil
	}
	op := "create"
	if exists {
		op = "update"
	}
	if err := a.svcAuthorize(ctx, kind, op, name, spec); err != nil {
		return false, err
	}
	if exists {
		err = a.svcUpdate(ctx, kind, name, spec, ns)
	} else {
		err = a.svcCreate(ctx, kind, name, spec, ns)
	}
	if err != nil {
		return false, fmt.Errorf("%s %s %q: %w", op, kind, name, err)
	}
	if err := a.svc.owners.put(ctx, kind, name, stack, ns, spec); err != nil {
		return false, fmt.Errorf("recording the owner of %s %q: %w", kind, name, err)
	}
	return !exists, nil
}

func specStrings(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, val := range m {
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

func (a *impersonatingApplier) svcCreate(ctx context.Context, kind, name string, spec map[string]any, ns string) error {
	str := func(k string) string { s, _ := spec[k].(string); return s }
	switch kind {
	case cfn.KindSQSQueue:
		url := str("url")
		if url == "" {
			return fmt.Errorf("no queue url")
		}
		_, err := a.svc.sqs.store.createQueue(ctx, name, url, specStrings(spec["attributes"]))
		return err
	case cfn.KindSNSTopic:
		arn := str("topicArn")
		if _, err := a.svc.sns.store.createTopic(ctx, arn, name); err != nil {
			return err
		}
		if attrs := specStrings(spec["attributes"]); len(attrs) > 0 {
			_, err := a.svc.sns.store.replaceTopicAttrs(ctx, arn, attrs)
			return err
		}
		return nil
	case cfn.KindSNSSubscription:
		return a.svcSubscribe(ctx, spec, ns)
	case cfn.KindSSMParameter:
		return a.svcPutParam(ctx, name, spec, false)
	case cfn.KindKMSKey:
		return a.svcCreateKey(ctx, name, spec)
	case cfn.KindKMSAlias:
		if _, ok, err := a.svc.kms.store.getKey(ctx, str("targetKeyId")); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("the alias's target key %s does not exist", str("targetKeyId"))
		}
		return a.svc.kms.store.createAlias(ctx, name, str("targetKeyId"))
	}
	return fmt.Errorf("unknown service kind %s", kind)
}

func (a *impersonatingApplier) svcUpdate(ctx context.Context, kind, name string, spec map[string]any, ns string) error {
	str := func(k string) string { s, _ := spec[k].(string); return s }
	switch kind {
	case cfn.KindSQSQueue:
		url, _, err := a.svc.sqs.store.queueURLByName(ctx, name)
		if err != nil {
			return err
		}
		_, err = a.svc.sqs.store.replaceQueueAttrs(ctx, url, specStrings(spec["attributes"]))
		return err
	case cfn.KindSNSTopic:
		arn, _, err := a.svc.sns.store.topicARNByName(ctx, name)
		if err != nil {
			return err
		}
		_, err = a.svc.sns.store.replaceTopicAttrs(ctx, arn, specStrings(spec["attributes"]))
		return err
	case cfn.KindSNSSubscription:
		if _, err := a.svc.sns.store.unsubscribe(ctx, str("subscriptionArn")); err != nil {
			return err
		}
		return a.svcSubscribe(ctx, spec, ns)
	case cfn.KindSSMParameter:
		return a.svcPutParam(ctx, name, spec, true)
	case cfn.KindKMSKey:
		return a.svcUpdateKey(ctx, name, spec)
	case cfn.KindKMSAlias:
		_, err := a.svc.kms.store.updateAlias(ctx, name, str("targetKeyId"))
		return err
	}
	return fmt.Errorf("unknown service kind %s", kind)
}

func (a *impersonatingApplier) svcSubscribe(ctx context.Context, spec map[string]any, ns string) error {
	str := func(k string) string { s, _ := spec[k].(string); return s }
	topicArn, ok, err := a.svc.sns.canonicalTopicArn(ctx, str("topicArn"))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the subscription's topic %s does not exist", str("topicArn"))
	}
	proto, endpoint := str("protocol"), str("endpoint")
	attrs := map[string]string{}
	switch proto {
	case "sqs":
		if a.svc.sns.sqs == nil {
			return fmt.Errorf("sqs delivery is not configured on this shim")
		}
		if _, ok, err := a.svc.sns.sqs.queueURLByName(ctx, nameFromArn(endpoint)); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("the sqs endpoint queue does not exist: %s", endpoint)
		}
	case "lambda":
		if a.svc.sns.invoker == nil {
			return fmt.Errorf("lambda delivery is not configured on this shim")
		}
		attrs[snsFnNamespaceAttr] = a.svc.lambdaNamespace(spec, ns)
	default:
		return fmt.Errorf("SNS protocol %q is not delivered by this shim", proto)
	}
	raw, _ := spec["raw"].(bool)
	return a.svc.sns.store.subscribeWith(ctx, str("subscriptionArn"), topicArn, proto, endpoint, raw, attrs)
}

func (a *impersonatingApplier) svcPutParam(ctx context.Context, name string, spec map[string]any, overwrite bool) error {
	str := func(k string) string { s, _ := spec[k].(string); return s }
	if name == "" || strings.Contains(name, ":") {
		return fmt.Errorf("a parameter name must not contain ':'")
	}
	ptype, value := str("type"), str("value")
	if len(value) > ssmMaxValueStandard {
		return fmt.Errorf("value length exceeds the Standard-tier 4 KB limit")
	}
	stored := value
	if ptype == "SecureString" {
		if a.svc.ssm.transit == nil {
			return fmt.Errorf("the SecureString crypto backend (Vault Transit) is not configured on this shim")
		}
		ct, err := a.svc.ssm.encryptValue(ctx, name, value)
		if err != nil {
			return err
		}
		stored = ct
	}
	_, err := a.svc.ssm.store.putParam(ctx, name, ptype, stored, overwrite, specStrings(spec["tags"]))
	return err
}

func (a *impersonatingApplier) svcCreateKey(ctx context.Context, keyID string, spec map[string]any) error {
	k := a.svc.kms
	str := func(k string) string { s, _ := spec[k].(string); return s }
	doc := str("keyPolicy")
	var translated []kmsTranslatedPolicy
	if strings.TrimSpace(doc) != "" {
		if k.dyn == nil {
			return fmt.Errorf("key-policy import is not configured on this shim (no cluster client)")
		}
		tp, err := translateKeyPolicy(doc, keyID)
		if err != nil {
			return fmt.Errorf("the key policy is malformed: %w", err)
		}
		translated = tp
	}
	if err := k.transit.createKey(ctx, keyID); err != nil {
		return err
	}
	rot, _ := spec["rotation"].(bool)
	arn := str("arn")
	if arn == "" {
		arn = k.keyARN(keyID)
	}
	m := keyMeta{KeyID: keyID, Arn: arn, Description: str("description"), KeyUsage: "ENCRYPT_DECRYPT",
		KeySpec: "SYMMETRIC_DEFAULT", State: "Enabled", Rotation: rot, Created: time.Now()}
	if err := k.store.createKey(ctx, m); err != nil {
		_ = k.transit.destroy(ctx, keyID)
		return err
	}
	if translated != nil {
		if err := k.materializeKeyPolicy(ctx, keyID, translated); err != nil {
			_ = k.deleteKeyPolicyCRs(ctx, keyID)
			_ = k.store.deleteKeyRow(ctx, keyID)
			_ = k.transit.destroy(ctx, keyID)
			return err
		}
		if err := k.store.putKeyPolicyDoc(ctx, keyID, doc); err != nil {
			_ = k.deleteKeyPolicyCRs(ctx, keyID)
			_ = k.store.deleteKeyRow(ctx, keyID)
			_ = k.transit.destroy(ctx, keyID)
			return err
		}
	}
	k.audit(ctx, "CreateKey", keyID, "via", "cloudformation")
	return nil
}

// svcUpdateKey brings a stack's key to its new spec, checking each change it makes as the KMS front door
// would check that call: UpdateKeyDescription, Enable/DisableKeyRotation, PutKeyPolicy.
func (a *impersonatingApplier) svcUpdateKey(ctx context.Context, keyID string, spec map[string]any) error {
	k := a.svc.kms
	cur, ok, err := k.store.getKey(ctx, keyID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("key %s does not exist", keyID)
	}
	check := func(svcOp string) error {
		verb, _ := verbForKMSOp(svcOp)
		if ok, reason := a.door.callerCan(ctx, a, verb, "openinfra.dev", "applications", a.door.authzNS, keyID); !ok {
			return cfn.Unauthorized("key " + keyID + " not updated: " + reason)
		}
		if ok, reason := a.door.callerPolicyAllows(ctx, a, "kms:"+svcOp, "Key", keyID); !ok {
			return cfn.Unauthorized("key " + keyID + " not updated: " + reason)
		}
		return nil
	}
	desc, _ := spec["description"].(string)
	if desc != cur.Description {
		if err := check("UpdateKeyDescription"); err != nil {
			return err
		}
		if err := k.store.setDescription(ctx, keyID, desc); err != nil {
			return err
		}
	}
	rot, _ := spec["rotation"].(bool)
	if rot != cur.Rotation {
		op := "DisableKeyRotation"
		if rot {
			op = "EnableKeyRotation"
		}
		if err := check(op); err != nil {
			return err
		}
		if _, err := k.store.setRotation(ctx, keyID, rot); err != nil {
			return err
		}
	}
	doc, _ := spec["keyPolicy"].(string)
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	if have, ok, err := k.store.getKeyPolicyDoc(ctx, keyID); err != nil {
		return err
	} else if ok && have == doc {
		return nil
	}
	if err := check("PutKeyPolicy"); err != nil {
		return err
	}
	if k.dyn == nil {
		return fmt.Errorf("key-policy import is not configured on this shim (no cluster client)")
	}
	translated, err := translateKeyPolicy(doc, keyID)
	if err != nil {
		return fmt.Errorf("the key policy is malformed: %w", err)
	}
	if err := k.materializeKeyPolicy(ctx, keyID, translated); err != nil {
		return err
	}
	return k.store.putKeyPolicyDoc(ctx, keyID, doc)
}

// svcDelete removes a service resource (a missing one is not an error, as `kubectl delete
// --ignore-not-found`). A KMS key is scheduled for deletion with its pending window, as CloudFormation
// deletes one; the shim's reaper erases it when the window ends.
func (a *impersonatingApplier) svcDelete(ctx context.Context, kind, name string) error {
	if err := a.svcFor(kind); err != nil {
		return err
	}
	exists, err := a.svcExists(ctx, kind, name)
	if err != nil {
		return err
	}
	_, ownSpec, _, err := a.svc.owners.get(ctx, kind, name)
	if err != nil {
		return err
	}
	if !exists {
		return a.svc.owners.del(ctx, kind, name)
	}
	if ownSpec == nil {
		ownSpec = map[string]any{}
	}
	if err := a.svcAuthorize(ctx, kind, "delete", name, ownSpec); err != nil {
		return err
	}
	switch kind {
	case cfn.KindSQSQueue:
		url, _, err := a.svc.sqs.store.queueURLByName(ctx, name)
		if err == nil {
			_, err = a.svc.sqs.store.deleteQueue(ctx, url)
		}
		if err != nil {
			return err
		}
	case cfn.KindSNSTopic:
		arn, _, err := a.svc.sns.store.topicARNByName(ctx, name)
		if err == nil {
			_, err = a.svc.sns.store.deleteTopic(ctx, arn)
		}
		if err != nil {
			return err
		}
	case cfn.KindSNSSubscription:
		arn, _ := ownSpec["subscriptionArn"].(string)
		if _, err := a.svc.sns.store.unsubscribe(ctx, arn); err != nil {
			return err
		}
	case cfn.KindSSMParameter:
		if _, err := a.svc.ssm.store.deleteParam(ctx, name); err != nil {
			return err
		}
	case cfn.KindKMSKey:
		window := toInt(ownSpec["pendingWindowInDays"])
		if window < 7 || window > 30 {
			window = 30
		}
		when := time.Now().Add(time.Duration(window) * 24 * time.Hour)
		if _, err := a.svc.kms.store.setState(ctx, name, "PendingDeletion", &when); err != nil {
			return err
		}
		a.svc.kms.audit(ctx, "ScheduleKeyDeletion", name, "via", "cloudformation")
	case cfn.KindKMSAlias:
		if _, err := a.svc.kms.store.deleteAlias(ctx, name); err != nil {
			return err
		}
	}
	return a.svc.owners.del(ctx, kind, name)
}

// svcLabels is the stack label a service resource carries: its recorded owner (found with no label when
// it exists but no stack made it).
func (a *impersonatingApplier) svcLabels(ctx context.Context, kind, name string) (map[string]string, bool, error) {
	if err := a.svcFor(kind); err != nil {
		return nil, false, err
	}
	exists, err := a.svcExists(ctx, kind, name)
	if err != nil || !exists {
		return nil, false, err
	}
	stack, _, found, err := a.svc.owners.get(ctx, kind, name)
	if err != nil {
		return nil, false, err
	}
	if !found || stack == "" {
		return map[string]string{}, true, nil
	}
	return map[string]string{"cfn.openinfra.dev/stack": stack, "app.kubernetes.io/managed-by": "cfn"}, true, nil
}

// svcSpec is a service resource's live spec, in the shape its manifest has: the applied spec, with what
// the store itself holds read back from it (so a change made through the API shows as drift).
func (a *impersonatingApplier) svcSpec(ctx context.Context, kind, name string) (map[string]any, bool, error) {
	if err := a.svcFor(kind); err != nil {
		return nil, false, err
	}
	exists, err := a.svcExists(ctx, kind, name)
	if err != nil || !exists {
		return nil, false, err
	}
	_, spec, _, err := a.svc.owners.get(ctx, kind, name)
	if err != nil {
		return nil, false, err
	}
	if spec == nil {
		spec = map[string]any{}
	}
	switch kind {
	case cfn.KindSQSQueue:
		if url, ok, err := a.svc.sqs.store.queueURLByName(ctx, name); err == nil && ok {
			if attrs, _, ok, err := a.svc.sqs.store.queueAttrs(ctx, url); err == nil && ok {
				spec["attributes"] = stringsToAny(attrs)
			}
		}
	case cfn.KindSNSTopic:
		if arn, ok, err := a.svc.sns.store.topicARNByName(ctx, name); err == nil && ok {
			if attrs, ok, err := a.svc.sns.store.topicAttrs(ctx, arn); err == nil && ok {
				spec["attributes"] = stringsToAny(attrs)
			}
		}
	case cfn.KindSSMParameter:
		if p, ok, err := a.svc.ssm.store.getParam(ctx, name); err == nil && ok {
			spec["type"] = p.Type
			if p.Type != "SecureString" {
				if v, ok, err := a.svc.ssm.store.getVersion(ctx, name, p.CurrentVer); err == nil && ok {
					spec["value"] = v
				}
			}
		}
	case cfn.KindKMSKey:
		if m, ok, err := a.svc.kms.store.getKey(ctx, name); err == nil && ok {
			if m.Description != "" || spec["description"] != nil {
				spec["description"] = m.Description
			}
			if m.Rotation || spec["rotation"] != nil {
				spec["rotation"] = m.Rotation
			}
		}
	case cfn.KindKMSAlias:
		if t, ok, err := a.svc.kms.store.aliasTarget(ctx, name); err == nil && ok {
			spec["targetKeyId"] = t
		}
	}
	return spec, true, nil
}

func stringsToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// svcWaitReady returns once the resource exists: a store write is complete when it returns, so this is
// immediate unless something removed it in between.
func (a *impersonatingApplier) svcWaitReady(ctx context.Context, kind, name string, timeout time.Duration) error {
	if err := a.svcFor(kind); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := a.svcExists(ctx, kind, name)
		if err == nil && ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s %q does not exist", kind, name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// svcWaitGone returns once the resource no longer exists.
func (a *impersonatingApplier) svcWaitGone(ctx context.Context, kind, name string, timeout time.Duration) error {
	if err := a.svcFor(kind); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := a.svcExists(ctx, kind, name)
		if err == nil && !ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s %q still exists", kind, name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
