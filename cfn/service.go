package cfn

// Stack resources served by the aws-shim's own AWS APIs (#347 J).
//
// A stack's queue, topic, parameter or key exists to be used through SQS, SNS, SSM or KMS: the
// application calls those APIs by the name or ARN the stack's Outputs report. Where the deploying
// environment serves an API from its own store (Capabilities.SQSAPI, …), the resource is provisioned
// IN that store — the queue is the very row SQS's ReceiveMessage reads — rather than as a separate
// kind (a NATS stream, a Vault entry) that the API cannot see. The engine treats such a resource like
// any other: a manifest of a service kind (apiVersion cfn.openinfra.dev/v1) that the Applier applies,
// reads, waits on and deletes; the in-cluster doorway's Applier routes those kinds to the service code
// the matching front door runs, under the caller's authority. Retain, rollback and teardown are the
// engine's, unchanged.
//
// Names are decided at translate time (a queue's name and URL, a topic's ARN, a parameter's name, a
// key's id), so a Ref or Fn::GetAtt elsewhere in the stack resolves to exactly what is created, and an
// update keeps what the stack recorded.
//
// Without the capability (the CLI, or a shim without that data layer) the translators keep their
// kind mappings (kind: Queue / Parameter); those are not reachable through the AWS APIs.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/cfn/snsfilter"
)

// ServiceAPIVersion is the apiVersion of every stack resource the shim's own AWS APIs serve.
const ServiceAPIVersion = "cfn.openinfra.dev/v1"

// The service kinds. Each names one AWS object the matching shim front door serves.
const (
	KindSQSQueue        = "SQSQueue"        // an SQS queue (name = queue name)
	KindSNSTopic        = "SNSTopic"        // an SNS topic (name = topic name)
	KindSNSSubscription = "SNSSubscription" // an SNS subscription (name = subscription id)
	KindSSMParameter    = "SSMParameter"    // an SSM parameter (name = parameter name)
	KindKMSKey          = "KMSKey"          // a KMS key (name = key id)
	KindKMSAlias        = "KMSAlias"        // a KMS alias (name = alias name, alias/…)

	// Served through their own front doors, as the caller (translate_service.go).
	KindSecretsManagerSecret = "SecretsManagerSecret" // a Secrets Manager secret (name = secret name)
	KindLogsLogGroup         = "LogsLogGroup"         // a CloudWatch Logs log group (name = group name)
	KindEventsRule           = "EventsRule"           // an EventBridge rule (name = rule name)
	KindEventsEventBus       = "EventsEventBus"       // an EventBridge custom bus (name = bus name)
	KindECRRepository        = "ECRRepository"        // an ECR repository (name = repository name)
	KindCloudWatchAlarm      = "CloudWatchAlarm"      // a CloudWatch alarm (name = alarm name)
)

// IsServiceKind reports whether apiVersion/kind is a resource the shim's AWS APIs serve.
func IsServiceKind(apiVersion, kind string) bool {
	if apiVersion != ServiceAPIVersion {
		return false
	}
	switch kind {
	case KindSQSQueue, KindSNSTopic, KindSNSSubscription, KindSSMParameter, KindKMSKey, KindKMSAlias,
		KindSecretsManagerSecret, KindLogsLogGroup, KindEventsRule, KindEventsEventBus, KindECRRepository, KindCloudWatchAlarm,
		KindSQSQueuePolicy, KindSNSTopicPolicy:
		return true
	}
	return false
}

// IsServiceResource reports whether a recorded stack resource is one of the service kinds.
func IsServiceResource(r StackResource) bool { return IsServiceKind(r.APIVersion, r.Kind) }

func serviceManifest(kind, name string, spec map[string]any) *Manifest {
	return &Manifest{APIVersion: ServiceAPIVersion, Kind: kind, Name: name, Spec: spec}
}

// region / account are the pseudo-parameters the stack sees, so names built here agree with
// ${AWS::Region} / ${AWS::AccountId} in the same template; both come from the install's identity.
func (c *stackCtx) region() string {
	if c != nil && c.resolver != nil {
		if v, ok := c.resolver.pseudo["AWS::Region"].(string); ok && v != "" {
			return v
		}
	}
	return awsidentity.Current().Region
}

func (c *stackCtx) account() string {
	if c != nil && c.resolver != nil {
		if v, ok := c.resolver.pseudo["AWS::AccountId"].(string); ok && v != "" {
			return v
		}
	}
	return awsidentity.Current().AccountID
}

// ident is the identity the stack's ARNs carry: its AWS::AccountId and AWS::Region.
func (c *stackCtx) ident() awsidentity.Identity {
	return awsidentity.Identity{AccountID: c.account(), Region: c.region()}
}

func (c *stackCtx) stackName() string {
	if c != nil && c.resolver != nil {
		if v, ok := c.resolver.pseudo["AWS::StackName"].(string); ok && v != "" {
			return v
		}
	}
	if c != nil && c.namer != nil {
		return c.namer.stack
	}
	return "stack"
}

// servedBy reports whether the stack's resource id is provisioned in the shim's own store for its type.
func (c *stackCtx) servedBy(id string) bool {
	if c == nil {
		return false
	}
	res, ok := c.template.Resources[id]
	if !ok {
		return false
	}
	switch res.Type {
	case "AWS::SQS::Queue", "AWS::SQS::QueuePolicy":
		return c.caps.SQSAPI
	case "AWS::SNS::Topic", "AWS::SNS::Subscription", "AWS::SNS::TopicPolicy":
		return c.caps.SNSAPI
	case "AWS::SSM::Parameter":
		return c.caps.SSMAPI
	case "AWS::KMS::Key", "AWS::KMS::Alias":
		return c.caps.KMSAPI
	}
	return false
}

// ---- names ----

var sqsQueueNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// svcQueueName is a queue's name: its QueueName when given, else the stack-qualified name the stack
// gives the resource (the same name an imported IAM policy scopes Queue::<name> to; inStackName).
//
// An unnamed FIFO queue served by the SQS API gets CloudFormation's .fifo suffix (a FIFO queue's name must
// end with it), within SQS's 80 characters.
func svcQueueName(id string, ctx *stackCtx) string {
	name := inStackName(id, "QueueName", ctx)
	p, _ := ctx.resolveProps(id)
	if n, _ := concrete(p["QueueName"]); n == "" && ctx.servedBy(id) {
		if b, ok := cfnBoolValue(p["FifoQueue"]); ok && b && !strings.HasSuffix(name, ".fifo") {
			if len(name) > 75 {
				name = name[:75]
			}
			name += ".fifo"
		}
	}
	return name
}

// svcTopicName is a topic's name: its TopicName when given, else the stack-qualified name.
func svcTopicName(id string, ctx *stackCtx) string { return inStackName(id, "TopicName", ctx) }

// svcQueueURL is the queue URL a stack records and reports: <base>/<account>/<name>. The base is the
// shim endpoint the deploying environment vouches for (Capabilities.SQSURLBase); the SQS front door
// answers any URL by the queue's name, so the URL works from wherever that endpoint is reachable.
func svcQueueURL(name string, ctx *stackCtx) string {
	base := strings.TrimRight(ctx.caps.SQSURLBase, "/")
	if base == "" {
		base = "https://sqs." + ctx.region() + ".amazonaws.com"
	}
	return base + "/" + ctx.account() + "/" + name
}

func svcQueueARN(name string, ctx *stackCtx) string { return ctx.ident().RegionalARN("sqs", name) }

func svcTopicARN(name string, ctx *stackCtx) string { return ctx.ident().RegionalARN("sns", name) }

// svcParamName is a parameter's name: its Name when given, else what CloudFormation generates for an
// unnamed one — <stack>-<logical id>-<suffix> — with a suffix fixed by the stack and logical id, so a
// Ref elsewhere in the stack resolves to it and an update keeps it (the recorded name wins).
func svcParamName(id string, ctx *stackCtx) string {
	p, _ := ctx.resolveProps(id)
	if n, ok := concrete(p["Name"]); ok && n != "" {
		return n
	}
	if v, ok := priorServiceName(id, KindSSMParameter, ctx); ok {
		return v
	}
	sum := sha256.Sum256([]byte(ctx.stackName() + "/" + id))
	return ctx.stackName() + "-" + id + "-" + strings.ToUpper(hex.EncodeToString(sum[:])[:12])
}

// priorServiceName is the name the existing stack recorded for resource id as service kind `kind`.
func priorServiceName(id, kind string, ctx *stackCtx) (string, bool) {
	if ctx == nil || ctx.namer == nil {
		return "", false
	}
	for _, r := range ctx.namer.priorRes {
		if r.LogicalID == id && r.APIVersion == ServiceAPIVersion && r.Kind == kind && r.Name != "" {
			return r.Name, true
		}
	}
	return "", false
}

// svcKMSKeyID is the id of the key a stack's AWS::KMS::Key is in the KMS store: the one the stack
// recorded (an update), else a new random key id — remembered for this operation, so every Ref to the
// key in the template resolves to it. Key ids are never reused: a deleted key waits out its pending
// window under its id, and a re-created stack gets a new key, as on AWS.
func svcKMSKeyID(id string, ctx *stackCtx) string {
	if ctx.svcIDs == nil {
		ctx.svcIDs = map[string]string{}
	}
	if v, ok := ctx.svcIDs[id]; ok {
		return v
	}
	if ctx.namer != nil {
		for _, r := range ctx.namer.priorRes {
			if r.Kind == KindKMSKey && strings.HasPrefix(r.LogicalID, id+"/") {
				ctx.svcIDs[id] = r.Name
				return r.Name
			}
		}
	}
	v := newKeyID()
	ctx.svcIDs[id] = v
	return v
}

// newKeyID mints a random KMS key id (a var so tests can make it deterministic).
var newKeyID = randomKeyID

func randomKeyID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func svcKeyARN(keyID string, ctx *stackCtx) string {
	return ctx.ident().RegionalARN("kms", "key/"+keyID)
}

// svcSubscriptionID names a subscription the stack creates: fixed by the stack and logical id (and the
// inline subscription's index on a topic), so an update finds the same one.
func svcSubscriptionID(stack, owner string) string {
	sum := sha256.Sum256([]byte(stack + "/" + owner))
	h := hex.EncodeToString(sum[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---- Ref / Fn::GetAtt of the service-backed types ----

// serviceRef is the Ref value of a service-backed resource: a queue's URL, a topic's ARN, a
// parameter's name, a key's id, an alias's name, a subscription's ARN. ok=false when id is not one.
func serviceRef(id string, ctx *stackCtx) (string, bool) {
	if !ctx.servedBy(id) {
		return "", false
	}
	switch ctx.template.Resources[id].Type {
	case "AWS::SQS::Queue":
		return svcQueueURL(svcQueueName(id, ctx), ctx), true
	case "AWS::SNS::Topic":
		return svcTopicARN(svcTopicName(id, ctx), ctx), true
	case "AWS::SNS::Subscription":
		return subscriptionARN(id, ctx)
	case "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy":
		return svcPolicyID(id, ctx), true
	case "AWS::SSM::Parameter":
		return svcParamName(id, ctx), true
	case "AWS::KMS::Key":
		return svcKMSKeyID(id, ctx), true
	case "AWS::KMS::Alias":
		p, _ := ctx.resolveProps(id)
		if n, ok := concrete(p["AliasName"]); ok {
			return n, true
		}
	}
	return "", false
}

// ServiceAtt is the Fn::GetAtt value of a service-backed resource's documented attribute (AWS's
// return values for the type). ok=false for any other resource or attribute — the caller then falls
// back to whatever else resolves the attribute.
func serviceAtt(id, attr string, ctx *stackCtx) (string, bool) {
	if v, ok := serviceStatic(id, attr, ctx); ok && attr != "" { // a secret, log group, rule, bus, repository, alarm
		return v, true
	}
	if !ctx.servedBy(id) {
		return "", false
	}
	switch ctx.template.Resources[id].Type {
	case "AWS::SQS::Queue":
		name := svcQueueName(id, ctx)
		switch attr {
		case "Arn":
			return svcQueueARN(name, ctx), true
		case "QueueName":
			return name, true
		case "QueueUrl":
			return svcQueueURL(name, ctx), true
		}
	case "AWS::SNS::Topic":
		name := svcTopicName(id, ctx)
		switch attr {
		case "TopicArn":
			return svcTopicARN(name, ctx), true
		case "TopicName":
			return name, true
		}
	case "AWS::SSM::Parameter":
		p, _ := ctx.resolveProps(id)
		switch attr {
		case "Type":
			t, _ := concrete(p["Type"])
			if t == "" {
				t = "String"
			}
			return t, true
		case "Value":
			if v, ok := concrete(p["Value"]); ok {
				return v, true
			}
		}
	case "AWS::KMS::Key":
		kid := svcKMSKeyID(id, ctx)
		switch attr {
		case "Arn":
			return svcKeyARN(kid, ctx), true
		case "KeyId":
			return kid, true
		}
	}
	return "", false
}

// subscriptionARN is an AWS::SNS::Subscription's ARN: <topic arn>:<subscription id>.
func subscriptionARN(id string, ctx *stackCtx) (string, bool) {
	raw, _ := ctx.rawProps(id)
	tid, ok := getAttTarget(raw["TopicArn"])
	if !ok || !ctx.isType(tid, "AWS::SNS::Topic") {
		return "", false
	}
	return svcTopicARN(svcTopicName(tid, ctx), ctx) + ":" + svcSubscriptionID(ctx.stackName(), id), true
}

// ---- translators ----

// translateSQSQueueAPI maps an AWS::SQS::Queue to a queue in the SQS front door's own store. The
// attributes CloudFormation sets are queue attributes there, honored by that store's send/receive
// path (visibility, delay, retention, long poll, size cap, dead-letter redrive).
func translateSQSQueueAPI(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"QueueName": true, "MessageRetentionPeriod": true, "Tags": true, "FifoQueue": true,
		"VisibilityTimeout": true, "DelaySeconds": true, "RedrivePolicy": true, "KmsMasterKeyId": true,
		"ReceiveMessageWaitTimeSeconds": true, "MaximumMessageSize": true, "ContentBasedDeduplication": true,
		"DeduplicationScope": true, "FifoThroughputLimit": true,
	}
	f := blockUnknownProps(id, props, known)
	fifo, ff := boolProp(id, props, "FifoQueue", false)
	f = append(f, ff...)
	name := svcQueueName(id, ctx)
	base, fifoName := strings.CutSuffix(name, ".fifo")
	switch {
	case fifo != fifoName:
		f = append(f, Finding{"Resource " + id, fmt.Sprintf("QueueName %q: a FIFO queue's name ends with .fifo, and only a FIFO queue's (FifoQueue: true)", name)})
	case len(name) > 80 || !sqsQueueNameRe.MatchString(base):
		f = append(f, Finding{"Resource " + id, fmt.Sprintf("QueueName %q is not a valid SQS queue name (1-80 letters, digits, hyphens, underscores; .fifo for a FIFO queue)", name)})
	}
	if _, ok := props["KmsMasterKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsMasterKeyId is not translatable — the SQS API keeps no per-queue encryption key"})
	}
	attrs := map[string]any{}
	for _, p := range []string{"VisibilityTimeout", "DelaySeconds", "MessageRetentionPeriod", "MaximumMessageSize", "ReceiveMessageWaitTimeSeconds"} {
		v, present := props[p]
		if !present || v == nil {
			continue
		}
		s, ok := concrete(v)
		if !ok || toInt(s) < 0 || fmt.Sprint(toInt(s)) != strings.TrimSpace(s) {
			f = append(f, Finding{"Resource " + id, p + " must resolve to a whole number of seconds/bytes"})
			continue
		}
		attrs[p] = strings.TrimSpace(s)
	}
	if rp, present := props["RedrivePolicy"]; present && rp != nil {
		s, err := redrivePolicyJSON(rp)
		if err != nil {
			f = append(f, Finding{"Resource " + id, "RedrivePolicy: " + err.Error()})
		} else if strings.Contains(s, `.fifo"`) != fifo {
			f = append(f, Finding{"Resource " + id, "RedrivePolicy: the dead-letter queue of a FIFO queue must be a FIFO queue, and that of a standard queue a standard queue"})
		} else {
			attrs["RedrivePolicy"] = s
		}
	}
	if fifo {
		// The FIFO contract the SQS API keeps: group order, five-minute deduplication.
		attrs["FifoQueue"] = "true"
		if cbd, present := props["ContentBasedDeduplication"]; present && cbd != nil {
			b, ok := cfnBoolValue(cbd)
			if !ok {
				f = append(f, Finding{"Resource " + id, "ContentBasedDeduplication must be true or false"})
			}
			attrs["ContentBasedDeduplication"] = fmt.Sprint(b)
		}
		for p, vals := range map[string][]string{"DeduplicationScope": {"queue", "messageGroup"}, "FifoThroughputLimit": {"perQueue", "perMessageGroupId"}} {
			v, present := props[p]
			if !present || v == nil {
				continue
			}
			s, ok := concrete(v)
			if !ok || (s != vals[0] && s != vals[1]) {
				f = append(f, Finding{"Resource " + id, p + " must be " + vals[0] + " or " + vals[1]})
				continue
			}
			attrs[p] = s
		}
		if attrs["FifoThroughputLimit"] == "perMessageGroupId" && attrs["DeduplicationScope"] != "messageGroup" {
			f = append(f, Finding{"Resource " + id, "FifoThroughputLimit perMessageGroupId requires DeduplicationScope messageGroup"})
		}
	}
	if len(f) > 0 {
		return nil, f
	}
	m := serviceManifest(KindSQSQueue, name, map[string]any{
		"queueName":  name,
		"url":        svcQueueURL(name, ctx),
		"attributes": attrs,
	})
	if !fifo {
		for _, p := range []string{"ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit"} {
			if _, ok := props[p]; ok {
				m.Caveats = append(m.Caveats, p+" ignored — it applies only to a FIFO queue")
			}
		}
	}
	if _, ok := props["Tags"]; ok {
		m.Caveats = append(m.Caveats, "Tags are not applied — the SQS API here keeps no queue tags")
	}
	return m, nil
}

// redrivePolicyJSON renders an SQS RedrivePolicy (CloudFormation gives it as an object or a JSON
// string) as the JSON string the queue attribute holds: {deadLetterTargetArn, maxReceiveCount}.
func redrivePolicyJSON(v any) (string, error) {
	var m map[string]any
	switch t := v.(type) {
	case map[string]any:
		m = t
	case string:
		if err := json.Unmarshal([]byte(t), &m); err != nil {
			return "", fmt.Errorf("not a JSON object: %v", err)
		}
	default:
		return "", fmt.Errorf("must be an object with deadLetterTargetArn and maxReceiveCount")
	}
	arn, ok := concrete(m["deadLetterTargetArn"])
	if !ok || !strings.HasPrefix(arn, "arn:") || !strings.Contains(arn, ":sqs:") {
		return "", fmt.Errorf("deadLetterTargetArn must resolve to an SQS queue ARN (e.g. !GetAtt DLQ.Arn)")
	}
	n := toInt(m["maxReceiveCount"])
	if n < 1 {
		return "", fmt.Errorf("maxReceiveCount must be a whole number of at least 1")
	}
	b, _ := json.Marshal(map[string]any{"deadLetterTargetArn": arn, "maxReceiveCount": n})
	return string(b), nil
}

// translateSNSTopicAPI maps an AWS::SNS::Topic to a topic in the SNS front door's own store; each
// inline Subscription becomes a subscription there (a companion), delivered by that front door.
func translateSNSTopicAPI(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"TopicName": true, "DisplayName": true, "Tags": true, "FifoTopic": true,
		"KmsMasterKeyId": true, "ContentBasedDeduplication": true, "Subscription": true,
	}
	f := blockUnknownProps(id, props, known)
	fifo, ff := boolProp(id, props, "FifoTopic", false)
	f = append(f, ff...)
	name := svcTopicName(id, ctx)
	if fifo || strings.HasSuffix(name, ".fifo") {
		f = append(f, Finding{"Resource " + id, "a FIFO topic is not served by this environment's SNS API (standard topics only)"})
	}
	if _, ok := props["KmsMasterKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsMasterKeyId is not translatable — the SNS API keeps no per-topic encryption key"})
	}
	attrs := map[string]any{}
	if dn, ok := concrete(props["DisplayName"]); ok && dn != "" {
		attrs["DisplayName"] = dn
	}
	topicARN := svcTopicARN(name, ctx)
	var subs []*Manifest
	raw, _ := ctx.rawProps(id)
	if list, ok := props["Subscription"].([]any); ok {
		rawList, _ := raw["Subscription"].([]any)
		for i, s := range list {
			sm, ok := s.(map[string]any)
			if !ok {
				f = append(f, Finding{"Resource " + id, "each Subscription must be an object with Protocol and Endpoint"})
				continue
			}
			var rawEP any
			if i < len(rawList) {
				if rm, ok := rawList[i].(map[string]any); ok {
					rawEP = rm["Endpoint"]
				}
			}
			proto, _ := concrete(sm["Protocol"])
			ep, epOK := concrete(sm["Endpoint"])
			spec, msg := snsSubscriptionSpec(proto, ep, epOK, rawEP, ctx)
			if msg != "" {
				f = append(f, Finding{"Resource " + id, "Subscription " + fmt.Sprint(i) + ": " + msg})
				continue
			}
			sid := svcSubscriptionID(ctx.stackName(), fmt.Sprintf("%s#%d", id, i))
			spec["topicArn"] = topicARN
			spec["subscriptionArn"] = topicARN + ":" + sid
			subs = append(subs, serviceManifest(KindSNSSubscription, sid, spec))
		}
	}
	if len(f) > 0 {
		return nil, f
	}
	m := serviceManifest(KindSNSTopic, name, map[string]any{"topicName": name, "topicArn": topicARN, "attributes": attrs})
	m.Extra = subs
	for _, p := range []string{"Tags", "ContentBasedDeduplication"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" is not applied — the SNS API here keeps no topic tags or FIFO dedup")
		}
	}
	return m, nil
}

// translateSNSSubscriptionAPI maps an AWS::SNS::Subscription to a subscription in the SNS front
// door's store, on an in-stack topic.
func translateSNSSubscriptionAPI(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"TopicArn": true, "Protocol": true, "Endpoint": true, "Region": true, "RawMessageDelivery": true,
		"FilterPolicy": true, "FilterPolicyScope": true}
	if f := blockUnknownProps(id, props, known); len(f) > 0 {
		for i := range f {
			f[i].Reason += " (a filter or delivery setting this front door does not apply would change which messages are delivered)"
		}
		return nil, f
	}
	raw, _ := ctx.rawProps(id)
	tid, ok := getAttTarget(raw["TopicArn"])
	if !ok || !ctx.isType(tid, "AWS::SNS::Topic") {
		return nil, []Finding{{"Resource " + id, "an AWS::SNS::Subscription's TopicArn must reference an in-stack AWS::SNS::Topic"}}
	}
	if r, ok := concrete(props["Region"]); ok && r != "" && r != ctx.region() {
		return nil, []Finding{{"Resource " + id, "a cross-region subscription (Region " + r + ") is not translatable"}}
	}
	proto, _ := concrete(props["Protocol"])
	ep, epOK := concrete(props["Endpoint"])
	spec, msg := snsSubscriptionSpec(proto, ep, epOK, raw["Endpoint"], ctx)
	if msg != "" {
		return nil, []Finding{{"Resource " + id, msg}}
	}
	rawDel, ff := boolProp(id, props, "RawMessageDelivery", false)
	if len(ff) > 0 {
		return nil, ff
	}
	spec["raw"] = rawDel
	// A FilterPolicy decides which messages the subscription receives, as the SNS front door applies it.
	scope, _ := concrete(props["FilterPolicyScope"])
	if fp, present := props["FilterPolicy"]; present && fp != nil {
		doc, df := policyDocJSON(id, fp)
		if len(df) > 0 {
			for i := range df {
				df[i].Reason = strings.Replace(df[i].Reason, "PolicyDocument", "FilterPolicy", 1)
			}
			return nil, df
		}
		if _, err := snsfilter.Parse(doc, scope); err != nil {
			return nil, []Finding{{"Resource " + id, "FilterPolicy: " + err.Error()}}
		}
		spec["filterPolicy"] = doc
	}
	if scope != "" {
		if scope != snsfilter.ScopeAttributes && scope != snsfilter.ScopeBody {
			return nil, []Finding{{"Resource " + id, "FilterPolicyScope must be MessageAttributes or MessageBody"}}
		}
		spec["filterPolicyScope"] = scope
	}
	topicARN := svcTopicARN(svcTopicName(tid, ctx), ctx)
	sid := svcSubscriptionID(ctx.stackName(), id)
	spec["topicArn"] = topicARN
	spec["subscriptionArn"] = topicARN + ":" + sid
	return serviceManifest(KindSNSSubscription, sid, spec), nil
}

// snsSubscriptionSpec checks one subscription's protocol and endpoint against what the SNS front door
// delivers: sqs to a queue in its SQS store, lambda to a Function (the stack's own, or by ARN). It
// returns the subscription spec, or a refusing message.
func snsSubscriptionSpec(proto, endpoint string, epOK bool, rawEP any, ctx *stackCtx) (map[string]any, string) {
	switch strings.ToLower(proto) {
	case "sqs":
		if !ctx.caps.SQSAPI {
			return nil, "an sqs subscription delivers to the SQS API's store, which this environment does not serve"
		}
		if !epOK || !strings.Contains(endpoint, ":sqs:") {
			return nil, "an sqs subscription's Endpoint must resolve to an SQS queue ARN (e.g. !GetAtt Queue.Arn)"
		}
		if strings.HasSuffix(endpoint, ".fifo") {
			return nil, "a FIFO queue cannot subscribe to a standard SNS topic (FIFO topics are not served here)"
		}
		return map[string]any{"protocol": "sqs", "endpoint": endpoint}, ""
	case "lambda":
		spec := map[string]any{"protocol": "lambda"}
		if eid, ok := getAttTarget(rawEP); ok && ctx.isType(eid, "AWS::Lambda::Function") {
			// The stack's own Function: delivered to its kind: Function in the stack's namespace.
			spec["endpoint"] = ctx.ident().RegionalARN("lambda", "function:"+ctx.functionName(eid))
			spec["function"] = ctx.functionName(eid)
			spec["inStack"] = true
			return spec, ""
		}
		if !epOK || !strings.Contains(endpoint, ":function:") {
			return nil, "a lambda subscription's Endpoint must resolve to a Lambda function ARN"
		}
		spec["endpoint"] = endpoint
		spec["function"] = lambdaFunctionName(endpoint)
		return spec, ""
	case "http", "https", "email", "email-json", "sms", "application", "firehose":
		return nil, "the \"" + proto + "\" SNS protocol has no delivery surface here (sqs and lambda are delivered)"
	}
	return nil, "SNS subscription protocol \"" + proto + "\" is not translatable"
}

// lambdaFunctionName is a function ARN's name, without a version or alias qualifier.
func lambdaFunctionName(arn string) string {
	i := strings.Index(arn, ":function:")
	if i < 0 {
		return arn
	}
	n := arn[i+len(":function:"):]
	if j := strings.Index(n, ":"); j >= 0 {
		n = n[:j]
	}
	return n
}

// translateSSMParameterAPI maps an AWS::SSM::Parameter to a parameter in the SSM front door's own
// store (Standard tier). Name is optional, as on AWS: an unnamed parameter gets CloudFormation's
// generated name.
func translateSSMParameterAPI(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"Name": true, "Value": true, "Type": true, "Tier": true,
		"Description": true, "AllowedPattern": true, "DataType": true, "Tags": true, "Policies": true,
	}
	f := blockUnknownProps(id, props, known)
	name := svcParamName(id, ctx)
	value, ok := concrete(props["Value"])
	if !ok {
		if _, present := props["Value"]; !present {
			f = append(f, Finding{"Resource " + id, "AWS::SSM::Parameter requires a Value"})
		} else {
			f = append(f, Finding{"Resource " + id, "Parameter Value references a value with no concrete result here — refusing rather than storing a placeholder"})
		}
	}
	ptype, ff := strProp(id, props, "Type")
	f = append(f, ff...)
	switch ptype {
	case "":
		ptype = "String"
	case "String", "StringList", "SecureString":
	default:
		f = append(f, Finding{"Resource " + id, "unknown SSM Parameter Type " + ptype + " (expected String, StringList, or SecureString)"})
	}
	tier, ff := strProp(id, props, "Tier")
	f = append(f, ff...)
	if tier != "" && tier != "Standard" {
		f = append(f, Finding{"Resource " + id, "Tier " + tier + " is not served — the SSM API here offers the Standard tier only (4 KB values, no parameter policies)"})
	}
	if pol, present := props["Policies"]; present && pol != nil {
		f = append(f, Finding{"Resource " + id, "parameter Policies (expiration/notification) need the Advanced tier, which the SSM API here does not offer — refusing rather than storing a value that would not expire"})
	}
	dt, ff := strProp(id, props, "DataType")
	f = append(f, ff...)
	if dt != "" && dt != "text" {
		f = append(f, Finding{"Resource " + id, "DataType " + dt + " is not validated by the SSM API here (text only)"})
	}
	ap, ff := strProp(id, props, "AllowedPattern")
	f = append(f, ff...)
	if ap != "" {
		if re, err := regexp.Compile(ap); err != nil {
			f = append(f, Finding{"Resource " + id, "AllowedPattern does not compile: " + err.Error()})
		} else if value != "" && !re.MatchString(value) {
			f = append(f, Finding{"Resource " + id, "Value does not match AllowedPattern"})
		}
	}
	if len(f) > 0 {
		return nil, f
	}
	spec := map[string]any{"name": name, "type": ptype, "value": value}
	// The declared values the SSM API here serves (the only ones it accepts), as the template set them.
	if tier != "" {
		spec["tier"] = tier
	}
	if dt != "" {
		spec["dataType"] = dt
	}
	if tags := tagMap(props["Tags"]); len(tags) > 0 {
		spec["tags"] = tags
	}
	m := serviceManifest(KindSSMParameter, name, spec)
	if _, ok := props["Description"]; ok {
		m.Caveats = append(m.Caveats, "Description is not kept — the SSM API here stores no parameter description")
	}
	if _, ok := props["AllowedPattern"]; ok {
		m.Caveats = append(m.Caveats, "AllowedPattern was checked against this stack's Value; the SSM API here does not enforce it on later PutParameter calls")
	}
	if ptype == "SecureString" {
		m.Caveats = append(m.Caveats, "SecureString: CloudFormation itself cannot create one on AWS (it accepts String and StringList only); here it is stored encrypted under the SSM default key")
	}
	return m, nil
}

// strProp reads an optional string property strictly: absent is "", a value that does not resolve to a
// scalar refuses (rather than reading as unset).
func strProp(id string, props map[string]any, key string) (string, []Finding) {
	v, present := props[key]
	if !present || v == nil {
		return "", nil
	}
	s, ok := concrete(v)
	if !ok {
		return "", []Finding{{"Resource " + id, key + " must resolve to a string"}}
	}
	return s, nil
}

// tagMap reads CloudFormation Tags given either as a {Key: Value} map (SSM's form) or a [{Key, Value}]
// list into a string map; non-concrete entries are skipped.
func tagMap(v any) map[string]any {
	out := map[string]any{}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := concrete(val); ok {
				out[k] = s
			}
		}
	case []any:
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				k, kok := concrete(m["Key"])
				val, vok := concrete(m["Value"])
				if kok && vok {
					out[k] = val
				}
			}
		}
	}
	return out
}

// kmsKeyCompanion is the KMS-store half of an AWS::KMS::Key when the deploying environment serves KMS:
// the key the KMS API lists, describes and encrypts with, under the id the stack's Refs resolve to. The
// kind: EncryptionKey the translator also emits stays the key's volume-encryption material.
func kmsKeyCompanion(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	usage, f := strProp(id, props, "KeyUsage")
	if usage != "" && usage != "ENCRYPT_DECRYPT" {
		f = append(f, Finding{"Resource " + id, "KeyUsage " + usage + " is not served — the KMS API here supports ENCRYPT_DECRYPT keys only"})
	}
	spec, sf := strProp(id, props, "KeySpec")
	f = append(f, sf...)
	if spec != "" && spec != "SYMMETRIC_DEFAULT" {
		f = append(f, Finding{"Resource " + id, "KeySpec " + spec + " is not served — the KMS API here supports SYMMETRIC_DEFAULT keys only"})
	}
	multi, mf := boolProp(id, props, "MultiRegion", false)
	f = append(f, mf...)
	if multi {
		f = append(f, Finding{"Resource " + id, "a multi-Region key is not served by the KMS API here"})
	}
	if len(f) > 0 {
		return nil, f
	}
	kid := svcKMSKeyID(id, ctx)
	s := map[string]any{"keyId": kid, "arn": svcKeyARN(kid, ctx)}
	// The declared values the KMS API here serves (the only ones it accepts), as the template set them.
	if usage != "" {
		s["keyUsage"] = usage
	}
	if spec != "" {
		s["keySpec"] = spec
	}
	if _, present := props["MultiRegion"]; present {
		s["multiRegion"] = multi
	}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		s["description"] = d
	}
	if rot, _ := boolProp(id, props, "EnableKeyRotation", false); rot {
		s["rotation"] = true
	}
	if en, present := props["Enabled"]; present && en != nil {
		if b, ok := cfnBoolValue(en); ok && !b {
			s["enabled"] = false
		}
	}
	if pw := toInt(props["PendingWindowInDays"]); pw > 0 {
		s["pendingWindowInDays"] = pw
	}
	if kp, ok := props["KeyPolicy"]; ok && kp != nil {
		if b, err := json.Marshal(kp); err == nil {
			s["keyPolicy"] = string(b)
		}
	}
	m := serviceManifest(KindKMSKey, kid, s)
	m.Caveats = append(m.Caveats, "the key is in the KMS API (ListKeys, Encrypt, Decrypt, …) under this id; an encrypted EBS volume that names it is keyed by the stack's kind: EncryptionKey, so disabling or deleting the key through the KMS API does not lock or erase those volumes — delete the stack (or a kind: Destruction) to erase them")
	return m, nil
}

// translateKMSAlias maps an AWS::KMS::Alias to an alias in the KMS front door's store. Without that
// front door there is nothing to alias, so it refuses.
func translateKMSAlias(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	f := blockUnknownProps(id, props, map[string]bool{"AliasName": true, "TargetKeyId": true})
	if !ctx.caps.KMSAPI {
		return nil, append(f, Finding{"Resource " + id, "an AWS::KMS::Alias needs the KMS API, which this deploy path does not serve"})
	}
	name, ok := concrete(props["AliasName"])
	if !ok || !strings.HasPrefix(name, "alias/") || strings.HasPrefix(name, "alias/aws/") || len(name) > 256 {
		f = append(f, Finding{"Resource " + id, "AliasName must be alias/<name> (not under the reserved alias/aws/ prefix)"})
	}
	raw, _ := ctx.rawProps(id)
	target := ""
	if tid, ok := getAttTarget(raw["TargetKeyId"]); ok && ctx.isType(tid, "AWS::KMS::Key") {
		target = svcKMSKeyID(tid, ctx)
	} else if t, ok := concrete(props["TargetKeyId"]); ok && t != "" {
		target = t
	} else {
		f = append(f, Finding{"Resource " + id, "TargetKeyId must resolve to a key id or ARN (e.g. !Ref Key)"})
	}
	if len(f) > 0 {
		return nil, f
	}
	if i := strings.LastIndex(target, "key/"); i >= 0 {
		target = target[i+len("key/"):]
	}
	return serviceManifest(KindKMSAlias, name, map[string]any{"aliasName": name, "targetKeyId": target}), nil
}
