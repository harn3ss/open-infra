// Resources that live in the aws-shim's own service stores, not in Kubernetes.
//
// A Secrets Manager secret, a CloudWatch Logs log group, an EventBridge rule or event bus, an ECR
// repository and a CloudWatch alarm are each held by the shim front door that serves its AWS API. A stack
// creates them there, so the resource is usable through that API under the name and ARN the template sees.
// Each translates to a service-kind manifest (ServiceAPIVersion, service.go): the deploy, update, rollback,
// destroy and recovery paths treat it like any other object, and the CloudFormation front door's applier
// carries it out as the caller, through that service's own front door (its authorization included). The
// CLI cannot (it has no such stores), so these types refuse there (Capabilities.SecretsManagerAPI, …).
package cfn

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

func init() {
	for typ, tr := range map[string]translator{
		"AWS::SecretsManager::Secret": translateSecretsManagerSecret,
		"AWS::Logs::LogGroup":         translateLogsLogGroup,
		"AWS::Events::Rule":           translateEventsRule,
		"AWS::Events::EventBus":       translateEventsEventBus,
		"AWS::ECR::Repository":        translateECRRepository,
		"AWS::CloudWatch::Alarm":      translateCloudWatchAlarm,
		"AWS::Lambda::Permission":     translateLambdaPermission,
	} {
		translators[typ] = tr
	}
	inShim := " The resource is created in the aws-shim's own store for that API, through its front door and under the caller's authority, so it is usable through the AWS API by the name and ARN the template sees. Needs the aws-shim CloudFormation front door (the cfn CLI refuses it)."
	for typ, e := range map[string]MapEntry{
		"AWS::SecretsManager::Secret":  {Kind: "Secrets Manager secret", Status: Supported, Note: "SecretString, or GenerateSecretString (generated once, at create; an update does not regenerate it), Description, Tags. KmsKeyId other than the default managed key and ReplicaRegions refuse (every secret is protected under the default managed key; one region). Ref and Fn::GetAtt Id are the secret's ARN." + inShim},
		"AWS::Logs::LogGroup":          {Kind: "CloudWatch Logs log group", Status: Supported, Note: "LogGroupName, RetentionInDays, Tags. KmsKeyId and DataProtectionPolicy refuse (no per-group encryption or masking); a LogGroupClass other than STANDARD and FieldIndexPolicies are caveats (one storage class, no field indexes). Ref is the name, Fn::GetAtt Arn its ARN." + inShim},
		"AWS::Events::Rule":            {Kind: "EventBridge rule", Status: Partial, Note: "ScheduleExpression and/or EventPattern on the default or a named bus, State, Targets with a constant Input. Targets are Lambda functions (in the stack, or by ARN) and SQS queues (by ARN, or the stack's own where the SQS API serves it); SNS, Step Functions and the other target types, a rule or target RoleArn, InputPath, InputTransformer, DeadLetterConfig and the per-service target parameters refuse (the shim delivers to Lambda and SQS, under the rule creator's authority); RetryPolicy is a caveat (delivery retries on the shim's own schedule). Ref is the rule name (bus|name on a named bus), Fn::GetAtt Arn its ARN." + inShim},
		"AWS::Events::EventBus":        {Kind: "EventBridge event bus", Status: Supported, Note: "a custom bus by Name. A partner EventSourceName, Policy, KmsKeyIdentifier and DeadLetterConfig refuse. Ref and Fn::GetAtt Name are the name, Fn::GetAtt Arn its ARN." + inShim},
		"AWS::ECR::Repository":         {Kind: "ECR repository", Status: Partial, Note: "RepositoryName, ImageTagMutability (MUTABLE/IMMUTABLE), EmptyOnDelete; EncryptionConfiguration AES256 when the environment encrypts object storage (KMS refuses). Image scanning, lifecycle policies, an Allow-only repository policy and Tags are caveats (not implemented; access is RBAC + Cedar); a repository policy with a Deny refuses. Ref is the name; Fn::GetAtt Arn and RepositoryUri (the in-cluster registry host + name)." + inShim},
		"AWS::CloudWatch::Alarm":       {Kind: "CloudWatch alarm", Status: Partial, Note: "a single-metric alarm (Namespace, MetricName, Dimensions, Statistic or a pNN ExtendedStatistic, Period, EvaluationPeriods, DatapointsToAlarm, Threshold, the four static comparison operators, TreatMissingData) with SNS AlarmActions (a topic by ARN, or the stack's own where the SNS API serves it), evaluated by the shim. Metric-math alarms (Metrics, ThresholdMetricId), anomaly-band operators, OKActions and InsufficientDataActions refuse (only ALARM fires SNS); Unit and EvaluateLowSampleCountPercentile are caveats. Ref is the name, Fn::GetAtt Arn its ARN." + inShim},
		"AWS::Lambda::Permission":      {Kind: "(implicit)", Status: Partial, Note: "a Lambda resource-based permission for an AWS service principal (events, sns, s3, apigateway, …) to invoke an in-stack Function provisions nothing: on open-infra the integration that invokes the Function is authorized when it is created, against its creator's own authority (an EventBridge target, an API Gateway integration), not by a resource policy. An account/ARN principal, a public function URL (FunctionUrlAuthType) and actions other than lambda:InvokeFunction refuse."},
		"AWS::Route53::RecordSet":      {Status: Unsupported, Note: "no backing service: open-infra serves no authoritative DNS zone a stack could own (cluster DNS is cluster-scoped and not tenant-writable, and LAN names come from the site's own DNS), so a record would be accepted and never answered. Publish the name in the site's DNS, or use the Elastic IP / StaticSite domain the stack already outputs."},
		"AWS::Route53::HostedZone":     {Status: Unsupported, Note: "no backing service: open-infra has no tenant-owned authoritative DNS (see AWS::Route53::RecordSet)."},
		"AWS::Route53::RecordSetGroup": {Status: Unsupported, Note: "no backing service: open-infra has no tenant-owned authoritative DNS (see AWS::Route53::RecordSet)."},
	} {
		mappingTable[typ] = e
	}
}

// serviceNameProp is the property that names each service resource.
var serviceNameProp = map[string]string{
	"AWS::SecretsManager::Secret": "Name", "AWS::Logs::LogGroup": "LogGroupName", "AWS::Events::Rule": "Name",
	"AWS::Events::EventBus": "Name", "AWS::ECR::Repository": "RepositoryName", "AWS::CloudWatch::Alarm": "AlarmName",
}

// secretARNSuffix is the six characters AWS appends to a secret's ARN. AWS picks them at random; here they
// are derived from the stack, the logical id and the name, so Ref is known before the secret exists and an
// update re-creates nothing. (A secret deleted and re-created by the same stack gets the same ARN.)
func secretARNSuffix(seed string) string {
	const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	h := sha256.Sum256([]byte(seed))
	out := make([]byte, 6)
	for i := range out {
		out[i] = abc[int(h[i])%len(abc)]
	}
	return string(out)
}

// eventBusOf is a rule's bus name: its EventBusName (a name, or an event bus ARN) or "default".
func eventBusOf(props map[string]any) string {
	b, _ := concrete(props["EventBusName"])
	if i := strings.LastIndex(b, "event-bus/"); i >= 0 {
		b = b[i+len("event-bus/"):]
	}
	if b == "" {
		return "default"
	}
	return b
}

// serviceStatic is a service resource's Ref (attr "") or Fn::GetAtt value when it is known before deploy:
// its name, or an ARN built from it. ok=false for any other resource or attribute.
func serviceStatic(id, attr string, ctx *stackCtx) (string, bool) {
	if ctx == nil || ctx.template == nil {
		return "", false
	}
	res, in := ctx.template.Resources[id]
	if !in {
		return "", false
	}
	prop, ok := serviceNameProp[res.Type]
	if !ok {
		return "", false
	}
	name := inStackName(id, prop, ctx)
	// The stack's pseudo parameters (the install's identity), so an ARN a template builds with
	// ${AWS::Region}/${AWS::AccountId} matches the one Ref returns.
	arn := func(service, rest string) string {
		return fmt.Sprintf("arn:aws:%s:%s:%s:%s", service, ctx.region(), ctx.account(), rest)
	}
	switch res.Type {
	case "AWS::SecretsManager::Secret":
		if attr == "" || attr == "Id" {
			return arn("secretsmanager", "secret:"+name+"-"+secretARNSuffix(ctx.stackName()+"/"+id+"/"+name)), true
		}
	case "AWS::Logs::LogGroup":
		switch attr {
		case "":
			return name, true
		case "Arn":
			return arn("logs", "log-group:"+name+":*"), true
		}
	case "AWS::Events::Rule":
		p, _ := ctx.resolveProps(id)
		bus := eventBusOf(p)
		switch attr {
		case "":
			if bus != "default" {
				return bus + "|" + name, true
			}
			return name, true
		case "Arn":
			if bus != "default" {
				return arn("events", "rule/"+bus+"/"+name), true
			}
			return arn("events", "rule/"+name), true
		}
	case "AWS::Events::EventBus":
		switch attr {
		case "", "Name":
			return name, true
		case "Arn":
			return arn("events", "event-bus/"+name), true
		}
	case "AWS::ECR::Repository":
		switch attr {
		case "":
			return name, true
		case "Arn":
			return arn("ecr", "repository/"+name), true
		case "RepositoryUri":
			if h := capsOf(ctx).ECRRepositoryHost; h != "" {
				return h + "/" + name, true
			}
		}
	case "AWS::CloudWatch::Alarm":
		switch attr {
		case "":
			return name, true
		case "Arn":
			return arn("cloudwatch", "alarm:"+name), true
		}
	}
	return "", false
}

// needsServiceStores refuses a service resource on a deploy path that does not serve its API from the
// shim's own store (the CLI).
func needsServiceStores(id, typ string, ctx *stackCtx) []Finding {
	c := capsOf(ctx)
	served := map[string]bool{
		"AWS::SecretsManager::Secret": c.SecretsManagerAPI, "AWS::Logs::LogGroup": c.LogsAPI,
		"AWS::Events::Rule": c.EventsAPI, "AWS::Events::EventBus": c.EventsAPI,
		"AWS::ECR::Repository": c.ECRAPI, "AWS::CloudWatch::Alarm": c.CloudWatchAPI,
	}
	if served[typ] {
		return nil
	}
	return []Finding{{"Resource " + id, typ + " lives in the aws-shim's own store for its API, which this deploy path does not serve — deploy it through the aws-shim CloudFormation front door (the cfn CLI has no such store)"}}
}

// stringList reads a list of concrete strings, refusing an element that is not one.
func stringList(id, prop string, v any) ([]string, []Finding) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, []Finding{{"Resource " + id, prop + " must be a list"}}
	}
	var out []string
	var f []Finding
	for _, e := range l {
		s, ok := concrete(e)
		if !ok || s == "" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s has an element that is not a concrete string (%v)", prop, e)})
			continue
		}
		out = append(out, s)
	}
	return out, f
}

// ---- AWS::SecretsManager::Secret ----

var generateSecretKnown = map[string]bool{
	"ExcludeCharacters": true, "ExcludeLowercase": true, "ExcludeNumbers": true, "ExcludePunctuation": true,
	"ExcludeUppercase": true, "GenerateStringKey": true, "IncludeSpace": true, "PasswordLength": true,
	"RequireEachIncludedType": true, "SecretStringTemplate": true,
}

func translateSecretsManagerSecret(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Name": true, "Description": true, "KmsKeyId": true, "SecretString": true,
		"GenerateSecretString": true, "Tags": true, "ReplicaRegions": true}
	f := blockUnknownProps(id, props, known)
	f = append(f, needsServiceStores(id, "AWS::SecretsManager::Secret", ctx)...)
	f = append(f, shapeFindings(id, props, []string{"Tags", "ReplicaRegions"}, []string{"GenerateSecretString"},
		[]string{"Name", "Description", "KmsKeyId", "SecretString"})...)
	if _, ok := props["ReplicaRegions"]; ok {
		f = append(f, Finding{"Resource " + id, "ReplicaRegions cannot be honored — open-infra is one region, so a replica would never exist"})
	}
	if k, _ := concrete(props["KmsKeyId"]); k != "" && k != "alias/aws/secretsmanager" {
		f = append(f, Finding{"Resource " + id, "KmsKeyId " + k + " cannot be honored — every secret is protected under the default managed key (Vault Transit); omit KmsKeyId"})
	}
	_, hasString := props["SecretString"]
	gen, hasGen := props["GenerateSecretString"].(map[string]any)
	switch {
	case hasString && hasGen:
		f = append(f, Finding{"Resource " + id, "SecretString and GenerateSecretString cannot both be set (CloudFormation refuses it too)"})
	case !hasString && !hasGen:
		f = append(f, Finding{"Resource " + id, "a secret with neither SecretString nor GenerateSecretString is an empty secret, which the Secrets Manager front door does not hold — set one of them"})
	}
	name, _ := serviceStatic(id, "", ctx)
	spec := map[string]any{"name": inStackName(id, "Name", ctx), "arn": name}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		spec["description"] = d
	}
	if hasString {
		s, ok := concrete(props["SecretString"])
		if !ok {
			f = append(f, Finding{"Resource " + id, "SecretString did not resolve to a string"})
		}
		spec["secretString"] = s
	}
	if hasGen {
		g, gf := generateSecretSpec(id, gen)
		f = append(f, gf...)
		spec["generateSecretString"] = g
	}
	if t := tagMap(props["Tags"]); len(t) > 0 {
		spec["tags"] = t
	}
	return &Manifest{APIVersion: ServiceAPIVersion, Kind: KindSecretsManagerSecret, Name: spec["name"].(string), Spec: spec}, f
}

// generateSecretSpec reads GenerateSecretString into the GetRandomPassword parameters the front door's
// applier generates the value with, plus the template/key it is placed in.
func generateSecretSpec(id string, gen map[string]any) (map[string]any, []Finding) {
	where := id + ".GenerateSecretString"
	f := blockUnknownProps(where, gen, generateSecretKnown)
	f = append(f, shapeFindings(id, gen, nil, nil, []string{"ExcludeCharacters", "GenerateStringKey", "SecretStringTemplate", "PasswordLength"})...)
	out := map[string]any{}
	for _, k := range []string{"ExcludeLowercase", "ExcludeNumbers", "ExcludePunctuation", "ExcludeUppercase", "IncludeSpace", "RequireEachIncludedType"} {
		if _, set := gen[k]; !set {
			continue
		}
		b, bf := boolProp(id, gen, k, false)
		f = append(f, bf...)
		out[k] = b
	}
	if v, set := gen["PasswordLength"]; set {
		n := toInt(v)
		if n < 1 || n > 4096 {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("GenerateSecretString.PasswordLength must be 1–4096 (got %v)", v)})
		}
		out["PasswordLength"] = n
	}
	if v, set := gen["ExcludeCharacters"]; set {
		s, _ := concrete(v)
		out["ExcludeCharacters"] = s
	}
	tmpl, hasTmpl := concrete(gen["SecretStringTemplate"])
	key, hasKey := concrete(gen["GenerateStringKey"])
	switch {
	case hasTmpl != hasKey:
		f = append(f, Finding{"Resource " + id, "GenerateSecretString.SecretStringTemplate and GenerateStringKey go together (CloudFormation refuses one without the other)"})
	case hasTmpl:
		var obj map[string]any
		if err := json.Unmarshal([]byte(tmpl), &obj); err != nil {
			f = append(f, Finding{"Resource " + id, "GenerateSecretString.SecretStringTemplate must be a JSON object: " + err.Error()})
		}
		out["SecretStringTemplate"], out["GenerateStringKey"] = tmpl, key
	}
	return out, f
}

// ---- AWS::Logs::LogGroup ----

var logRetentionDays = map[int]bool{1: true, 3: true, 5: true, 7: true, 14: true, 30: true, 60: true, 90: true, 120: true,
	150: true, 180: true, 365: true, 400: true, 545: true, 731: true, 1096: true, 1827: true, 2192: true, 2557: true,
	2922: true, 3288: true, 3653: true}

func translateLogsLogGroup(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"LogGroupName": true, "RetentionInDays": true, "KmsKeyId": true, "Tags": true,
		"DataProtectionPolicy": true, "LogGroupClass": true, "FieldIndexPolicies": true}
	f := blockUnknownProps(id, props, known)
	f = append(f, needsServiceStores(id, "AWS::Logs::LogGroup", ctx)...)
	f = append(f, shapeFindings(id, props, []string{"Tags", "FieldIndexPolicies"}, []string{"DataProtectionPolicy"},
		[]string{"LogGroupName", "KmsKeyId", "LogGroupClass"})...)
	if _, ok := props["KmsKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsKeyId cannot be honored — log groups have no per-group encryption here; omit it"})
	}
	if _, ok := props["DataProtectionPolicy"]; ok {
		f = append(f, Finding{"Resource " + id, "DataProtectionPolicy cannot be honored — log events are not masked or audited for sensitive data"})
	}
	name := inStackName(id, "LogGroupName", ctx)
	spec := map[string]any{"name": name}
	m := &Manifest{APIVersion: ServiceAPIVersion, Kind: KindLogsLogGroup, Name: name, Spec: spec}
	if v, ok := props["RetentionInDays"]; ok {
		n := toInt(v)
		if !logRetentionDays[n] {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("RetentionInDays %v is not one CloudWatch Logs allows (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653)", v)})
		}
		spec["retentionInDays"] = n
	}
	if c, _ := concrete(props["LogGroupClass"]); c != "" {
		switch c {
		case "STANDARD":
		case "INFREQUENT_ACCESS", "DELIVERY":
			m.Caveats = append(m.Caveats, "LogGroupClass "+c+" is not modeled — the group behaves as STANDARD (every Logs feature is available on it)")
		default:
			f = append(f, Finding{"Resource " + id, "LogGroupClass must be STANDARD, INFREQUENT_ACCESS or DELIVERY (got " + c + ")"})
		}
		spec["logGroupClass"] = c
	}
	if p, ok := props["FieldIndexPolicies"]; ok {
		m.Caveats = append(m.Caveats, "FieldIndexPolicies are not applied — queries scan the group's events without field indexes (results are the same)")
		spec["fieldIndexPolicies"] = p
	}
	if t := tagMap(props["Tags"]); len(t) > 0 {
		spec["tags"] = t
	}
	return m, f
}

// ---- AWS::Events::Rule ----

// ruleTargetKnown are the target properties read; the per-service target parameters (EcsParameters,
// HttpParameters, ...) are not, so a target carrying one refuses as untranslatable.
var ruleTargetKnown = map[string]bool{
	"Id": true, "Arn": true, "Input": true, "InputPath": true, "InputTransformer": true, "RoleArn": true,
	"RetryPolicy": true, "DeadLetterConfig": true, "SqsParameters": true,
}

func translateEventsRule(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Name": true, "Description": true, "EventBusName": true, "EventPattern": true,
		"ScheduleExpression": true, "State": true, "Targets": true, "RoleArn": true, "Tags": true}
	f := blockUnknownProps(id, props, known)
	f = append(f, needsServiceStores(id, "AWS::Events::Rule", ctx)...)
	f = append(f, shapeFindings(id, props, []string{"Targets", "Tags"}, nil,
		[]string{"Name", "Description", "EventBusName", "ScheduleExpression", "State", "RoleArn"})...)
	if _, ok := props["RoleArn"]; ok {
		f = append(f, Finding{"Resource " + id, "RoleArn cannot be honored — a rule's targets are invoked under its creator's authority, not a role's"})
	}
	name := inStackName(id, "Name", ctx)
	spec := map[string]any{"name": name, "eventBusName": eventBusOf(props)}
	m := &Manifest{APIVersion: ServiceAPIVersion, Kind: KindEventsRule, Name: name, Spec: spec}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		spec["description"] = d
	}
	if s, ok := concrete(props["ScheduleExpression"]); ok && s != "" {
		if !strings.HasPrefix(s, "rate(") && !strings.HasPrefix(s, "cron(") {
			f = append(f, Finding{"Resource " + id, "ScheduleExpression must be rate(...) or cron(...) (got " + s + ")"})
		}
		spec["scheduleExpression"] = s
	}
	if p, ok := props["EventPattern"]; ok {
		switch v := p.(type) {
		case string:
			var obj map[string]any
			if json.Unmarshal([]byte(v), &obj) != nil {
				f = append(f, Finding{"Resource " + id, "EventPattern must be a JSON object"})
			}
			spec["eventPattern"] = v
		case map[string]any:
			b, _ := json.Marshal(v)
			spec["eventPattern"] = string(b)
			if strings.Contains(string(b), "<") {
				f = append(f, Finding{"Resource " + id, "EventPattern carries a value that did not resolve"})
			}
		default:
			f = append(f, Finding{"Resource " + id, "EventPattern must be an object"})
		}
	}
	if spec["scheduleExpression"] == nil && spec["eventPattern"] == nil {
		f = append(f, Finding{"Resource " + id, "a rule needs a ScheduleExpression or an EventPattern"})
	}
	state := "ENABLED"
	if s, _ := concrete(props["State"]); s != "" {
		switch s {
		case "ENABLED", "DISABLED":
			state = s
		case "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS":
			state = "ENABLED"
			m.Caveats = append(m.Caveats, "State ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS: there are no CloudTrail management events here, so the rule matches only the events put on its bus")
		default:
			f = append(f, Finding{"Resource " + id, "State must be ENABLED or DISABLED (got " + s + ")"})
		}
	}
	spec["state"] = state
	targets, tf := ruleTargets(id, ctx, m)
	f = append(f, tf...)
	if len(targets) > 5 {
		f = append(f, Finding{"Resource " + id, "a rule can have at most 5 targets"})
	}
	if len(targets) > 0 {
		spec["targets"] = targets
	}
	if t := tagMap(props["Tags"]); len(t) > 0 {
		spec["tags"] = t
	}
	return m, f
}

// ruleTargets reads a rule's Targets. A target names a Lambda function (in the stack — followed through its
// raw {Fn::GetAtt: [Fn, Arn]} or {Ref: Fn} — or by ARN) or an SQS queue by ARN: what the EventBridge front
// door delivers to. An in-stack function is marked so the front door invokes it in the stack's namespace.
func ruleTargets(id string, ctx *stackCtx, m *Manifest) ([]any, []Finding) {
	var raw []any
	if ctx != nil {
		if rp, ok := ctx.rawProps(id); ok {
			raw, _ = rp["Targets"].([]any)
		}
	}
	var out []any
	var f []Finding
	for i, rt := range raw {
		where := fmt.Sprintf("%s.Targets[%d]", id, i)
		t, ok := ctx.resolveVal(rt).(map[string]any)
		if !ok {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("Targets[%d] must be an object", i)})
			continue
		}
		f = append(f, blockUnknownProps(where, t, ruleTargetKnown)...)
		for _, p := range []string{"InputPath", "InputTransformer", "RoleArn", "DeadLetterConfig", "SqsParameters"} {
			if _, set := t[p]; set {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("Targets[%d].%s cannot be honored — the EventBridge front door delivers the event (or a constant Input) under the rule creator's authority, with no input transformation, target role, dead-letter queue or message group", i, p)})
			}
		}
		tid, _ := concrete(t["Id"])
		if tid == "" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("Targets[%d] needs an Id", i)})
		}
		out1 := map[string]any{"id": tid}
		rawT, _ := rt.(map[string]any)
		if fn, ok := inStackFunctionOf(rawT["Arn"], ctx); ok {
			out1["function"] = ctx.functionName(fn)
		} else if q, ok := inStackOfType(rawT["Arn"], "AWS::SQS::Queue", ctx); ok {
			// EventBridge delivers to a queue in the SQS API's store: the stack's queue is one when this
			// deploy path serves SQS (service.go); otherwise it is a kind: Queue stream SQS cannot see.
			if arn, served := serviceAtt(q, "Arn", ctx); served {
				out1["arn"] = arn
			} else {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("Targets[%d] is the in-stack queue %s, which is not a queue of the SQS API (where EventBridge delivers) on this deploy path — a kind: Queue stream", i, q)})
			}
		} else {
			arn, ok := concrete(t["Arn"])
			switch {
			case !ok || arn == "":
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("Targets[%d].Arn did not resolve to an ARN", i)})
			case strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":lambda:"):
				out1["arn"] = arn
			case strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":sqs:"):
				out1["arn"] = arn
			default:
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("Targets[%d].Arn %s is not a Lambda function or an SQS queue — the EventBridge front door delivers to those two only", i, arn)})
			}
		}
		if in, ok := t["Input"]; ok {
			s, isStr := in.(string)
			if !isStr {
				b, _ := json.Marshal(in)
				s = string(b)
			}
			out1["input"] = s
		}
		if _, ok := t["RetryPolicy"]; ok {
			m.Caveats = append(m.Caveats, fmt.Sprintf("Targets[%d].RetryPolicy is not applied — a failed delivery is retried on the front door's own schedule (attempts spaced over minutes, then dead-lettered)", i))
			out1["retryPolicy"] = t["RetryPolicy"]
		}
		out = append(out, out1)
	}
	return out, f
}

// inStackFunctionOf follows a raw {Fn::GetAtt: [Fn, Arn]} / {Ref: Fn} to an in-stack Lambda function.
func inStackFunctionOf(raw any, ctx *stackCtx) (string, bool) {
	return inStackOfType(raw, "AWS::Lambda::Function", ctx)
}

// inStackOfType follows a raw Ref or Fn::GetAtt to an in-stack resource of typ.
func inStackOfType(raw any, typ string, ctx *stackCtx) (string, bool) {
	if ctx == nil || ctx.template == nil {
		return "", false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	var target string
	if r, ok := m["Ref"].(string); ok {
		target = r
	} else if ga, ok := m["Fn::GetAtt"]; ok {
		switch a := ga.(type) {
		case []any:
			if len(a) > 0 {
				target, _ = a[0].(string)
			}
		case string:
			target, _, _ = strings.Cut(a, ".")
		}
	}
	if res, ok := ctx.template.Resources[target]; ok && res.Type == typ {
		return target, true
	}
	return "", false
}

// ---- AWS::Events::EventBus ----

func translateEventsEventBus(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Name": true, "Description": true, "EventSourceName": true, "Policy": true,
		"KmsKeyIdentifier": true, "DeadLetterConfig": true, "Tags": true}
	f := blockUnknownProps(id, props, known)
	f = append(f, needsServiceStores(id, "AWS::Events::EventBus", ctx)...)
	for _, p := range []string{"EventSourceName", "Policy", "KmsKeyIdentifier", "DeadLetterConfig"} {
		if _, ok := props[p]; ok {
			f = append(f, Finding{"Resource " + id, p + " cannot be honored — the EventBridge front door holds custom buses only (no partner sources, bus policies, per-bus encryption or dead-letter queues)"})
		}
	}
	name, _ := concrete(props["Name"])
	if name == "" {
		f = append(f, Finding{"Resource " + id, "an event bus needs a Name"})
		name = inStackName(id, "Name", ctx)
	}
	if name == "default" {
		f = append(f, Finding{"Resource " + id, "the default bus always exists — a stack cannot create it"})
	}
	spec := map[string]any{"name": name}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		spec["description"] = d
	}
	if t := tagMap(props["Tags"]); len(t) > 0 {
		spec["tags"] = t
	}
	return &Manifest{APIVersion: ServiceAPIVersion, Kind: KindEventsEventBus, Name: name, Spec: spec}, f
}

// ---- AWS::ECR::Repository ----

func translateECRRepository(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"RepositoryName": true, "ImageTagMutability": true, "ImageScanningConfiguration": true,
		"LifecyclePolicy": true, "RepositoryPolicyText": true, "EncryptionConfiguration": true, "EmptyOnDelete": true,
		"Tags": true, "ImageTagMutabilityExclusionFilters": true}
	f := blockUnknownProps(id, props, known)
	f = append(f, needsServiceStores(id, "AWS::ECR::Repository", ctx)...)
	f = append(f, shapeFindings(id, props, []string{"Tags", "ImageTagMutabilityExclusionFilters"},
		[]string{"ImageScanningConfiguration", "LifecyclePolicy", "EncryptionConfiguration"},
		[]string{"RepositoryName", "ImageTagMutability"})...)
	name := inStackName(id, "RepositoryName", ctx)
	spec := map[string]any{"name": name}
	m := &Manifest{APIVersion: ServiceAPIVersion, Kind: KindECRRepository, Name: name, Spec: spec}
	mut, _ := concrete(props["ImageTagMutability"])
	switch mut {
	case "", "MUTABLE":
		mut = "MUTABLE"
	case "IMMUTABLE":
	default:
		f = append(f, Finding{"Resource " + id, "ImageTagMutability must be MUTABLE or IMMUTABLE (got " + mut + "; exclusion filters are not implemented)"})
	}
	spec["imageTagMutability"] = mut
	if _, ok := props["ImageTagMutabilityExclusionFilters"]; ok {
		f = append(f, Finding{"Resource " + id, "ImageTagMutabilityExclusionFilters cannot be honored — tag mutability is one setting for the whole repository"})
	}
	empty, ef := boolProp(id, props, "EmptyOnDelete", false)
	f = append(f, ef...)
	if empty {
		spec["emptyOnDelete"] = true
	}
	if sc, ok := props["ImageScanningConfiguration"].(map[string]any); ok {
		f = append(f, blockUnknownProps(id+".ImageScanningConfiguration", sc, map[string]bool{"ScanOnPush": true})...)
		on, sf := boolProp(id, sc, "ScanOnPush", false)
		f = append(f, sf...)
		if on {
			m.Caveats = append(m.Caveats, "ImageScanningConfiguration ScanOnPush: images are not scanned — the registry has no scanner")
			spec["scanOnPush"] = true
		}
	}
	if lp, ok := props["LifecyclePolicy"].(map[string]any); ok {
		f = append(f, blockUnknownProps(id+".LifecyclePolicy", lp, map[string]bool{"LifecyclePolicyText": true, "RegistryId": true})...)
		m.Caveats = append(m.Caveats, "LifecyclePolicy is not applied — images are never expired")
		spec["lifecyclePolicy"] = lp
	}
	if pt, ok := props["RepositoryPolicyText"]; ok {
		if policyHasDeny(pt) {
			f = append(f, Finding{"Resource " + id, "RepositoryPolicyText has a Deny statement, which cannot be honored — access to the repository is RBAC + Cedar, and a Deny this policy carries would not apply"})
		} else {
			m.Caveats = append(m.Caveats, "RepositoryPolicyText (Allow only) is not applied — access to the repository is RBAC + Cedar; grant it there")
		}
		spec["repositoryPolicy"] = pt
	}
	if ec, ok := props["EncryptionConfiguration"].(map[string]any); ok {
		f = append(f, blockUnknownProps(id+".EncryptionConfiguration", ec, map[string]bool{"EncryptionType": true, "KmsKey": true})...)
		et, _ := concrete(ec["EncryptionType"])
		switch {
		case et == "KMS" || et == "KMS_DSSE" || ec["KmsKey"] != nil:
			f = append(f, Finding{"Resource " + id, "EncryptionConfiguration KMS cannot be honored — the registry's storage has no per-repository key"})
		case et == "AES256" && !capsOf(ctx).ObjectEncryption:
			f = append(f, Finding{"Resource " + id, "EncryptionConfiguration AES256 cannot be honored here — this environment does not encrypt object storage at rest (see docs/encryption.md); refusing rather than deploy an unencrypted repository the template asked to encrypt"})
		case et == "AES256":
			m.Caveats = append(m.Caveats, "EncryptionConfiguration AES256: images are encrypted at rest by the platform's object storage (SSE-KMS), not per repository")
		default:
			f = append(f, Finding{"Resource " + id, "EncryptionConfiguration.EncryptionType must be AES256 or KMS (got " + et + ")"})
		}
		spec["encryption"] = et
	}
	if t := tagMap(props["Tags"]); len(t) > 0 {
		m.Caveats = append(m.Caveats, "Tags are not stored on the repository — the ECR front door does not implement repository tags")
		spec["tags"] = t
	}
	return m, f
}

// policyHasDeny reports whether a policy document (an object, or its JSON string) has a Deny statement.
func policyHasDeny(v any) bool {
	if s, ok := v.(string); ok {
		var obj any
		if json.Unmarshal([]byte(s), &obj) != nil {
			return true // unreadable: treat as unsafe
		}
		v = obj
	}
	b, _ := json.Marshal(v)
	return strings.Contains(string(b), `"Effect":"Deny"`)
}

// ---- AWS::CloudWatch::Alarm ----

var alarmOperators = map[string]bool{"GreaterThanThreshold": true, "GreaterThanOrEqualToThreshold": true,
	"LessThanThreshold": true, "LessThanOrEqualToThreshold": true}

func translateCloudWatchAlarm(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"AlarmName": true, "AlarmDescription": true, "ActionsEnabled": true, "AlarmActions": true,
		"OKActions": true, "InsufficientDataActions": true, "ComparisonOperator": true, "EvaluationPeriods": true,
		"DatapointsToAlarm": true, "MetricName": true, "Namespace": true, "Statistic": true, "ExtendedStatistic": true,
		"Period": true, "Threshold": true, "Dimensions": true, "Unit": true, "TreatMissingData": true, "Metrics": true,
		"ThresholdMetricId": true, "EvaluateLowSampleCountPercentile": true, "Tags": true}
	f := blockUnknownProps(id, props, known)
	f = append(f, needsServiceStores(id, "AWS::CloudWatch::Alarm", ctx)...)
	f = append(f, shapeFindings(id, props, []string{"AlarmActions", "OKActions", "InsufficientDataActions", "Dimensions", "Metrics", "Tags"}, nil,
		[]string{"AlarmName", "AlarmDescription", "ComparisonOperator", "MetricName", "Namespace", "Statistic", "ExtendedStatistic", "Unit", "TreatMissingData", "ThresholdMetricId", "EvaluateLowSampleCountPercentile"})...)
	for _, p := range []string{"Metrics", "ThresholdMetricId"} {
		if _, ok := props[p]; ok {
			f = append(f, Finding{"Resource " + id, p + " cannot be honored — the alarm evaluator watches one metric (no metric math or anomaly band)"})
		}
	}
	name := inStackName(id, "AlarmName", ctx)
	spec := map[string]any{"name": name}
	m := &Manifest{APIVersion: ServiceAPIVersion, Kind: KindCloudWatchAlarm, Name: name, Spec: spec}
	str := func(p string) string { s, _ := concrete(props[p]); return s }
	for _, p := range []string{"Namespace", "MetricName"} {
		if str(p) == "" && props["Metrics"] == nil {
			f = append(f, Finding{"Resource " + id, "a single-metric alarm needs " + p})
		}
	}
	spec["namespace"], spec["metricName"] = str("Namespace"), str("MetricName")
	if d := str("AlarmDescription"); d != "" {
		spec["description"] = d
	}
	op := str("ComparisonOperator")
	if !alarmOperators[op] {
		f = append(f, Finding{"Resource " + id, "ComparisonOperator must be GreaterThanThreshold, GreaterThanOrEqualToThreshold, LessThanThreshold or LessThanOrEqualToThreshold (got " + op + "; anomaly-band operators need metric math)"})
	}
	spec["comparisonOperator"] = op
	stat, ext := str("Statistic"), str("ExtendedStatistic")
	switch {
	case stat == "" && ext == "":
		f = append(f, Finding{"Resource " + id, "an alarm needs a Statistic or an ExtendedStatistic"})
	case stat != "":
		switch stat {
		case "Average", "Sum", "Minimum", "Maximum", "SampleCount":
		default:
			f = append(f, Finding{"Resource " + id, "Statistic must be Average, Sum, Minimum, Maximum or SampleCount (got " + stat + ")"})
		}
		spec["statistic"] = stat
	}
	if ext != "" {
		if !strings.HasPrefix(ext, "p") {
			f = append(f, Finding{"Resource " + id, "ExtendedStatistic must be a percentile (pNN) — trimmed means and the other extended statistics are not computed (got " + ext + ")"})
		}
		spec["extendedStatistic"] = ext
	}
	for _, p := range []string{"Period", "EvaluationPeriods", "DatapointsToAlarm"} {
		if v, ok := props[p]; ok {
			spec[strings.ToLower(p[:1])+p[1:]] = toInt(v)
		}
	}
	if props["EvaluationPeriods"] == nil {
		f = append(f, Finding{"Resource " + id, "an alarm needs EvaluationPeriods"})
	}
	thr, ok := props["Threshold"]
	if !ok {
		f = append(f, Finding{"Resource " + id, "an alarm needs a Threshold"})
	}
	spec["threshold"] = fmt.Sprint(thr)
	if tmd := str("TreatMissingData"); tmd != "" {
		switch tmd {
		case "missing", "notBreaching", "breaching", "ignore":
		default:
			f = append(f, Finding{"Resource " + id, "TreatMissingData must be missing, notBreaching, breaching or ignore (got " + tmd + ")"})
		}
		spec["treatMissingData"] = tmd
	}
	if dl, ok := props["Dimensions"].([]any); ok {
		var dims []any
		var rawDims []any
		if ctx != nil {
			if rp, ok := ctx.rawProps(id); ok {
				rawDims, _ = rp["Dimensions"].([]any)
			}
		}
		for i, d := range dl {
			dm, _ := d.(map[string]any)
			n, nok := concrete(dm["Name"])
			v, vok := concrete(dm["Value"])
			if nok && !vok && i < len(rawDims) {
				// A dimension naming an in-stack instance (Value: !Ref <instance>, or its InstanceId) is that
				// instance's id — its VM's name, what its Ref is (#350 X).
				rd, _ := rawDims[i].(map[string]any)
				if inst, lid, ok := instanceIDRef(rd["Value"], ctx); ok {
					v, vok = inst, true
					m.Caveats = append(m.Caveats, fmt.Sprintf("Dimensions[%d] names the in-stack instance %s: no AWS/EC2 metrics are published for an instance, so a metric of it reaches the alarm only if something puts it (PutMetricData)", i, lid))
				}
			}
			if !nok || !vok {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("Dimensions[%d] needs a concrete Name and Value", i)})
				continue
			}
			dims = append(dims, map[string]any{"Name": n, "Value": v})
		}
		spec["dimensions"] = dims
	}
	for _, p := range []string{"OKActions", "InsufficientDataActions"} {
		if l, _ := props[p].([]any); len(l) > 0 {
			f = append(f, Finding{"Resource " + id, p + " cannot be honored — the alarm evaluator fires only the ALARM transition's SNS actions"})
		}
	}
	enabled, ef := boolProp(id, props, "ActionsEnabled", true)
	f = append(f, ef...)
	actions, af := stringList(id, "AlarmActions", props["AlarmActions"])
	f = append(f, af...)
	var rawActions []any
	if ctx != nil {
		if rp, ok := ctx.rawProps(id); ok {
			rawActions, _ = rp["AlarmActions"].([]any)
		}
	}
	for i, a := range actions {
		if !strings.HasPrefix(a, "arn:") || !strings.Contains(a, ":sns:") {
			f = append(f, Finding{"Resource " + id, "AlarmActions " + a + " is not an SNS topic — the alarm evaluator fires SNS actions only"})
		}
		if i < len(rawActions) {
			// The alarm publishes to a topic in the SNS API's store: the stack's topic is one when this deploy
			// path serves SNS (service.go); otherwise it is a kind: Queue stream SNS cannot see.
			if t, in := inStackOfType(rawActions[i], "AWS::SNS::Topic", ctx); in && !ctx.servedBy(t) {
				f = append(f, Finding{"Resource " + id, "AlarmActions names the in-stack topic " + t + ", which is not a topic of the SNS API (where the alarm publishes) on this deploy path — a kind: Queue stream"})
			}
		}
	}
	if !enabled {
		actions = nil
		spec["actionsEnabled"] = false
	}
	if len(actions) > 0 {
		spec["alarmActions"] = actions
	}
	if u := str("Unit"); u != "" {
		m.Caveats = append(m.Caveats, "Unit "+u+" does not filter the datapoints the alarm evaluates — datapoints of every unit for the metric count")
		spec["unit"] = u
	}
	if e := str("EvaluateLowSampleCountPercentile"); e != "" {
		m.Caveats = append(m.Caveats, "EvaluateLowSampleCountPercentile is not applied — a percentile is computed over however many samples there are")
		spec["evaluateLowSampleCountPercentile"] = e
	}
	if t := tagMap(props["Tags"]); len(t) > 0 {
		spec["tags"] = t
	}
	return m, f
}

// instanceIDRef resolves a raw value that is an in-stack AWS::EC2::Instance's id — {Ref: X} or
// {Fn::GetAtt: [X, InstanceId]} — to that id: the instance's VM name, its Ref (resource_attrs.go).
func instanceIDRef(raw any, ctx *stackCtx) (id, logicalID string, ok bool) {
	if ctx == nil {
		return "", "", false
	}
	m, _ := raw.(map[string]any)
	var target string
	if ref, isRef := m["Ref"].(string); isRef {
		target = ref
	} else if ga, isAtt := m["Fn::GetAtt"].([]any); isAtt && len(ga) == 2 && fmt.Sprint(ga[1]) == "InstanceId" {
		target = fmt.Sprint(ga[0])
	}
	if r, in := ctx.template.Resources[target]; !in || r.Type != "AWS::EC2::Instance" || !ctx.included(r) {
		return "", "", false
	}
	return ctx.name(target), target, true
}

// ---- AWS::Lambda::Permission ----

// lambdaServicePrincipals are the AWS services whose invocation of a function an open-infra integration
// authorizes itself, when it is created, against its creator's authority.
var lambdaServicePrincipals = map[string]bool{
	"events.amazonaws.com": true, "sns.amazonaws.com": true, "s3.amazonaws.com": true, "apigateway.amazonaws.com": true,
	"sqs.amazonaws.com": true, "logs.amazonaws.com": true, "cloudformation.amazonaws.com": true, "states.amazonaws.com": true,
	"scheduler.amazonaws.com": true, "elasticloadbalancing.amazonaws.com": true, "cognito-idp.amazonaws.com": true,
	"appsync.amazonaws.com": true, "dynamodb.amazonaws.com": true, "kinesis.amazonaws.com": true,
}

func translateLambdaPermission(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Action": true, "FunctionName": true, "Principal": true, "SourceArn": true,
		"SourceAccount": true, "EventSourceToken": true, "FunctionUrlAuthType": true, "PrincipalOrgID": true,
		"InvokedViaFunctionUrl": true}
	f := blockUnknownProps(id, props, known)
	act, _ := concrete(props["Action"])
	if act != "lambda:InvokeFunction" {
		f = append(f, Finding{"Resource " + id, "Action " + act + " cannot be honored — only lambda:InvokeFunction permissions have an open-infra meaning (the integration that invokes is authorized itself)"})
	}
	p, _ := concrete(props["Principal"])
	if !lambdaServicePrincipals[p] {
		f = append(f, Finding{"Resource " + id, "Principal " + p + " cannot be honored — a resource policy for an account or role principal has no open-infra form (grant lambda:InvokeFunction to that identity with a kind: Policy)"})
	}
	for _, k := range []string{"FunctionUrlAuthType", "InvokedViaFunctionUrl", "EventSourceToken", "PrincipalOrgID"} {
		if _, ok := props[k]; ok {
			f = append(f, Finding{"Resource " + id, k + " cannot be honored — function URLs and partner or organization principals are not modeled (a Function's own expose setting publishes it)"})
		}
	}
	var raw map[string]any
	if ctx != nil {
		raw, _ = ctx.rawProps(id)
	}
	if _, in := inStackFunctionOf(raw["FunctionName"], ctx); !in {
		f = append(f, Finding{"Resource " + id, "FunctionName must name an in-stack AWS::Lambda::Function — a permission on a function outside the stack is a change to that function, not this stack's"})
	}
	return nil, f
}

// capsOf is ctx's Capabilities (the zero value, fail-closed, without a context).
func capsOf(ctx *stackCtx) Capabilities {
	if ctx == nil {
		return Capabilities{}
	}
	return ctx.caps
}
