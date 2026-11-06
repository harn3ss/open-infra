package policyengine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// SupportedServices are the AWS data-plane services the aws-shim enforces, so an AWS policy's
// statements for these can be honored faithfully. Anything else is reported, never silently granted.
// Every service here is one the aws-shim actually ENFORCES at the data plane (a deniedByDataPlane
// check with this "<svc>:" action prefix), so importing its actions is faithful — never a grant the
// shim won't honor. Keep this in lockstep with the shim's deniedByDataPlane call sites.
// The aws-shim test TestImportableServicesMatchTheShimsChecks keeps this in lockstep with the shim: every
// service here must be checked for Users as well as assumed roles (an imported Deny a User's requests never
// meet would be a silent hole), and every service the shim checks is either here or listed there with why.
var SupportedServices = map[string]bool{
	"s3": true, "dynamodb": true, "lambda": true,
	"sqs": true, "sns": true, "kinesis": true, "kms": true, "ssm": true,
	"secretsmanager": true, "ecr": true, "ecs": true, "logs": true, "rds": true,
	"ses": true, "apigateway": true, "cloudwatch": true, "cloudfront": true,
	"iam": true, "states": true, "cloudformation": true, "appsync": true, "acm": true,
	"cognito-idp": true, "glue": true, "athena": true, "eks": true, "events": true,
	"servicequotas": true,
}

// SupportedActions are the actions of a service the aws-shim enforces only in part: just these import
// (named exactly — a wildcard such as ec2:* would also cover actions it does not enforce, so it is
// refused like any unsupported action). ec2: a CloudFormation stack's Elastic IP allocations and the EC2
// front door's operations. ec2messages: the SSM agent's command channel (an instance role's
// AmazonSSMManagedInstanceCore), which the aws-shim checks when a VM's metadata agent fetches and reports
// Run Command invocations.
var SupportedActions = map[string]map[string]bool{
	"ec2": {"AllocateAddress": true, "ReleaseAddress": true, "DescribeAddresses": true, "AssociateAddress": true, "DisassociateAddress": true,
		"DescribeInstances": true, "DescribeVolumes": true, "DescribeSecurityGroups": true, "DescribeVpcs": true, "DescribeSubnets": true,
		"DescribeImages": true, "DescribeRegions": true, "DescribeAvailabilityZones": true, "DescribeKeyPairs": true,
		"ImportKeyPair": true, "CreateKeyPair": true, "DeleteKeyPair": true, "DeleteVolume": true,
		"DescribeInternetGateways": true, "DescribeRouteTables": true, "DescribeNetworkAcls": true, "DescribeVpcEndpoints": true},
	"ec2messages": {"GetMessages": true, "SendReply": true, "AcknowledgeMessage": true, "DeleteMessage": true, "FailMessage": true, "GetEndpoint": true},
}

// condType classifies a populated request-context attribute by value type, which fixes the AWS
// condition operators that map onto it faithfully.
type condType int

const (
	condBool   condType = iota // a boolean attr — the Bool operator
	condIP                     // a string attr holding an IP — IpAddress / NotIpAddress (or an exact StringEquals)
	condString                 // a plain string attr — StringEquals (exact) / StringLike / StringNotLike (wildcard)
	condTime                   // a datetime attr (RFC3339 string) — DateLessThan / DateGreaterThan [Equals]
	condNumber                 // an integer attr — the Numeric* operators
)

// ConditionKey is one request-context attribute the aws-shim's requestContext() populates and that the
// AWS importer may therefore map a condition onto. Aliases are the key spellings accepted in an
// imported AWS Condition (e.g. "aws:SourceIp" resolves to the "sourceIp" attr).
//
// THE KEY-POPULATION INVARIANT (security-critical). This registry is the SINGLE source of truth for
// which condition keys are importable, and its Attr set MUST equal the attributes requestContext()
// actually sets. A condition is honored ONLY if its key resolves here, because honoring a condition on
// a key the shim never populates is a fail-open hole: in Cedar a `forbid ... when <absent attr>` is
// SKIPPED, so the Deny silently never fires. Adding an entry here without also populating that attr in
// the shim reopens that hole — the drift test in the aws-shim package
// (TestSupportedConditionKeysMatchRequestContext) fails if the two ever diverge. (Belt-and-braces, the
// engine additionally DENIES a forbid whose read attribute is absent or malformed — see engine.go.)
//
// An Optional key is one AWS leaves out of some requests on purpose, so its absence means something:
// aws:MultiFactorAuthPresent is absent for a request signed with long-term access keys, and
// aws:MultiFactorAuthAge for any request not authenticated with MFA. Its conditions are KeyConditions, which
// say what an absent key does exactly as AWS's operators do (see KeyCondition), instead of the absent-key
// guard the other conditions carry. The shim still populates it wherever the credential carries it: the
// drift test exercises requestContext() with an MFA-authenticated session to see it set.
type ConditionKey struct {
	Attr     string
	Type     condType
	Aliases  []string
	Optional bool
}

// SupportedConditionKeys is the condition-import whitelist. Everything not expressible through it stays
// refused (the wholesale fail-closed behavior the importer began with).
var SupportedConditionKeys = []ConditionKey{
	{Attr: "authenticated", Type: condBool, Aliases: []string{"authenticated"}},
	{Attr: "sourceIp", Type: condIP, Aliases: []string{"aws:SourceIp", "sourceIp"}},
	// The calling principal's name (a kind: User's name, or an assumed kind: Role's name) — the shim
	// populates it from the data-plane principal id. Honors "only this principal" conditions
	// (StringEquals) and prefix/pattern conditions (StringLike/StringNotLike).
	{Attr: "username", Type: condString, Aliases: []string{"aws:username", "username"}},
	// The request time — the shim populates it from the clock. Honors time-window conditions
	// (DateGreaterThan/DateLessThan[Equals]), e.g. temporary access that expires.
	{Attr: "currentTime", Type: condTime, Aliases: []string{"aws:CurrentTime", "currentTime"}},
	// Multi-factor authentication. The shim populates both from the credential (s3authz.RequestContext):
	// multiFactorAuthPresent on every temporary credential (a console session, an STS session) — true when it
	// was authenticated with an MFA code — and absent for long-term access keys; multiFactorAuthAge, the
	// seconds since that MFA authentication, only when there was one. Honors Bool / BoolIfExists, the
	// Numeric* operators and their IfExists forms, and Null, with AWS's absent-key semantics.
	{Attr: "multiFactorAuthPresent", Type: condBool, Optional: true, Aliases: []string{"aws:MultiFactorAuthPresent", "multiFactorAuthPresent"}},
	{Attr: "multiFactorAuthAge", Type: condNumber, Optional: true, Aliases: []string{"aws:MultiFactorAuthAge", "multiFactorAuthAge"}},
}

// SupportedConditionAttrs is the set of request-context attributes the importer may reference — the
// exact set requestContext() must populate. The aws-shim drift test compares this to requestContext().
func SupportedConditionAttrs() map[string]bool {
	m := make(map[string]bool, len(SupportedConditionKeys))
	for _, k := range SupportedConditionKeys {
		m[k.Attr] = true
	}
	return m
}

// resolveConditionKey finds a condition key by any of its spellings. AWS condition key names are not
// case-sensitive (aws:SourceIp is aws:sourceip), so neither is the lookup.
func resolveConditionKey(key string) (ConditionKey, bool) {
	for _, k := range SupportedConditionKeys {
		for _, a := range k.Aliases {
			if strings.EqualFold(a, key) {
				return k, true
			}
		}
	}
	return ConditionKey{}, false
}

// ImportAWS converts an AWS IAM policy document (JSON) into open-infra data-plane Statements. It
// returns the statements for the supported services and a list of parts it could NOT honor — actions
// for services with no open-infra data plane, ARNs it can't map, or conditions (not importable yet).
// Those are reported so the caller can refuse rather than silently grant or drop them. Effect and
// wildcards ("s3:*", "*") carry over faithfully.
//
// NotAction/NotResource are supported and carry over as the COMPLEMENT axes (Statement.NotActions/
// NotResources), which the engine renders as a negated match ("any except these"). They are handled
// fail-closed: a statement cannot set both Action and NotAction (or both Resource and NotResource) — a
// malformed AWS document that does errors; and a NotResource whose excluded ARN does not map to a
// shim-fronted resource is REFUSED (reported, not emitted) rather than dropping the carve-out, which
// would silently WIDEN the grant to all resources. NotAction exclusions are kept verbatim — an excluded
// action for a service the shim does not front is a harmless no-op carve-out (it only ever narrows).
func ImportAWS(policyDocument string) ([]Statement, []string, error) {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyDocument), &doc); err != nil {
		return nil, nil, fmt.Errorf("not a JSON policy document: %w", err)
	}
	var raw []map[string]any
	if err := json.Unmarshal(doc.Statement, &raw); err != nil {
		var one map[string]any
		if json.Unmarshal(doc.Statement, &one) != nil {
			return nil, nil, fmt.Errorf("policy Statement must be an object or an array")
		}
		raw = []map[string]any{one}
	}

	var out []Statement
	var unsupported []string
	for i, st := range raw {
		effect := Effect(awsStr(st["Effect"]))
		if effect != Allow && effect != Deny {
			return nil, nil, fmt.Errorf("statement %d: Effect must be Allow or Deny", i)
		}
		var eq map[string]string
		var ips []IPCondition
		var likes []LikeCondition
		var times []TimeCondition
		var keyConds []KeyCondition
		if rawCond, ok := st["Condition"]; ok {
			cm, isMap := rawCond.(map[string]any)
			if !isMap {
				unsupported = append(unsupported, fmt.Sprintf("statement %d: Condition must be an object", i))
				continue
			}
			var reason string
			var mapped bool
			eq, ips, likes, times, keyConds, reason, mapped = importCondition(cm)
			if !mapped {
				// Refuse the WHOLE statement — never emit it with the condition dropped. Dropping an
				// Allow's condition would WIDEN the grant; dropping a Deny's condition would widen the
				// deny. Either way the imported policy would be MORE permissive than authored, the very
				// fail-open the wholesale refusal guarded. Block it; author it natively on dataPlane.
				unsupported = append(unsupported, fmt.Sprintf("statement %d: Condition is not importable (%s) — author it natively on kind: Policy dataPlane", i, reason))
				continue
			}
		}
		_, hasAction := st["Action"]
		_, hasNotAction := st["NotAction"]
		_, hasResource := st["Resource"]
		_, hasNotResource := st["NotResource"]
		if hasAction && hasNotAction {
			return nil, nil, fmt.Errorf("statement %d: a statement cannot set both Action and NotAction", i)
		}
		if hasResource && hasNotResource {
			return nil, nil, fmt.Errorf("statement %d: a statement cannot set both Resource and NotResource", i)
		}

		// --- action axis ---
		var actions, notActions []string
		if hasNotAction {
			// NotAction grants every action EXCEPT these. The exclusion set is kept verbatim: an entry for
			// a service the shim does not front is a harmless no-op carve-out (it only narrows, never
			// grants). An empty NotAction excludes nothing, i.e. any action (AWS treats it as Action:"*").
			notActions = awsList(st["NotAction"])
			if len(notActions) == 0 {
				actions, notActions = []string{"*"}, nil
			}
		} else {
			var aUn []string
			actions, aUn = importActions(awsList(st["Action"]))
			unsupported = append(unsupported, aUn...)
			if len(actions) == 0 {
				continue // nothing data-plane here (every Action was for an unfronted service)
			}
		}

		// --- resource axis ---
		var resources, notResources []string
		if hasNotResource {
			// NotResource scopes to every resource EXCEPT these. Every excluded ARN MUST map to a typed
			// resource: an unmappable exclusion would silently WIDEN the grant (the carve-out would be
			// lost, leaving "all resources"), so the whole statement is refused rather than emitted.
			var nrUn []string
			notResources, nrUn = importResources(awsList(st["NotResource"]))
			if len(nrUn) > 0 {
				unsupported = append(unsupported, fmt.Sprintf("statement %d: NotResource has an ARN that does not map to a shim-fronted resource (%s) — refused rather than silently widening the grant by dropping the exclusion; author it natively on kind: Policy spec.dataPlane", i, strings.Join(nrUn, "; ")))
				continue
			}
			if len(notResources) == 0 {
				resources, notResources = []string{"*"}, nil // excludes nothing → any resource
			}
		} else {
			var rUn []string
			resources, rUn = importResources(awsList(st["Resource"]))
			unsupported = append(unsupported, rUn...)
			if len(resources) == 0 {
				// A data-plane action with no mappable Resource would compile to a rule that matches
				// nothing (silently inert) — report it instead of emitting it.
				unsupported = append(unsupported, fmt.Sprintf("statement %d: %s has no mappable Resource (an identity policy must scope to an ARN or \"*\")", i, actionAxisDisplay(actions, notActions)))
				continue
			}
		}

		s := Statement{Effect: effect, Actions: actions, NotActions: notActions, Resources: resources, NotResources: notResources, IPConditions: ips, LikeConditions: likes, TimeConditions: times, KeyConditions: keyConds}
		if len(eq) > 0 {
			s.Condition = eq
		}
		out = append(out, s)
	}
	return out, unsupported, nil
}

// importCondition maps a statement's AWS Condition block onto the whitelist. It returns the equality
// conditions (attr -> value; "true"/"false" for a Bool), the IP CIDR conditions, the StringLike pattern
// conditions, the Date* datetime conditions and the conditions on Optional keys, plus ok=false with a
// reason if ANY operator / key / shape is not faithfully mappable — in which case the caller refuses the
// whole statement. Only Bool (on a boolean attr), single-valued StringEquals (on a non-boolean populated
// attr), StringLike/StringNotLike (on a string attr), Date{Greater,Less}Than[Equals] (on a datetime attr),
// IpAddress / NotIpAddress (CIDR, on an IP attr), and on an Optional key Bool / Numeric* (and their
// IfExists forms) and Null are honored; every other operator, an unpopulated key, and any multi-valued list
// stay refused (fail closed).
func importCondition(cond map[string]any) (eq map[string]string, ips []IPCondition, likes []LikeCondition, times []TimeCondition, keys []KeyCondition, reason string, ok bool) {
	eq = map[string]string{}
	fail := func(format string, a ...any) (map[string]string, []IPCondition, []LikeCondition, []TimeCondition, []KeyCondition, string, bool) {
		return nil, nil, nil, nil, nil, fmt.Sprintf(format, a...), false
	}
	for op, kv := range cond {
		m, isMap := kv.(map[string]any)
		if !isMap {
			return fail("operator %q has a non-object body", op)
		}
		for key, rawVal := range m {
			ck, known := resolveConditionKey(key)
			if !known {
				return fail("key %q is not a request attribute the shim populates", key)
			}
			val, single := singleValue(rawVal)
			if !single {
				return fail("%q on %q is multi-valued (only single-valued is importable)", op, key)
			}
			if ck.Optional {
				kc, why := optionalKeyCondition(op, key, ck, val)
				if why != "" {
					return fail("%s", why)
				}
				keys = append(keys, kc)
				continue
			}
			switch op {
			case "Bool":
				if ck.Type != condBool || (val != "true" && val != "false") {
					return fail("Bool on %q is not a boolean request attribute", key)
				}
				eq[ck.Attr] = val
			case "StringEquals":
				if ck.Type == condBool || ck.Type == condTime {
					return fail("StringEquals on %q is not faithful (use the type's operator)", key)
				}
				eq[ck.Attr] = val
			case "StringLike", "StringNotLike":
				if ck.Type != condString {
					return fail("%q on non-string key %q", op, key)
				}
				// Cedar's `like` wildcard is `*` only; AWS StringLike also allows `?` (single char), which
				// Cedar can't express — refuse rather than approximate (an over-broad `*` would widen the
				// match). A literal `*`/`?` would need escaping, also not faithfully expressible — refuse.
				if strings.Contains(val, "?") {
					return fail("%q value %q uses '?' which Cedar's pattern match can't express", op, val)
				}
				likes = append(likes, LikeCondition{Key: ck.Attr, Pattern: val, Negate: op == "StringNotLike"})
			case "DateGreaterThan", "DateGreaterThanEquals", "DateLessThan", "DateLessThanEquals":
				if ck.Type != condTime {
					return fail("%q on non-time key %q", op, key)
				}
				// Validate with the SAME parser Cedar's datetime() uses, so a value accepted here cannot
				// then error at eval (an errored datetime test would skip a forbid → fail open). Note AWS
				// values must be Cedar-parseable (e.g. "...Z" or "+0000", not "+00:00").
				if _, err := types.ParseDatetime(val); err != nil {
					return fail("%q value %q is not a Cedar-parseable datetime (want e.g. 2025-01-01T00:00:00Z)", op, val)
				}
				times = append(times, TimeCondition{Key: ck.Attr, Op: dateOp(op), Target: val})
			case "IpAddress", "NotIpAddress":
				if ck.Type != condIP {
					return fail("%q on non-IP key %q", op, key)
				}
				// Validate with the SAME parser Cedar's ip() uses, so a value accepted here cannot then
				// error inside the compiled policy (an errored IP test would skip a forbid → fail open).
				if _, err := types.ParseIPAddr(val); err != nil {
					return fail("%q value %q is not a valid IP or CIDR", op, val)
				}
				ips = append(ips, IPCondition{Key: ck.Attr, CIDR: val, Negate: op == "NotIpAddress"})
			default:
				return fail("operator %q is not importable", op)
			}
		}
	}
	return eq, ips, likes, times, keys, "", true
}

// numericOps maps an AWS Numeric* operator to its comparison.
var numericOps = map[string]string{
	"NumericEquals": "==", "NumericNotEquals": "!=",
	"NumericLessThan": "<", "NumericLessThanEquals": "<=",
	"NumericGreaterThan": ">", "NumericGreaterThanEquals": ">=",
}

// optionalKeyCondition maps one AWS operator on an Optional key (aws:MultiFactorAuthPresent,
// aws:MultiFactorAuthAge) to its KeyCondition, or says why it cannot: Bool / BoolIfExists on a boolean key,
// Numeric* / Numeric*IfExists with an integer on a number key, and Null on either. Anything else — a string
// operator, a decimal, a value that is not a boolean — is refused, never approximated.
func optionalKeyCondition(op, key string, ck ConditionKey, val string) (KeyCondition, string) {
	if op == "Null" {
		v := strings.ToLower(strings.TrimSpace(val))
		if v != "true" && v != "false" {
			return KeyCondition{}, fmt.Sprintf("Null on %q needs true or false, not %q", key, val)
		}
		return KeyCondition{Key: ck.Attr, Op: KeyNull, Value: v}, ""
	}
	base, ifExists := strings.CutSuffix(op, "IfExists")
	switch ck.Type {
	case condBool:
		if base != "Bool" {
			return KeyCondition{}, fmt.Sprintf("%q on the boolean key %q is not importable (use Bool or BoolIfExists)", op, key)
		}
		v := strings.ToLower(strings.TrimSpace(val))
		if v != "true" && v != "false" {
			return KeyCondition{}, fmt.Sprintf("%q on %q needs true or false, not %q", op, key, val)
		}
		return KeyCondition{Key: ck.Attr, Op: "==", Value: v, IfExists: ifExists}, ""
	case condNumber:
		cmp, isNumeric := numericOps[base]
		if !isNumeric {
			return KeyCondition{}, fmt.Sprintf("%q on the numeric key %q is not importable (use a Numeric operator)", op, key)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			return KeyCondition{}, fmt.Sprintf("%q value %q on %q is not an integer", op, val, key)
		}
		return KeyCondition{Key: ck.Attr, Op: cmp, Value: strconv.FormatInt(n, 10), IfExists: ifExists}, ""
	}
	return KeyCondition{}, fmt.Sprintf("%q on %q is not importable", op, key)
}

// dateOp maps an AWS Date* condition operator to the Cedar datetime comparison operator.
func dateOp(awsOp string) string {
	switch awsOp {
	case "DateGreaterThan":
		return ">"
	case "DateGreaterThanEquals":
		return ">="
	case "DateLessThan":
		return "<"
	case "DateLessThanEquals":
		return "<="
	}
	return ""
}

// singleValue reads a single-valued AWS condition value (a string, a bool, or a one-element array).
// A multi-element array is NOT single-valued (ok=false) — multi-valued conditions stay refused.
func singleValue(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case []any:
		if len(x) == 1 {
			return singleValue(x[0])
		}
	}
	return "", false
}

// importActions keeps the actions for supported services (and a bare "*"), reporting the rest.
func importActions(actions []string) (kept, unsupported []string) {
	for _, a := range actions {
		if a == "*" {
			kept = append(kept, "*")
			continue
		}
		svc, op, ok := strings.Cut(a, ":")
		if ok && (SupportedServices[svc] || SupportedActions[svc][op]) {
			kept = append(kept, a)
		} else {
			unsupported = append(unsupported, "action "+a+" has no open-infra data plane")
		}
	}
	return kept, unsupported
}

// importResources maps AWS ARNs to open-infra typed resources, reporting ARNs it can't map.
// Distinct ARNs can collapse to the same typed resource (a KMS key's ARN and its alias, an SNS topic and
// one of its subscriptions), so the result is de-duplicated.
func importResources(arns []string) (kept, unsupported []string) {
	seen := map[string]bool{}
	add := func(res string) {
		if !seen[res] {
			seen[res] = true
			kept = append(kept, res)
		}
	}
	for _, r := range arns {
		if r == "*" {
			add("*")
			continue
		}
		if res, ok := arnToResource(r); ok {
			add(res)
		} else if why := narrowerThanAuthorized(r); why != "" {
			unsupported = append(unsupported, "resource "+r+" "+why)
		} else {
			unsupported = append(unsupported, "resource "+r+" is not a recognizable ARN for a shim-fronted service")
		}
	}
	return kept, unsupported
}

// arnToResource maps an AWS ARN to the open-infra "Type::id" the aws-shim data-plane check uses for
// that service (wildcards preserved via like-patterns). The Type for each service MATCHES the one the
// shim passes to deniedByDataPlane (e.g. sqs -> Queue, sns -> Topic), so an imported resource grant
// lands on the same resource the shim enforces. An ARN form it can't map is reported, not guessed.
func arnToResource(arn string) (string, bool) {
	parts := strings.SplitN(arn, ":", 6) // arn:aws:<svc>:<region>:<acct>:<resource>
	if len(parts) < 6 || parts[0] != "arn" {
		return "", false
	}
	svc, tail := parts[2], parts[5]
	cut := func(prefix, typ string) (string, bool) {
		if n, ok := strings.CutPrefix(tail, prefix); ok && n != "" {
			return typ + "::" + n, true
		}
		return "", false
	}
	switch svc {
	case "s3":
		// arn:aws:s3:::bucket -> Bucket::bucket; an object ARN keeps its key: arn:aws:s3:::bucket/* ->
		// Bucket::bucket/* (every object, not the bucket), arn:aws:s3:::bucket/uploads/* ->
		// Bucket::bucket/uploads/*, arn:aws:s3:::bucket/report.csv -> Bucket::bucket/report.csv. The shim
		// authorizes an object operation on its object (Bucket::<bucket>/<key>) and a bucket operation
		// (ListBucket …) on the bucket, as AWS does, so each ARN grants exactly what it grants on AWS.
		if bucket, _, _ := strings.Cut(tail, "/"); bucket != "" {
			return "Bucket::" + tail, true
		}
	case "dynamodb":
		return cut("table/", "Table")
	case "lambda":
		return cut("function:", "Function")
	case "sqs": // arn:aws:sqs:r:a:QueueName
		if tail != "" {
			return "Queue::" + tail, true
		}
	case "sns": // arn:aws:sns:r:a:TopicName[:subid] -> scope to the topic
		if topic, _, _ := strings.Cut(tail, ":"); topic != "" {
			return "Topic::" + topic, true
		}
	case "kinesis":
		return cut("stream/", "Stream")
	case "kms": // key/<id> or alias/<name>
		if r, ok := cut("key/", "Key"); ok {
			return r, true
		}
		return cut("alias/", "Key")
	case "ssm": // parameter/<name>; document/<name> (arn:aws:ssm:<r>::document/AWS-RunShellScript)
		if r, ok := cut("document/", "Document"); ok {
			return r, true
		}
		return cut("parameter/", "Parameter")
	case "secretsmanager": // secret:<name>-<6 random> -> strip the AWS suffix
		if n, ok := strings.CutPrefix(tail, "secret:"); ok && n != "" {
			return "Secret::" + secretSuffixRe.ReplaceAllString(n, ""), true
		}
	case "ecr":
		return cut("repository/", "Repository")
	case "ecs": // service/<cluster>/<name> -> Service::<name>
		if n, ok := strings.CutPrefix(tail, "service/"); ok && n != "" {
			if i := strings.LastIndex(n, "/"); i >= 0 {
				n = n[i+1:]
			}
			if n != "" {
				return "Service::" + n, true
			}
		}
	case "logs": // log-group:<name>[:log-stream:...|:*]
		if n, ok := strings.CutPrefix(tail, "log-group:"); ok {
			n, _, _ = strings.Cut(n, ":")
			if n != "" {
				return "LogGroup::" + n, true
			}
		}
	case "rds": // db:<id> -> DBInstance, snapshot:<id> -> DBSnapshot (the shim authorizes both)
		if r, ok := cut("db:", "DBInstance"); ok {
			return r, true
		}
		return cut("snapshot:", "DBSnapshot")
	case "ses":
		return cut("identity/", "Identity")
	case "cloudfront": // arn:aws:cloudfront::<acct>:distribution/<id>, and the configuration reads' <type>/<id>
		for _, m := range []struct{ prefix, typ string }{
			{"distribution/", "Distribution"}, {"cache-policy/", "CachePolicy"},
			{"origin-request-policy/", "OriginRequestPolicy"}, {"response-headers-policy/", "ResponseHeadersPolicy"},
			{"origin-access-control/", "OriginAccessControl"}, {"origin-access-identity/", "OriginAccessIdentity"},
		} {
			if r, ok := cut(m.prefix, m.typ); ok {
				return r, true
			}
		}
	case "ec2": // arn:aws:ec2:<r>:<acct>:<type>/<id>: Elastic IP allocations, and the EC2 front door's resources
		for _, m := range []struct{ prefix, typ string }{
			{"elastic-ip/", "ElasticIp"}, {"instance/", "Instance"}, {"volume/", "Volume"},
			{"key-pair/", "KeyPair"}, {"security-group/", "SecurityGroup"},
		} {
			if r, ok := cut(m.prefix, m.typ); ok {
				return r, true
			}
		}
	case "apigateway": // arn:aws:apigateway:r::/restapis/<id>[/...]
		if n, ok := strings.CutPrefix(tail, "/restapis/"); ok && n != "" {
			n, _, _ = strings.Cut(n, "/")
			if n != "" {
				return "Api::" + n, true
			}
		}
	case "iam": // arn:aws:iam::<acct>:role/<name>, user/<name>, policy/<name> (no path: open-infra principals have none)
		for _, m := range []struct{ prefix, typ string }{{"role/", "Role"}, {"user/", "User"}, {"policy/", "Policy"}} {
			if n, ok := strings.CutPrefix(tail, m.prefix); ok && n != "" && !strings.Contains(n, "/") {
				return m.typ + "::" + n, true
			}
		}
	case "states": // arn:aws:states:<r>:<acct>:stateMachine:<name> (an execution is authorized on its state machine)
		if n, ok := strings.CutPrefix(tail, "stateMachine:"); ok && n != "" && !strings.Contains(n, ":") {
			return "StateMachine::" + n, true
		}
	case "cloudformation": // arn:aws:cloudformation:<r>:<acct>:stack/<name>/* (the shim authorizes per stack name)
		if n, ok := strings.CutPrefix(tail, "stack/"); ok {
			name, id, hasID := strings.Cut(n, "/")
			if name != "" && (!hasID || id == "*") {
				return "Stack::" + name, true
			}
		}
	case "appsync": // arn:aws:appsync:<r>:<acct>:apis/<id> (the API itself; apis/* is every API)
		if n, ok := strings.CutPrefix(tail, "apis/"); ok && n != "" && !strings.Contains(n, "/") {
			return "GraphQLApi::" + n, true
		}
	case "acm": // arn:aws:acm:<r>:<acct>:certificate/<id>
		return cut("certificate/", "Certificate")
	case "servicequotas": // arn:aws:servicequotas:<r>:<acct>:<service-code>/<quota-code> (a quota code or *)
		if svc, code, has := strings.Cut(tail, "/"); has && svc != "" && code != "" && !strings.Contains(code, "/") {
			return "Quota::" + svc + "/" + code, true
		}
	case "cognito-idp": // arn:aws:cognito-idp:<r>:<acct>:userpool/<id>
		return cut("userpool/", "UserPool")
	case "glue": // database/<db>, table/<db>/<table> (the shim's Table::<db>/<table>); the catalog has no resource here
		if r, ok := cut("database/", "Database"); ok && !strings.Contains(r, "/") {
			return r, true
		}
		if n, ok := strings.CutPrefix(tail, "table/"); ok {
			if db, tbl, has := strings.Cut(n, "/"); has && db != "" && tbl != "" && !strings.Contains(tbl, "/") {
				return "Table::" + db + "/" + tbl, true
			}
		}
	case "athena": // arn:aws:athena:<r>:<acct>:workgroup/<name>
		return cut("workgroup/", "WorkGroup")
	case "eks": // arn:aws:eks:<r>:<acct>:cluster/<name>
		if r, ok := cut("cluster/", "Cluster"); ok && !strings.Contains(r, "/") {
			return r, true
		}
	case "events": // event-bus/<name>; rule/<name> (the default bus) or rule/<bus>/<name> — the shim's Rule::[<bus>/]<name>
		if r, ok := cut("event-bus/", "EventBus"); ok && !strings.Contains(r, "/") {
			return r, true
		}
		if n, ok := strings.CutPrefix(tail, "rule/"); ok && n != "" && strings.Count(n, "/") <= 1 && !strings.HasSuffix(n, "/") && !strings.HasPrefix(n, "/") {
			return "Rule::" + n, true
		}
	}
	return "", false
}

// narrowerThanAuthorized explains why an ARN of a fronted service has no faithful form: it names something
// narrower than (or beside) the resource the shim authorizes, so mapping it to that resource would widen the
// grant. "" when there is no specific reason (the caller then reports a generic unrecognizable ARN).
func narrowerThanAuthorized(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	svc, tail := parts[2], parts[5]
	switch svc {
	case "iam":
		for _, p := range []string{"role/", "user/", "policy/"} {
			if n, ok := strings.CutPrefix(tail, p); ok && strings.Contains(n, "/") {
				return "has an IAM path — open-infra roles, users and policies have none, so a path-scoped grant has no faithful form (a wildcard path would widen to every name)"
			}
		}
	case "states":
		if strings.HasPrefix(tail, "execution:") || strings.HasPrefix(tail, "express:") {
			return "names executions — the shim authorizes an execution on its state machine, so honoring it would widen the grant to the state machine; scope it to the stateMachine ARN"
		}
		if strings.HasPrefix(tail, "activity:") {
			return "names an activity — Step Functions activities are not served"
		}
	case "cloudformation":
		if n, ok := strings.CutPrefix(tail, "stack/"); ok && strings.Contains(n, "/") {
			return "names one stack instance by id — the shim authorizes per stack name, so honoring it would also cover a later stack of that name; use stack/<name>/*"
		}
		if strings.HasPrefix(tail, "changeSet/") || strings.HasPrefix(tail, "stackset/") {
			return "names a change set or stack set — the shim authorizes change sets on their stack; scope it to the stack ARN"
		}
	case "appsync":
		if n, ok := strings.CutPrefix(tail, "apis/"); ok && strings.Contains(n, "/") {
			return "names part of an API (types, fields, data sources) — the shim authorizes per API, so honoring it would widen the grant to the whole API"
		}
	case "glue":
		if strings.HasPrefix(tail, "catalog") {
			return "names the Glue catalog — the shim authorizes databases and tables, not the catalog"
		}
	}
	return ""
}

// secretSuffixRe matches the "-" + 6 random chars AWS appends to a Secrets Manager secret ARN.
var secretSuffixRe = regexp.MustCompile(`-[A-Za-z0-9]{6}$`)

// actionAxisDisplay renders a statement's action axis for a diagnostic — the Action set, or the
// NotAction set when the statement uses the complement form.
func actionAxisDisplay(actions, notActions []string) string {
	if len(notActions) > 0 {
		return fmt.Sprintf("NotAction %v", notActions)
	}
	return fmt.Sprintf("%v", actions)
}

func awsStr(v any) string { s, _ := v.(string); return s }

// awsList reads an AWS policy field that is either a string or a list of strings.
func awsList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
