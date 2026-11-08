package policyengine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ParseAWSDocument checks that document is an AWS IAM policy document in AWS's shape — what
// IAM CreatePolicy / PutUserPolicy accept — and returns it as an object to store as written (kind:
// Policy spec.document, an inline policy's document). It checks the structure only: Version (when set)
// is 2012-10-17 or 2008-10-17; Statement is an object or a non-empty list of them; each statement's
// Effect is Allow or Deny, it sets Action or NotAction (not both) and Resource or NotResource (not both,
// unless it is a resource policy's statement naming a Principal), and its Condition is an object of
// objects. What a statement grants is the evaluator's business (iamauthz), not this check's.
func ParseAWSDocument(document string) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, fmt.Errorf("MalformedPolicyDocument: not a JSON policy document: %v", err)
	}
	if v, ok := doc["Version"]; ok {
		if s, _ := v.(string); s != "2012-10-17" && s != "2008-10-17" {
			return nil, fmt.Errorf("MalformedPolicyDocument: Version must be 2012-10-17 or 2008-10-17")
		}
	}
	var stmts []map[string]any
	switch s := doc["Statement"].(type) {
	case map[string]any:
		stmts = []map[string]any{s}
	case []any:
		for i, x := range s {
			m, ok := x.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("MalformedPolicyDocument: statement %d is not an object", i)
			}
			stmts = append(stmts, m)
		}
	default:
		return nil, fmt.Errorf("MalformedPolicyDocument: Statement must be an object or a list of objects")
	}
	if len(stmts) == 0 {
		return nil, fmt.Errorf("MalformedPolicyDocument: a policy needs at least one statement")
	}
	for i, st := range stmts {
		if e, _ := st["Effect"].(string); e != "Allow" && e != "Deny" {
			return nil, fmt.Errorf("MalformedPolicyDocument: statement %d: Effect must be Allow or Deny", i)
		}
		_, a := st["Action"]
		_, na := st["NotAction"]
		if a == na {
			return nil, fmt.Errorf("MalformedPolicyDocument: statement %d must set exactly one of Action and NotAction", i)
		}
		_, r := st["Resource"]
		_, nr := st["NotResource"]
		_, principal := st["Principal"]
		_, notPrincipal := st["NotPrincipal"]
		if r && nr {
			return nil, fmt.Errorf("MalformedPolicyDocument: statement %d sets both Resource and NotResource", i)
		}
		if !r && !nr && !principal && !notPrincipal {
			return nil, fmt.Errorf("MalformedPolicyDocument: statement %d needs a Resource or NotResource", i)
		}
		if c, ok := st["Condition"]; ok {
			cm, isMap := c.(map[string]any)
			if !isMap {
				return nil, fmt.Errorf("MalformedPolicyDocument: statement %d: Condition must be an object", i)
			}
			for op, body := range cm {
				if _, isMap := body.(map[string]any); !isMap {
					return nil, fmt.Errorf("MalformedPolicyDocument: statement %d: Condition operator %s must map keys to values", i, op)
				}
			}
		}
	}
	return doc, nil
}

// ResourceARN is the AWS ARN of an open-infra typed resource ("Type::id") — the reverse of the importer's
// ARN mapping, so a statement written natively exports to an AWS document that imports back to it. The
// region and account are "*" (open-infra resources are addressed by name; an account-scoped ARN is the
// evaluator's to compare). ok=false for a type with no ARN form.
func ResourceARN(res string) (string, bool) {
	if res == "*" {
		return "*", true
	}
	typ, id, ok := strings.Cut(res, "::")
	if !ok || id == "" {
		return "", false
	}
	arn := func(svc, tail string) (string, bool) { return "arn:aws:" + svc + ":*:*:" + tail, true }
	switch typ {
	case "Bucket":
		return "arn:aws:s3:::" + id, true
	case "Table":
		if db, tbl, glue := strings.Cut(id, "/"); glue {
			return arn("glue", "table/"+db+"/"+tbl) // a Glue catalog table (Table::<db>/<table>)
		}
		return arn("dynamodb", "table/"+id)
	case "Function":
		return arn("lambda", "function:"+id)
	case "Queue":
		return arn("sqs", id)
	case "Topic":
		return arn("sns", id)
	case "Stream":
		return arn("kinesis", "stream/"+id)
	case "Key":
		return arn("kms", "key/"+id)
	case "Document":
		return arn("ssm", "document/"+id)
	case "Parameter":
		return arn("ssm", "parameter/"+id)
	case "Secret":
		return arn("secretsmanager", "secret:"+id)
	case "Repository":
		return arn("ecr", "repository/"+id)
	case "Service":
		return arn("ecs", "service/*/"+id)
	case "LogGroup":
		return arn("logs", "log-group:"+id)
	case "DBInstance":
		return arn("rds", "db:"+id)
	case "DBSnapshot":
		return arn("rds", "snapshot:"+id)
	case "Identity":
		return arn("ses", "identity/"+id)
	case "Distribution":
		return "arn:aws:cloudfront::*:distribution/" + id, true
	case "CachePolicy":
		return "arn:aws:cloudfront::*:cache-policy/" + id, true
	case "OriginRequestPolicy":
		return "arn:aws:cloudfront::*:origin-request-policy/" + id, true
	case "ResponseHeadersPolicy":
		return "arn:aws:cloudfront::*:response-headers-policy/" + id, true
	case "OriginAccessControl":
		return "arn:aws:cloudfront::*:origin-access-control/" + id, true
	case "OriginAccessIdentity":
		return "arn:aws:cloudfront::*:origin-access-identity/" + id, true
	case "ElasticIp":
		return arn("ec2", "elastic-ip/"+id)
	case "Instance":
		return arn("ec2", "instance/"+id)
	case "Volume":
		return arn("ec2", "volume/"+id)
	case "KeyPair":
		return arn("ec2", "key-pair/"+id)
	case "SecurityGroup":
		return arn("ec2", "security-group/"+id)
	case "Api":
		return "arn:aws:apigateway:*::/restapis/" + id, true
	case "Role":
		return "arn:aws:iam::*:role/" + id, true
	case "User":
		return "arn:aws:iam::*:user/" + id, true
	case "Policy":
		return "arn:aws:iam::*:policy/" + id, true
	case "StateMachine":
		return arn("states", "stateMachine:"+id)
	case "Stack":
		return arn("cloudformation", "stack/"+id+"/*")
	case "GraphQLApi":
		return arn("appsync", "apis/"+id)
	case "Certificate":
		return arn("acm", "certificate/"+id)
	case "Quota":
		return arn("servicequotas", id)
	case "UserPool":
		return arn("cognito-idp", "userpool/"+id)
	case "Database":
		return arn("glue", "database/"+id)
	case "WorkGroup":
		return arn("athena", "workgroup/"+id)
	case "Cluster":
		return arn("eks", "cluster/"+id)
	case "EventBus":
		return arn("events", "event-bus/"+id)
	case "Rule":
		return arn("events", "rule/"+id)
	case "FirewallDomainList":
		return arn("route53resolver", "firewall-domain-list/"+id)
	case "FirewallRuleGroup":
		return arn("route53resolver", "firewall-rule-group/"+id)
	case "FirewallRuleGroupAssociation":
		return arn("route53resolver", "firewall-rule-group-association/"+id)
	case "FirewallConfig":
		return arn("route53resolver", "firewall-config/"+id)
	case "ResolverQueryLogConfig":
		return arn("route53resolver", "resolver-query-log-config/"+id)
	}
	return "", false
}

// awsConditionKey is the AWS spelling of a request attribute (the first alias that is not the bare attr).
func awsConditionKey(attr string) string {
	for _, k := range SupportedConditionKeys {
		if k.Attr != attr {
			continue
		}
		for _, a := range k.Aliases {
			if strings.Contains(a, ":") {
				return a
			}
		}
		return k.Aliases[0]
	}
	return attr
}

func conditionType(attr string) (condType, bool) {
	for _, k := range SupportedConditionKeys {
		if k.Attr == attr {
			return k.Type, true
		}
	}
	return 0, false
}

// awsDateOp is the AWS operator of a Cedar datetime comparison (the reverse of dateOp).
func awsDateOp(op string) string {
	switch op {
	case ">":
		return "DateGreaterThan"
	case ">=":
		return "DateGreaterThanEquals"
	case "<":
		return "DateLessThan"
	case "<=":
		return "DateLessThanEquals"
	}
	return ""
}

// awsKeyOp is the AWS operator of a KeyCondition (the reverse of optionalKeyCondition), "" when AWS has
// none (a boolean compared with !=).
func awsKeyOp(c KeyCondition) string {
	if c.Op == KeyNull {
		return "Null"
	}
	suffix := ""
	if c.IfExists {
		suffix = "IfExists"
	}
	if c.kind() == "bool" {
		if c.Op != "==" {
			return ""
		}
		return "Bool" + suffix
	}
	if c.kind() == "string" {
		op := map[string]string{"==": "StringEquals", "!=": "StringNotEquals", "like": "StringLike", "!like": "StringNotLike"}[c.Op]
		if op == "" {
			return ""
		}
		return op + suffix
	}
	for op, cmp := range numericOps {
		if cmp == c.Op {
			return op + suffix
		}
	}
	return ""
}

// ExportAWS writes data-plane statements as an AWS IAM policy document — the reverse of ImportAWS, so a
// policy authored in the earlier native form (kind: Policy spec.dataPlane) becomes a spec.document that
// imports back to the same statements. A statement it cannot write faithfully (a resource type with no
// ARN form, two conditions on one key and operator, which an AWS Condition cannot hold) is reported in
// skipped by index and left out; the caller keeps the native form for that policy rather than migrate it
// partly.
func ExportAWS(stmts []Statement) (document string, skipped []string, err error) {
	type st struct {
		Effect      string                    `json:"Effect"`
		Action      []string                  `json:"Action,omitempty"`
		NotAction   []string                  `json:"NotAction,omitempty"`
		Resource    []string                  `json:"Resource,omitempty"`
		NotResource []string                  `json:"NotResource,omitempty"`
		Condition   map[string]map[string]any `json:"Condition,omitempty"`
	}
	var out []st
	for i, s := range stmts {
		e := st{Effect: string(s.Effect), Action: s.Actions, NotAction: s.NotActions}
		if len(e.Action) == 0 && len(e.NotAction) == 0 {
			e.Action = []string{"*"}
		}
		bad := ""
		for _, r := range s.Resources {
			a, ok := ResourceARN(r)
			if !ok {
				bad = "resource " + r + " has no ARN form"
				break
			}
			e.Resource = append(e.Resource, a)
		}
		for _, r := range s.NotResources {
			a, ok := ResourceARN(r)
			if !ok {
				bad = "excluded resource " + r + " has no ARN form"
				break
			}
			e.NotResource = append(e.NotResource, a)
		}
		if len(e.Resource) == 0 && len(e.NotResource) == 0 {
			e.Resource = []string{"*"}
		}
		cond := map[string]map[string]any{}
		put := func(op, key string, v any) {
			if bad != "" {
				return
			}
			if cond[op] == nil {
				cond[op] = map[string]any{}
			}
			if _, dup := cond[op][key]; dup {
				bad = fmt.Sprintf("two %s conditions on %s cannot be one AWS Condition", op, key)
				return
			}
			cond[op][key] = v
		}
		attrs := make([]string, 0, len(s.Condition))
		for k := range s.Condition {
			attrs = append(attrs, k)
		}
		sort.Strings(attrs)
		for _, k := range attrs {
			v := s.Condition[k]
			t, known := conditionType(k)
			switch {
			case !known:
				bad = "condition on " + k + " has no AWS key"
			case t == condBool:
				put("Bool", awsConditionKey(k), v)
			case t == condTime:
				bad = "an equality condition on " + k + " has no faithful AWS operator"
			default:
				put("StringEquals", awsConditionKey(k), v)
			}
		}
		for _, c := range s.IPConditions {
			op := "IpAddress"
			if c.Negate {
				op = "NotIpAddress"
			}
			put(op, awsConditionKey(c.Key), c.CIDR)
		}
		for _, c := range s.LikeConditions {
			op := "StringLike"
			if c.Negate {
				op = "StringNotLike"
			}
			put(op, awsConditionKey(c.Key), c.Pattern)
		}
		for _, c := range s.TimeConditions {
			op := awsDateOp(c.Op)
			if op == "" {
				bad = "time condition operator " + c.Op + " has no AWS form"
				break
			}
			put(op, awsConditionKey(c.Key), c.Target)
		}
		for _, c := range s.KeyConditions {
			op := awsKeyOp(c)
			if op == "" {
				bad = "condition " + c.Op + " on " + c.Key + " has no AWS operator"
				break
			}
			put(op, awsConditionKey(c.Key), c.Value)
		}
		if bad != "" {
			skipped = append(skipped, fmt.Sprintf("statement %d: %s", i, bad))
			continue
		}
		if len(cond) > 0 {
			e.Condition = cond
		}
		out = append(out, e)
	}
	b, err := json.Marshal(struct {
		Version   string `json:"Version"`
		Statement []st   `json:"Statement"`
	}{"2012-10-17", out})
	return string(b), skipped, err
}
