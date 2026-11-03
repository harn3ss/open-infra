package policyengine

import (
	"strings"
	"testing"
)

// #348: IAM, Step Functions, CloudFormation and AppSync policies import, as do the resources the #353 reads
// authorize (CloudFront configuration, ACM certificates) and the other services the shim checks (Cognito,
// Glue, Athena, EKS). Each ARN maps to the resource type and id the shim passes to its data-plane check.
func TestImportAWS_ControlServicesMapToTheShimsResources(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:role/app-runner":                                  "Role::app-runner",
		"arn:aws:iam::123456789012:role/*":                                           "Role::*",
		"arn:aws:iam::123456789012:user/alice":                                       "User::alice",
		"arn:aws:iam::123456789012:policy/AppAccess":                                 "Policy::AppAccess",
		"arn:aws:states:us-east-1:123456789012:stateMachine:payroll":                 "StateMachine::payroll",
		"arn:aws:states:us-east-1:123456789012:stateMachine:*":                       "StateMachine::*",
		"arn:aws:cloudformation:us-east-1:123456789012:stack/web/*":                  "Stack::web",
		"arn:aws:cloudformation:us-east-1:123456789012:stack/app-*/*":                "Stack::app-*",
		"arn:aws:cloudformation:us-east-1:123456789012:stack/*":                      "Stack::*",
		"arn:aws:appsync:us-east-1:123456789012:apis/abcdefghijklmnopqrstuvwxyz":     "GraphQLApi::abcdefghijklmnopqrstuvwxyz",
		"arn:aws:appsync:us-east-1:123456789012:apis/*":                              "GraphQLApi::*",
		"arn:aws:acm:us-east-1:123456789012:certificate/0123abcd-0000-0000-0000-000": "Certificate::0123abcd-0000-0000-0000-000",
		"arn:aws:cloudfront::123456789012:cache-policy/658327ea":                     "CachePolicy::658327ea",
		"arn:aws:cloudfront::123456789012:origin-request-policy/216adef6":            "OriginRequestPolicy::216adef6",
		"arn:aws:cloudfront::123456789012:response-headers-policy/67f7725c":          "ResponseHeadersPolicy::67f7725c",
		"arn:aws:cloudfront::123456789012:origin-access-control/E1ABC":               "OriginAccessControl::E1ABC",
		"arn:aws:cloudfront::123456789012:origin-access-identity/E2ABC":              "OriginAccessIdentity::E2ABC",
		"arn:aws:cloudfront::123456789012:distribution/E3ABC":                        "Distribution::E3ABC",
		"arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc":          "UserPool::us-east-1_abc",
		"arn:aws:glue:us-east-1:123456789012:database/sales":                         "Database::sales",
		"arn:aws:glue:us-east-1:123456789012:table/sales/orders":                     "Table::sales/orders",
		"arn:aws:glue:us-east-1:123456789012:table/sales/*":                          "Table::sales/*",
		"arn:aws:athena:us-east-1:123456789012:workgroup/primary":                    "WorkGroup::primary",
		"arn:aws:eks:us-east-1:123456789012:cluster/main":                            "Cluster::main",
	} {
		if got, ok := arnToResource(arn); !ok || got != want {
			t.Errorf("%s -> %q %v, want %q", arn, got, ok, want)
		}
	}

	stmts, unsupported, err := ImportAWS(`{"Statement":[
	  {"Effect":"Allow","Action":["iam:PassRole","iam:GetRole"],"Resource":"arn:aws:iam::123456789012:role/app-runner"},
	  {"Effect":"Allow","Action":"states:StartExecution","Resource":"arn:aws:states:us-east-1:123456789012:stateMachine:payroll"},
	  {"Effect":"Allow","Action":["cloudformation:DescribeStacks","cloudformation:SignalResource"],"Resource":"arn:aws:cloudformation:us-east-1:123456789012:stack/web/*"},
	  {"Effect":"Deny","Action":"appsync:DeleteGraphqlApi","Resource":"arn:aws:appsync:us-east-1:123456789012:apis/abc"},
	  {"Effect":"Allow","Action":["acm:DescribeCertificate","cloudfront:GetCachePolicy"],"Resource":"*"}]}`)
	if err != nil || len(unsupported) != 0 || len(stmts) != 5 {
		t.Fatalf("import: %v unsupported=%v stmts=%d", err, unsupported, len(stmts))
	}
}

// An ARN narrower than (or beside) what the shim authorizes is refused with its reason, never mapped to the
// broader resource — that would widen the grant.
func TestImportAWS_NarrowerControlServiceArnsAreRefusedNotWidened(t *testing.T) {
	for arn, reason := range map[string]string{
		"arn:aws:iam::123456789012:role/service-role/app":                              "IAM path",
		"arn:aws:iam::123456789012:role/team/*":                                        "IAM path",
		"arn:aws:states:us-east-1:123456789012:execution:payroll:*":                    "executions",
		"arn:aws:states:us-east-1:123456789012:execution:payroll:run-1":                "executions",
		"arn:aws:cloudformation:us-east-1:123456789012:stack/web/0123abcd-4567-89ef":   "one stack instance",
		"arn:aws:cloudformation:us-east-1:123456789012:changeSet/cs-1/0123abcd":        "change set",
		"arn:aws:appsync:us-east-1:123456789012:apis/abc/types/Query/fields/getSecret": "part of an API",
		"arn:aws:appsync:us-east-1:123456789012:apis/abc/*":                            "part of an API",
		"arn:aws:glue:us-east-1:123456789012:catalog":                                  "catalog",
	} {
		if got, ok := arnToResource(arn); ok {
			t.Errorf("%s mapped to %q; it names something narrower than the shim authorizes and must be refused", arn, got)
			continue
		}
		_, unsupported, err := ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"` + arn + `"}]}`)
		if err != nil {
			t.Fatal(err)
		}
		if j := strings.Join(unsupported, "\n"); !strings.Contains(j, reason) {
			t.Errorf("%s: reported %q, want a reason mentioning %q", arn, j, reason)
		}
	}
}

// A Deny scoped to a narrower ARN is refused as a whole statement under NotResource (dropping the carve-out
// would widen), and an Allow with only refused resources emits nothing.
func TestImportAWS_NarrowerArnNeverWidensAGrant(t *testing.T) {
	stmts, unsupported, err := ImportAWS(`{"Statement":[
	  {"Effect":"Allow","Action":"appsync:GraphQL","Resource":"arn:aws:appsync:us-east-1:123456789012:apis/abc/types/Query/fields/getSecret"},
	  {"Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:states:us-east-1:123456789012:execution:payroll:*"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 0 || len(unsupported) < 2 {
		t.Fatalf("stmts=%#v unsupported=%v: a field-scoped Allow and an execution-scoped NotResource must both be refused", stmts, unsupported)
	}
}
