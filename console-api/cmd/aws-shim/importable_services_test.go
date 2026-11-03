package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

// dataPlaneCall is one data-plane check found in the shim's source.
type dataPlaneCall struct {
	where     string
	svc       string // the action's service prefix ("" when the action is not a literal)
	resType   string // "" when the resource type is not a literal
	roleOnly  bool   // inside `if claims.AssumedRole != ""` (or allowedForAssumedRole itself)
	checkFunc string
}

// notImportable lists the services the shim checks that the policy importer deliberately does not accept,
// each with why. Anything the shim checks is either importable or here.
var notImportable = map[string]string{
	"ec2messages": "the SSM agent's channel; only its named actions import (policyengine.SupportedActions)",
	"ec2":         "the EC2 front door serves part of EC2; only its named actions import (policyengine.SupportedActions)",
}

// dynamicResourceTypes are the resource types of the checks whose type is a variable, per file (read from
// the code next to the call): each must be one the importer can produce.
var dynamicResourceTypes = map[string][]string{
	"iam.go":                {"Role", "User", "Policy"},
	"cloudfront_read.go":    {"CachePolicy", "OriginRequestPolicy", "ResponseHeadersPolicy", "OriginAccessControl", "OriginAccessIdentity"},
	"glue.go":               {"Database", "Table"},
	"athena.go":             {"WorkGroup", "Table"},
	"ec2.go":                {"Instance", "Volume", "SecurityGroup", "KeyPair", "ElasticIp"},
	"eventbridge.go":        {"EventBus", "Rule"},
	"rds.go":                {"DBInstance", "DBSnapshot"},
	"cfn_services.go":       {"Queue", "Topic", "Parameter", "Key", "ElasticIp", "Repository", "EventBus", "LogGroup", "Secret", "Namespace", "Function"},
	"cfn_services_doors.go": {"Secret", "LogGroup", "Rule", "EventBus", "Repository", "Namespace"},
}

// dynamicServices are the services of checks whose action is a variable, per file.
var dynamicServices = map[string][]string{
	"acm.go":            {"acm"},
	"athena.go":         {"glue"}, // the per-table checks: glue:GetTable / glue:UpdateTable
	"ecr_token.go":      {"ecr"},
	"dynamo.go":         {"dynamodb"},
	"kms.go":            {"kms"},
	"lambda_read.go":    {"lambda"},
	"rds.go":            {"rds"},
	"s3.go":             {"s3"},
	"ses.go":            {"ses"},
	"ssm_runcommand.go": {"ssm"},
	"vmcommands.go":     {"ssm", "ec2messages"},
	"cfn_services.go":   {"sqs", "sns", "ssm", "kms", "ec2", "ecr", "events", "logs", "secretsmanager", "cloudwatch", "lambda"},
	// a stack delete's pre-flight, through each front-door kind's deleteCheck
	"cfn_services_doors.go": {"secretsmanager", "logs", "events", "ecr", "cloudwatch"},
}

// delegated are services whose data-plane check lives in a shared package the shim calls, each with that
// package's source file, the call the shim makes into it, and the check the package runs for a User (a
// governed User's Deny holds), and the resource type it checks.
var delegated = map[string]struct{ file, shimCall, userCheck, resType string }{
	"s3": {"../../internal/s3authz/s3authz.go", "s3authz.Gate{", "g.Authz.Authorize(ctx, c.PrincipalType(), c.PrincipalID()", "Bucket"},
}

// passThrough are wrappers whose own data-plane call forwards their parameters; their callers are scanned
// instead (callerPolicyAllows: action and type at arguments 2 and 3).
var passThrough = map[string]bool{"callerPolicyAllows": true}

// exampleArn is one ARN per resource type the shim checks, which the importer must map to that type.
var exampleArn = map[string]string{
	"Bucket": "arn:aws:s3:::b", "Table": "arn:aws:dynamodb:us-east-1:1:table/t", "Function": "arn:aws:lambda:us-east-1:1:function:f",
	"Queue": "arn:aws:sqs:us-east-1:1:q", "Topic": "arn:aws:sns:us-east-1:1:t", "Stream": "arn:aws:kinesis:us-east-1:1:stream/s",
	"Key": "arn:aws:kms:us-east-1:1:key/k", "Parameter": "arn:aws:ssm:us-east-1:1:parameter/p", "Document": "arn:aws:ssm:us-east-1::document/d",
	"Instance": "arn:aws:ec2:us-east-1:1:instance/i-1", "Secret": "arn:aws:secretsmanager:us-east-1:1:secret:s-AbCdEf",
	"Repository": "arn:aws:ecr:us-east-1:1:repository/r", "Service": "arn:aws:ecs:us-east-1:1:service/c/s",
	"LogGroup": "arn:aws:logs:us-east-1:1:log-group:g", "DBInstance": "arn:aws:rds:us-east-1:1:db:d",
	"DBSnapshot": "arn:aws:rds:us-east-1:1:snapshot:s", "Identity": "arn:aws:ses:us-east-1:1:identity/example.com",
	"Distribution": "arn:aws:cloudfront::1:distribution/E1", "Api": "arn:aws:apigateway:us-east-1::/restapis/a1",
	"Role": "arn:aws:iam::1:role/r", "User": "arn:aws:iam::1:user/u", "Policy": "arn:aws:iam::1:policy/p",
	"StateMachine": "arn:aws:states:us-east-1:1:stateMachine:m", "Stack": "arn:aws:cloudformation:us-east-1:1:stack/s/*",
	"GraphQLApi": "arn:aws:appsync:us-east-1:1:apis/a", "Certificate": "arn:aws:acm:us-east-1:1:certificate/c",
	"CachePolicy": "arn:aws:cloudfront::1:cache-policy/c", "OriginRequestPolicy": "arn:aws:cloudfront::1:origin-request-policy/o",
	"ResponseHeadersPolicy": "arn:aws:cloudfront::1:response-headers-policy/r", "OriginAccessControl": "arn:aws:cloudfront::1:origin-access-control/o",
	"OriginAccessIdentity": "arn:aws:cloudfront::1:origin-access-identity/o", "UserPool": "arn:aws:cognito-idp:us-east-1:1:userpool/p",
	"Database": "arn:aws:glue:us-east-1:1:database/d", "WorkGroup": "arn:aws:athena:us-east-1:1:workgroup/w",
	"Cluster": "arn:aws:eks:us-east-1:1:cluster/c", "Volume": "arn:aws:ec2:us-east-1:1:volume/v",
	"SecurityGroup": "arn:aws:ec2:us-east-1:1:security-group/sg", "KeyPair": "arn:aws:ec2:us-east-1:1:key-pair/k",
	"ElasticIp": "arn:aws:ec2:us-east-1:1:elastic-ip/e", "EventBus": "arn:aws:events:us-east-1:1:event-bus/b",
	"Rule": "arn:aws:events:us-east-1:1:rule/b/r",
}

// notImportableTypes are resource types the shim checks that no AWS ARN names, each with why.
var notImportableTypes = map[string]string{
	"Namespace": "CloudWatch metrics and alarms are authorized per namespace, which AWS policies scope with a condition (cloudwatch:namespace), not an ARN; Resource \"*\" imports",
}

// scanDataPlaneCalls parses the shim's non-test sources and returns every data-plane check.
func scanDataPlaneCalls(t *testing.T) []dataPlaneCall {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]bool{"deniedByDataPlane": true, "dataPlaneDenied": true, "dataPlaneVerdict": true, "allowedForAssumedRole": true}
	fset := token.NewFileSet()
	var out []dataPlaneCall
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "policycheck.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		var stack []ast.Node
		enclosingFunc := func() string {
			for i := len(stack) - 1; i >= 0; i-- {
				if fd, ok := stack[i].(*ast.FuncDecl); ok {
					return fd.Name.Name
				}
			}
			return ""
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			actionArg := 3
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name, actionArg = fn.Sel.Name, 2
			}
			switch {
			case checks[name] && actionArg == 3 && len(call.Args) >= 6:
			case passThrough[name] && actionArg == 2 && len(call.Args) >= 5:
			default:
				return true
			}
			if passThrough[enclosingFunc()] {
				return true
			}
			c := dataPlaneCall{where: fset.Position(call.Pos()).String(), checkFunc: name, roleOnly: name == "allowedForAssumedRole"}
			c.svc = actionService(call.Args[actionArg])
			if lit, ok := call.Args[actionArg+1].(*ast.BasicLit); ok {
				c.resType, _ = strconv.Unquote(lit.Value)
			}
			for i := len(stack) - 2; i >= 0; i-- {
				ifs, ok := stack[i].(*ast.IfStmt)
				if !ok || !within(ifs.Body, call) {
					continue
				}
				if cond := string(src[fset.Position(ifs.Cond.Pos()).Offset:fset.Position(ifs.Cond.End()).Offset]); strings.Contains(cond, `AssumedRole != ""`) {
					c.roleOnly = true
				}
			}
			out = append(out, c)
			return true
		})
	}
	return out
}

func within(body *ast.BlockStmt, n ast.Node) bool {
	return body != nil && n.Pos() >= body.Pos() && n.End() <= body.End()
}

// actionService reads the service prefix of a literal action ("svc:Op") or a literal-prefixed one ("svc:"+op).
func actionService(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.BasicLit:
		s, _ := strconv.Unquote(x.Value)
		svc, _, _ := strings.Cut(s, ":")
		return svc
	case *ast.BinaryExpr:
		return actionService(x.X)
	}
	return ""
}

// Every service the policy importer accepts is enforced for Users as well as assumed roles — an imported
// Deny that a User's requests never meet would be a silent hole — and every service the shim checks is
// importable or listed with why. Every resource type the shim checks has an AWS ARN the importer maps to it.
func TestImportableServicesMatchTheShimsChecks(t *testing.T) {
	calls := scanDataPlaneCalls(t)
	if len(calls) < 40 {
		t.Fatalf("found only %d data-plane checks; the scan is broken", len(calls))
	}
	userChecked := map[string]bool{}
	checked := map[string]bool{}
	types := map[string]bool{}
	for _, c := range calls {
		file := filepath.Base(strings.SplitN(c.where, ":", 2)[0])
		svcs := []string{c.svc}
		if c.svc == "" {
			svcs = dynamicServices[file]
			if len(svcs) == 0 {
				t.Errorf("%s: %s's action is not a literal and %s has no dynamicServices entry", c.where, c.checkFunc, file)
			}
		}
		for _, s := range svcs {
			checked[s] = true
			if !c.roleOnly {
				userChecked[s] = true
			}
		}
		if c.resType != "" {
			types[c.resType] = true
		} else if dt, ok := dynamicResourceTypes[file]; ok {
			for _, ty := range dt {
				types[ty] = true
			}
		} else {
			t.Errorf("%s: %s's resource type is not a literal and %s has no dynamicResourceTypes entry", c.where, c.checkFunc, file)
		}
	}
	shimSrc := ""
	if files, err := filepath.Glob("*.go"); err == nil {
		for _, f := range files {
			if !strings.HasSuffix(f, "_test.go") {
				b, _ := os.ReadFile(f)
				shimSrc += string(b)
			}
		}
	}
	for svc, d := range delegated {
		src, err := os.ReadFile(d.file)
		if err != nil {
			t.Fatalf("%s's check: %v", svc, err)
		}
		if !strings.Contains(shimSrc, d.shimCall) || !strings.Contains(string(src), d.userCheck) {
			t.Errorf("service %q is meant to be checked in %s (the shim calling %s, the package checking a User with %s), and it is not", svc, d.file, d.shimCall, d.userCheck)
			continue
		}
		checked[svc], userChecked[svc], types[d.resType] = true, true, true
	}
	for svc := range policyengine.SupportedServices {
		if !userChecked[svc] {
			t.Errorf("service %q imports, but the shim never checks it for a User (every check is role-only, or there is none)", svc)
		}
	}
	var list []string
	for svc := range checked {
		list = append(list, svc)
	}
	sort.Strings(list)
	for _, svc := range list {
		if !policyengine.SupportedServices[svc] && len(policyengine.SupportedActions[svc]) == 0 && notImportable[svc] == "" {
			t.Errorf("the shim checks %q, but the policy importer refuses it: add it to policyengine.SupportedServices (with its ARN forms) or to notImportable with why", svc)
		}
	}
	for ty := range types {
		if notImportableTypes[ty] != "" {
			continue
		}
		arn, ok := exampleArn[ty]
		if !ok {
			t.Errorf("the shim checks resource type %q, but no AWS ARN maps to it: map one in policyengine.arnToResource and add it to exampleArn", ty)
			continue
		}
		stmts, unsupported, err := policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"` + arn + `"}]}`)
		if err != nil || len(unsupported) != 0 || len(stmts) != 1 || len(stmts[0].Resources) != 1 || !strings.HasPrefix(stmts[0].Resources[0], ty+"::") {
			t.Errorf("%s should import to %s::…: %v %v %#v", arn, ty, err, unsupported, stmts)
		}
	}
}
