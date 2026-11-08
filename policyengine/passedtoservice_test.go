package policyengine

import (
	"strings"
	"testing"
)

// decidePassRole evaluates iam:PassRole on Role::exec under doc, as the shim asks it: with the service the
// role is passed to in passedToService ("" leaves the key out, as every other request does).
func decidePassRole(t *testing.T, doc, service string) Decision {
	t.Helper()
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) > 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := map[string]any{"authenticated": true}
	if service != "" {
		ctx["passedToService"] = service
	}
	return eng.Authorize(Request{Principal: Principal{Type: "User", ID: "alice"}, Action: "iam:PassRole",
		Resource: Resource{Type: "Role", ID: "exec"}, Context: ctx})
}

// AWSLambda_FullAccess's PassRole statement: iam:PassRole where iam:PassedToService is lambda.amazonaws.com.
// It passes a role to Lambda and to no other service, and grants nothing where the key is absent.
func TestPassedToService_LambdaFullAccess(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*",
	  "Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}`
	for service, allow := range map[string]bool{"lambda.amazonaws.com": true, "ec2.amazonaws.com": false, "states.amazonaws.com": false, "": false} {
		if d := decidePassRole(t, doc, service); d.Allowed != allow {
			t.Errorf("passed to %q: allowed=%v, want %v (%s)", service, d.Allowed, allow, d.Reason)
		}
	}
}

// StringLike, and the negated operators' absent-key semantics: a Deny with StringNotEquals applies where the
// key is absent (AWS's negated operators match an absent key), and its IfExists-free StringEquals form does
// not.
func TestPassedToService_Operators(t *testing.T) {
	like := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*",
	  "Condition":{"StringLike":{"iam:PassedToService":"*.amazonaws.com"}}}]}`
	if d := decidePassRole(t, like, "ecs-tasks.amazonaws.com"); !d.Allowed {
		t.Errorf("StringLike *.amazonaws.com must match: %s", d.Reason)
	}
	if d := decidePassRole(t, like, ""); d.Allowed {
		t.Error("StringLike must not match an absent key")
	}
	denyNot := `{"Statement":[` + allowAll + `,{"Effect":"Deny","Action":"iam:PassRole","Resource":"*",
	  "Condition":{"StringNotEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}`
	if d := decidePassRole(t, denyNot, "lambda.amazonaws.com"); !d.Allowed {
		t.Errorf("a Deny unless lambda spares lambda: %s", d.Reason)
	}
	if d := decidePassRole(t, denyNot, "ec2.amazonaws.com"); d.Allowed || !d.ExplicitDeny {
		t.Errorf("a Deny unless lambda denies ec2: %+v", d)
	}
	if d := decidePassRole(t, denyNot, ""); d.Allowed || !d.ExplicitDeny {
		t.Errorf("StringNotEquals matches an absent key, so the Deny applies: %+v", d)
	}
}

// A value that is not a service name or pattern, an operator AWS does not apply to the key, and a value of
// the wrong type on a request are refused, never approximated.
func TestPassedToService_Refusals(t *testing.T) {
	for _, cond := range []string{
		`{"StringEquals":{"iam:PassedToService":"lambda\"amazonaws"}}`,
		`{"StringEqualsIgnoreCase":{"iam:PassedToService":"lambda.amazonaws.com"}}`,
		`{"StringEquals":{"iam:PassedToService":"*.amazonaws.com"}}`,
		`{"StringEquals":{"iam:PassedToService":["lambda.amazonaws.com","states.amazonaws.com"]}}`,
	} {
		_, unsupported, err := ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":` + cond + `}]}`)
		if err == nil && len(unsupported) == 0 {
			t.Errorf("%s must be refused", cond)
		}
	}
	stmts, _, _ := ImportAWS(`{"Statement":[` + allowAll + `,{"Effect":"Deny","Action":"iam:PassRole","Resource":"*",
	  "Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}]}`)
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatal(err)
	}
	d := eng.Authorize(Request{Principal: Principal{Type: "User", ID: "alice"}, Action: "iam:PassRole",
		Resource: Resource{Type: "Role", ID: "exec"}, Context: map[string]any{"passedToService": true}})
	if d.Allowed || !strings.Contains(d.Reason, "malformed") {
		t.Errorf("a passedToService that is not a string must be denied outright: %+v", d)
	}
}

// The exporter writes the condition back as AWS wrote it.
func TestPassedToService_ExportRoundTrips(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":["*"],"Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}`
	stmts, _, err := ImportAWS(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, skipped, err := ExportAWS(stmts)
	if err != nil || len(skipped) > 0 || !strings.Contains(out, `"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}`) {
		t.Fatalf("export: %s %v %v", out, skipped, err)
	}
}
