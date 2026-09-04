package policyengine

import (
	"strings"
	"testing"
)

func TestImportAWS_DataPlane(t *testing.T) {
	doc := `{
	  "Version": "2012-10-17",
	  "Statement": [
	    { "Effect": "Allow", "Action": ["s3:GetObject","s3:PutObject"], "Resource": "arn:aws:s3:::reports/*" },
	    { "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*" },
	    { "Effect": "Allow", "Action": "dynamodb:Query", "Resource": "arn:aws:dynamodb:us-east-1:123:table/metrics" }
	  ]
	}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", unsupported)
	}
	if len(stmts) != 3 {
		t.Fatalf("want 3 statements, got %d: %#v", len(stmts), stmts)
	}
	// The imported policy must ENFORCE as intended: allow get, deny delete, allow the metrics query.
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile imported: %v", err)
	}
	p := Principal{Type: "User", ID: "a"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "reports"}, nil}); !d.Allowed {
		t.Errorf("get reports should be allowed")
	}
	if d := eng.Authorize(Request{p, "s3:DeleteObject", Resource{"Bucket", "reports"}, nil}); d.Allowed {
		t.Errorf("delete must be denied (forbid)")
	}
	if d := eng.Authorize(Request{p, "dynamodb:Query", Resource{"Table", "metrics"}, nil}); !d.Allowed {
		t.Errorf("query metrics should be allowed")
	}
	if d := eng.Authorize(Request{p, "dynamodb:Query", Resource{"Table", "other"}, nil}); d.Allowed {
		t.Errorf("query a different table must be denied")
	}
}

func TestImportAWS_ReportsUnsupported(t *testing.T) {
	doc := `{"Statement":[
	  {"Effect":"Allow","Action":["ec2:RunInstances","s3:GetObject"],"Resource":"*"},
	  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}
	]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	joined := strings.Join(unsupported, "\n")
	if !strings.Contains(joined, "ec2:RunInstances") {
		t.Errorf("ec2 action must be reported unsupported: %v", unsupported)
	}
	if !strings.Contains(joined, "Condition") {
		t.Errorf("a Condition must be reported (not silently imported): %v", unsupported)
	}
	// The ec2+s3 statement still imports its s3 action (ec2 dropped + reported).
	if len(stmts) != 1 || len(stmts[0].Actions) != 1 || stmts[0].Actions[0] != "s3:GetObject" {
		t.Fatalf("expected one statement with the s3 action kept: %#v", stmts)
	}
}
