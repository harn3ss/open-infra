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

// §5: IpAddress aws:SourceIp imports to an IP condition and ENFORCES the CIDR exactly (in-range 200,
// out-of-range denied) — the highest-value AWS condition, honored via Cedar's ipaddr extension.
func TestImportAWS_IPCondition(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(unsupported) != 0 {
		t.Fatalf("IpAddress must import, got unsupported: %v", unsupported)
	}
	if len(stmts) != 1 || len(stmts[0].IPConditions) != 1 {
		t.Fatalf("want one statement with one IP condition, got %#v", stmts)
	}
	if ip := stmts[0].IPConditions[0]; ip.Key != "sourceIp" || ip.CIDR != "10.0.0.0/8" || ip.Negate {
		t.Fatalf("unexpected IP condition: %#v", ip)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "a"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "reports"}, map[string]any{"sourceIp": "10.1.2.3"}}); !d.Allowed {
		t.Error("10.1.2.3 is in range → allowed")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "reports"}, map[string]any{"sourceIp": "8.8.8.8"}}); d.Allowed {
		t.Error("8.8.8.8 is out of range → denied")
	}
}

// §5: Bool on the native "authenticated" attr imports to an equality condition.
func TestImportAWS_BoolCondition(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"authenticated":"true"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	if len(stmts) != 1 || stmts[0].Condition["authenticated"] != "true" {
		t.Fatalf("want authenticated==true equality, got %#v", stmts)
	}
}

// §5 doc acceptance #4: a condition on a key the shim does NOT populate is REFUSED — the whole
// statement blocks, never silently accepted (which would fail open for a Deny). This is the
// key-population invariant enforced at import: aws:PrincipalTag/team is not in SupportedConditionKeys.
func TestImportAWS_RefusesUnpopulatedConditionKey(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"x"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 {
		t.Fatalf("an unpopulated-key condition must NOT import a statement, got %#v", stmts)
	}
	if joined := strings.Join(unsupported, "\n"); !strings.Contains(joined, "Condition") || !strings.Contains(joined, "aws:PrincipalTag/team") {
		t.Fatalf("refusal must name the Condition + the unpopulated key: %v", unsupported)
	}
}

// §5 doc acceptance #3: a statement mixing a mappable IpAddress with an UNMAPPABLE operator
// (DateGreaterThan) blocks the WHOLE statement — nothing is applied partially (dropping the date
// condition would broaden the grant beyond what was authored).
func TestImportAWS_RefusesWholeStatementOnUnmappableOperator(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 {
		t.Fatalf("an unmappable operator must block the whole statement, got %#v", stmts)
	}
	if !strings.Contains(strings.Join(unsupported, "\n"), "Condition") {
		t.Fatalf("must report the Condition as unimportable: %v", unsupported)
	}
}

// §5: a multi-valued condition list is refused (only single-valued is faithfully importable).
func TestImportAWS_RefusesMultiValuedCondition(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","192.168.0.0/16"]}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 || !strings.Contains(strings.Join(unsupported, "\n"), "multi-valued") {
		t.Fatalf("multi-valued must be refused, got stmts=%#v unsupported=%v", stmts, unsupported)
	}
}

// §5: a malformed CIDR is refused at import (so the engine never compiles an ip() that would error).
func TestImportAWS_RefusesMalformedCIDR(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"IpAddress":{"aws:SourceIp":"not-a-cidr"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 || !strings.Contains(strings.Join(unsupported, "\n"), "valid IP") {
		t.Fatalf("malformed CIDR must be refused, got stmts=%#v unsupported=%v", stmts, unsupported)
	}
}

// A bucket ARN and its object ARN both scope to the same Bucket resource — the result must dedupe.
func TestImportAWS_DeduplicatesResources(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::reports","arn:aws:s3:::reports/*"]}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	if len(stmts) != 1 || len(stmts[0].Resources) != 1 || stmts[0].Resources[0] != "Bucket::reports" {
		t.Fatalf("want a single deduped Bucket::reports, got %#v", stmts[0].Resources)
	}
}
