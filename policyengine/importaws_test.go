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

// #265: the import now covers every service the shim enforces at the data plane, mapping each ARN to
// the exact Type the shim checks (sqs->Queue, sns->Topic, ...). None of these should report unsupported.
func TestImportAWS_ExtendedServices(t *testing.T) {
	doc := `{"Statement":[
	  {"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123:orders"},
	  {"Effect":"Allow","Action":"sns:Publish","Resource":"arn:aws:sns:us-east-1:123:events"},
	  {"Effect":"Allow","Action":"kinesis:PutRecord","Resource":"arn:aws:kinesis:us-east-1:123:stream/clicks"},
	  {"Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:123:key/abcd-1234"},
	  {"Effect":"Allow","Action":"ssm:GetParameter","Resource":"arn:aws:ssm:us-east-1:123:parameter/app/db"},
	  {"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:123:secret:db-creds-AbCdEf"},
	  {"Effect":"Allow","Action":"ecr:BatchGetImage","Resource":"arn:aws:ecr:us-east-1:123:repository/web"},
	  {"Effect":"Allow","Action":"ecs:UpdateService","Resource":"arn:aws:ecs:us-east-1:123:service/prod/api"},
	  {"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"arn:aws:logs:us-east-1:123:log-group:/app/web:*"},
	  {"Effect":"Allow","Action":"rds:DescribeDBInstances","Resource":"arn:aws:rds:us-east-1:123:db:pg1"},
	  {"Effect":"Allow","Action":"ses:SendEmail","Resource":"arn:aws:ses:us-east-1:123:identity/noreply@x.test"}
	]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(unsupported) != 0 {
		t.Fatalf("every service here is shim-enforced; nothing should be unsupported: %v", unsupported)
	}
	got := map[string]bool{}
	for _, s := range stmts {
		for _, r := range s.Resources {
			got[r] = true
		}
	}
	for _, want := range []string{
		"Queue::orders", "Topic::events", "Stream::clicks", "Key::abcd-1234",
		"Parameter::app/db", "Secret::db-creds", "Repository::web", "Service::api",
		"LogGroup::/app/web", "DBInstance::pg1", "Identity::noreply@x.test",
	} {
		if !got[want] {
			t.Errorf("missing mapped resource %q; got %v", want, got)
		}
	}
	// Spot-check enforcement: the imported sqs grant allows the named queue, denies another.
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "a"}
	if d := eng.Authorize(Request{p, "sqs:SendMessage", Resource{"Queue", "orders"}, nil}); !d.Allowed {
		t.Errorf("send to orders should be allowed")
	}
	if d := eng.Authorize(Request{p, "sqs:SendMessage", Resource{"Queue", "other"}, nil}); d.Allowed {
		t.Errorf("send to a different queue must be denied")
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
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},"NumericLessThan":{"aws:username":"3600"}}}]}`
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

// §266: StringEquals on aws:username imports to an equality condition and enforces it.
func TestImportAWS_UsernameStringEquals(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:username":"alice"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	if len(stmts) != 1 || stmts[0].Condition["username"] != "alice" {
		t.Fatalf("want username==alice, got %#v", stmts)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "x"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"username": "alice"}}); !d.Allowed {
		t.Error("alice should be allowed")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"username": "bob"}}); d.Allowed {
		t.Error("bob should be denied")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, nil}); d.Allowed {
		t.Error("absent username should be denied (allow condition unsatisfied)")
	}
}

// §266: StringLike on aws:username imports to a wildcard condition and enforces the pattern.
func TestImportAWS_UsernameStringLike(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringLike":{"aws:username":"admin-*"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	if len(stmts) != 1 || len(stmts[0].LikeConditions) != 1 || stmts[0].LikeConditions[0].Pattern != "admin-*" {
		t.Fatalf("want one like condition admin-*, got %#v", stmts)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "x"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"username": "admin-ops"}}); !d.Allowed {
		t.Error("admin-ops should match admin-* → allowed")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"username": "dev-x"}}); d.Allowed {
		t.Error("dev-x should not match admin-* → denied")
	}
}

// §266 security: a Deny gated on StringNotLike aws:username fails CLOSED when username is absent.
func TestImportAWS_UsernameDenyFailsClosedOnAbsent(t *testing.T) {
	// Allow everything, but Deny unless the username is like "admin-*" (StringNotLike = deny when NOT matching).
	doc := `{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringNotLike":{"aws:username":"admin-*"}}}
	]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "x"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"username": "admin-ops"}}); !d.Allowed {
		t.Error("admin-ops matches → NotLike false → deny does not fire → allowed")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"username": "intruder"}}); d.Allowed {
		t.Error("intruder → NotLike true → deny fires → denied")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, nil}); d.Allowed {
		t.Error("FAIL-OPEN: absent username must DENY (the forbid absent-key guard)")
	}
}

// §266: AWS '?' in StringLike is refused (Cedar's `like` can't express a single-char wildcard).
func TestImportAWS_StringLikeQuestionMarkRefused(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringLike":{"aws:username":"a?b"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 {
		t.Fatalf("a '?' StringLike must refuse the statement, got %#v", stmts)
	}
	if !strings.Contains(strings.Join(unsupported, "\n"), "?") {
		t.Fatalf("expected a '?' refusal reason, got %v", unsupported)
	}
}

// §266 time: Date{Greater,Less}Than on aws:CurrentTime imports to a datetime window and enforces it.
func TestImportAWS_CurrentTimeWindow(t *testing.T) {
	// Allow s3:GetObject only within [2025-01-01, 2026-01-01).
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2025-01-01T00:00:00Z"},"DateLessThan":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	if len(stmts) != 1 || len(stmts[0].TimeConditions) != 2 {
		t.Fatalf("want 1 stmt with 2 time conditions, got %#v", stmts)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "x"}
	in := map[string]any{"currentTime": "2025-06-15T12:00:00Z"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, in}); !d.Allowed {
		t.Error("in-window request should be allowed")
	}
	before := map[string]any{"currentTime": "2024-12-31T23:59:59Z"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, before}); d.Allowed {
		t.Error("before-window request should be denied")
	}
	after := map[string]any{"currentTime": "2026-02-01T00:00:00Z"}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, after}); d.Allowed {
		t.Error("after-window request should be denied")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, nil}); d.Allowed {
		t.Error("absent currentTime should be denied (allow condition unsatisfied)")
	}
}

// §266 security: a Deny gated on a Date* aws:CurrentTime condition fails CLOSED when currentTime is
// absent or malformed — the forbid absent-key guard must deny, never fail open.
func TestImportAWS_CurrentTimeDenyFailsClosed(t *testing.T) {
	// Allow everything, but Deny s3:GetObject after a cutoff (DateGreaterThan).
	doc := `{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2025-01-01T00:00:00Z"}}}
	]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) != 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "x"}
	// Before the cutoff: allowed (deny's DateGreaterThan not satisfied).
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"currentTime": "2024-06-01T00:00:00Z"}}); !d.Allowed {
		t.Error("before-cutoff request should be allowed")
	}
	// After the cutoff: denied.
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"currentTime": "2025-06-01T00:00:00Z"}}); d.Allowed {
		t.Error("after-cutoff request should be denied")
	}
	// Absent currentTime: the Deny's forbid absent-key guard must fire → DENY (fail closed).
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, nil}); d.Allowed {
		t.Error("FAIL-OPEN: absent currentTime must DENY (the forbid absent-key guard)")
	}
	// Malformed currentTime: sanitised to absent → same forbid guard denies (fail closed).
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "b"}, map[string]any{"currentTime": "not-a-date"}}); d.Allowed {
		t.Error("FAIL-OPEN: malformed currentTime must DENY (sanitised to absent)")
	}
}

// §266 time: a Date* value Cedar's datetime() can't parse is refused (fail closed, never approximated).
func TestImportAWS_CurrentTimeUnparseableRefused(t *testing.T) {
	// "+00:00" offset form: RFC3339 but NOT the form cedar-go's datetime() accepts.
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2025-01-01T00:00:00+00:00"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 {
		t.Fatalf("an unparseable datetime must refuse the statement, got %#v", stmts)
	}
	if !strings.Contains(strings.Join(unsupported, "\n"), "datetime") {
		t.Fatalf("expected a datetime refusal reason, got %v", unsupported)
	}
}

// §266 time: Date* on a non-time key (and StringEquals on aws:CurrentTime) is refused — operator/type
// mismatches must fail closed, never silently coerce.
func TestImportAWS_DateOperatorTypeMismatchRefused(t *testing.T) {
	// Date* on aws:username (a string key) is refused.
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"DateGreaterThan":{"aws:username":"2025-01-01T00:00:00Z"}}}]}`
	stmts, _, err := ImportAWS(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts) != 0 {
		t.Fatalf("Date* on a string key must refuse the statement, got %#v", stmts)
	}
	// StringEquals on aws:CurrentTime (a time key) is refused — use the Date* operators.
	doc2 := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:CurrentTime":"2025-01-01T00:00:00Z"}}}]}`
	stmts2, _, err := ImportAWS(doc2)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(stmts2) != 0 {
		t.Fatalf("StringEquals on a time key must refuse the statement, got %#v", stmts2)
	}
}
