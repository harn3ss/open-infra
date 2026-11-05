package policyengine

import (
	"reflect"
	"strings"
	"testing"
)

// A native statement exports to an AWS document that imports back to the same statement — every resource
// type the importer maps, the complement axes, and each condition form — so migrating a policy from the
// earlier dataPlane form to spec.document changes nothing it grants.
func TestExportAWS_RoundTripsThroughImport(t *testing.T) {
	types := []string{"Bucket::assets", "Bucket::assets/uploads/*", "Table::orders", "Table::sales/daily", "Function::worker",
		"Queue::jobs", "Topic::events", "Stream::clicks", "Key::1234abcd", "Document::AWS-RunShellScript", "Parameter::app/db-host",
		"Secret::db-credentials", "Repository::app", "Service::web", "LogGroup::/aws/lambda/worker", "DBInstance::db1",
		"DBSnapshot::snap1", "Identity::example.com", "Distribution::E2ABC", "CachePolicy::cp1", "OriginRequestPolicy::orp1",
		"ResponseHeadersPolicy::rhp1", "OriginAccessControl::oac1", "OriginAccessIdentity::oai1", "ElasticIp::eipalloc-1",
		"Instance::i-0123", "Volume::vol-1", "KeyPair::deploy", "SecurityGroup::sg-1", "Api::a1b2c3", "Role::app", "User::alice",
		"Policy::reader", "StateMachine::orders", "Stack::app", "GraphQLApi::api1", "Certificate::c1", "UserPool::pool1", "Quota::lambda/L-B99A9384",
		"Database::sales", "WorkGroup::primary", "Cluster::prod", "EventBus::orders", "Rule::orders/new-order", "*"}
	for _, res := range types {
		in := []Statement{{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{res}}}
		assertRoundTrip(t, res, in)
	}
	cases := map[string][]Statement{
		"deny with a complement": {{Effect: Deny, NotActions: []string{"s3:GetObject"}, NotResources: []string{"Bucket::public"}}},
		"bool condition":         {{Effect: Allow, Actions: []string{"s3:PutObject"}, Resources: []string{"*"}, Condition: map[string]string{"authenticated": "true"}}},
		"string condition":       {{Effect: Allow, Actions: []string{"dynamodb:Query"}, Resources: []string{"Table::t"}, Condition: map[string]string{"username": "alice"}}},
		"ip condition":           {{Effect: Deny, Actions: []string{"*"}, Resources: []string{"*"}, IPConditions: []IPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8", Negate: true}}}},
		"like condition":         {{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}, LikeConditions: []LikeCondition{{Key: "username", Pattern: "admin-*"}}}},
		"time condition":         {{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}, TimeConditions: []TimeCondition{{Key: "currentTime", Op: "<", Target: "2027-01-01T00:00:00Z"}}}},
	}
	for name, in := range cases {
		assertRoundTrip(t, name, in)
	}
}

func assertRoundTrip(t *testing.T, name string, in []Statement) {
	t.Helper()
	doc, skipped, err := ExportAWS(in)
	if err != nil || len(skipped) > 0 {
		t.Fatalf("%s: export %v skipped %v", name, err, skipped)
	}
	if _, err := ParseAWSDocument(doc); err != nil {
		t.Fatalf("%s: the exported document is not an AWS document: %v\n%s", name, err, doc)
	}
	out, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) > 0 {
		t.Fatalf("%s: import %v unsupported %v\n%s", name, err, unsupported, doc)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("%s: round trip changed the statement:\n in  %+v\n out %+v\n doc %s", name, in, out, doc)
	}
}

// A statement with no faithful AWS form is reported and left out, never written approximately.
func TestExportAWS_ReportsWhatHasNoAWSForm(t *testing.T) {
	_, skipped, err := ExportAWS([]Statement{
		{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Mystery::x"}},
		{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"},
			IPConditions: []IPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8"}, {Key: "sourceIp", CIDR: "192.168.0.0/16"}}},
		{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}},
	})
	if err != nil || len(skipped) != 2 || !strings.Contains(skipped[0], "statement 0") || !strings.Contains(skipped[1], "statement 1") {
		t.Fatalf("skipped %v err %v", skipped, err)
	}
}

// ParseAWSDocument accepts AWS's shapes (a Statement object or list, an identity or a resource policy)
// and refuses what IAM refuses.
func TestParseAWSDocument(t *testing.T) {
	ok := []string{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`,
		`{"Statement":[{"Effect":"Deny","NotAction":["iam:*"],"NotResource":"arn:aws:s3:::x"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Sid":"p","Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`,
	}
	for _, d := range ok {
		if _, err := ParseAWSDocument(d); err != nil {
			t.Errorf("refused a valid document %s: %v", d, err)
		}
	}
	bad := map[string]string{
		"not json":                `{`,
		"bad version":             `{"Version":"2020-01-01","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		"no statement":            `{"Version":"2012-10-17"}`,
		"empty statement list":    `{"Statement":[]}`,
		"bad effect":              `{"Statement":{"Effect":"Maybe","Action":"*","Resource":"*"}}`,
		"action and notaction":    `{"Statement":{"Effect":"Allow","Action":"*","NotAction":"iam:*","Resource":"*"}}`,
		"no action":               `{"Statement":{"Effect":"Allow","Resource":"*"}}`,
		"no resource":             `{"Statement":{"Effect":"Allow","Action":"*"}}`,
		"condition not an object": `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":"x"}}`,
	}
	for name, d := range bad {
		if _, err := ParseAWSDocument(d); err == nil || !strings.HasPrefix(err.Error(), "MalformedPolicyDocument") {
			t.Errorf("%s: accepted (or wrong error) %s: %v", name, d, err)
		}
	}
}
