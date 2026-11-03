package cfn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const paramsTemplate = `
Parameters:
  Env:
    Type: String
    AllowedValues: [dev, prod]
    Default: dev
  Name:
    Type: String
    AllowedPattern: "[a-z][a-z0-9-]*"
    MinLength: 3
    MaxLength: 8
  Count:
    Type: Number
    MinValue: 1
    MaxValue: 5
    Default: 2
  Ports:
    Type: List<Number>
    Default: "80,443"
  Tier:
    Type: String
    AllowedValues: [web, db]
    ConstraintDescription: must be web or db
    Default: web
  Secret:
    Type: String
    NoEcho: true
    Default: x
Resources:
  Q:
    Type: AWS::SQS::Queue
`

func checkMsg(t *testing.T, tmpl string, given map[string]string, prev []string, ap Applier) string {
	t.Helper()
	err := CheckParameters(context.Background(), []byte(tmpl), given, prev, ap)
	if err == nil {
		return ""
	}
	var pe *ParameterError
	if !errors.As(err, &pe) {
		t.Fatalf("CheckParameters returned a %T (%v), want a *ParameterError", err, err)
	}
	return pe.Message
}

// #347 item 25 / #350 U: a parameter the template does not declare is refused in AWS's words — on a
// create, an update and a change set alike (they all call CheckParameters) — and a UsePreviousValue key
// counts.
func TestCheckParametersUnknown(t *testing.T) {
	got := checkMsg(t, paramsTemplate, map[string]string{"Name": "abc", "Bogus": "1", "Alpha": "2"}, nil, nil)
	if want := "Parameters: [Alpha, Bogus] do not exist in the template"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got = checkMsg(t, paramsTemplate, map[string]string{"Name": "abc"}, []string{"Gone"}, nil)
	if want := "Parameters: [Gone] do not exist in the template"; got != want {
		t.Fatalf("UsePreviousValue key: got %q, want %q", got, want)
	}
	// Unknown is reported before missing, as on AWS.
	got = checkMsg(t, paramsTemplate, map[string]string{"Bogus": "1"}, nil, nil)
	if !strings.Contains(got, "do not exist in the template") {
		t.Fatalf("unknown + missing: got %q", got)
	}
}

func TestCheckParametersMissing(t *testing.T) {
	got := checkMsg(t, paramsTemplate, map[string]string{}, nil, nil)
	if want := "Parameters: [Name] must have values"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCheckParametersConstraints(t *testing.T) {
	cases := []struct {
		given map[string]string
		want  string
	}{
		{map[string]string{"Name": "abc"}, ""},
		{map[string]string{"Name": "abc", "Env": "stage"}, "Parameter 'Env' must be one of AllowedValues"},
		{map[string]string{"Name": "Abc"}, "Parameter 'Name' must match pattern [a-z][a-z0-9-]*"},
		{map[string]string{"Name": "abc def"}, "Parameter 'Name' must match pattern [a-z][a-z0-9-]*"}, // a full match, not a substring
		{map[string]string{"Name": "ab"}, "Parameter 'Name' must contain at least 3 characters"},
		{map[string]string{"Name": "abcdefghi"}, "Parameter 'Name' must contain at most 8 characters"},
		{map[string]string{"Name": "abc", "Count": "0"}, "Parameter 'Count' must be a number not less than 1"},
		{map[string]string{"Name": "abc", "Count": "6"}, "Parameter 'Count' must be a number not greater than 5"},
		{map[string]string{"Name": "abc", "Count": "two"}, "Parameter 'Count' must be a number"},
		{map[string]string{"Name": "abc", "Ports": "80,http"}, "Parameter 'Ports' must be a number"},
		{map[string]string{"Name": "abc", "Tier": "cache"}, "Parameter 'Tier' failed to satisfy constraint: must be web or db"},
	}
	for _, c := range cases {
		if got := checkMsg(t, paramsTemplate, c.given, nil, nil); got != c.want {
			t.Errorf("%v: got %q, want %q", c.given, got, c.want)
		}
	}
}

// A Default is checked like a supplied value (AWS refuses a stack whose Default breaks its own
// constraint, when the Default is used); a Number AllowedValues admits the same number written another way.
func TestCheckParametersDefaultAndNumberAllowed(t *testing.T) {
	tmpl := `
Parameters:
  Size:
    Type: Number
    AllowedValues: [1, 2]
    Default: 3
Resources:
  Q:
    Type: AWS::SQS::Queue
`
	if got := checkMsg(t, tmpl, nil, nil, nil); got != "Parameter 'Size' must be one of AllowedValues" {
		t.Fatalf("default: got %q", got)
	}
	if got := checkMsg(t, tmpl, map[string]string{"Size": "2.0"}, nil, nil); got != "" {
		t.Fatalf("2.0 for AllowedValues [1, 2]: got %q", got)
	}
}

// #350 U: an AWS-specific parameter type's value must name a subnet / security group / VPC that exists
// (a kind: Subnet / SecurityGroup / Vpc of that name), or the operation is refused before anything is
// created — a list parameter's every element too. A NoEcho value is masked in the message.
func TestCheckParametersExistence(t *testing.T) {
	tmpl := `
Parameters:
  SubnetId:
    Type: AWS::EC2::Subnet::Id
  Groups:
    Type: List<AWS::EC2::SecurityGroup::Id>
  Vpc:
    Type: AWS::EC2::VPC::Id
    NoEcho: true
  Key:
    Type: AWS::EC2::KeyPair::KeyName
    Default: whatever
Resources:
  Q:
    Type: AWS::SQS::Queue
`
	ap := &fakeApplier{liveSpecs: map[string]map[string]any{
		"Subnet/app": {}, "SecurityGroup/web": {}, "SecurityGroup/db": {}, "Vpc/main": {},
	}}
	ok := map[string]string{"SubnetId": "app", "Groups": "web, db", "Vpc": "main"}
	if got := checkMsg(t, tmpl, ok, nil, ap); got != "" {
		t.Fatalf("existing values: got %q", got)
	}
	bad := map[string]string{"SubnetId": "subnet-0abc", "Groups": "web", "Vpc": "main"}
	if got, want := checkMsg(t, tmpl, bad, nil, ap), "Parameter validation failed: parameter value subnet-0abc for parameter name SubnetId does not exist"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	bad = map[string]string{"SubnetId": "app", "Groups": "web,nope", "Vpc": "main"}
	if got := checkMsg(t, tmpl, bad, nil, ap); !strings.Contains(got, "parameter value nope for parameter name Groups does not exist") {
		t.Fatalf("list element: got %q", got)
	}
	bad = map[string]string{"SubnetId": "app", "Groups": "web", "Vpc": "other"}
	if got := checkMsg(t, tmpl, bad, nil, ap); got != "Parameter validation failed: parameter value **** for parameter name Vpc does not exist" {
		t.Fatalf("NoEcho: got %q", got)
	}
	bad = map[string]string{"SubnetId": "Not/A Name", "Groups": "web", "Vpc": "main"}
	if got := checkMsg(t, tmpl, bad, nil, ap); !strings.Contains(got, "for parameter name SubnetId does not exist") {
		t.Fatalf("not an object name: got %q", got)
	}
	// Without an Applier (plan), the lookup is skipped.
	if got := checkMsg(t, tmpl, bad, nil, nil); got != "" {
		t.Fatalf("no applier: got %q", got)
	}
}

// The CLI path: plan reports an unknown parameter and a constraint failure as blockers too, so a CLI
// deploy refuses them as the doorway does.
func TestPlanParameterBlockers(t *testing.T) {
	plan, err := BuildPlan([]byte(paramsTemplate), map[string]string{"Name": "abc", "Bogus": "1"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != Rejected || !strings.Contains(strings.Join(plan.Blockers, "\n"), "Parameters: [Bogus] do not exist in the template") {
		t.Fatalf("unknown parameter: verdict %s, blockers %v", plan.Verdict, plan.Blockers)
	}
	plan, err = BuildPlan([]byte(paramsTemplate), map[string]string{"Name": "ab"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != Rejected || !strings.Contains(strings.Join(plan.Blockers, "\n"), "Parameter 'Name' must contain at least 3 characters") {
		t.Fatalf("constraint: verdict %s, blockers %v", plan.Verdict, plan.Blockers)
	}
	// ValidateTemplate (no values) does not report a value error.
	vp, err := ValidatePlan([]byte(paramsTemplate), nil, "s", Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range vp.Blockers {
		if strings.Contains(b, "Parameter") {
			t.Fatalf("ValidatePlan reported a value error: %v", vp.Blockers)
		}
	}
	// A pattern that is not a regular expression is a template error.
	bad := strings.Replace(paramsTemplate, `"[a-z][a-z0-9-]*"`, `"[a-z"`, 1)
	vp, err = ValidatePlan([]byte(bad), nil, "s", Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if vp.Verdict != Rejected {
		t.Fatalf("bad AllowedPattern: verdict %s", vp.Verdict)
	}
}
