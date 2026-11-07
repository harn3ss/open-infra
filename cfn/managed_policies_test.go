package cfn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

// A role's ManagedPolicyArns attach the platform's copies of those AWS managed policies by name
// (spec.policies), as AWS attaches them by ARN; one the library does not ship stays a caveat, attaching
// nothing.
func TestRole_ManagedPolicyArnsAttachTheShippedOnes(t *testing.T) {
	order, err := buildManifests([]byte(`
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ]
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly
        - arn:aws:iam::aws:policy/AdministratorAccess
        - arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole
        - arn:aws:iam::123456789012:policy/CustomerManaged
`), DeployOptions{StackName: "app", Namespace: "n"})
	if err != nil {
		t.Fatal(err)
	}
	var role *StackResource
	var cav string
	for i, b := range order {
		if b.res.Kind == "Role" {
			role = &order[i].res
		}
		if b.res.Kind == "Policy" {
			t.Fatalf("a managed policy must not become a companion kind: Policy: %s", b.res.Name)
		}
		cav += strings.Join(b.cav, "\n")
	}
	if role == nil {
		t.Fatal("no Role")
	}
	got := fmt.Sprint(role.Spec["policies"])
	for _, want := range []string{"aws-amazonec2containerregistryreadonly", "aws-amazonssmmanagedinstancecore",
		"aws-amazonec2containerregistrypullonly", "aws-administratoraccess"} {
		if !strings.Contains(got, want) {
			t.Fatalf("spec.policies = %s, want %s", got, want)
		}
	}
	if strings.Contains(got, "glue") || strings.Contains(got, "customer") {
		t.Fatalf("an unshipped policy must attach nothing: %s", got)
	}
	for _, want := range []string{"AWSGlueServiceRole is NOT attached", "arn:aws:iam::123456789012:policy/CustomerManaged are NOT attached",
		"AmazonSSMManagedInstanceCore is attached", "ssmmessages"} {
		if !strings.Contains(cav, want) {
			t.Fatalf("caveats lack %q:\n%s", want, cav)
		}
	}
}

// A long stack name and a long policy name still give companion policy names (inline policies) that fit,
// unique per policy, and a name that already fits is left exactly as it was.
func TestRole_CompanionPolicyNamesFit(t *testing.T) {
	order, err := buildManifests([]byte(`
Resources:
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ]
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
        - arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
      Policies:
        - PolicyName: read-the-application-configuration-parameters-for-this-environment
          PolicyDocument: { Statement: [ { Effect: Allow, Action: "ssm:GetParameter", Resource: "*" } ] }
        - PolicyName: read-the-application-configuration-parameters-for-this-environment-too
          PolicyDocument: { Statement: [ { Effect: Allow, Action: "ssm:GetParameters", Resource: "*" } ] }
`), DeployOptions{StackName: "lsfix-0123abcd-with-a-long-name", Namespace: "n"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	n := 0
	for _, b := range order {
		if b.res.Kind != "Policy" {
			continue
		}
		n++
		name := b.res.Name
		if len(name) > 63 || !fnNameRE.MatchString(name) {
			t.Fatalf("companion policy name %q (%d chars) is not a valid 63-character name", name, len(name))
		}
		if seen[name] {
			t.Fatalf("companion policy name %q is not unique", name)
		}
		seen[name] = true
	}
	if n != 2 {
		t.Fatalf("got %d companion policies (the two inline ones), want 2", n)
	}
	if got := companionPolicyName("approle", "read-config"); got != "approle-read-config" {
		t.Fatalf("a name that fits must not change: %q", got)
	}
}

// The library file is generated from awsManagedPolicies; a stale file fails here (regenerate with
// UPDATE_MANAGED_POLICIES=1).
func TestManagedPolicyLibraryIsCurrent(t *testing.T) {
	got, err := ManagedPolicyLibrary()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", ManagedPolicyLibraryPath)
	if os.Getenv("UPDATE_MANAGED_POLICIES") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate it: UPDATE_MANAGED_POLICIES=1 go test ./cfn -run TestManagedPolicyLibraryIsCurrent)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: regenerate it with UPDATE_MANAGED_POLICIES=1 go test ./cfn -run TestManagedPolicyLibraryIsCurrent", ManagedPolicyLibraryPath)
	}
}

var k8sObjectNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Every shipped policy has a name a Role can attach (spec.policies: an RFC 1123 name of at most 56
// characters), an AWS ARN, a document that parses and keeps at least one statement, and derived
// data-plane statements that are never wider than the document: each derived action or carve-out is one
// the document names.
func TestManagedPolicies_WellFormedAndNeverWider(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range ManagedPolicies() {
		name := p.ObjectName()
		if len(name) > 56 || !k8sObjectNameRE.MatchString(name) || seen[name] {
			t.Errorf("%s: object name %q is not a unique attachable name", p.Name, name)
		}
		seen[name] = true
		if !strings.HasPrefix(p.ARN(), "arn:aws:iam::aws:policy/") || !strings.HasSuffix(p.ARN(), "/"+p.Name) {
			t.Errorf("%s: ARN %s", p.Name, p.ARN())
		}
		if got, ok := ManagedPolicyByARN(p.ARN()); !ok || got.Name != p.Name {
			t.Errorf("%s: not found by its ARN", p.Name)
		}
		doc, _, err := p.ServedDocument()
		if err != nil || len(doc.Statement) == 0 || doc.Version != "2012-10-17" {
			t.Errorf("%s: document %v (err %v)", p.Name, doc, err)
			continue
		}
		raw, _ := json.Marshal(doc)
		stmts, err := p.DataPlaneStatements()
		if err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
		for _, s := range stmts {
			for _, a := range s.Actions {
				if a != "*" && !strings.Contains(string(raw), `"`+a+`"`) {
					t.Errorf("%s: derived action %s is not in the document", p.Name, a)
				}
			}
			for _, a := range s.NotActions {
				if !strings.Contains(string(raw), `"`+a+`"`) {
					t.Errorf("%s: derived carve-out %s is not in the document", p.Name, a)
				}
			}
		}
	}
	if _, ok := ManagedPolicyByARN("arn:aws:iam::123456789012:policy/AdministratorAccess"); ok {
		t.Error("a customer policy that shares an AWS name must not resolve to the AWS managed policy")
	}
}

// PowerUserAccess is AWS's document unchanged, and so denies IAM writes (and Organizations and Account
// management) while allowing every other service — the meaning AWS documents. AdministratorAccess allows
// everything; ReadOnlyAccess reads but never writes; ViewOnlyAccess lists but does not read data.
func TestManagedPolicies_JobFunctionsMeanWhatAWSDocuments(t *testing.T) {
	pu, _ := ManagedPolicyByName("PowerUserAccess")
	if !strings.Contains(pu.Doc, `"NotAction":["iam:*","organizations:*","account:*"]`) || !pu.Exact {
		t.Fatalf("PowerUserAccess must be AWS's exact NotAction document: %s", pu.Doc)
	}
	alice := policyengine.Principal{Type: "User", ID: "alice"}
	ctx := map[string]any{"authenticated": true}
	type check struct {
		action string
		res    policyengine.Resource
		want   bool
	}
	user := policyengine.Resource{Type: "User", ID: "bob"}
	role := policyengine.Resource{Type: "Role", ID: "app"}
	bucket := policyengine.Resource{Type: "Bucket", ID: "assets"}
	object := policyengine.Resource{Type: "Bucket", ID: "assets/k"}
	table := policyengine.Resource{Type: "Table", ID: "orders"}
	cases := map[string][]check{
		"PowerUserAccess": {
			{"iam:CreateUser", user, false}, {"iam:AttachUserPolicy", user, false}, {"iam:CreateAccessKey", user, false},
			{"iam:PutRolePolicy", role, false}, {"iam:DeleteRole", role, false}, {"iam:PassRole", role, false},
			{"iam:ListRoles", role, true}, {"iam:CreateServiceLinkedRole", role, true},
			{"s3:PutObject", object, true}, {"s3:DeleteBucket", bucket, true}, {"dynamodb:PutItem", table, true},
			{"lambda:InvokeFunction", policyengine.Resource{Type: "Function", ID: "f"}, true},
		},
		"AdministratorAccess": {{"iam:CreateUser", user, true}, {"s3:PutObject", object, true}},
		"ReadOnlyAccess": {
			{"s3:GetObject", object, true}, {"s3:ListBucket", bucket, true}, {"dynamodb:Query", table, true},
			{"s3:PutObject", object, false}, {"dynamodb:PutItem", table, false}, {"iam:CreateUser", user, false},
			{"iam:GetUser", user, true}, {"secretsmanager:GetSecretValue", policyengine.Resource{Type: "Secret", ID: "s"}, false},
		},
		"ViewOnlyAccess":         {{"s3:ListBucket", bucket, true}, {"s3:GetObject", object, false}, {"dynamodb:Query", table, false}},
		"AmazonS3ReadOnlyAccess": {{"s3:GetObject", object, true}, {"s3:PutObject", object, false}},
	}
	for name, checks := range cases {
		p, ok := ManagedPolicyByName(name)
		if !ok {
			t.Fatalf("%s is not shipped", name)
		}
		stmts, err := p.DataPlaneStatements()
		if err != nil {
			t.Fatal(err)
		}
		eng, err := policyengine.NewEngine(stmts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range checks {
			if got := eng.Authorize(policyengine.Request{Principal: alice, Action: c.action, Resource: c.res, Context: ctx}).Allowed; got != c.want {
				t.Errorf("%s: %s on %s::%s allowed=%v, want %v", name, c.action, c.res.Type, c.res.ID, got, c.want)
			}
		}
	}
}

// Every kebab-case built-in (platform/security/managed-policies.yaml) names its AWS equivalent — a policy
// this library ships — or "none" with a reason; scripts/iam-migrate re-points attachments by it.
func TestManagedPolicies_BuiltInsCoverWhatNoAWSPolicyDoes(t *testing.T) {
	raw, err := os.ReadFile("../platform/security/managed-policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	eqRE := regexp.MustCompile(`openinfra.dev/aws-equivalent: (\S+)`)
	kindRE := regexp.MustCompile(`(?m)^kind: Policy$`)
	n := 0
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		if !kindRE.MatchString(doc) {
			continue
		}
		n++
		eq := eqRE.FindStringSubmatch(doc)
		if eq == nil {
			t.Errorf("a built-in policy names no openinfra.dev/aws-equivalent:\n%s", doc[:min(len(doc), 300)])
			continue
		}
		if eq[1] == "none" {
			if !strings.Contains(doc, "openinfra.dev/aws-equivalent-reason:") {
				t.Errorf("a built-in with no AWS equivalent must say why")
			}
			continue
		}
		// The deprecated aliases of AWS managed policies were removed at the IAM cutover: a built-in here
		// covers open-infra kinds no AWS managed policy does.
		t.Errorf("a built-in policy aliases the AWS managed policy %s; attach the AWS policy itself", eq[1])
	}
	if n != 9 {
		t.Fatalf("found %d built-in policies, want the 9 platform policies", n)
	}
}
