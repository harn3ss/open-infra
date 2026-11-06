package cfn

import (
	"slices"
	"strings"
	"testing"
)

const iamRoleTmpl = `
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      Description: app instance role
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" }
      ManagedPolicyArns: [arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore]
      Policies:
        - PolicyName: app-access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: ["s3:GetObject", "s3:ListBucket"], Resource: "arn:aws:s3:::app-config/*" }
              - { Effect: Allow, Action: ["sqs:SendMessage", "sqs:ReceiveMessage"], Resource: "arn:aws:sqs:us-east-1:1:app-queue" }
  UserRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { AWS: "arn:aws:iam::123456789012:root" }, Action: "sts:AssumeRole" }
  AppProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Roles: [ { Ref: AppRole } ] }
  AppInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      IamInstanceProfile: { Ref: AppProfile }
`

// An EC2 instance-trust role (Principal: ec2.amazonaws.com) translates to a kind: Role that trusts the
// "vm" service principal, and its inline Policies become companion kind: Policy objects (data-plane)
// that govern the role's assumed sessions — so a VM booted from it actually HAS s3/sqs permissions.
// ManagedPolicyArns attach the platform's copies of those AWS managed policies by name.
func TestTranslate_IAMRole_Ec2TrustToVm(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an ec2-trust role with an s3/sqs inline policy must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "Role" || m.APIVersion != "iam.openinfra.dev/v1" {
		t.Fatalf("bad head: %+v", m)
	}
	trust, _ := m.Spec["trust"].([]any)
	if len(trust) != 1 || trust[0] != "vm" {
		t.Fatalf("ec2.amazonaws.com trust must map to spec.trust: [vm], got %#v", m.Spec["trust"])
	}
	// The inline policy is now a companion kind: Policy (data-plane), applied to this role; the AWS managed
	// policy attaches as the platform's copy of it, by name (managed_policies.go).
	if len(m.Extra) != 1 {
		t.Fatalf("the inline Policy must become 1 companion kind: Policy object, got %d", len(m.Extra))
	}
	if pols, _ := m.Spec["policies"].([]any); len(pols) != 1 || pols[0] != "aws-amazonssmmanagedinstancecore" {
		t.Fatalf("the managed policy must attach by name in spec.policies, got %#v", m.Spec["policies"])
	}
	pol := m.Extra[0]
	if pol.Kind != "Policy" || pol.Name != "approle-app-access" {
		t.Fatalf("companion policy head wrong: kind=%q name=%q", pol.Kind, pol.Name)
	}
	dp, _ := pol.Spec["dataPlane"].(map[string]any)
	at, _ := dp["appliesTo"].([]any)
	if len(at) != 1 || at[0] != "Role::approle" {
		t.Fatalf("companion policy must applyTo Role::approle, got %#v", dp["appliesTo"])
	}
	flat := strings.ToLower(strings.Join(deepStrings(dp["statements"]), " "))
	if !strings.Contains(flat, "s3:getobject") || !strings.Contains(flat, "sqs:sendmessage") {
		t.Fatalf("companion policy must carry the s3/sqs statements, got %#v", dp["statements"])
	}
	cav := strings.Join(m.Caveats, "\n")
	if !strings.Contains(cav, "inline Policies translated to 1 companion") || !strings.Contains(cav, "managed policy AmazonSSMManagedInstanceCore is attached") || !strings.Contains(cav, "ssmmessages") {
		t.Fatalf("inline-translated + managed-attached (and what of it is not) must surface as caveats: %v", m.Caveats)
	}
}

// An inline policy whose Resource is an in-stack resource's !GetAtt <X>.Arn (a bucket, a queue) is
// resolved to that resource's ARN before import, so the companion Policy scopes to the real resource
// instead of refusing an unresolvable <X.Arn> (#344 4.5).
func TestTranslate_IAMRole_InStackArnInInlinePolicy(t *testing.T) {
	tmpl := `
Resources:
  Config:
    Type: AWS::S3::Bucket
    Properties: { BucketName: app-config }
  Jobs:
    Type: AWS::SQS::Queue
    Properties: { QueueName: app-jobs }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - PolicyName: app
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: "s3:GetObject", Resource: !GetAtt Config.Arn }
              - { Effect: Allow, Action: "sqs:SendMessage", Resource: !GetAtt Jobs.Arn }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an in-stack !GetAtt .Arn Resource must resolve, not refuse: %s", findingsText(fs))
	}
	if len(m.Extra) != 1 {
		t.Fatalf("want 1 companion Policy, got %d", len(m.Extra))
	}
	dp, _ := m.Extra[0].Spec["dataPlane"].(map[string]any)
	flat := strings.ToLower(strings.Join(deepStrings(dp["statements"]), " "))
	// The companion policy must scope to the in-stack bucket + queue by their AWS names.
	if !strings.Contains(flat, "app-config") || !strings.Contains(flat, "app-jobs") {
		t.Fatalf("the in-stack ARNs must resolve to the bucket/queue names, got %#v", dp["statements"])
	}
}

// #347 Phase 0.4 (regression): an inline Policies entry wrapped in !If must resolve to its chosen
// branch, not be read as a literal {Fn::If: ...} map with no PolicyDocument and refused. The fix
// resolves the WHOLE raw Policies list (synthInStackARNs + resolve) before reading entries, so the
// !If evaluates and an AWS::NoValue branch drops out.
func TestTranslate_IAMRole_InlinePolicyIfResolves(t *testing.T) {
	tmpl := `
Parameters:
  Extra: { Type: String, Default: "true" }
Conditions:
  ExtraOn: !Equals [!Ref Extra, "true"]
Resources:
  Config:
    Type: AWS::S3::Bucket
    Properties: { BucketName: app-config }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - !If
          - ExtraOn
          - PolicyName: app
            PolicyDocument:
              Version: "2012-10-17"
              Statement:
                - { Effect: Allow, Action: "s3:GetObject", Resource: !GetAtt Config.Arn }
          - !Ref AWS::NoValue
`
	// ON (default): the !If resolves to its first branch and becomes a companion Policy. Before
	// the fix the raw entry was the literal {Fn::If: ...} with no PolicyDocument, so it refused.
	on := ecsCtx(t, tmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, on, "AppRole"), on)
	if len(fs) != 0 {
		t.Fatalf("an !If-wrapped inline policy must resolve, not refuse: %s", findingsText(fs))
	}
	if len(m.Extra) != 1 {
		t.Fatalf("want 1 companion Policy from the ON branch, got %d", len(m.Extra))
	}
	dp, _ := m.Extra[0].Spec["dataPlane"].(map[string]any)
	flat := strings.ToLower(strings.Join(deepStrings(dp["statements"]), " "))
	if !strings.Contains(flat, "app-config") {
		t.Fatalf("the resolved policy must scope to the in-stack bucket, got %#v", dp["statements"])
	}
	// OFF: the entry resolves to AWS::NoValue and drops out — no companion, and no finding (a
	// conditioned-off inline policy is absent, not an error).
	off := ctxWithParams(t, tmpl, map[string]string{"Extra": "false"})
	mOff, fsOff := translateIAMRole("AppRole", resolvedProps(t, off, "AppRole"), off)
	if len(fsOff) != 0 {
		t.Fatalf("a conditioned-OFF inline policy must not produce a finding: %s", findingsText(fsOff))
	}
	if len(mOff.Extra) != 0 {
		t.Fatalf("the OFF branch must yield no companion Policy, got %d", len(mOff.Extra))
	}
}

// roleStatements translates AppRole and returns its single companion Policy's dataPlane statements.
func roleStatements(t *testing.T, ctx *stackCtx) []map[string]any {
	t.Helper()
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("the role must translate cleanly: %s", findingsText(fs))
	}
	if len(m.Extra) != 1 {
		t.Fatalf("want 1 companion Policy, got %d", len(m.Extra))
	}
	dp, _ := m.Extra[0].Spec["dataPlane"].(map[string]any)
	raw, _ := dp["statements"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, s := range raw {
		sm, _ := s.(map[string]any)
		out = append(out, sm)
	}
	return out
}

// strs renders a statement's list field as []string.
func strs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func sameStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ECR statements in an instance role's inline policy translate to data-plane statements on
// Repository::<name> — ecr:GetAuthorizationToken on "*" stays "*" (it has no resource on AWS either), a
// repository ARN (literal, or built with ${AWS::Region}/${AWS::AccountId}/a parameter) maps to its
// repository, and ecr:* on a repository prefix keeps both wildcards.
func TestTranslate_IAMRole_ECRStatements(t *testing.T) {
	tmpl := `
Parameters:
  AppRepositoryName: { Type: String, Default: team/app }
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - PolicyName: ecr-pull
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: [ecr:GetAuthorizationToken], Resource: "*" }
              - Effect: Allow
                Action: [ecr:BatchGetImage, ecr:GetDownloadUrlForLayer]
                Resource: !Sub "arn:${AWS::Partition}:ecr:${AWS::Region}:${AWS::AccountId}:repository/${AppRepositoryName}"
              - { Effect: Allow, Action: "ecr:*", Resource: "arn:aws:ecr:us-east-1:123456789012:repository/tools/*" }
              - { Effect: Deny, Action: [ecr:PutImage], Resource: "arn:aws:ecr:us-east-1:123456789012:repository/team/app" }
`
	st := roleStatements(t, ecsCtx(t, tmpl))
	want := []struct {
		effect    string
		actions   []string
		resources []string
	}{
		{"Allow", []string{"ecr:GetAuthorizationToken"}, []string{"*"}},
		{"Allow", []string{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"}, []string{"Repository::team/app"}},
		{"Allow", []string{"ecr:*"}, []string{"Repository::tools/*"}},
		{"Deny", []string{"ecr:PutImage"}, []string{"Repository::team/app"}},
	}
	if len(st) != len(want) {
		t.Fatalf("want %d statements, got %d: %#v", len(want), len(st), st)
	}
	for i, w := range want {
		if st[i]["effect"] != w.effect || !sameStrs(strs(st[i]["actions"]), w.actions) || !sameStrs(strs(st[i]["resources"]), w.resources) {
			t.Errorf("statement %d = %#v, want %s %v on %v", i, st[i], w.effect, w.actions, w.resources)
		}
	}
}

// `Resource: !Sub "${Bucket.Arn}/*"` — the most common object-ARN form — resolves to the in-stack bucket
// exactly as `!GetAtt Bucket.Arn` does, and so do `!Sub "arn:aws:s3:::${Bucket}/*"` (the Ref form) and the
// [string, vars] form. Escapes and Sub variables are left alone; the bare-attribute and Ref forms of other
// fronted types resolve too.
func TestTranslate_IAMRole_SubInStackArn(t *testing.T) {
	tmpl := `
Resources:
  Assets: { Type: AWS::S3::Bucket }
  Config:
    Type: AWS::S3::Bucket
    Properties: { BucketName: app-config }
  Orders:
    Type: AWS::DynamoDB::Table
    Properties: { TableName: orders }
  Alerts: { Type: AWS::SNS::Topic }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - PolicyName: app
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: s3:GetObject, Resource: !Sub "${Assets.Arn}/*" }
              - { Effect: Allow, Action: s3:PutObject, Resource: !Sub "arn:aws:s3:::${Config}/*" }
              - Effect: Allow
                Action: s3:DeleteObject
                Resource: !Sub ["${B}/*", { B: !GetAtt Config.Arn }]
              - { Effect: Allow, Action: dynamodb:GetItem, Resource: !Sub "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${Orders}" }
              - { Effect: Allow, Action: sns:Publish, Resource: !Sub "${Alerts}" }
`
	st := roleStatements(t, ecsCtx(t, tmpl))
	want := [][]string{
		{"Bucket::assets/*"}, // the bucket's objects, as the ARN names them
		{"Bucket::app-config/*"},
		{"Bucket::app-config/*"},
		{"Table::orders"},
		{"Topic::alerts"},
	}
	if len(st) != len(want) {
		t.Fatalf("want %d statements, got %d: %#v", len(want), len(st), st)
	}
	for i, w := range want {
		if got := strs(st[i]["resources"]); !sameStrs(got, w) {
			t.Errorf("statement %d resources = %v, want %v", i, got, w)
		}
	}
}

// A grant on part of a bucket (a key prefix) translates to that prefix's objects: the S3 front door checks
// an object operation on its object, so the grant reaches the keys under uploads/ and nothing else.
func TestTranslate_IAMRole_S3PrefixScopesToItsKeys(t *testing.T) {
	tmpl := `
Resources:
  Config:
    Type: AWS::S3::Bucket
    Properties: { BucketName: app-config }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - PolicyName: app
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: s3:PutObject, Resource: !Sub "arn:aws:s3:::${Config}/uploads/*" }
`
	st := roleStatements(t, ecsCtx(t, tmpl))
	if len(st) != 1 || !sameStrs(strs(st[0]["resources"]), []string{"Bucket::app-config/uploads/*"}) {
		t.Fatalf("want one statement on Bucket::app-config/uploads/*, got %#v", st)
	}
}

// The Sub rewrite only touches in-stack shim-fronted resources: a ${!Literal} escape, a Sub variable that
// shadows a resource name, and parameters are left to the normal resolver.
func TestSynthSubTemplate_LeavesOthersAlone(t *testing.T) {
	ctx := ecsCtx(t, `
Parameters:
  Env: { Type: String, Default: prod }
Resources:
  Assets: { Type: AWS::S3::Bucket }
  Jobs: { Type: AWS::SQS::Queue }
`)
	cases := []struct {
		in   string
		vars map[string]any
		want string
	}{
		{"${Assets.Arn}/*", nil, "arn:aws:s3:::assets/*"},
		{"arn:aws:s3:::${Assets}/${Env}/*", nil, "arn:aws:s3:::assets/${Env}/*"},
		{"${!Assets.Arn}", nil, "${!Assets.Arn}"},
		{"${Assets}", map[string]any{"Assets": "other"}, "${Assets}"},
		{"${Assets.DomainName}", nil, "${Assets.DomainName}"},
		{"${Jobs}", nil, "${Jobs}"}, // a queue's Ref is its URL — never part of an ARN
		{"${Jobs.Arn}", nil, "arn:aws:sqs:us-east-1:000000000000:jobs"},
		{"${AWS::Region}:${Unknown.Arn}", nil, "${AWS::Region}:${Unknown.Arn}"},
		{"unterminated ${Assets", nil, "unterminated ${Assets"},
	}
	for _, c := range cases {
		if got := synthSubTemplate(c.in, c.vars, ctx); got != c.want {
			t.Errorf("synthSubTemplate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A placeholder that survives inside an otherwise-recognizable ARN (here a queue's Ref, a URL, spliced into
// an S3 ARN) names no real resource — the role refuses rather than granting on it.
func TestTranslate_IAMRole_UnresolvedResourceRefuses(t *testing.T) {
	tmpl := `
Resources:
  Jobs: { Type: AWS::SQS::Queue }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - PolicyName: app
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: s3:GetObject, Resource: !Sub "arn:aws:s3:::${Jobs}/*" }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if m != nil || !strings.Contains(findingsText(fs), "does not resolve here") {
		t.Fatalf("a placeholder resource must refuse the role, got m=%v findings=%s", m, findingsText(fs))
	}
}

// An AWS::IAM::Policy (attached to a literal group) gets the same in-stack resolution as a Role's inline
// policy: `!Sub "${Assets.Arn}/*"` names the in-stack bucket, and a spliced-in unresolvable Ref refuses.
func TestTranslate_IAMPolicy_SubInStackArn(t *testing.T) {
	tmpl := `
Resources:
  Assets: { Type: AWS::S3::Bucket }
  Jobs: { Type: AWS::SQS::Queue }
  ReadAssets:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: read-assets
      Users: [analyst]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Action: s3:GetObject, Resource: !Sub "${Assets.Arn}/*" }
  Broken:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: broken
      Users: [analyst]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Action: s3:GetObject, Resource: !Sub "arn:aws:s3:::${Jobs}/*" }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateIAMPolicy("ReadAssets", resolvedProps(t, ctx, "ReadAssets"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an in-stack ${X.Arn} must resolve: %s", findingsText(fs))
	}
	dp, _ := m.Spec["dataPlane"].(map[string]any)
	if flat := strings.Join(deepStrings(dp["statements"]), " "); !strings.Contains(flat, "Bucket::assets") {
		t.Fatalf("the policy must scope to the in-stack bucket, got %#v", dp["statements"])
	}
	if _, fs := translateIAMPolicy("Broken", resolvedProps(t, ctx, "Broken"), ctx); !strings.Contains(findingsText(fs), "does not resolve here") {
		t.Fatalf("a placeholder resource must refuse, got %s", findingsText(fs))
	}
}

// The #347 lift-and-shift instance role, end to end: an app bucket read through `!Sub "${AppBucket.Arn}/*"`
// + ListBucket on the bucket, and an ECR pull of the app's own repository — plans PROVISIONABLE(_WITH_
// CAVEATS) and deploys a companion Policy that grants exactly that.
func TestPlan_InstanceRoleS3AndECRPull(t *testing.T) {
	tmpl := []byte(`
Parameters: { AppRepositoryName: { Type: String } }
Resources:
  AppBucket: { Type: AWS::S3::Bucket }
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole } ] }
      Policies:
        - PolicyName: app-access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: [s3:GetObject], Resource: !Sub "${AppBucket.Arn}/*" }
              - { Effect: Allow, Action: [s3:ListBucket], Resource: !GetAtt AppBucket.Arn }
              - { Effect: Allow, Action: [ecr:GetAuthorizationToken], Resource: "*" }
              - { Effect: Allow, Action: [ecr:DescribeRepositories, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer, ecr:BatchCheckLayerAvailability], Resource: !Sub "arn:aws:ecr:${AWS::Region}:${AWS::AccountId}:repository/${AppRepositoryName}" }
`)
	params := map[string]string{"AppRepositoryName": "app"}
	p := mustPlan(t, tmpl, params, "s")
	if p.Verdict != Provisionable && p.Verdict != ProvisionableWithCaveats {
		t.Fatalf("verdict %s, blockers: %v", p.Verdict, p.Blockers)
	}
	built, err := buildManifests(tmpl, DeployOptions{StackName: "s", Namespace: "app", Params: params})
	if err != nil {
		t.Fatalf("buildManifests: %v", err)
	}
	var policy string
	for _, b := range built {
		if b.res.Kind == "Policy" {
			policy = string(b.yml)
		}
	}
	if policy == "" {
		t.Fatalf("no companion Policy was built: %+v", built)
	}
	for _, want := range []string{"Role::s-instancerole", "Bucket::s-appbucket", "s3:GetObject", "s3:ListBucket",
		"ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "Repository::app"} {
		if !strings.Contains(policy, want) {
			t.Errorf("companion Policy lacks %q:\n%s", want, policy)
		}
	}
	if strings.Contains(policy, "<") {
		t.Errorf("companion Policy carries an unresolved placeholder:\n%s", policy)
	}
}

// A role trusting anything other than AWS service principals (here an AWS account principal) refuses —
// no template-derivable open-infra trust.
func TestTranslate_IAMRole_NonEc2TrustRefuses(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	_, fs := translateIAMRole("UserRole", resolvedProps(t, ctx, "UserRole"), ctx)
	if !strings.Contains(findingsText(fs), "AWS service principals (<service>.amazonaws.com) and nothing else") {
		t.Fatalf("a non-service-trust role must refuse with help, got: %s", findingsText(fs))
	}
}

// An AppSync service role (trusting appsync.amazonaws.com) translates: the role exists, as on AWS, with
// its inline policy attached — but with no trust entry, since nothing here assumes it (open-appsync reaches
// its sources with its own connection), so it grants nothing, and a caveat says so. A role trusting both
// ec2 and appsync is assumable by its VMs only. A Lambda execution role trusts the Lambda service
// (TestTranslate_IAMRole_ServiceTrust).
func TestTranslate_IAMRole_AppSyncServiceRole(t *testing.T) {
	tmpl := `
Resources:
  Table: { Type: AWS::DynamoDB::Table, Properties: { TableName: todos, BillingMode: PAY_PER_REQUEST, AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ], KeySchema: [ { AttributeName: id, KeyType: HASH } ] } }
  DsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [ { Effect: Allow, Principal: { Service: appsync.amazonaws.com }, Action: sts:AssumeRole } ]
      Policies:
        - PolicyName: table
          PolicyDocument:
            Version: "2012-10-17"
            Statement: [ { Effect: Allow, Action: [ "dynamodb:GetItem", "dynamodb:PutItem" ], Resource: !GetAtt Table.Arn } ]
  Both:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: [ ec2.amazonaws.com, appsync.amazonaws.com ] }, Action: sts:AssumeRole } ]
  Fn:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: lambda.amazonaws.com }, Action: sts:AssumeRole } ]
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateIAMRole("DsRole", resolvedProps(t, ctx, "DsRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an AppSync service role must translate: %s", findingsText(fs))
	}
	if trust, _ := m.Spec["trust"].([]any); len(trust) != 0 {
		t.Fatalf("an AppSync service role must trust nobody here (nothing assumes it), got %#v", m.Spec["trust"])
	}
	if len(m.Extra) != 1 || m.Extra[0].Kind != "Policy" {
		t.Fatalf("its inline policy must be attached as a companion kind: Policy, got %d extras", len(m.Extra))
	}
	if cav := strings.Join(m.Caveats, "\n"); !strings.Contains(cav, "nothing assumes it") {
		t.Fatalf("the role must say nothing assumes it: %v", m.Caveats)
	}

	m, fs = translateIAMRole("Both", resolvedProps(t, ctx, "Both"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an ec2+appsync role must translate: %s", findingsText(fs))
	}
	if trust, _ := m.Spec["trust"].([]any); len(trust) != 1 || trust[0] != "vm" {
		t.Fatalf("an ec2+appsync role must be assumable by its VMs only, got %#v", m.Spec["trust"])
	}

	m, fs = translateIAMRole("Fn", resolvedProps(t, ctx, "Fn"), ctx)
	if len(fs) != 0 {
		t.Fatalf("a Lambda execution role must translate: %s", findingsText(fs))
	}
	if trust, _ := m.Spec["trust"].([]any); len(trust) != 1 || trust[0] != "Service::lambda.amazonaws.com" {
		t.Fatalf("a Lambda execution role trusts the Lambda service, got %#v", m.Spec["trust"])
	}
}

// A service role's trust is recorded as IAM's CreateRole records it: EC2's as the instance principal, any
// other service as Service::<service>. Lambda's and Step Functions' are assumed (by a function or a state
// machine that names the role); another service's is recorded but grants nothing, with a caveat saying so.
// A principal that is no AWS service still refuses.
func TestTranslate_IAMRole_ServiceTrust(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: lambda.amazonaws.com }, Action: sts:AssumeRole } ]
  FnAndInstance:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - { Effect: Allow, Principal: { Service: [ lambda.amazonaws.com, ec2.amazonaws.com ] }, Action: sts:AssumeRole }
  Flow:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: states.amazonaws.com }, Action: "sts:AssumeRole" } ]
  Task:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: [ ecs-tasks.amazonaws.com, events.amazonaws.com ] }, Action: sts:AssumeRole } ]
  Odd:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: "lambda.example.com" }, Action: sts:AssumeRole } ]
`
	ctx := ecsCtx(t, tmpl)
	for id, want := range map[string][]any{
		"Fn":            {"Service::lambda.amazonaws.com"},
		"FnAndInstance": {"vm", "Service::lambda.amazonaws.com"},
		"Flow":          {"Service::states.amazonaws.com"},
		"Task":          {"Service::ecs-tasks.amazonaws.com", "Service::events.amazonaws.com"},
	} {
		m, fs := translateIAMRole(id, resolvedProps(t, ctx, id), ctx)
		if len(fs) != 0 {
			t.Fatalf("%s must translate: %s", id, findingsText(fs))
		}
		got, _ := m.Spec["trust"].([]any)
		if len(got) != len(want) {
			t.Fatalf("%s trust = %#v, want %#v", id, got, want)
		}
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("%s trust = %#v, want %#v", id, got, want)
			}
		}
		idleCaveat := strings.Contains(strings.Join(m.Caveats, "\n"), "no open-infra service assumes a role for")
		if idleCaveat != (id == "Task") {
			t.Errorf("%s: a caveat that no service assumes it = %v (caveats %v)", id, idleCaveat, m.Caveats)
		}
	}
	if _, fs := translateIAMRole("Odd", resolvedProps(t, ctx, "Odd"), ctx); len(fs) == 0 {
		t.Error("a principal that is no AWS service must refuse")
	}
}

// A real AppSync template — an API whose DynamoDB data source names an in-stack service role by
// !GetAtt — plans with no blocker: the role is a kind: Role nothing assumes, and both the role and the
// data source say that its policy does not limit the engine.
func TestPlan_AppSyncWithInStackServiceRole(t *testing.T) {
	tmpl := `
Resources:
  Table: { Type: AWS::DynamoDB::Table, Properties: { TableName: todos, BillingMode: PAY_PER_REQUEST, AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ], KeySchema: [ { AttributeName: id, KeyType: HASH } ] } }
  DsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [ { Effect: Allow, Principal: { Service: appsync.amazonaws.com }, Action: sts:AssumeRole } ]
      Policies:
        - PolicyName: table
          PolicyDocument:
            Version: "2012-10-17"
            Statement: [ { Effect: Allow, Action: [ "dynamodb:GetItem", "dynamodb:PutItem" ], Resource: !GetAtt Table.Arn } ]
  Api: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: todos, AuthenticationType: AWS_IAM } }
  Schema:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt Api.ApiId, Definition: "type Query { todo(id: ID!): String @aws_iam }" }
  Ds:
    Type: AWS::AppSync::DataSource
    Properties:
      ApiId: !GetAtt Api.ApiId
      Name: todos
      Type: AMAZON_DYNAMODB
      ServiceRoleArn: !GetAtt DsRole.Arn
      DynamoDBConfig: { TableName: !Ref Table, AwsRegion: !Ref AWS::Region }
  Get:
    Type: AWS::AppSync::Resolver
    Properties:
      ApiId: !GetAtt Api.ApiId
      TypeName: Query
      FieldName: todo
      DataSourceName: !GetAtt Ds.Name
      RequestMappingTemplate: '{"version":"2017-02-28","operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}'
      ResponseMappingTemplate: '$util.toJson($ctx.result)'
`
	p := mustPlan(t, []byte(tmpl), nil, "todos")
	if p.Verdict == Rejected {
		t.Fatalf("an AppSync template with an in-stack service role must plan, got blockers: %v", p.Blockers)
	}
	var notes []string
	for _, f := range p.Fidelity {
		notes = append(notes, f.Resource+": "+f.Detail)
	}
	all := strings.Join(notes, "\n")
	if !strings.Contains(all, "nothing assumes it") || !strings.Contains(all, "ServiceRoleArn is not assumed") {
		t.Fatalf("the plan must say the role is not assumed:\n%s", all)
	}
}

// An instance profile provisions nothing on its own (implicit) — the binding is on the VM.
func TestTranslate_IAMInstanceProfile_Implicit(t *testing.T) {
	m, fs := translateIAMInstanceProfile("AppProfile", map[string]any{"Roles": []any{map[string]any{"Ref": "AppRole"}}}, nil)
	if m != nil || len(fs) != 0 {
		t.Fatalf("an instance profile must be an implicit no-op, got m=%v fs=%s", m, findingsText(fs))
	}
}

// An EC2 instance whose IamInstanceProfile !Refs an in-stack profile binds spec.instanceRole to the
// profile's in-stack role — the EC2 instance-profile → VM role analog.
func TestTranslate_EC2Instance_IamInstanceProfileToRole(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	m, fs := translateEC2Instance("AppInstance", resolvedProps(t, ctx, "AppInstance"), ctx)
	if len(fs) != 0 {
		t.Fatalf("the instance must translate cleanly: %s", findingsText(fs))
	}
	if m.Spec["instanceRole"] != "approle" {
		t.Fatalf("IamInstanceProfile should resolve to spec.instanceRole=approle, got %#v", m.Spec["instanceRole"])
	}
}

// Plan-level: with the Role/InstanceProfile translators, a role+profile+instance stack has no gated
// IAM resources — the Role is create-deployable, the profile implicit.
func TestPlan_InstanceRoleChainDeployable(t *testing.T) {
	p := mustPlan(t, []byte(iamRoleTmpl), nil, "s")
	for _, r := range p.Resources {
		if r.CFNType == "AWS::IAM::Role" && r.LogicalID == "AppRole" && !r.Deployable {
			t.Errorf("an ec2-trust Role should be create-deployable")
		}
		if r.CFNType == "AWS::IAM::InstanceProfile" && !r.Deployable {
			t.Errorf("an InstanceProfile should be create-deployable (implicit)")
		}
	}
}

// A role's MaxSessionDuration becomes its spec.maxSessionDuration (the shim caps sessions at it); a value
// outside AWS's 3600..43200 blocks the role, as AWS refuses it.
func TestTranslate_IAMRole_MaxSessionDuration(t *testing.T) {
	tmpl := func(v string) string {
		return strings.Replace(iamRoleTmpl, "      Description: app instance role\n", "      Description: app instance role\n      MaxSessionDuration: "+v+"\n", 1)
	}
	ctx := ecsCtx(t, tmpl("7200"))
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("findings: %s", findingsText(fs))
	}
	if m.Spec["maxSessionDuration"] != 7200 {
		t.Fatalf("spec.maxSessionDuration = %#v, want 7200", m.Spec["maxSessionDuration"])
	}
	for _, bad := range []string{"60", "50000"} {
		ctx := ecsCtx(t, tmpl(bad))
		if _, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx); len(fs) == 0 {
			t.Errorf("MaxSessionDuration %s translated; want a finding", bad)
		}
	}
}

// resolvedProps resolves a resource's properties through the stack's resolver (so a literal field is
// usable and a !Ref stays followable via ctx.rawProps).
func resolvedProps(t *testing.T, ctx *stackCtx, id string) map[string]any {
	t.Helper()
	ctx.resolver.where = "Resource " + id
	m, _ := ctx.resolver.resolve(ctx.template.Resources[id].Properties).(map[string]any)
	return m
}
