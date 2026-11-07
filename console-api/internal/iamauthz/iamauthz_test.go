package iamauthz

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// powerUserAccess is AWS's PowerUserAccess managed policy document, verbatim.
const powerUserAccess = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole", "iam:ListRoles",
      "organizations:DescribeOrganization", "account:ListRegions", "account:GetAccountInformation"], "Resource": "*"}
  ]
}`

const administratorAccess = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

func mustDoc(t *testing.T, name, doc string) Policy {
	t.Helper()
	stmts, report, err := CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return Policy{Name: name, Statements: stmts, Report: report}
}

func evaluator(w World, opts ...Option) *Evaluator {
	return New(func(context.Context) (World, error) { return w, nil }, 0, append([]Option{WithMode(ModeEnforce)}, opts...)...)
}

func user(id string, groups ...string) Principal {
	return Principal{Type: User, ID: id, Groups: groups}
}

var ctxAuth = map[string]any{"authenticated": true}

type check struct {
	name     string
	p        Principal
	action   string
	resource string
	opts     []RequestOption
	ctx      map[string]any
	allow    bool
	explicit bool
}

func runChecks(t *testing.T, e *Evaluator, checks []check) {
	t.Helper()
	for _, c := range checks {
		rc := c.ctx
		if rc == nil {
			rc = ctxAuth
		}
		d := e.Authorize(context.Background(), c.p, c.action, c.resource, rc, c.opts...)
		if d.Allowed != c.allow || (c.explicit && !d.ExplicitDeny) {
			t.Errorf("%s: %s %s as %s: allowed=%v explicit=%v (%s), want allowed=%v explicit=%v",
				c.name, c.action, c.resource, c.p.ARN(), d.Allowed, d.ExplicitDeny, d.Reason, c.allow, c.explicit)
		}
	}
}

func TestAuthorize_ExplicitDenyWins(t *testing.T) {
	w := World{
		Docs: []Policy{
			mustDoc(t, "admin", administratorAccess),
			mustDoc(t, "no-delete", `{"Statement":{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::assets/*"}}`),
		},
		Attach: map[string][]string{"User::alice": {"admin", "no-delete"}},
	}
	runChecks(t, evaluator(w), []check{
		{name: "deny wins over admin", p: user("alice"), action: "s3:DeleteObject", resource: "arn:aws:s3:::assets/k", explicit: true},
		{name: "the rest of admin stands", p: user("alice"), action: "s3:GetObject", resource: "arn:aws:s3:::assets/k", allow: true},
		{name: "deny is scoped to its resource", p: user("alice"), action: "s3:DeleteObject", resource: "arn:aws:s3:::other/k", allow: true},
	})
}

func TestAuthorize_NoPolicyIsDeniedEverywhere(t *testing.T) {
	e := evaluator(World{})
	for _, a := range []string{"s3:GetObject", "sqs:SendMessage", "iam:CreateUser", "openinfra:ListDataFlows", "openinfra-operator:ListPods"} {
		if d := e.Authorize(context.Background(), user("nobody"), a, "*", ctxAuth); d.Allowed || d.ExplicitDeny {
			t.Errorf("%s: a principal with no policy got allowed=%v explicit=%v, want a default deny", a, d.Allowed, d.ExplicitDeny)
		}
	}
}

// D1: today a User the data-plane policies do not govern for a service falls through to its coarse RBAC
// tier (a readers User reads every object). The evaluator gives no implicit authority.
func TestAuthorize_UngovernedUserIsNotAllowed(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "sqs-only", `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`)},
		Attach: map[string][]string{"User::reader": {"sqs-only"}}}
	if d := evaluator(w).Authorize(context.Background(), user("reader"), "s3:GetObject", "Bucket::any/k", ctxAuth); d.Allowed {
		t.Fatalf("a user with only an SQS policy was allowed s3:GetObject: %s", d.Reason)
	}
	// The legacy model would let it through: no data-plane policy governs s3 for it.
	if governs := CoversService(w.StatementsFor("User", "reader", nil)[0].Actions, "s3"); governs {
		t.Fatal("expected the legacy model to treat s3 as ungoverned for this user")
	}
}

func TestAuthorize_PowerUserAccessIsDeniedIAMWrites(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "PowerUserAccess", powerUserAccess)},
		Attach: map[string][]string{"Group::powerusers": {"PowerUserAccess"}}}
	p := user("pat", "powerusers")
	runChecks(t, evaluator(w), []check{
		{name: "iam write", p: p, action: "iam:CreateUser", resource: "arn:aws:iam::000000000000:user/x"},
		{name: "iam attach", p: p, action: "iam:AttachUserPolicy", resource: "arn:aws:iam::000000000000:user/x"},
		{name: "iam role policy", p: p, action: "iam:PutRolePolicy", resource: "arn:aws:iam::000000000000:role/r"},
		{name: "organizations", p: p, action: "organizations:CreateAccount", resource: "*"},
		{name: "the listed iam read", p: p, action: "iam:ListRoles", resource: "*", allow: true},
		{name: "everything else", p: p, action: "s3:PutObject", resource: "arn:aws:s3:::b/k", allow: true},
		{name: "platform kinds", p: p, action: "openinfra:CreateDataFlow", resource: "*", allow: true},
		// The operator surface (raw Kubernetes objects, Secrets among them) is no AWS service, so
		// PowerUserAccess's "everything but IAM" does not reach it.
		{name: "operator: secrets", p: p, action: "openinfra-operator:GetSecret", resource: "*"},
		{name: "operator: pods", p: p, action: "openinfra-operator:ListPod", resource: "*"},
	})
}

// Only an Allow that names the operator actions — or "*", as AdministratorAccess — grants them.
func TestAuthorize_OperatorSurfaceNeedsAnAllowThatNamesIt(t *testing.T) {
	w := World{Docs: []Policy{
		mustDoc(t, "AdministratorAccess", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`),
		mustDoc(t, "operator", `{"Statement":{"Effect":"Allow","Action":"openinfra-operator:*","Resource":"*"}}`),
		mustDoc(t, "all-but-s3", `{"Statement":{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}}`),
		mustDoc(t, "deny-all-but-s3", `{"Statement":{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}}`),
	}, Attach: map[string][]string{
		"User::admin": {"AdministratorAccess"}, "User::op": {"operator"}, "User::na": {"all-but-s3"},
		"User::denied": {"AdministratorAccess", "deny-all-but-s3"},
	}}
	runChecks(t, evaluator(w), []check{
		{name: "AdministratorAccess", p: user("admin"), action: "openinfra-operator:GetSecret", resource: "*", allow: true},
		{name: "named", p: user("op"), action: "openinfra-operator:GetSecret", resource: "*", allow: true},
		{name: "NotAction allow", p: user("na"), action: "openinfra-operator:GetSecret", resource: "*"},
		{name: "NotAction allow, elsewhere", p: user("na"), action: "sqs:SendMessage", resource: "*", allow: true},
		{name: "NotAction deny still applies", p: user("denied"), action: "openinfra-operator:GetSecret", resource: "*"},
	})
}

// The operator surface is the management account's alone: a member account's administrator, root and a
// policy naming the operator actions outright are all refused it, while the rest of AdministratorAccess
// stands in their own account.
func TestAuthorize_OperatorSurfaceIsTheManagementAccounts(t *testing.T) {
	w := World{Docs: []Policy{
		mustDoc(t, "AdministratorAccess", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`),
		mustDoc(t, "operator", `{"Statement":{"Effect":"Allow","Action":"openinfra-operator:*","Resource":"*"}}`),
	}, Attach: map[string][]string{"User::admin": {"AdministratorAccess"}, "User::op": {"operator"},
		"Role::OrganizationAccountAccessRole": {"AdministratorAccess"}}}
	const member = "900000000001"
	madmin := Principal{Account: member, Type: User, ID: "admin"}
	mop := Principal{Account: member, Type: User, ID: "op"}
	mrole := Principal{Account: member, Type: Role, ID: "OrganizationAccountAccessRole"}
	mroot := Principal{Account: member, Type: Root, ID: "root"}
	own := "arn:aws:openinfra-operator:us-east-1:" + member + ":secrets/team/s"
	runChecks(t, evaluator(w), []check{
		{name: "member administrator: a Secret", p: madmin, action: "openinfra-operator:GetSecret", resource: own},
		{name: "member administrator: pods", p: madmin, action: "openinfra-operator:ListPods", resource: "*"},
		{name: "member administrator: exec", p: madmin, action: "openinfra-operator:CreatePodExec", resource: own},
		{name: "member, a policy naming it", p: mop, action: "openinfra-operator:ListNodes", resource: "*"},
		{name: "member role session", p: mrole, action: "openinfra-operator:GetSecret", resource: own},
		{name: "member root", p: mroot, action: "openinfra-operator:ListNamespaces", resource: "*"},
		{name: "member administrator: its own bucket", p: madmin, action: "s3:CreateBucket", resource: "arn:aws:s3:::b", allow: true},
		{name: "management administrator", p: user("admin"), action: "openinfra-operator:GetSecret", resource: "*", allow: true},
	})
	if d := (*Evaluator)(nil).Authorize(context.Background(), mroot, "openinfra-operator:GetSecret", "*", ctxAuth); d.Allowed {
		t.Error("with no policy world a member account's root reached the operator surface")
	}
}

func TestAuthorize_PermissionBoundaryIntersects(t *testing.T) {
	w := World{
		Docs: []Policy{
			mustDoc(t, "s3-all", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`),
			mustDoc(t, "read-only-boundary", `{"Statement":{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}}`),
		},
		Attach:   map[string][]string{"User::bo": {"s3-all"}, "User::typo": {"s3-all"}},
		Boundary: map[string]string{"User::bo": "read-only-boundary", "User::typo": "no-such-policy"},
	}
	runChecks(t, evaluator(w), []check{
		{name: "inside the boundary", p: user("bo"), action: "s3:GetObject", resource: "Bucket::b/k", allow: true},
		{name: "outside the boundary", p: user("bo"), action: "s3:PutObject", resource: "Bucket::b/k"},
		{name: "a boundary naming no policy allows nothing", p: user("typo"), action: "s3:GetObject", resource: "Bucket::b/k"},
	})
}

func TestAuthorize_SessionPolicyIntersects(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "s3-all", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)},
		Attach: map[string][]string{"Role::deployer": {"s3-all"}}}
	sess, _, err := CompileDocument(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	if err != nil {
		t.Fatal(err)
	}
	role := Principal{Type: Role, ID: "deployer", Session: &Session{Name: "ci", Policies: sess}}
	runChecks(t, evaluator(w), []check{
		{name: "inside the session policy", p: role, action: "s3:GetObject", resource: "Bucket::b/k", allow: true},
		{name: "outside the session policy", p: role, action: "s3:PutObject", resource: "Bucket::b/k"},
		{name: "no session policy: the role's own", p: Principal{Type: Role, ID: "deployer"}, action: "s3:PutObject", resource: "Bucket::b/k", allow: true},
	})
}

func TestAuthorize_SameAccountResourcePolicyAlone(t *testing.T) {
	rp, _, err := ParseResourcePolicy(`{"Statement":[
	  {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/carol"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
	  {"Effect":"Allow","Principal":{"AWS":"000000000000"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::shared/*"},
	  {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/public/*"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	e := evaluator(World{})
	runChecks(t, e, []check{
		{name: "the resource policy names the user", p: user("carol"), action: "s3:GetObject", resource: "arn:aws:s3:::shared/k", opts: []RequestOption{WithResourcePolicy(rp)}, allow: true},
		{name: "another user", p: user("dave"), action: "s3:GetObject", resource: "arn:aws:s3:::shared/k", opts: []RequestOption{WithResourcePolicy(rp)}},
		{name: "naming the account delegates to identity policies", p: user("dave"), action: "s3:PutObject", resource: "arn:aws:s3:::shared/k", opts: []RequestOption{WithResourcePolicy(rp)}},
		{name: "public", p: user("dave"), action: "s3:GetObject", resource: "arn:aws:s3:::shared/public/x", opts: []RequestOption{WithResourcePolicy(rp)}, allow: true},
	})
}

func TestAuthorize_CrossAccountNeedsBothSides(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "send", `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`)},
		Attach: map[string][]string{"User::eve": {"send"}}}
	eve := Principal{Account: "111111111111", Type: User, ID: "eve"}
	frank := Principal{Account: "111111111111", Type: User, ID: "frank"} // no identity policy
	q := "arn:aws:sqs:us-east-1:222222222222:jobs"
	trustAcct, _, err := ParseResourcePolicy(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sqs:SendMessage","Resource":"*"}}`)
	if err != nil {
		t.Fatal(err)
	}
	trustFrank, _, _ := ParseResourcePolicy(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/frank"},"Action":"sqs:SendMessage","Resource":"*"}}`)
	runChecks(t, evaluator(w), []check{
		{name: "identity only", p: eve, action: "sqs:SendMessage", resource: q},
		{name: "identity and the resource policy", p: eve, action: "sqs:SendMessage", resource: q, opts: []RequestOption{WithResourcePolicy(trustAcct)}, allow: true},
		{name: "resource policy only", p: frank, action: "sqs:SendMessage", resource: q, opts: []RequestOption{WithResourcePolicy(trustFrank)}},
		{name: "the account given explicitly", p: eve, action: "sqs:SendMessage", resource: "Queue::jobs", opts: []RequestOption{WithResourceAccount("222222222222")}},
	})
}

// An identity policy naming another account's resource grants nothing on a same-named resource of the
// caller's own account (ARNs carry the account).
func TestAuthorize_ARNAccountConstrains(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "theirs", `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:222222222222:jobs"}}`)},
		Attach: map[string][]string{"User::eve": {"theirs"}}}
	eve := Principal{Account: "111111111111", Type: User, ID: "eve"}
	runChecks(t, evaluator(w), []check{
		{name: "own account's queue of the same name", p: eve, action: "sqs:SendMessage", resource: "arn:aws:sqs:us-east-1:111111111111:jobs"},
	})
}

func TestAuthorize_NotActionAndNotResource(t *testing.T) {
	w := World{Docs: []Policy{
		mustDoc(t, "all-but-secret", `{"Statement":{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret"}}`),
		mustDoc(t, "no-deletes", `{"Statement":{"Effect":"Deny","NotAction":["s3:Get*","s3:List*","s3:Put*"],"Resource":"*"}}`),
	}, Attach: map[string][]string{"User::gil": {"all-but-secret", "no-deletes"}}}
	runChecks(t, evaluator(w), []check{
		{name: "not the excluded bucket's objects", p: user("gil"), action: "s3:GetObject", resource: "Bucket::secret/k"},
		{name: "other buckets", p: user("gil"), action: "s3:GetObject", resource: "Bucket::open/k", allow: true},
		{name: "deny every other action", p: user("gil"), action: "s3:DeleteObject", resource: "Bucket::open/k", explicit: true},
	})
}

func TestAuthorize_Conditions(t *testing.T) {
	w := World{Docs: []Policy{
		mustDoc(t, "office", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}}`),
		mustDoc(t, "tagged", `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"x"}}}}`),
		mustDoc(t, "deny-untagged", `{"Statement":{"Effect":"Deny","Action":"sns:*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}}`),
		mustDoc(t, "sns", `{"Statement":{"Effect":"Allow","Action":"sns:*","Resource":"*"}}`),
	}, Attach: map[string][]string{"User::hal": {"office", "tagged", "deny-untagged", "sns"}}}
	in := map[string]any{"authenticated": true, "sourceIp": "10.1.2.3"}
	out := map[string]any{"authenticated": true, "sourceIp": "192.168.1.9"}
	runChecks(t, evaluator(w), []check{
		{name: "condition holds", p: user("hal"), action: "s3:GetObject", resource: "Bucket::b/k", ctx: in, allow: true},
		{name: "condition fails", p: user("hal"), action: "s3:GetObject", resource: "Bucket::b/k", ctx: out},
		{name: "an Allow with an unsupported condition grants nothing", p: user("hal"), action: "sqs:SendMessage", resource: "Queue::q"},
		{name: "a Deny with an unsupported condition applies unconditionally", p: user("hal"), action: "sns:Publish", resource: "Topic::t", explicit: true},
	})
	if r := mustDoc(t, "x", `{"Statement":{"Effect":"Deny","Action":"sns:*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}}`).Report; len(r) == 0 || !strings.Contains(r[0], "unconditionally") {
		t.Errorf("the unconditional Deny is not reported: %v", r)
	}
}

func TestAuthorize_RootOfTheAccount(t *testing.T) {
	root := Principal{Type: Root, ID: "root"}
	deny, _, _ := ParseResourcePolicy(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::locked"}}`)
	runChecks(t, evaluator(World{}), []check{
		{name: "anything in its own account", p: root, action: "iam:CreateUser", resource: "*", allow: true},
		{name: "a resource policy's Deny still applies", p: root, action: "s3:DeleteBucket", resource: "arn:aws:s3:::locked", opts: []RequestOption{WithResourcePolicy(deny)}, explicit: true},
		{name: "another account's resource", p: root, action: "sqs:SendMessage", resource: "arn:aws:sqs:us-east-1:222222222222:q"},
	})
}

func TestAuthorize_GroupsArePolicyContainers(t *testing.T) {
	w := World{
		Docs:   []Policy{mustDoc(t, "ReadOnly", `{"Statement":{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}}`)},
		Attach: map[string][]string{"Group::readers": {"ReadOnly"}, "Group::users": {"ReadOnly"}},
		Inline: map[string][]Policy{"Group::dev": {mustDoc(t, "dev-writes", `{"Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}}`)}},
	}
	runChecks(t, evaluator(w), []check{
		{name: "a group's managed policy", p: user("ivy", "readers"), action: "s3:GetObject", resource: "Bucket::b/k", allow: true},
		{name: "a group's inline policy", p: user("ivy", "dev"), action: "s3:PutObject", resource: "Bucket::b/k", allow: true},
		{name: "no group", p: user("ivy"), action: "s3:GetObject", resource: "Bucket::b/k"},
	})
	// D5: the implicit users group confers nothing — a principal from claims with no groups is in none.
	p := PrincipalFromClaims(iam.Claims{Sub: "joe", Groups: iam.GroupsFromSpec(nil)}, "")
	if len(p.Groups) != 0 {
		t.Fatalf("groups from the implicit users group: %v", p.Groups)
	}
	if d := evaluator(w).Authorize(context.Background(), p, "s3:GetObject", "Bucket::b/k", ctxAuth); d.Allowed {
		t.Fatal("a policy attached to the implicit users group reached a principal with no groups")
	}
}

func TestAuthorize_PlatformKindsByARN(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "team", `{"Statement":{"Effect":"Allow","Action":"openinfra:*DataFlow","Resource":"arn:aws:openinfra:us-east-1:000000000000:dataflow/team/*"}}`)},
		Attach: map[string][]string{"User::kai": {"team"}}}
	runChecks(t, evaluator(w), []check{
		{name: "its namespace", p: user("kai"), action: "openinfra:CreateDataFlow", resource: "arn:aws:openinfra:us-east-1:000000000000:dataflow/team/f", allow: true},
		{name: "another namespace", p: user("kai"), action: "openinfra:CreateDataFlow", resource: "arn:aws:openinfra:us-east-1:000000000000:dataflow/other/f"},
		{name: "another action", p: user("kai"), action: "openinfra:CreateQuery", resource: "arn:aws:openinfra:us-east-1:000000000000:dataflow/team/f"},
	})
}

func TestAuthorize_MatchedPolicyAndFailClosedLoad(t *testing.T) {
	w := World{Docs: []Policy{mustDoc(t, "AdministratorAccess", administratorAccess)}, Attach: map[string][]string{"User::lu": {"AdministratorAccess"}}}
	if d := evaluator(w).Authorize(context.Background(), user("lu"), "s3:GetObject", "*", ctxAuth); !d.Allowed || d.MatchedPolicy != "AdministratorAccess" {
		t.Errorf("got %+v, want allowed by AdministratorAccess", d)
	}
	broken := New(func(context.Context) (World, error) { return World{}, context.DeadlineExceeded }, 0, WithMode(ModeEnforce))
	if d := broken.Authorize(context.Background(), user("lu"), "s3:GetObject", "*", ctxAuth); d.Allowed {
		t.Error("an unloadable policy world allowed a request")
	}
}

func TestDecide_Modes(t *testing.T) {
	w := World{Enforce: map[string]bool{"User::canary": true}}
	legacyAllows := func() (bool, string) { return true, "legacy" }
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	load := func(context.Context) (World, error) { return w, nil }
	ctx := context.Background()

	if d := New(load, 0, WithMode(ModeLegacy), WithLogger(log)).Decide(ctx, user("x"), "s3:GetObject", "*", ctxAuth, legacyAllows); !d.Allowed || d.Mode != ModeLegacy {
		t.Errorf("legacy: %+v", d)
	}
	shadow := New(load, 0, WithMode(ModeShadow), WithLogger(log))
	if d := shadow.Decide(ctx, user("x"), "s3:GetObject", "Bucket::b/k", ctxAuth, legacyAllows); !d.Allowed || d.Mode != ModeShadow {
		t.Errorf("shadow must return the legacy decision: %+v", d)
	}
	if !strings.Contains(buf.String(), "iam-shadow deny") || !strings.Contains(buf.String(), "legacy=allow") {
		t.Errorf("shadow difference not logged: %q", buf.String())
	}
	if d := shadow.Decide(ctx, user("canary"), "s3:GetObject", "Bucket::b/k", ctxAuth, legacyAllows); d.Allowed || d.Mode != ModeEnforce {
		t.Errorf("a canary-labelled principal must be enforced: %+v", d)
	}
	if d := New(load, 0, WithMode(ModeLegacy)).Decide(ctx, user("canary"), "s3:GetObject", "*", ctxAuth, legacyAllows); !d.Allowed {
		t.Error("legacy is a full rollback: the canary label must not enforce")
	}
	if d := New(load, 0, WithMode(ModeEnforce)).Decide(ctx, user("x"), "s3:GetObject", "*", ctxAuth, legacyAllows); d.Allowed || d.Mode != ModeEnforce {
		t.Errorf("enforce: %+v", d)
	}
	if ParseMode("bogus") != ModeLegacy || ParseMode(" Enforce ") != ModeEnforce {
		t.Error("ParseMode")
	}
}

// Old-vs-new equivalence on today's policies: an assumed role was already evaluated as AWS does (its
// policies alone, default deny), so the evaluator and the legacy checker agree on every request; so do
// a User's requests on a service its policies govern, wherever its coarse RBAC tier allows.
func TestAuthorize_AgreesWithTheLegacyModelWhereItWasAlreadyAWS(t *testing.T) {
	w := World{
		Docs: []Policy{
			{Name: "app", Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"s3:GetObject", "s3:PutObject"}, Resources: []string{"Bucket::app"}},
				{Effect: policyengine.Deny, Actions: []string{"s3:PutObject"}, Resources: []string{"Bucket::app/locked/*"}},
				{Effect: policyengine.Allow, Actions: []string{"sqs:*"}, Resources: []string{"Queue::jobs"}},
			}},
			{Name: "tables", AppliesTo: []string{"Role::worker"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"dynamodb:GetItem"}, Resources: []string{"Table::*"}},
			}},
		},
		Attach: map[string][]string{"Role::worker": {"app"}, "User::uma": {"app"}},
	}
	load := func(context.Context) (World, error) { return w, nil }
	e := New(load, 0, WithMode(ModeEnforce))
	legacy := legacyDecide(w)
	reqs := []struct{ action, typ, id string }{
		{"s3:GetObject", "Bucket", "app/k"}, {"s3:PutObject", "Bucket", "app/k"}, {"s3:PutObject", "Bucket", "app/locked/k"},
		{"s3:GetObject", "Bucket", "other/k"}, {"s3:DeleteObject", "Bucket", "app/k"}, {"sqs:SendMessage", "Queue", "jobs"},
		{"sqs:SendMessage", "Queue", "other"}, {"dynamodb:GetItem", "Table", "t"}, {"kms:Decrypt", "Key", "k"},
	}
	for _, r := range reqs {
		for _, p := range []Principal{{Type: Role, ID: "worker"}, {Type: User, ID: "uma"}} {
			gotOld, governed := legacy(string(p.Type), p.ID, r.action, r.typ, r.id)
			if p.Type == User && !governed {
				continue // the legacy model deferred to the coarse RBAC tier here (D1)
			}
			if d := e.Authorize(context.Background(), p, r.action, r.typ+"::"+r.id, ctxAuth); d.Allowed != gotOld {
				t.Errorf("%s %s %s::%s: evaluator %v, legacy %v", p.Type, r.action, r.typ, r.id, d.Allowed, gotOld)
			}
		}
	}
}

// legacyDecide is the legacy data-plane decision (dataplaneauthz.Checker.Decide), restated here over a
// World so the equivalence test has no import cycle.
func legacyDecide(w World) func(ptype, pid, action, typ, id string) (allowed, governed bool) {
	return func(ptype, pid, action, typ, id string) (bool, bool) {
		stmts := w.StatementsFor(ptype, pid, nil)
		service := ServiceOf(action)
		governs := false
		for _, s := range stmts {
			if CoversService(s.Actions, service) || NotActionsCoverService(s.NotActions, service) {
				governs = true
			}
		}
		if !governs && ptype != "Role" {
			return true, false
		}
		eng, err := policyengine.NewEngine(stmts)
		if err != nil {
			return false, true
		}
		return eng.Authorize(policyengine.Request{Principal: policyengine.Principal{Type: ptype, ID: pid}, Action: action,
			Resource: policyengine.Resource{Type: typ, ID: id}, Context: ctxAuth}).Allowed, true
	}
}

func TestPrincipalFromClaims(t *testing.T) {
	if p := PrincipalFromClaims(iam.Claims{Sub: "root", Role: "root"}, ""); p.Type != Root || p.ARN() != "arn:aws:iam::000000000000:root" {
		t.Errorf("root: %+v %s", p, p.ARN())
	}
	if p := PrincipalFromClaims(iam.Claims{Sub: "ops", Role: "admin"}, ""); p.Type != User || len(p.Groups) != 1 || p.Groups[0] != "admins" {
		t.Errorf("Secret-backed admin: %+v", p)
	}
	p := PrincipalFromClaims(iam.Claims{Sub: "deployer/ci-run", AssumedRole: "deployer", Account: "123456789012"}, "")
	if p.Type != Role || p.Session == nil || p.ARN() != "arn:aws:sts::123456789012:assumed-role/deployer/ci-run" {
		t.Errorf("assumed role: %+v %s", p, p.ARN())
	}
	if p := PrincipalFromClaims(iam.Claims{Sub: "x", Groups: []string{"openinfra:dev", "openinfra:users"}}, ""); len(p.Groups) != 1 || p.Groups[0] != "dev" {
		t.Errorf("groups: %v", p.Groups)
	}
	if got := (Principal{Account: "123456789012", Type: User, ID: "team/alice"}).ARN(); got != "arn:aws:iam::123456789012:user/alice" {
		t.Errorf("namespaced user ARN: %s", got)
	}
}

func TestCompileDocument_RejectsMalformed(t *testing.T) {
	for _, doc := range []string{`not json`, `{"Statement":{"Effect":"Maybe","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","NotAction":"s3:*","Resource":"*"}}`} {
		if _, _, err := CompileDocument(doc); err == nil {
			t.Errorf("accepted %s", doc)
		}
	}
}
