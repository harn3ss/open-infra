package main

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

// enforceChecker is a data-plane checker whose IAM evaluator runs in mode (IAM_AUTHZ is read when the
// checker is built), over docs.
func checkerInMode(t *testing.T, mode string, docs ...dataplaneauthz.PolicyDoc) *dataplaneauthz.Checker {
	t.Helper()
	t.Setenv(iamauthz.EnvMode, mode)
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: docs}, nil
	}, time.Minute)
}

func userDoc(stmts ...policyengine.Statement) dataplaneauthz.PolicyDoc {
	return dataplaneauthz.PolicyDoc{Name: "user-policy", AppliesTo: []string{"User::tester"}, Statements: stmts}
}

func roleDoc(stmts ...policyengine.Statement) dataplaneauthz.PolicyDoc {
	return dataplaneauthz.PolicyDoc{Name: "role-policy", AppliesTo: []string{"Role::" + ecrTestRole}, Statements: stmts}
}

// The account's root user, as the shim sees it: the Secret-backed root (role root, no groups).
var rootClaims = iam.Claims{Sub: "root", Role: "root"}

// In enforce, every front door is IAM policy alone, with AWS's evaluation logic. The SubjectAccessReview
// allows everything in every case here, so a denial can only come from IAM policy: a User with no policy
// is denied (the coarse RBAC grant no longer counts), exactly its policy allows, an explicit Deny wins; an
// assumed role likewise; the account's root user is allowed with no policy at all.
func TestEnforce_EveryFrontDoorIsIAMPolicyAlone(t *testing.T) {
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
	role := ecrRoleClaims()
	for _, tc := range roleDoorCases() {
		tc := tc
		t.Run(tc.door+"/"+tc.op, func(t *testing.T) {
			service := strings.SplitN(tc.action, ":", 2)[0]
			expect := func(name string, authz *dataplaneauthz.Checker, claims iam.Claims, wantDenied bool) {
				t.Helper()
				w := tc.call(t, authz, claims)
				if got := isDenied(w, tc.denyCode); got != wantDenied {
					t.Errorf("%s: denied=%v, want %v (status %d, body %.300s)", name, got, wantDenied, w.Code, w.Body.String())
				}
			}
			expect("user with no policy (RBAC allows)", checkerInMode(t, "enforce"), user, true)
			expect("user with "+tc.action+" on *", checkerInMode(t, "enforce", userDoc(dpAllow([]string{tc.action}, "*"))), user, false)
			expect("user with "+service+":* on *", checkerInMode(t, "enforce", userDoc(dpAllow([]string{service + ":*"}, "*"))), user, false)
			expect("user with an explicit Deny", checkerInMode(t, "enforce", userDoc(dpAllow([]string{"*"}, "*"), dpDeny([]string{tc.action}, "*"))), user, true)
			expect("user with only another service", checkerInMode(t, "enforce", userDoc(dpAllow([]string{"nosuchservice:*"}, "*"))), user, true)
			if tc.resName != "" {
				expect("user with "+tc.action+" on "+tc.resType+"::"+tc.resName,
					checkerInMode(t, "enforce", userDoc(dpAllow([]string{tc.action}, tc.resType+"::"+tc.resName))), user, false)
				expect("user with "+tc.action+" on another resource",
					checkerInMode(t, "enforce", userDoc(dpAllow([]string{tc.action}, tc.resType+"::some-other"))), user, true)
			}
			expect("role with no policy", checkerInMode(t, "enforce"), role, true)
			expect("role with "+tc.action+" on *", checkerInMode(t, "enforce", roleDoc(dpAllow([]string{tc.action}, "*"))), role, false)
			// Root is allowed by IAM policy everywhere in its account; where the door then writes as the
			// caller (CloudFormation's impersonating applier) the shim refuses to act as root, whose
			// identities its impersonation ceiling denies (root has no access keys).
			if tc.door == "cloudformation" {
				w := tc.call(t, checkerInMode(t, "enforce"), rootClaims)
				if !strings.Contains(w.Body.String(), "never acts as the account") {
					t.Errorf("CloudFormation must not act as root: status %d, body %.300s", w.Code, w.Body.String())
				}
				return
			}
			expect("the account's root user, no policy", checkerInMode(t, "enforce"), rootClaims, false)
		})
	}
}

// The shim never impersonates root: neither of its names (openinfra:root, openinfra:<account>:root) is
// ever an identity the shim writes as, in any mode or case; a role named root is a role.
func TestCallerIdentity_NeverRoot(t *testing.T) {
	for _, mode := range []string{"legacy", "enforce"} {
		authz := checkerInMode(t, mode)
		for _, c := range []iam.Claims{rootClaims, {Sub: "root", Groups: []string{"openinfra:admins"}}, {Sub: "ROOT"},
			{Sub: "root", Account: testMgmt}, {Sub: "Root", Account: testMember}} {
			if user, _, ok := callerIdentity(context.Background(), authz, c); ok {
				t.Errorf("%s: %+v acts as %s, want no identity", mode, c, user)
			}
		}
		if user, _, ok := callerIdentity(context.Background(), authz, iam.Claims{Sub: "alice"}); !ok || user == "" {
			t.Errorf("%s: alice must have an identity", mode)
		}
	}
	if user, _, ok := callerIdentity(context.Background(), checkerInMode(t, "enforce"),
		iam.Claims{Sub: "root/s1", AssumedRole: "root"}); !ok || user != "openinfra:"+iam.ManagementAccount+":role/root" {
		t.Errorf("a role named root is a role: %q %v", user, ok)
	}
}

// Legacy is today's decision: with IAM_AUTHZ unset (or legacy) the coarse RBAC grant still lets a User
// with no policy through, as before — the mode is the only switch.
func TestLegacy_UserWithNoPolicyKeepsItsRBACGrant(t *testing.T) {
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
	for _, tc := range roleDoorCases() {
		if w := tc.call(t, checkerInMode(t, "legacy"), user); isDenied(w, tc.denyCode) {
			t.Errorf("%s/%s: a User with RBAC and no policy was denied in legacy (status %d, %.200s)", tc.door, tc.op, w.Code, w.Body.String())
		}
	}
}

// Shadow returns legacy's decision and logs where IAM policy differs.
func TestShadow_ReturnsLegacyAndLogsTheDifference(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	authz := checkerInMode(t, "shadow")
	h := newSQSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
	h.authz = authz
	w := serveWith(h, jsonOp("AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`), testUser)
	if isDenied(w, "AccessDenied") {
		t.Fatalf("shadow must return legacy's allow: %d %s", w.Code, w.Body)
	}
	if out := buf.String(); !strings.Contains(out, "iam-shadow deny") || !strings.Contains(out, "sqs:CreateQueue") ||
		!strings.Contains(out, "legacy=allow") {
		t.Fatalf("shadow must log IAM's deny beside legacy's allow, got: %s", out)
	}
	// A principal labelled as a canary is enforced while the platform shadows.
	canary := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Enforce: map[string]bool{"User::tester": true}}, nil
	}, time.Minute)
	h.authz = canary
	if w := serveWith(h, jsonOp("AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`), testUser); !isDenied(w, "AccessDenied") {
		t.Fatalf("a canary principal with no policy must be denied in shadow: %d %s", w.Code, w.Body)
	}
}

// AWS's PowerUserAccess, as AWS writes it (NotAction iam:*, organizations:*, account:*), is denied IAM
// writes through the IAM API and allowed elsewhere.
func TestEnforce_PowerUserAccessIsDeniedIAMWrites(t *testing.T) {
	stmts, _, err := iamauthz.CompileDocument(`{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},
	  {"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles",
	    "organizations:DescribeOrganization","account:ListRegions"],"Resource":"*"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	authz := checkerInMode(t, "enforce", dataplaneauthz.PolicyDoc{Name: "PowerUserAccess", AppliesTo: []string{"User::tester"}, Statements: stmts})
	ih := newIAMHandler(csWithSAR(true), fakeDynWith(gvrRoles, gvrPolicies, gvrUsers), nil, authz, "open-infra-console", "000000000000", "us-east-1", discardLogger())
	for _, form := range []url.Values{
		{"Action": {"CreateUser"}, "UserName": {"x"}},
		{"Action": {"AttachUserPolicy"}, "UserName": {"tester"}, "PolicyArn": {"arn:aws:iam::aws:policy/AdministratorAccess"}},
		{"Action": {"AddUserToGroup"}, "UserName": {"tester"}, "GroupName": {"admins"}},
		{"Action": {"PutUserPolicy"}, "UserName": {"tester"}, "PolicyName": {"p"}, "PolicyDocument": {"{}"}},
		{"Action": {"DeleteUserPermissionsBoundary"}, "UserName": {"tester"}},
		{"Action": {"PutRolePolicy"}, "RoleName": {"r"}, "PolicyName": {"p"}, "PolicyDocument": {"{}"}},
		{"Action": {"CreateAccessKey"}, "UserName": {"x"}},
	} {
		if w := serveWith(ih, formOp(form), testUser); !isDenied(w, "AccessDenied") {
			t.Errorf("PowerUserAccess %s: %d %.200s, want AccessDenied", form.Get("Action"), w.Code, w.Body.String())
		}
	}
	sh := newSQSHandler(csWithSAR(false), "default", "open-infra", "us-east-1", nil, discardLogger())
	sh.authz = authz
	if w := serveWith(sh, jsonOp("AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`), testUser); isDenied(w, "AccessDenied") {
		t.Errorf("PowerUserAccess must allow SQS (with RBAC denying): %d %s", w.Code, w.Body)
	}
}

// Across accounts, IAM policy needs both sides, as AWS: a member account's user with an identity grant is
// denied a management-account queue unless the queue's own policy names its account, and a resource
// policy alone does not let it in. The member's user is its home's (memberHome/bob), and a member
// account's principal is decided by IAM policy whatever the mode.
func TestEnforce_CrossAccountNeedsTheResourcePolicyToo(t *testing.T) {
	member := iam.Claims{Sub: "bob", Account: testMember, Groups: []string{"openinfra:users"}}
	grant := dataplaneauthz.PolicyDoc{Name: "bob-sqs", AppliesTo: []string{"User::" + memberHome + "/bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"sqs:SendMessage"}, "*")}}
	queuePolicy := func(acct string) []iamauthz.RequestOption {
		stmts, _, err := iamauthz.ParseResourcePolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + acct +
			`:root"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:000000000000:jobs"}]}`)
		if err != nil {
			t.Fatal(err)
		}
		return []iamauthz.RequestOption{iamauthz.WithResourcePolicy(stmts), iamauthz.WithResourceAccount(testMgmt)}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := withAccountHome(context.Background(), memberHome)
	check := func(name string, authz *dataplaneauthz.Checker, opts []iamauthz.RequestOption, want bool) {
		t.Helper()
		opts = append(opts, iamauthz.WithResourceAccount(testMgmt))
		if ok, why := decide(ctx, r, authz, member, "sqs:SendMessage", "Queue", "jobs", nil, opts...); ok != want {
			t.Errorf("%s: allowed=%v (%s), want %v", name, ok, why, want)
		}
	}
	withGrant := checkerInMode(t, "enforce", grant)
	check("identity grant, no resource policy", withGrant, nil, false)
	check("identity grant, the queue's policy names the member account", withGrant, queuePolicy(testMember), true)
	check("identity grant, the queue's policy names another account", withGrant, queuePolicy("955555555555"), false)
	check("no identity grant, the queue's policy names the member account", checkerInMode(t, "enforce"), queuePolicy(testMember), false)
	check("in legacy, identity grant, the queue's policy names the member account", checkerInMode(t, "legacy", grant), queuePolicy(testMember), true)
	check("in legacy, identity grant, no resource policy", checkerInMode(t, "legacy", grant), nil, false)
}

// A member account's user is never the management account's user of the same name: the management
// account's bob's grant does not reach the member's bob, in its own account or any other, and a member
// account's principal with no home on the request is no principal any policy names.
func TestEnforce_MemberUserIsNotTheManagementUserOfItsName(t *testing.T) {
	mgmtBob := dataplaneauthz.PolicyDoc{Name: "bob-admin", AppliesTo: []string{"User::bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"*"}, "*")}}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	member := iam.Claims{Sub: "bob", Account: testMember}
	authz := checkerInMode(t, "enforce", mgmtBob)
	for _, ctx := range []context.Context{withAccountHome(context.Background(), memberHome), context.Background()} {
		if ok, why := decide(ctx, r, authz, member, "sqs:SendMessage", "Queue", "jobs", nil); ok {
			t.Errorf("the member account's bob was allowed by the management account's bob's policy (%s)", why)
		}
	}
	if ok, why := decide(context.Background(), r, authz, iam.Claims{Sub: "bob"}, "sqs:SendMessage", "Queue", "jobs", nil); !ok {
		t.Errorf("the management account's bob must keep its own policy: %s", why)
	}
	group := dataplaneauthz.PolicyDoc{Name: "devs", AppliesTo: []string{"Group::" + memberHome + "/devs"},
		Statements: []policyengine.Statement{dpAllow([]string{"sqs:SendMessage"}, "*")}}
	inGroup := iam.Claims{Sub: "bob", Account: testMember, Groups: []string{"openinfra:devs"}}
	if ok, why := decide(withAccountHome(context.Background(), memberHome), r, checkerInMode(t, "enforce", group), inGroup,
		"sqs:SendMessage", "Queue", "jobs", nil, iamauthz.WithResourceAccount(testMember)); !ok {
		t.Errorf("a member account's group in its home must apply to its members: %s", why)
	}
	// A door's resource is the management account's unless the door names its account: a member
	// account's identity grant alone does not reach it.
	if ok, _ := decide(withAccountHome(context.Background(), memberHome), r, checkerInMode(t, "enforce", group), inGroup,
		"sqs:SendMessage", "Queue", "jobs", nil); ok {
		t.Error("a member account's principal reached a management-account queue on its identity policy alone")
	}
}

// The denial a caller sees in enforce is AWS's: who, what, on what.
func TestEnforce_DenialIsAWSShaped(t *testing.T) {
	authz := checkerInMode(t, "enforce")
	_, why := decide(context.Background(), httptest.NewRequest(http.MethodPost, "/", nil), authz,
		iam.Claims{Sub: "alice"}, "sqs:SendMessage", "Queue", "jobs", nil)
	want := "User: arn:aws:iam::000000000000:user/alice is not authorized to perform: sqs:SendMessage on resource: Queue::jobs"
	if !strings.HasPrefix(why, want) {
		t.Fatalf("denial %q, want prefix %q", why, want)
	}
}

// Every legacy authorization check — the coarse SubjectAccessReview (iam.CanDo) and the data-plane
// refinements — runs only as a front door's legacy decision: inside a function literal handed to decide /
// decision / decideEach (so legacy, shadow and enforce all apply), inside the shared legacy closures, or in
// a function that is itself only a legacy decision. A check outside them would keep deciding in enforce,
// beside IAM policy: a second, divergent authorization plane.
func TestEveryLegacyCheckRunsOnlyAsALegacyDecision(t *testing.T) {
	checks := map[string]bool{"dataPlaneDenied": true, "deniedByDataPlane": true, "dataPlaneVerdict": true, "allowedForAssumedRole": true}
	deciders := map[string]bool{"decide": true, "decision": true, "decideEach": true}
	// Files and functions whose every call is a legacy decision by construction, each with its reason.
	allowedFiles := map[string]string{
		"authz_decide.go":   "the shared legacy closures themselves",
		"policycheck.go":    "the legacy data-plane refinement itself",
		"s3.go":             "S3 authorizes through internal/s3authz, which decides through iamauthz itself",
		"cfn_authz_test.go": "",
	}
	allowedFuncs := map[string]string{
		"canDo":                "CloudFormation's coarse gate: every caller passes it inside a legacy closure",
		"legacyAuthorizeScope": "the ECR token's decision before IAM policy (decided per action in authorizeScope)",
		"identityDenied":       "SES's legacy branch; in enforce it returns identityDeniedIAM first",
	}
	fset := token.NewFileSet()
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, e := range files {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, ok := allowedFiles[name]; ok {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, ok := allowedFuncs[fn.Name.Name]; ok {
				continue
			}
			var stack []ast.Node
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := calleeName(call.Fun)
				if callee != "iam.CanDo" && !checks[callee] {
					return true
				}
				if insideDeciderLiteral(stack, deciders) {
					return true
				}
				bad = append(bad, fset.Position(call.Pos()).String()+" "+fn.Name.Name+": "+callee)
				return true
			})
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("legacy authorization checks outside a front door's legacy decision (wrap them in decide's legacy closure):\n%s", strings.Join(bad, "\n"))
	}
}

func calleeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
		return x.Sel.Name
	}
	return ""
}

// insideDeciderLiteral reports whether the innermost node on stack sits in a function literal that is an
// argument of a decide / decision / decideEach call, directly or through a call that builds the closure.
func insideDeciderLiteral(stack []ast.Node, deciders map[string]bool) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		if _, ok := stack[i].(*ast.FuncLit); !ok {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if call, ok := stack[j].(*ast.CallExpr); ok && deciders[calleeName(call.Fun)] {
				return true
			}
		}
	}
	return false
}
