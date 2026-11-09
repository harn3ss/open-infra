package iamauthz

import (
	"context"
	"testing"
	"time"
)

func TestAuthorizeTrust_MFAConditions(t *testing.T) {
	const acct = "123456789012"
	alice := Principal{Account: acct, Type: User, ID: "alice"}
	role := "arn:aws:iam::" + acct + ":role/admin"
	requireMFA := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + acct + `"},
	  "Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`
	noMFA := map[string]any{"authenticated": true, "multiFactorAuthPresent": false}
	withMFA := map[string]any{"authenticated": true, "multiFactorAuthPresent": true, "multiFactorAuthAge": int64(20)}
	longTerm := map[string]any{"authenticated": true}

	if ok, why := AuthorizeTrust(requireMFA, alice, "sts:AssumeRole", role, withMFA); !ok {
		t.Errorf("an MFA-authenticated caller of the trusted account must assume: %s", why)
	}
	for name, ctx := range map[string]map[string]any{"session without MFA": noMFA, "long-term key": longTerm} {
		if ok, _ := AuthorizeTrust(requireMFA, alice, "sts:AssumeRole", role, ctx); ok {
			t.Errorf("%s: a trust policy requiring MFA must refuse it", name)
		}
	}
	other := Principal{Account: "999999999999", Type: User, ID: "alice"}
	if ok, _ := AuthorizeTrust(requireMFA, other, "sts:AssumeRole", role, withMFA); ok {
		t.Error("a caller of another account is not named by the trust policy")
	}

	// A Deny naming the caller, with its condition met, refuses; an age limit is a Numeric condition.
	denyStale := `{"Statement":[
	  {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + acct + `:user/alice"},"Action":"sts:AssumeRole"},
	  {"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"NumericGreaterThanIfExists":{"aws:MultiFactorAuthAge":"900"}}}]}`
	if ok, why := AuthorizeTrust(denyStale, alice, "sts:AssumeRole", role, withMFA); !ok {
		t.Errorf("a fresh MFA passes the age limit: %s", why)
	}
	stale := map[string]any{"multiFactorAuthPresent": true, "multiFactorAuthAge": int64(3600)}
	if ok, _ := AuthorizeTrust(denyStale, alice, "sts:AssumeRole", role, stale); ok {
		t.Error("an hour-old MFA must be refused by the age Deny")
	}
	if ok, _ := AuthorizeTrust(denyStale, alice, "sts:AssumeRole", role, longTerm); ok {
		t.Error("IfExists matches an absent age: a long-term key is refused")
	}

	// A trust condition the platform cannot evaluate never widens: its Allow grants nothing.
	externalID := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}}}`
	if ok, _ := AuthorizeTrust(externalID, alice, "sts:AssumeRole", role, withMFA); ok {
		t.Error("an unsupported trust condition must not be dropped into a grant")
	}
	// No conditions: the document adds nothing to the principals spec.trust holds (whatever account
	// spelling its ARNs use).
	plain := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::open-infra:user/alice"},"Action":"sts:AssumeRole"}}`
	if ok, why := AuthorizeTrust(plain, alice, "sts:AssumeRole", role, longTerm); !ok {
		t.Errorf("an unconditioned trust adds nothing: %s", why)
	}
	if ok, _ := AuthorizeTrust("not json", alice, "sts:AssumeRole", role, longTerm); ok {
		t.Error("a trust document that does not parse allows nothing")
	}
}

// A role's spec.trust reads as an AWS trust policy's principals: a bare name is a user of the role's own
// account, an account id is that account, and entries naming no IAM principal name no one.
func TestTrustStatements_ReadAsATrustPolicy(t *testing.T) {
	const roleAcct, other = "111122223333", "444455556666"
	stmts, err := TrustStatements([]string{"alice", "User::bob", "Role::ops", other,
		"arn:aws:iam::" + other + ":user/carol", "system:serviceaccount:team:app", "OIDC::idp", "vm", "team/ops"}, roleAcct)
	if err != nil || len(stmts) != 1 {
		t.Fatalf("TrustStatements: %v (%d statements)", err, len(stmts))
	}
	for _, c := range []struct {
		p    Principal
		want string
	}{
		{Principal{Account: roleAcct, Type: User, ID: "alice"}, "specific"},
		{Principal{Account: roleAcct, Type: User, ID: "bob"}, "specific"},
		{Principal{Account: roleAcct, Type: Role, ID: "ops", Session: &Session{Name: "s"}}, "specific"},
		{Principal{Account: other, Type: User, ID: "carol"}, "specific"},
		{Principal{Account: other, Type: User, ID: "dave"}, "account"},
		{Principal{Account: other, Type: User, ID: "alice"}, "account"}, // the role account's alice, not this one
		{Principal{Account: "777788889999", Type: User, ID: "alice"}, ""},
		{Principal{Account: roleAcct, Type: User, ID: "erin"}, ""},
	} {
		if got := stmts[0].appliesToPrincipal(c.p); got != c.want {
			t.Errorf("%s: %q, want %q", c.p.ARN(), got, c.want)
		}
	}
	if s, err := TrustStatements([]string{"system:serviceaccount:team:app", "vm", ""}, roleAcct); err != nil || s != nil {
		t.Errorf("a trust naming no IAM principal is no statement: %v %v", s, err)
	}

	// Through the evaluator: another account's role needs the trust and the caller's policy; in the role's
	// own account a trust naming the caller is enough.
	admin := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`
	adminStmts, _, err := CompileDocument(admin)
	if err != nil {
		t.Fatal(err)
	}
	w := World{Docs: []Policy{{Name: "assume", Statements: adminStmts}}, Attach: map[string][]string{"User::dave": {"assume"}},
		Boundary: map[string]string{}, Inline: map[string][]Policy{}, Enforce: map[string]bool{}}
	e := New(func(context.Context) (World, error) { return w, nil }, time.Minute, WithMode(ModeEnforce))
	role := "arn:aws:iam::" + roleAcct + ":role/target"
	for _, c := range []struct {
		name  string
		p     Principal
		trust []string
		want  bool
	}{
		{"another account's caller, trusted by account and allowed by its policy", Principal{Account: other, Type: User, ID: "dave"}, []string{other}, true},
		{"…with no trust", Principal{Account: other, Type: User, ID: "dave"}, nil, false},
		{"…named by a bare name, which is the role account's user", Principal{Account: other, Type: User, ID: "dave"}, []string{"dave"}, false},
		{"another account's caller no policy allows, though trusted", Principal{Account: other, Type: User, ID: "carol"}, []string{other}, false},
		{"the role account's own user named by the trust, with no policy", Principal{Account: roleAcct, Type: User, ID: "alice"}, []string{"alice"}, true},
		{"the role account's own user, trusted only by account, with no policy", Principal{Account: roleAcct, Type: User, ID: "alice"}, []string{roleAcct}, false},
	} {
		stmts, err := TrustStatements(c.trust, roleAcct)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if d := e.Authorize(context.Background(), c.p, "sts:AssumeRole", role, nil, WithResourcePolicy(stmts)); d.Allowed != c.want {
			t.Errorf("%s: allowed=%v (%s), want %v", c.name, d.Allowed, d.Reason, c.want)
		}
	}
}
