package iamauthz

import "testing"

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
