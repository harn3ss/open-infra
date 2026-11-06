package policyengine

import (
	"strings"
	"testing"
)

// The three kinds of request an MFA condition meets, as the shim's request context carries them: a
// long-term access key (no MFA keys at all), a temporary credential not authenticated with MFA
// (multiFactorAuthPresent false, no age), and one authenticated with MFA (present true, its age).
var (
	longTermKey  = map[string]any{"authenticated": true}
	sessionNoMFA = map[string]any{"authenticated": true, "multiFactorAuthPresent": false}
	sessionMFA   = func(age int64) map[string]any {
		return map[string]any{"authenticated": true, "multiFactorAuthPresent": true, "multiFactorAuthAge": age}
	}
)

func decideDoc(t *testing.T, doc string, ctx map[string]any) Decision {
	t.Helper()
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) > 0 {
		t.Fatalf("import: err=%v unsupported=%v", err, unsupported)
	}
	eng, err := NewEngine(stmts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return eng.Authorize(Request{Principal: Principal{Type: "User", ID: "alice"}, Action: "s3:GetObject",
		Resource: Resource{Type: "Bucket", ID: "b/k"}, Context: ctx})
}

const allowAll = `{"Effect":"Allow","Action":"*","Resource":"*"}`

// AWS's recommended "deny unless MFA": Deny + BoolIfExists aws:MultiFactorAuthPresent false denies every
// request not authenticated with MFA — long-term keys too — and nothing else.
func TestMFA_DenyBoolIfExistsFalse(t *testing.T) {
	doc := `{"Statement":[` + allowAll + `,{"Effect":"Deny","NotAction":"iam:ListMFADevices","Resource":"*",
	  "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	for name, c := range map[string]struct {
		ctx   map[string]any
		allow bool
	}{
		"long-term key":       {longTermKey, false},
		"session without MFA": {sessionNoMFA, false},
		"session with MFA":    {sessionMFA(30), true},
	} {
		d := decideDoc(t, doc, c.ctx)
		if d.Allowed != c.allow {
			t.Errorf("%s: allowed=%v, want %v (%s)", name, d.Allowed, c.allow, d.Reason)
		}
		if !c.allow && !d.ExplicitDeny {
			t.Errorf("%s: denied, but not by the explicit Deny (%s)", name, d.Reason)
		}
	}
}

// AWS's documented caveat: Deny + Bool (no IfExists) false does NOT deny a long-term key — the key is
// absent, so the condition does not match.
func TestMFA_DenyBoolFalseSparesLongTermKeys(t *testing.T) {
	doc := `{"Statement":[` + allowAll + `,{"Effect":"Deny","Action":"*","Resource":"*",
	  "Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	if d := decideDoc(t, doc, longTermKey); !d.Allowed {
		t.Errorf("a long-term key is not denied by Bool false on AWS: %s", d.Reason)
	}
	if d := decideDoc(t, doc, sessionNoMFA); d.Allowed || !d.ExplicitDeny {
		t.Errorf("a session without MFA must be denied by Bool false: %+v", d)
	}
	if d := decideDoc(t, doc, sessionMFA(5)); !d.Allowed {
		t.Errorf("a session with MFA must be allowed: %s", d.Reason)
	}
}

// Allow + Bool true grants only MFA-authenticated requests; Allow + BoolIfExists true also long-term keys.
func TestMFA_AllowBoolTrue(t *testing.T) {
	strict := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`
	loose := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}}]}`
	for _, c := range []struct {
		doc, name string
		ctx       map[string]any
		allow     bool
	}{
		{strict, "Bool true / long-term key", longTermKey, false},
		{strict, "Bool true / session without MFA", sessionNoMFA, false},
		{strict, "Bool true / session with MFA", sessionMFA(1), true},
		{loose, "BoolIfExists true / long-term key", longTermKey, true},
		{loose, "BoolIfExists true / session without MFA", sessionNoMFA, false},
		{loose, "BoolIfExists true / session with MFA", sessionMFA(1), true},
	} {
		if d := decideDoc(t, c.doc, c.ctx); d.Allowed != c.allow {
			t.Errorf("%s: allowed=%v, want %v (%s)", c.name, d.Allowed, c.allow, d.Reason)
		}
	}
}

// aws:MultiFactorAuthAge: a Numeric comparison on the seconds since MFA; absent (no MFA) never matches a
// plain Numeric operator, always matches its IfExists form.
func TestMFA_Age(t *testing.T) {
	recent := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}]}`
	for _, c := range []struct {
		name  string
		ctx   map[string]any
		allow bool
	}{
		{"10 minutes after MFA", sessionMFA(600), true},
		{"two hours after MFA", sessionMFA(7200), false},
		{"no MFA (no age)", sessionNoMFA, false},
		{"long-term key", longTermKey, false},
	} {
		if d := decideDoc(t, recent, c.ctx); d.Allowed != c.allow {
			t.Errorf("%s: allowed=%v, want %v (%s)", c.name, d.Allowed, c.allow, d.Reason)
		}
	}
	stale := `{"Statement":[` + allowAll + `,{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NumericGreaterThanIfExists":{"aws:MultiFactorAuthAge":"3600"}}}]}`
	if d := decideDoc(t, stale, sessionMFA(7200)); d.Allowed {
		t.Error("a Deny on an MFA older than an hour must deny it")
	}
	if d := decideDoc(t, stale, sessionMFA(60)); !d.Allowed {
		t.Errorf("a recent MFA must pass: %s", d.Reason)
	}
	if d := decideDoc(t, stale, longTermKey); d.Allowed {
		t.Error("NumericGreaterThanIfExists matches an absent age: the Deny must apply")
	}
	// A negated operator matches an absent key, as AWS's do.
	notEq := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericNotEquals":{"aws:MultiFactorAuthAge":"0"}}}]}`
	if d := decideDoc(t, notEq, longTermKey); !d.Allowed {
		t.Errorf("NumericNotEquals on an absent key matches on AWS: %s", d.Reason)
	}
}

// Null tests the key's presence.
func TestMFA_Null(t *testing.T) {
	doc := `{"Statement":[` + allowAll + `,{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Null":{"aws:MultiFactorAuthAge":"true"}}}]}`
	if d := decideDoc(t, doc, sessionNoMFA); d.Allowed {
		t.Error("Null true on an absent age must deny")
	}
	if d := decideDoc(t, doc, sessionMFA(10)); !d.Allowed {
		t.Errorf("Null true on a present age must not deny: %s", d.Reason)
	}
}

// Condition key names are not case-sensitive on AWS.
func TestMFA_KeyNameCaseInsensitive(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"AWS:multifactorauthpresent":"True"}}}]}`
	if d := decideDoc(t, doc, sessionMFA(1)); !d.Allowed {
		t.Errorf("a differently-cased key must import: %s", d.Reason)
	}
}

// What cannot be honoured is refused, never approximated: a string operator on the boolean key, a decimal
// age, a non-boolean value, a multi-valued list.
func TestMFA_Refused(t *testing.T) {
	for name, cond := range map[string]string{
		"StringEquals on present": `{"StringEquals":{"aws:MultiFactorAuthPresent":"true"}}`,
		"Bool on age":             `{"Bool":{"aws:MultiFactorAuthAge":"true"}}`,
		"decimal age":             `{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600.5"}}`,
		"non-boolean":             `{"Bool":{"aws:MultiFactorAuthPresent":"yes"}}`,
		"multi-valued":            `{"NumericLessThan":{"aws:MultiFactorAuthAge":["60","120"]}}`,
		"Null with a non-boolean": `{"Null":{"aws:MultiFactorAuthAge":"maybe"}}`,
		"Date on age":             `{"DateLessThan":{"aws:MultiFactorAuthAge":"2020-01-01T00:00:00Z"}}`,
		"IfExists on a plain key": `{"BoolIfExists":{"authenticated":"true"}}`,
	} {
		doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":` + cond + `}]}`
		stmts, unsupported, err := ImportAWS(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(stmts) != 0 || len(unsupported) == 0 || !strings.Contains(strings.Join(unsupported, " "), "Condition") {
			t.Errorf("%s: must be refused and reported, got stmts=%v unsupported=%v", name, stmts, unsupported)
		}
	}
}

// A request attribute of the wrong type never makes a Deny evaporate: the request is denied outright.
func TestMFA_MalformedAttributeDenies(t *testing.T) {
	doc := `{"Statement":[` + allowAll + `,{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	for name, ctx := range map[string]map[string]any{
		"string true":     {"multiFactorAuthPresent": "true"},
		"number for bool": {"multiFactorAuthPresent": int64(1)},
	} {
		if d := decideDoc(t, doc, ctx); d.Allowed {
			t.Errorf("%s: a malformed attribute must deny", name)
		}
	}
	age := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}]}`
	if d := decideDoc(t, age, map[string]any{"multiFactorAuthPresent": true, "multiFactorAuthAge": "60"}); d.Allowed {
		t.Error("a string age must deny")
	}
	if d := decideDoc(t, age, map[string]any{"multiFactorAuthPresent": true, "multiFactorAuthAge": 60}); !d.Allowed {
		t.Errorf("an int age is a Cedar long: %s", d.Reason)
	}
}

// The native form compiles too, and a malformed one does not.
func TestMFA_KeyConditionCompile(t *testing.T) {
	bad := []KeyCondition{
		{Key: "multiFactorAuthPresent", Op: "<", Value: "true"},
		{Key: "multiFactorAuthAge", Op: "~", Value: "1"},
		{Key: "multiFactorAuthAge", Op: "<", Value: "soon"},
		{Key: "bad key", Op: "==", Value: "true"},
		{Key: "multiFactorAuthAge", Op: KeyNull, Value: "x"},
	}
	for _, kc := range bad {
		if _, err := NewEngine([]Statement{{Effect: Deny, Actions: []string{"*"}, Resources: []string{"*"}, KeyConditions: []KeyCondition{kc}}}); err == nil {
			t.Errorf("%+v must not compile", kc)
		}
	}
	mixed := []Statement{
		{Effect: Allow, Actions: []string{"*"}, Resources: []string{"*"}, KeyConditions: []KeyCondition{{Key: "x", Op: "==", Value: "true"}}},
		{Effect: Allow, Actions: []string{"*"}, Resources: []string{"*"}, KeyConditions: []KeyCondition{{Key: "x", Op: "<", Value: "1"}}},
	}
	if _, err := NewEngine(mixed); err == nil {
		t.Error("one attribute compared as a boolean and a number must not compile")
	}
}

// ExportAWS writes key conditions back as the AWS operators they came from.
func TestMFA_ExportRoundTrip(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{
	  "BoolIfExists":{"aws:MultiFactorAuthPresent":"false"},"NumericGreaterThan":{"aws:MultiFactorAuthAge":"3600"}}}]}`
	stmts, unsupported, err := ImportAWS(doc)
	if err != nil || len(unsupported) > 0 || len(stmts) != 1 || len(stmts[0].KeyConditions) != 2 {
		t.Fatalf("import: %v %v %#v", err, unsupported, stmts)
	}
	out, skipped, err := ExportAWS(stmts)
	if err != nil || len(skipped) > 0 {
		t.Fatalf("export: %v %v", err, skipped)
	}
	for _, want := range []string{`"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}`, `"NumericGreaterThan":{"aws:MultiFactorAuthAge":"3600"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("export lacks %s: %s", want, out)
		}
	}
	back, unsupported, err := ImportAWS(out)
	if err != nil || len(unsupported) > 0 || len(back) != 1 || len(back[0].KeyConditions) != 2 {
		t.Fatalf("re-import: %v %v %#v", err, unsupported, back)
	}
}
