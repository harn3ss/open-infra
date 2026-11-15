package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

func sessionPolicyRequest(form url.Values) *http.Request {
	r := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	return r
}

// The parameters, as AWS takes them: a valid document is kept; PolicyArns resolve to the policies the
// role's account can name; too long, too many, malformed or not an ARN is refused with AWS's error.
func TestSessionPolicies_Parameters(t *testing.T) {
	mp, ok := cfn.ManagedPolicyByARN("arn:aws:iam::aws:policy/ReadOnlyAccess")
	if !ok {
		t.Skip("the shipped managed policy library has no ReadOnlyAccess")
	}
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	form := url.Values{"Policy": {doc},
		"PolicyArns.member.2.arn": {"arn:aws:iam::111122223333:policy/team/Readers"},
		"PolicyArns.member.1.arn": {"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		"PolicyArns.member.3.arn": {"arn:aws:iam::444455556666:policy/Theirs"}}
	got, refs, code, msg := sessionPolicies(sessionPolicyRequest(form), "111122223333", "acct-home")
	if code != "" || got != doc {
		t.Fatalf("a valid request: %s %s", code, msg)
	}
	want := []string{mp.ObjectName(), "acct-home/readers", "unresolvable:arn:aws:iam::444455556666:policy/Theirs"}
	if strings.Join(refs, " ") != strings.Join(want, " ") {
		t.Fatalf("refs %v, want %v", refs, want)
	}
	if _, refs, _, _ := sessionPolicies(sessionPolicyRequest(url.Values{"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:policy/Mine"}}), "000000000000", ""); len(refs) != 1 || refs[0] != "mine" {
		t.Fatalf("the management account's policy: %v", refs)
	}
	many := url.Values{}
	for i := 1; i <= 11; i++ {
		many.Set("PolicyArns.member."+strconv.Itoa(i)+".arn", "arn:aws:iam::aws:policy/ReadOnlyAccess")
	}
	for name, c := range map[string]struct {
		form url.Values
		code string
	}{
		"too long":   {url.Values{"Policy": {strings.Repeat(" ", 2049)}}, "ValidationError"},
		"too many":   {many, "ValidationError"},
		"malformed":  {url.Values{"Policy": {`{"Statement":`}}, "MalformedPolicyDocument"},
		"not an ARN": {url.Values{"PolicyArns.member.1.arn": {"ReadOnlyAccess"}}, "ValidationError"},
		"a role ARN": {url.Values{"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:role/x"}}, "ValidationError"},
		"bad effect": {url.Values{"Policy": {`{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`}}, "MalformedPolicyDocument"},
	} {
		if _, _, code, _ := sessionPolicies(sessionPolicyRequest(c.form), "000000000000", ""); code != c.code {
			t.Errorf("%s: %q, want %q", name, code, c.code)
		}
	}
}

// A session given a session policy may do only what both its role and the session policy allow: the
// role allows all of S3, the session's inline policy only GetObject, its managed one only ListBucket.
func TestAssumeRole_SessionPolicyNarrowsTheSession(t *testing.T) {
	h, minter := newSTS(t, fakeRoles{"deploy-role": {trust: []string{"alice"}, groups: []string{"openinfra:users"}}})
	compile := func(name, doc string) iamauthz.Policy {
		stmts, _, err := iamauthz.CompileDocument(doc)
		if err != nil {
			t.Fatal(err)
		}
		return iamauthz.Policy{Name: name, Statements: stmts}
	}
	world := iamauthz.World{
		Docs: []iamauthz.Policy{
			compile("s3-all", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`),
			compile("list-only", `{"Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}}`),
		},
		Attach: map[string][]string{"Role::deploy-role": {"s3-all"}},
	}
	ev := iamauthz.New(func(context.Context) (iamauthz.World, error) { return world, nil }, time.Minute,
		iamauthz.WithMode(iamauthz.ModeEnforce))

	session := func(form url.Values) iam.Claims {
		t.Helper()
		form.Set("Action", "AssumeRole")
		form.Set("RoleArn", "deploy-role")
		form.Set("RoleSessionName", "narrow")
		r := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.serve(w, r, iam.Claims{Sub: "alice"}, "rid")
		if w.Code != http.StatusOK {
			t.Fatalf("assume: %d %s", w.Code, w.Body.String())
		}
		var resp assumeRoleResponse
		_ = xml.Unmarshal(w.Body.Bytes(), &resp)
		c := resp.Result.Credentials
		auth := &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false }, sts: minter}
		claims, err := auth.authenticate(context.Background(), signedSessionRequest(t, c.AccessKeyId, c.SecretAccessKey, c.SessionToken))
		if err != nil {
			t.Fatal(err)
		}
		return claims
	}
	decide := func(c iam.Claims, action string) bool {
		d := ev.Decide(context.Background(), iamauthz.PrincipalFromClaims(c, ""), action, "arn:aws:s3:::b/k", nil, nil)
		return d.Allowed
	}

	plain := session(url.Values{})
	if !decide(plain, "s3:PutObject") {
		t.Fatal("without a session policy the role's own permissions apply")
	}
	inline := session(url.Values{"Policy": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}})
	if !decide(inline, "s3:GetObject") || decide(inline, "s3:PutObject") {
		t.Fatal("the inline session policy must narrow the session to s3:GetObject")
	}
	managed := session(url.Values{"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:policy/list-only"}})
	if !decide(managed, "s3:ListBucket") || decide(managed, "s3:GetObject") {
		t.Fatal("the managed session policy must narrow the session to s3:ListBucket")
	}
	gone := session(url.Values{"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:policy/no-such-policy"}})
	if decide(gone, "s3:GetObject") {
		t.Fatal("a session policy that resolves to nothing must allow nothing, not the role's all")
	}
	wider := session(url.Values{"Policy": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}})
	if decide(wider, "iam:CreateUser") {
		t.Fatal("a session policy can't widen the role")
	}
}
