package main

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

func assumeWithDuration(role, secs string) *http.Request {
	form := url.Values{"Action": {"AssumeRole"}, "RoleArn": {role}, "RoleSessionName": {"s"}, "DurationSeconds": {secs}}
	req := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// A trust entry names one kind of principal: a role session cannot assume a role that trusts a User of
// the same name, a User cannot assume one that trusts a role (or the VM instance principal) of its name.
func TestAssumeRole_TrustIsTypedByPrincipalKind(t *testing.T) {
	for _, tc := range []struct {
		trust  string
		claims iam.Claims
		want   int
	}{
		{"deployer", iam.Claims{Sub: "deployer"}, 200},                                         // a bare name is a User
		{"User::deployer", iam.Claims{Sub: "deployer"}, 200},                                   // ...and so is User::
		{"deployer", iam.Claims{Sub: "assumed-role/deployer/s", AssumedRole: "deployer"}, 403}, // not the role of that name
		{"User::deployer", iam.Claims{Sub: "assumed-role/deployer/s", AssumedRole: "deployer"}, 403},
		{"Role::deployer", iam.Claims{Sub: "assumed-role/deployer/s", AssumedRole: "deployer"}, 200}, // role chaining, by type
		{"Role::deployer", iam.Claims{Sub: "deployer"}, 403},                                         // not the user of that name
		{"apps/runner", iam.Claims{Sub: "assumed-role/runner/s", AssumedRole: "apps/runner"}, 200},   // a Role outside home
		{"Role::apps/runner", iam.Claims{Sub: "assumed-role/runner/s", AssumedRole: "apps/runner"}, 200},
		{"vm", iam.Claims{Sub: "vm"}, 403}, // the instance principal is not a User
		{"OIDC::deployer", iam.Claims{Sub: "deployer"}, 403},
		{"system:serviceaccount:apps:deployer", iam.Claims{Sub: "deployer"}, 403},
	} {
		h, _ := newSTS(t, fakeRoles{"target": {trust: []string{tc.trust}, groups: []string{"openinfra:users"}}})
		w := httptest.NewRecorder()
		h.serve(w, assumeRequest("target", "s"), tc.claims, "rid")
		if w.Code != tc.want {
			t.Errorf("trust %q, caller %+v: status %d, want %d (%s)", tc.trust, tc.claims, w.Code, tc.want, w.Body.String())
		}
	}
}

// A session is capped at the role's MaxSessionDuration (1h unless the role says otherwise), and a
// request for longer is refused, as on AWS; a session assumed by role chaining is capped at 1h.
func TestAssumeRole_DurationCappedAtRoleMaximum(t *testing.T) {
	roles := fakeRoles{
		"default-max": {trust: []string{"*"}},
		"long":        {trust: []string{"*"}, maxSession: 6 * time.Hour},
	}
	h, _ := newSTS(t, roles)
	expiry := func(w *httptest.ResponseRecorder) time.Duration {
		var resp assumeRoleResponse
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		exp, err := time.Parse(time.RFC3339, resp.Result.Credentials.Expiration)
		if err != nil {
			t.Fatal(err)
		}
		return time.Until(exp).Round(time.Minute)
	}
	alice := iam.Claims{Sub: "alice"}
	chained := iam.Claims{Sub: "assumed-role/other/s", AssumedRole: "other"}
	for _, tc := range []struct {
		role, secs string
		claims     iam.Claims
		want       int
		ttl        time.Duration
	}{
		{"default-max", "", alice, 200, time.Hour},
		{"default-max", "3600", alice, 200, time.Hour},
		{"default-max", "43200", alice, 400, 0}, // was granted 12h
		{"default-max", "3601", alice, 400, 0},
		{"default-max", "600", alice, 400, 0}, // under 15 minutes
		{"default-max", "abc", alice, 400, 0},
		{"long", "21600", alice, 200, 6 * time.Hour},
		{"long", "21601", alice, 400, 0},
		{"long", "", alice, 200, time.Hour},
		{"long", "7200", chained, 400, 0}, // role chaining: 1h
		{"long", "3600", chained, 200, time.Hour},
	} {
		w := httptest.NewRecorder()
		h.serve(w, assumeWithDuration(tc.role, tc.secs), tc.claims, "rid")
		if w.Code != tc.want {
			t.Errorf("%s DurationSeconds=%q (%s): status %d, want %d (%s)", tc.role, tc.secs, tc.claims.Sub, w.Code, tc.want, w.Body.String())
			continue
		}
		if tc.want == 200 {
			if got := expiry(w); got != tc.ttl {
				t.Errorf("%s DurationSeconds=%q: session of %v, want %v", tc.role, tc.secs, got, tc.ttl)
			}
		} else if !strings.Contains(w.Body.String(), "ValidationError") {
			t.Errorf("%s DurationSeconds=%q: refusal is not a ValidationError: %s", tc.role, tc.secs, w.Body.String())
		}
	}
}

// The resolver reads spec.maxSessionDuration within AWS's 1h..12h, else the 1h default.
func TestRoleMaxSession(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want time.Duration
	}{
		{nil, time.Hour},
		{int64(7200), 2 * time.Hour},
		{float64(43200), 12 * time.Hour},
		{int64(60), time.Hour},
		{int64(50000), time.Hour},
	} {
		spec := map[string]any{}
		if tc.v != nil {
			spec["maxSessionDuration"] = tc.v
		}
		if got := roleMaxSession(map[string]any{"spec": spec}); got != tc.want {
			t.Errorf("maxSessionDuration %v: %v, want %v", tc.v, got, tc.want)
		}
	}
}
