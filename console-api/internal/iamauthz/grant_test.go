package iamauthz

import (
	"context"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// A Grant has a window only once a second person has approved it, with a duration of whole hours,
// minutes or seconds of at most 24h; the window runs from the approval.
func TestGrantWindow(t *testing.T) {
	approved := GrantSpec{SubjectKind: "User", SubjectName: "alice", Policies: []string{"aws-readonlyaccess"},
		Duration: "4h", RequestedBy: "alice", ApprovedBy: "carol", ApprovedAt: "2026-11-07T10:00:00Z"}
	with := func(f func(*GrantSpec)) GrantSpec { g := approved; f(&g); return g }
	cases := []struct {
		name string
		g    GrantSpec
		why  string // "" = has a window
	}{
		{"approved by a second person", approved, ""},
		{"requested from kubectl (no requester), approved", with(func(g *GrantSpec) { g.RequestedBy = "" }), ""},
		{"a group", with(func(g *GrantSpec) { g.SubjectKind = "Group"; g.SubjectName = "oncall" }), ""},
		{"exactly 24h", with(func(g *GrantSpec) { g.Duration = "24h" }), ""},
		{"1h30m", with(func(g *GrantSpec) { g.Duration = "1h30m" }), ""},
		{"awaiting approval", with(func(g *GrantSpec) { g.ApprovedBy = ""; g.ApprovedAt = "" }), "awaiting approval"},
		{"self-approved", with(func(g *GrantSpec) { g.ApprovedBy = "alice" }), "someone other than the requester"},
		{"over 24h", with(func(g *GrantSpec) { g.Duration = "25h" }), "at most 24h"},
		{"24h1s", with(func(g *GrantSpec) { g.Duration = "24h0m1s" }), "at most 24h"},
		{"zero", with(func(g *GrantSpec) { g.Duration = "0h" }), "at most 24h"},
		{"fractional", with(func(g *GrantSpec) { g.Duration = "0.5h" }), "at most 24h"},
		{"days", with(func(g *GrantSpec) { g.Duration = "1d" }), "at most 24h"},
		{"empty duration", with(func(g *GrantSpec) { g.Duration = "" }), "at most 24h"},
		{"unreadable approval time", with(func(g *GrantSpec) { g.ApprovedAt = "yesterday" }), "no valid time"},
		{"no policy", with(func(g *GrantSpec) { g.Policies = nil }), "no policy"},
		{"no subject", with(func(g *GrantSpec) { g.SubjectName = "" }), "no user or group"},
		{"a role subject", with(func(g *GrantSpec) { g.SubjectKind = "Role" }), "no user or group"},
		{"a subject in another namespace", with(func(g *GrantSpec) { g.SubjectName = "team-b/alice" }), "the grant's own namespace"},
	}
	for _, c := range cases {
		from, until, why := GrantWindow(c.g)
		if c.why == "" {
			if why != "" {
				t.Errorf("%s: no window: %s", c.name, why)
				continue
			}
			d, _ := ParseGrantDuration(c.g.Duration)
			if want := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC); !from.Equal(want) || !until.Equal(want.Add(d)) {
				t.Errorf("%s: window %v..%v, want from the approval for %s", c.name, from, until, c.g.Duration)
			}
			continue
		}
		if !strings.Contains(why, c.why) {
			t.Errorf("%s: why = %q, want it to say %q", c.name, why, c.why)
		}
	}
}

// The one evaluator honours an approved Grant as an attachment of its policies for the window, to the
// user or to each member of the group, and nothing outside the window.
func TestAuthorize_GrantAttachesItsPoliciesForTheWindow(t *testing.T) {
	now := time.Now()
	ro := mustDoc(t, "aws-readonlyaccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}]}`)
	pu := mustDoc(t, "aws-poweruseraccess", powerUserAccess)
	open := func(grant string, pols ...string) TemporaryAttachment {
		return TemporaryAttachment{Grant: grant, Policies: pols, From: now.Add(-time.Hour), Until: now.Add(time.Hour)}
	}
	w := World{Docs: []Policy{ro, pu}, Temporary: map[string][]TemporaryAttachment{
		"User::alice":   {open("jit-alice", "aws-poweruseraccess")},
		"User::bob":     {{Grant: "jit-bob", Policies: []string{"aws-poweruseraccess"}, From: now.Add(-5 * time.Hour), Until: now.Add(-time.Minute)}},
		"User::dana":    {{Grant: "jit-dana", Policies: []string{"aws-poweruseraccess"}, From: now.Add(time.Hour), Until: now.Add(2 * time.Hour)}},
		"Group::oncall": {open("jit-oncall", "aws-readonlyaccess")},
	}}
	runChecks(t, evaluator(w), []check{
		{name: "alice holds PowerUserAccess while her grant is open", p: user("alice"), action: "sqs:CreateQueue", resource: "*", allow: true},
		{name: "a granted policy is no more than the policy: PowerUserAccess still has no IAM", p: user("alice"), action: "iam:CreateUser", resource: "*"},
		{name: "bob's grant has expired: nothing", p: user("bob"), action: "sqs:CreateQueue", resource: "*"},
		{name: "dana's window has not opened: nothing", p: user("dana"), action: "sqs:CreateQueue", resource: "*"},
		{name: "a member of oncall reads through the group's grant", p: user("erin", "oncall"), action: "s3:GetObject", resource: "arn:aws:s3:::logs/a", allow: true},
		{name: "the group's grant is only ReadOnlyAccess", p: user("erin", "oncall"), action: "s3:PutObject", resource: "arn:aws:s3:::logs/a"},
		{name: "a non-member gets nothing from the group's grant", p: user("frank"), action: "s3:GetObject", resource: "arn:aws:s3:::logs/a"},
	})
	if got := w.ActiveTemporary("User", "erin", []string{"openinfra:oncall"}, now); len(got) != 1 || got[0].Grant != "jit-oncall" {
		t.Errorf("a member's active grants (impersonation prefix dropped) = %+v", got)
	}
	// The evaluator checks the window itself: the same World, cached, stops counting a grant at its end.
	if pols := w.PoliciesAt("User", "alice", nil, now.Add(2*time.Hour)); len(pols) != 0 {
		t.Errorf("after the window alice holds %v, want nothing", pols)
	}
}

func grantObj(ns, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1", "kind": "Grant",
		"metadata": map[string]any{"name": name, "namespace": ns}, "spec": spec,
	}}
}

func grantSpec(subjectKind, subject, requestedBy, approvedBy string, approvedAt time.Time, duration string, policies ...string) map[string]any {
	ps := make([]any, len(policies))
	for i, p := range policies {
		ps[i] = p
	}
	spec := map[string]any{"subject": map[string]any{"kind": subjectKind, "name": subject}, "policies": ps,
		"duration": duration, "requestedBy": requestedBy}
	if approvedBy != "" {
		spec["approval"] = map[string]any{"approvedBy": approvedBy, "approvedAt": approvedAt.UTC().Format(time.RFC3339)}
	}
	return spec
}

func loaderListKinds() map[schema.GroupVersionResource]string {
	return map[schema.GroupVersionResource]string{policyGVR: "PolicyList", roleGVR: "RoleList", userGVR: "UserList",
		groupGVR: "GroupList", GrantGVR: "GrantList"}
}

// The loader reads an approved, unexpired Grant as an attachment of its policies to its subject; an
// unapproved, self-approved or expired one attaches nothing.
func TestK8sLoader_Grants(t *testing.T) {
	now := time.Now()
	policy := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1", "kind": "Policy",
		"metadata": map[string]any{"name": "aws-poweruseraccess", "namespace": DefaultHomeNamespace},
		"spec":     map[string]any{"document": powerUserAccess},
	}}
	objs := []runtime.Object{policy,
		grantObj(DefaultHomeNamespace, "jit-alice", grantSpec("User", "alice", "alice", "carol", now.Add(-time.Hour), "4h", "aws-poweruseraccess")),
		grantObj(DefaultHomeNamespace, "jit-oncall", grantSpec("Group", "oncall", "alice", "carol", now.Add(-time.Hour), "2h", "aws-poweruseraccess")),
		grantObj(DefaultHomeNamespace, "pending", grantSpec("User", "bob", "bob", "", time.Time{}, "4h", "aws-poweruseraccess")),
		grantObj(DefaultHomeNamespace, "self", grantSpec("User", "mallory", "mallory", "mallory", now.Add(-time.Minute), "4h", "aws-poweruseraccess")),
		grantObj(DefaultHomeNamespace, "expired", grantSpec("User", "dana", "dana", "carol", now.Add(-5*time.Hour), "4h", "aws-poweruseraccess")),
		grantObj(DefaultHomeNamespace, "too-long", grantSpec("User", "erin", "erin", "carol", now.Add(-time.Minute), "48h", "aws-poweruseraccess")),
		grantObj("team-a", "jit-team", grantSpec("User", "ted", "ted", "carol", now.Add(-time.Minute), "1h", "aws-poweruseraccess")),
		// A home grant cannot reach a principal of another namespace (another account) by naming it so.
		grantObj(DefaultHomeNamespace, "reach", grantSpec("User", "team-a/ted", "alice", "carol", now.Add(-time.Minute), "1h", "aws-poweruseraccess")),
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), loaderListKinds(), objs...)
	w, err := K8sLoaderIn(dc, DefaultHomeNamespace)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for k, as := range w.Temporary {
		for _, a := range as {
			keys[k] = a.Grant + "=" + strings.Join(a.Policies, ",")
		}
	}
	want := map[string]string{
		"User::alice":      "jit-alice=aws-poweruseraccess",
		"Group::oncall":    "jit-oncall=aws-poweruseraccess",
		"User::team-a/ted": "team-a/jit-team=aws-poweruseraccess", // a principal of the grant's own namespace
	}
	if len(keys) != len(want) {
		t.Errorf("temporary attachments = %v, want %v", keys, want)
	}
	for k, v := range want {
		if keys[k] != v {
			t.Errorf("%s: %q, want %q", k, keys[k], v)
		}
	}
	e := evaluator(w)
	runChecks(t, e, []check{
		{name: "alice's approved grant attaches PowerUserAccess", p: user("alice"), action: "sqs:CreateQueue", resource: "*", allow: true},
		{name: "bob's pending request attaches nothing", p: user("bob"), action: "sqs:CreateQueue", resource: "*"},
		{name: "mallory approved her own request: nothing", p: user("mallory"), action: "sqs:CreateQueue", resource: "*"},
		{name: "dana's grant has expired", p: user("dana"), action: "sqs:CreateQueue", resource: "*"},
		{name: "erin's 48h grant is over the cap: nothing", p: user("erin"), action: "sqs:CreateQueue", resource: "*"},
	})
}

// A cluster without the Grant kind has no grants; a Grant list that fails otherwise fails the load
// (closed), as any other list does.
func TestK8sLoader_GrantListErrors(t *testing.T) {
	for _, c := range []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"no Grant kind", apierrors.NewNotFound(schema.GroupResource{Group: "iam.openinfra.dev", Resource: "grants"}, ""), false},
		{"forbidden", apierrors.NewForbidden(schema.GroupResource{Group: "iam.openinfra.dev", Resource: "grants"}, "", nil), true},
	} {
		dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), loaderListKinds())
		e := c.err
		dc.PrependReactor("list", "grants", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, e })
		_, err := K8sLoaderIn(dc, DefaultHomeNamespace)(context.Background())
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
		}
	}
}
