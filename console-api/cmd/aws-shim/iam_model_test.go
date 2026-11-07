package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const iamHome = "open-infra-console"

var iamAdmin = iam.Claims{Sub: "admin", Groups: []string{"openinfra:admins"}}

// iamWorld is an IAM front door over a fake cluster holding the shipped AWS managed policies
// AdministratorAccess and PowerUserAccess, in the management account (legacy: RBAC allows).
func iamWorld(t *testing.T) (*iamHandler, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	dyn := fakeDynWith(gvrPolicies, gvrRoles, gvrUsers, gvrGroups, iamauthz.GrantGVR)
	for _, p := range []struct{ obj, name, doc string }{
		{"aws-administratoraccess", "AdministratorAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
		{"aws-poweruseraccess", "PowerUserAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"}]}`},
	} {
		doc, _, err := parseDocument(p.doc)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "iam.openinfra.dev/v1", "kind": "Policy",
			"metadata": map[string]any{"name": p.obj, "namespace": iamHome,
				"labels": map[string]any{awsManagedPolicyLabel: "true", managedPolicyLabelShim: "true"}},
			"spec": map[string]any{"policyName": p.name, "arn": "arn:aws:iam::aws:policy/" + p.name, "document": doc},
		}}
		if _, err := dyn.Resource(gvrPolicies).Namespace(iamHome).Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return newIAMHandler(csWithSAR(true), dyn, awskeys.NewStore(csWithSAR(true), "default"), nil, iamHome, testMgmt, "us-east-1", discardLogger()), dyn
}

// call serves one IAM request as claims and returns the response, failing the test on a status other than want.
func call(t *testing.T, h *iamHandler, ctx context.Context, claims iam.Claims, want int, kv ...string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		form.Add(kv[i], kv[i+1])
	}
	r := formOp(form)
	if ctx != nil {
		r = r.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req")
	if w.Code != want {
		t.Fatalf("%s: status %d, want %d: %s", form.Get("Action"), w.Code, want, w.Body.String())
	}
	return w
}

func object(t *testing.T, dyn dynamic.Interface, e iamEntity, ns, name string) *unstructured.Unstructured {
	t.Helper()
	u, err := dyn.Resource(e.gvr).Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("%s %s/%s: %v", e.kind, ns, name, err)
	}
	return u
}

func policyObject(t *testing.T, dyn dynamic.Interface, ns, name string) *unstructured.Unstructured {
	return object(t, dyn, iamEntity{kind: "Policy", gvr: gvrPolicies}, ns, name)
}

const queueDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}`

// CreatePolicy stores the AWS document as written on spec.document (no native statements), keeps a
// mixed-case PolicyName as spec.policyName, and refuses what is not a policy document.
func TestIAM_CreatePolicyWritesTheDocument(t *testing.T) {
	h, dyn := iamWorld(t)
	w := call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicy", "PolicyName", "QueueWriter", "PolicyDocument", queueDoc)
	if !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::"+testMgmt+":policy/QueueWriter</Arn>") {
		t.Errorf("CreatePolicy's ARN: %s", w.Body.String())
	}
	u := policyObject(t, dyn, iamHome, "queuewriter")
	if got, _, _ := unstructured.NestedString(u.Object, "spec", "policyName"); got != "QueueWriter" {
		t.Errorf("spec.policyName = %q", got)
	}
	if got := documentJSON(u.Object["spec"].(map[string]any)["document"]); !strings.Contains(got, `"sqs:SendMessage"`) {
		t.Errorf("spec.document = %s", got)
	}
	for _, f := range []string{"dataPlane", "statements"} {
		if _, ok := u.Object["spec"].(map[string]any)[f]; ok {
			t.Errorf("spec.%s written; the document is the policy", f)
		}
	}
	// A document with a condition the evaluator cannot evaluate is stored as written, as AWS stores it.
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicy", "PolicyName", "tagged", "PolicyDocument",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"a"}}}]}`)
	for _, bad := range []string{`not json`, `{"Version":"2012-10-17"}`, `{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`} {
		if w := call(t, h, nil, iamAdmin, 400, "Action", "CreatePolicy", "PolicyName", "bad", "PolicyDocument", bad); !strings.Contains(w.Body.String(), "MalformedPolicyDocument") {
			t.Errorf("%s: %s", bad, w.Body.String())
		}
	}
	call(t, h, nil, iamAdmin, 409, "Action", "CreatePolicy", "PolicyName", "queuewriter", "PolicyDocument", queueDoc)
}

// Attaching a managed policy writes its object name into spec.policies — an AWS managed policy's ARN
// resolves to the shipped library — and detaching removes it; a policy that does not exist is NoSuchEntity.
func TestIAM_AttachWritesSpecPolicies(t *testing.T) {
	h, dyn := iamWorld(t)
	call(t, h, nil, iamAdmin, 200, "Action", "CreateUser", "UserName", "alice")
	call(t, h, nil, iamAdmin, 200, "Action", "CreateGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 200, "Action", "CreateRole", "RoleName", "app", "AssumeRolePolicyDocument",
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+testMgmt+`:user/alice"},"Action":"sts:AssumeRole"}]}`)
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicy", "PolicyName", "queue-writer", "PolicyDocument", queueDoc)
	for _, tc := range []struct {
		e    iamEntity
		name string
	}{{userEntity, "alice"}, {groupEntity, "devs"}, {roleEntity, "app"}} {
		op := "Attach" + tc.e.kind + "Policy"
		call(t, h, nil, iamAdmin, 200, "Action", op, tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
		call(t, h, nil, iamAdmin, 200, "Action", op, tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::"+testMgmt+":policy/queue-writer")
		call(t, h, nil, iamAdmin, 200, "Action", op, tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess") // idempotent
		call(t, h, nil, iamAdmin, 404, "Action", op, tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::aws:policy/NoSuchPolicy")
		call(t, h, nil, iamAdmin, 404, "Action", op, tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::"+testMgmt+":policy/missing")
		call(t, h, nil, iamAdmin, 404, "Action", op, tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::955555555555:policy/queue-writer")
		got, _, _ := unstructured.NestedStringSlice(object(t, dyn, tc.e, iamHome, tc.name).Object, "spec", "policies")
		if strings.Join(got, ",") != "aws-poweruseraccess,queue-writer" {
			t.Errorf("%s %s spec.policies = %v", tc.e.kind, tc.name, got)
		}
		w := call(t, h, nil, iamAdmin, 200, "Action", "ListAttached"+tc.e.kind+"Policies", tc.e.param, tc.name)
		if !strings.Contains(w.Body.String(), "<PolicyName>PowerUserAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/PowerUserAccess</PolicyArn>") ||
			!strings.Contains(w.Body.String(), "<PolicyArn>arn:aws:iam::"+testMgmt+":policy/queue-writer</PolicyArn>") {
			t.Errorf("ListAttached%sPolicies: %s", tc.e.kind, w.Body.String())
		}
		call(t, h, nil, iamAdmin, 200, "Action", "Detach"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
		call(t, h, nil, iamAdmin, 404, "Action", "Detach"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
		got, _, _ = unstructured.NestedStringSlice(object(t, dyn, tc.e, iamHome, tc.name).Object, "spec", "policies")
		if strings.Join(got, ",") != "queue-writer" {
			t.Errorf("after detach, %s %s spec.policies = %v", tc.e.kind, tc.name, got)
		}
	}
	// An attached policy cannot be deleted (DeleteConflict), nor can an AWS managed one.
	call(t, h, nil, iamAdmin, 409, "Action", "DeletePolicy", "PolicyArn", "arn:aws:iam::"+testMgmt+":policy/queue-writer")
	call(t, h, nil, iamAdmin, 400, "Action", "DeletePolicy", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
}

// Inline policies are {name, document} entries of spec.inlinePolicies on users, groups and roles; a
// role's inline policy from an earlier release (its own kind: Policy) is replaced, not added to.
func TestIAM_InlinePoliciesWriteSpecInlinePolicies(t *testing.T) {
	h, dyn := iamWorld(t)
	call(t, h, nil, iamAdmin, 200, "Action", "CreateUser", "UserName", "alice")
	call(t, h, nil, iamAdmin, 200, "Action", "CreateGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 200, "Action", "CreateRole", "RoleName", "app", "AssumeRolePolicyDocument",
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`)
	legacy := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1", "kind": "Policy",
		"metadata": map[string]any{"name": "role-app-send", "namespace": iamHome},
		"spec":     map[string]any{"dataPlane": map[string]any{"appliesTo": []any{"Role::app"}, "statements": []any{}}},
	}}
	if _, err := dyn.Resource(gvrPolicies).Namespace(iamHome).Create(context.Background(), legacy, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		e    iamEntity
		name string
	}{{userEntity, "alice"}, {groupEntity, "devs"}, {roleEntity, "app"}} {
		call(t, h, nil, iamAdmin, 200, "Action", "Put"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyName", "send", "PolicyDocument", queueDoc)
		call(t, h, nil, iamAdmin, 200, "Action", "Put"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyName", "send", "PolicyDocument", queueDoc)
		inline := inlinePolicies(object(t, dyn, tc.e, iamHome, tc.name))
		if len(inline) != 1 || inline[0]["name"] != "send" || !strings.Contains(documentJSON(inline[0]["document"]), "sqs:SendMessage") {
			t.Errorf("%s inlinePolicies = %v", tc.e.kind, inline)
		}
		w := call(t, h, nil, iamAdmin, 200, "Action", "Get"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyName", "send")
		if !strings.Contains(w.Body.String(), "<PolicyDocument>"+xmlEscape(encodeDocument(documentJSON(inline[0]["document"])))+"</PolicyDocument>") {
			t.Errorf("Get%sPolicy must return the URL-encoded document: %s", tc.e.kind, w.Body.String())
		}
		if w := call(t, h, nil, iamAdmin, 200, "Action", "List"+tc.e.kind+"Policies", tc.e.param, tc.name); !strings.Contains(w.Body.String(), "<member>send</member>") {
			t.Errorf("List%sPolicies: %s", tc.e.kind, w.Body.String())
		}
		call(t, h, nil, iamAdmin, 200, "Action", "Delete"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyName", "send")
		call(t, h, nil, iamAdmin, 404, "Action", "Delete"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyName", "send")
		call(t, h, nil, iamAdmin, 404, "Action", "Get"+tc.e.kind+"Policy", tc.e.param, tc.name, "PolicyName", "send")
	}
	if _, err := dyn.Resource(gvrPolicies).Namespace(iamHome).Get(context.Background(), "role-app-send", metav1.GetOptions{}); err == nil {
		t.Error("the role's earlier-form inline policy survived PutRolePolicy")
	}
}

// Groups are policy containers; membership is the user's spec.groups. A group with members or policies
// is a DeleteConflict.
func TestIAM_GroupsAndMembership(t *testing.T) {
	h, dyn := iamWorld(t)
	call(t, h, nil, iamAdmin, 200, "Action", "CreateUser", "UserName", "alice")
	w := call(t, h, nil, iamAdmin, 200, "Action", "CreateGroup", "GroupName", "devs")
	if !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::"+testMgmt+":group/devs</Arn>") {
		t.Errorf("CreateGroup: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 409, "Action", "CreateGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 404, "Action", "AddUserToGroup", "GroupName", "nope", "UserName", "alice")
	call(t, h, nil, iamAdmin, 200, "Action", "AddUserToGroup", "GroupName", "devs", "UserName", "alice")
	call(t, h, nil, iamAdmin, 200, "Action", "AddUserToGroup", "GroupName", "devs", "UserName", "alice")
	if got, _, _ := unstructured.NestedStringSlice(object(t, dyn, userEntity, iamHome, "alice").Object, "spec", "groups"); strings.Join(got, ",") != "devs" {
		t.Errorf("alice spec.groups = %v", got)
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "GetGroup", "GroupName", "devs"); !strings.Contains(w.Body.String(), "<UserName>alice</UserName>") {
		t.Errorf("GetGroup must list alice: %s", w.Body.String())
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListGroupsForUser", "UserName", "alice"); !strings.Contains(w.Body.String(), "<GroupName>devs</GroupName>") {
		t.Errorf("ListGroupsForUser: %s", w.Body.String())
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListGroups"); !strings.Contains(w.Body.String(), "<GroupName>devs</GroupName>") {
		t.Errorf("ListGroups: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 409, "Action", "DeleteGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 200, "Action", "RemoveUserFromGroup", "GroupName", "devs", "UserName", "alice")
	call(t, h, nil, iamAdmin, 200, "Action", "AttachGroupPolicy", "GroupName", "devs", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
	call(t, h, nil, iamAdmin, 409, "Action", "DeleteGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 200, "Action", "DetachGroupPolicy", "GroupName", "devs", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
	call(t, h, nil, iamAdmin, 200, "Action", "DeleteGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 404, "Action", "GetGroup", "GroupName", "devs")
}

// CreatePolicyVersion keeps spec.document the default version; the others are kept on the object, at most
// five in all, and a policy with versions besides its default is not deleted until they are.
func TestIAM_PolicyVersions(t *testing.T) {
	h, dyn := iamWorld(t)
	arn := "arn:aws:iam::" + testMgmt + ":policy/p"
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicy", "PolicyName", "p", "PolicyDocument", queueDoc)
	v2 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*"}]}`
	if w := call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicyVersion", "PolicyArn", arn, "PolicyDocument", v2, "SetAsDefault", "true"); !strings.Contains(w.Body.String(), "<VersionId>v2</VersionId><IsDefaultVersion>true</IsDefaultVersion>") {
		t.Fatalf("CreatePolicyVersion: %s", w.Body.String())
	}
	u := policyObject(t, dyn, iamHome, "p")
	if !strings.Contains(documentJSON(u.Object["spec"].(map[string]any)["document"]), "sqs:ReceiveMessage") || defaultVersion(u) != "v2" {
		t.Fatalf("the default version must be spec.document: %v", u.Object["spec"])
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "GetPolicyVersion", "PolicyArn", arn, "VersionId", "v1"); !strings.Contains(w.Body.String(), encodeDocument(`"sqs:SendMessage"`)) {
		t.Errorf("GetPolicyVersion v1 must be the first document: %s", w.Body.String())
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "GetPolicy", "PolicyArn", arn); !strings.Contains(w.Body.String(), "<DefaultVersionId>v2</DefaultVersionId>") {
		t.Errorf("GetPolicy: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicyVersion", "PolicyArn", arn, "PolicyDocument", queueDoc)
	w := call(t, h, nil, iamAdmin, 200, "Action", "ListPolicyVersions", "PolicyArn", arn)
	for _, want := range []string{"<VersionId>v3</VersionId><IsDefaultVersion>false", "<VersionId>v2</VersionId><IsDefaultVersion>true", "<VersionId>v1</VersionId><IsDefaultVersion>false"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("ListPolicyVersions lacks %s: %s", want, w.Body.String())
		}
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicyVersion", "PolicyArn", arn, "PolicyDocument", queueDoc)
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicyVersion", "PolicyArn", arn, "PolicyDocument", queueDoc)
	call(t, h, nil, iamAdmin, 409, "Action", "CreatePolicyVersion", "PolicyArn", arn, "PolicyDocument", queueDoc) // the sixth
	call(t, h, nil, iamAdmin, 409, "Action", "DeletePolicyVersion", "PolicyArn", arn, "VersionId", "v2")          // the default
	call(t, h, nil, iamAdmin, 409, "Action", "DeletePolicy", "PolicyArn", arn)
	call(t, h, nil, iamAdmin, 200, "Action", "SetDefaultPolicyVersion", "PolicyArn", arn, "VersionId", "v1")
	if u := policyObject(t, dyn, iamHome, "p"); defaultVersion(u) != "v1" || !strings.Contains(documentJSON(u.Object["spec"].(map[string]any)["document"]), "sqs:SendMessage") {
		t.Errorf("SetDefaultPolicyVersion v1: %v", u.Object["spec"])
	}
	for _, v := range []string{"v2", "v3", "v4", "v5"} {
		call(t, h, nil, iamAdmin, 200, "Action", "DeletePolicyVersion", "PolicyArn", arn, "VersionId", v)
	}
	call(t, h, nil, iamAdmin, 404, "Action", "GetPolicyVersion", "PolicyArn", arn, "VersionId", "v2")
	call(t, h, nil, iamAdmin, 200, "Action", "DeletePolicy", "PolicyArn", arn)
	// An AWS managed policy's versions are readable, never writable.
	call(t, h, nil, iamAdmin, 200, "Action", "GetPolicyVersion", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess", "VersionId", "v1")
	call(t, h, nil, iamAdmin, 400, "Action", "CreatePolicyVersion", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess", "PolicyDocument", queueDoc)
}

// The user name root is the account's root user's: CreateUser refuses it in any case, with IAM's
// InvalidInput, and creates nothing.
func TestIAM_CreateUserRefusesRoot(t *testing.T) {
	h, dyn := iamWorld(t)
	for _, name := range []string{"root", "Root", "ROOT"} {
		if w := call(t, h, nil, iamAdmin, 400, "Action", "CreateUser", "UserName", name); !strings.Contains(w.Body.String(), "<Code>InvalidInput</Code>") {
			t.Errorf("CreateUser %s: %s", name, w.Body.String())
		}
	}
	list, _ := dyn.Resource(gvrUsers).Namespace(iamHome).List(context.Background(), metav1.ListOptions{})
	if len(list.Items) != 0 {
		t.Errorf("a user was created: %v", list.Items)
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreateUser", "UserName", "rooted")
}

// Users, groups, roles and policies made through the IAM API are what the one evaluator reads: a user
// with no policy is denied, its attached policy, a group's policy, its inline policy each allow, a
// permissions boundary caps them, and a detach takes the grant away.
func TestIAM_WhatTheAPIWritesTheEvaluatorReads(t *testing.T) {
	h, dyn := iamWorld(t)
	t.Setenv(iamauthz.EnvMode, "enforce")
	alice := iam.Claims{Sub: "alice"}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	allowed := func(claims iam.Claims, action string) bool {
		t.Helper()
		authz := dataplaneauthz.New(dataplaneauthz.K8sLoaderIn(dyn, iamHome), time.Minute)
		ok, _ := decide(context.Background(), r, authz, claims, action, "Queue", "jobs", nil)
		return ok
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreateUser", "UserName", "alice")
	if allowed(alice, "sqs:SendMessage") {
		t.Fatal("a user with no policy was allowed")
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicy", "PolicyName", "queue-writer", "PolicyDocument", queueDoc)
	call(t, h, nil, iamAdmin, 200, "Action", "AttachUserPolicy", "UserName", "alice", "PolicyArn", "arn:aws:iam::"+testMgmt+":policy/queue-writer")
	if !allowed(alice, "sqs:SendMessage") || allowed(alice, "sqs:DeleteQueue") {
		t.Fatal("the attached customer policy must allow exactly sqs:SendMessage")
	}
	call(t, h, nil, iamAdmin, 200, "Action", "DetachUserPolicy", "UserName", "alice", "PolicyArn", "arn:aws:iam::"+testMgmt+":policy/queue-writer")
	if allowed(alice, "sqs:SendMessage") {
		t.Fatal("a detached policy still allowed")
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreateGroup", "GroupName", "devs")
	call(t, h, nil, iamAdmin, 200, "Action", "AttachGroupPolicy", "GroupName", "devs", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
	call(t, h, nil, iamAdmin, 200, "Action", "AddUserToGroup", "GroupName", "devs", "UserName", "alice")
	member := iam.Claims{Sub: "alice", Groups: []string{"openinfra:devs"}}
	if !allowed(member, "sqs:DeleteQueue") || allowed(member, "iam:CreateUser") {
		t.Fatal("the group's PowerUserAccess must allow SQS and not IAM")
	}
	call(t, h, nil, iamAdmin, 200, "Action", "PutUserPolicy", "UserName", "alice", "PolicyName", "deny-delete", "PolicyDocument",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"sqs:DeleteQueue","Resource":"*"}]}`)
	if allowed(member, "sqs:DeleteQueue") || !allowed(member, "sqs:SendMessage") {
		t.Fatal("the user's inline Deny must win over its group's allow")
	}
	call(t, h, nil, iamAdmin, 200, "Action", "CreatePolicy", "PolicyName", "only-receive", "PolicyDocument",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*"}]}`)
	call(t, h, nil, iamAdmin, 200, "Action", "PutUserPermissionsBoundary", "UserName", "alice", "PermissionsBoundary", "arn:aws:iam::"+testMgmt+":policy/only-receive")
	if allowed(member, "sqs:SendMessage") || !allowed(member, "sqs:ReceiveMessage") {
		t.Fatal("the permissions boundary must cap the user")
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "GetUser", "UserName", "alice"); !strings.Contains(w.Body.String(), "<PermissionsBoundaryArn>arn:aws:iam::"+testMgmt+":policy/only-receive</PermissionsBoundaryArn>") {
		t.Errorf("GetUser must show the boundary: %s", w.Body.String())
	}
	w := call(t, h, nil, iamAdmin, 200, "Action", "GetAccountAuthorizationDetails")
	for _, want := range []string{"<UserName>alice</UserName>", "<PolicyName>deny-delete</PolicyName>", "<GroupList><member>devs</member></GroupList>",
		"<GroupName>devs</GroupName>", "<PolicyArn>arn:aws:iam::aws:policy/PowerUserAccess</PolicyArn>", "<PolicyName>only-receive</PolicyName>"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("GetAccountAuthorizationDetails lacks %s", want)
		}
	}
	call(t, h, nil, iamAdmin, 200, "Action", "DeleteUserPermissionsBoundary", "UserName", "alice")
	if !allowed(member, "sqs:SendMessage") {
		t.Fatal("with the boundary gone the group's policy allows again")
	}
}

// A member account's IAM API acts in its account: its entities in its home, its ARNs, its keys (which
// record the account) — and a user of the same name in another account is another user.
func TestIAM_MemberAccountActsInItsAccount(t *testing.T) {
	h, dyn := iamWorld(t)
	bob := iam.Claims{Sub: "bob", Account: testMember}
	t.Setenv(iamauthz.EnvMode, "legacy") // a member account's principal is decided by IAM policy whatever the mode
	h.authz = dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "bob-iam", AppliesTo: []string{"User::" + memberHome + "/bob"},
			Statements: []policyengine.Statement{dpAllow([]string{"iam:*"}, "*")}}}}, nil
	}, time.Minute)
	ctx := withAccountHome(awsidentity.WithIdentity(context.Background(), awsidentity.Current().ForAccount(testMember, memberHome)), memberHome)

	// The management account's bob, with a key.
	call(t, h, nil, iamAdmin, 200, "Action", "CreateUser", "UserName", "bob")
	call(t, h, nil, iamAdmin, 200, "Action", "CreateAccessKey", "UserName", "bob")

	w := call(t, h, ctx, bob, 200, "Action", "CreateUser", "UserName", "bob")
	if !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::"+testMember+":user/bob</Arn>") {
		t.Errorf("a member account's user's ARN: %s", w.Body.String())
	}
	object(t, dyn, userEntity, memberHome, "bob")
	if w := call(t, h, ctx, bob, 200, "Action", "ListAccessKeys", "UserName", "bob"); strings.Contains(w.Body.String(), "<AccessKeyId>") {
		t.Errorf("the member account listed the management account's bob's key: %s", w.Body.String())
	}
	w = call(t, h, ctx, bob, 200, "Action", "CreateAccessKey", "UserName", "bob")
	id := between(w.Body.String(), "<AccessKeyId>", "</AccessKeyId>")
	if m, ok := h.keys.Describe(context.Background(), id); !ok || m.Account != testMember {
		t.Errorf("the member account's key must record its account: %+v", m)
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListAccessKeys", "UserName", "bob"); strings.Contains(w.Body.String(), id) {
		t.Errorf("the management account listed the member account's bob's key: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 404, "Action", "DeleteAccessKey", "UserName", "bob", "AccessKeyId", id)

	// Its policies are its own; an AWS managed policy is the library's, by namespace.
	call(t, h, ctx, bob, 200, "Action", "CreatePolicy", "PolicyName", "queue-writer", "PolicyDocument", queueDoc)
	policyObject(t, dyn, memberHome, "queue-writer")
	call(t, h, ctx, bob, 404, "Action", "AttachUserPolicy", "UserName", "bob", "PolicyArn", "arn:aws:iam::"+testMgmt+":policy/queue-writer")
	call(t, h, ctx, bob, 200, "Action", "AttachUserPolicy", "UserName", "bob", "PolicyArn", "arn:aws:iam::"+testMember+":policy/queue-writer")
	call(t, h, ctx, bob, 200, "Action", "AttachUserPolicy", "UserName", "bob", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
	got, _, _ := unstructured.NestedStringSlice(object(t, dyn, userEntity, memberHome, "bob").Object, "spec", "policies")
	if strings.Join(got, ",") != "queue-writer,"+iamHome+"/aws-poweruseraccess" {
		t.Errorf("member bob spec.policies = %v", got)
	}
	if w := call(t, h, ctx, bob, 200, "Action", "ListPolicies", "Scope", "Local"); strings.Contains(w.Body.String(), "PowerUserAccess") || !strings.Contains(w.Body.String(), "arn:aws:iam::"+testMember+":policy/queue-writer") {
		t.Errorf("ListPolicies Local: %s", w.Body.String())
	}
	if w := call(t, h, ctx, bob, 200, "Action", "ListPolicies"); !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::aws:policy/PowerUserAccess</Arn>") {
		t.Errorf("ListPolicies All must include the AWS managed library: %s", w.Body.String())
	}
	if got, _, _ := unstructured.NestedStringSlice(object(t, dyn, userEntity, iamHome, "bob").Object, "spec", "policies"); len(got) != 0 {
		t.Errorf("the management account's bob was changed: %v", got)
	}

	// A role's spec.policies are bare Policy names (the Role schema refuses a "/"): an AWS managed policy is
	// attached to a member account's role as the library's bare name, and listed back as AWS's ARN.
	call(t, h, ctx, bob, 200, "Action", "CreateRole", "RoleName", "app", "AssumeRolePolicyDocument",
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+testMember+`:user/bob"},"Action":"sts:AssumeRole"}]}`)
	call(t, h, ctx, bob, 200, "Action", "AttachRolePolicy", "RoleName", "app", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
	got, _, _ = unstructured.NestedStringSlice(object(t, dyn, roleEntity, memberHome, "app").Object, "spec", "policies")
	if strings.Join(got, ",") != "aws-poweruseraccess" {
		t.Errorf("member role spec.policies = %v, want [aws-poweruseraccess]", got)
	}
	if w := call(t, h, ctx, bob, 200, "Action", "ListAttachedRolePolicies", "RoleName", "app"); !strings.Contains(w.Body.String(), "arn:aws:iam::aws:policy/PowerUserAccess") {
		t.Errorf("ListAttachedRolePolicies: %s", w.Body.String())
	}
	call(t, h, ctx, bob, 200, "Action", "DetachRolePolicy", "RoleName", "app", "PolicyArn", "arn:aws:iam::aws:policy/PowerUserAccess")
	// An account's own policy of the library's name would stand in for AWS's: the attach is refused.
	call(t, h, ctx, bob, 200, "Action", "CreatePolicy", "PolicyName", "aws-AdministratorAccess", "PolicyDocument", queueDoc)
	call(t, h, ctx, bob, 400, "Action", "AttachRolePolicy", "RoleName", "app", "PolicyArn", "arn:aws:iam::aws:policy/AdministratorAccess")
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	if j := strings.Index(s, b); j >= 0 {
		return s[:j]
	}
	return s
}
