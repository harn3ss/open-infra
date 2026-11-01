package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// csWithSARFunc answers each SubjectAccessReview with allow(attrs).
func csWithSARFunc(allow func(a *authzv1.ResourceAttributes) bool) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(act ktesting.Action) (bool, runtime.Object, error) {
		sar := act.(ktesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allow(sar.Spec.ResourceAttributes)}}, nil
	})
	return cs
}

// readerSAR allows reads only (what openinfra:readers holds).
func readerSAR() *fake.Clientset {
	return csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return a.Verb == "get" || a.Verb == "list" })
}

const secretTmpl = "Parameters:\n  DbPassword: { Type: String, NoEcho: true }\n  Env: { Type: String, Default: dev }\n" +
	"Resources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k1 }\n"

// cfnServeDoorway is the test doorway with its caller client kept in the fake, and one seeded stack.
func cfnServeDoorway(t *testing.T) (*cfnDoorway, *impersonatingApplier) {
	t.Helper()
	h, ap := cfnTestDoorway(t, "")
	h.callerDyn = func(string, []string) (dynamic.Interface, error) { return ap.caller, nil }
	if err := ap.putRecord(context.Background(), &cfn.StackRecord{Name: "app", Namespace: "default", Status: "CREATE_COMPLETE",
		Template: secretTmpl, Parameters: map[string]string{"Env": "prod", "DbPassword": "legacy-plaintext"}}); err != nil {
		t.Fatal(err)
	}
	return h, ap
}

func cfnServe(h *cfnDoorway, form url.Values) *httptest.ResponseRecorder {
	return serveWith(h, formOp(form), testUser)
}

// A User needs the action's RBAC verb: a key without it reads nothing — not the stack list, not a
// template, not parameters — even though the records are read with the shim's own client.
func TestCFN_UserWithoutRBACIsDenied(t *testing.T) {
	h, _ := cfnServeDoorway(t)
	h.cs = csWithSAR(false)
	for _, form := range []url.Values{
		{"Action": {"DescribeStacks"}},
		{"Action": {"DescribeStacks"}, "StackName": {"app"}},
		{"Action": {"GetTemplate"}, "StackName": {"app"}},
		{"Action": {"GetTemplateSummary"}, "StackName": {"app"}},
		{"Action": {"ListStacks"}},
		{"Action": {"DeleteChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"x"}},
	} {
		w := cfnServe(h, form)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("%v: want AccessDenied, got %d %s", form, w.Code, w.Body.String())
		}
		if b := w.Body.String(); strings.Contains(b, "<StackName>") || strings.Contains(b, "KMS") || strings.Contains(b, "legacy-plaintext") {
			t.Errorf("%v: a denied call leaked stack data: %s", form, w.Body.String())
		}
	}
}

// With RBAC the reads work; a reader (get only) cannot create, update or delete.
func TestCFN_UserRBACVerbs(t *testing.T) {
	h, _ := cfnServeDoorway(t)
	h.cs = readerSAR()
	if w := cfnServe(h, url.Values{"Action": {"DescribeStacks"}, "StackName": {"app"}}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<StackName>app</StackName>") {
		t.Fatalf("a reader may describe: %d %s", w.Code, w.Body.String())
	}
	if w := cfnServe(h, url.Values{"Action": {"GetTemplate"}, "StackName": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("a reader may get the template: %d %s", w.Code, w.Body.String())
	}
	for _, form := range []url.Values{
		{"Action": {"CreateStack"}, "StackName": {"new"}, "TemplateBody": {secretTmpl}},
		{"Action": {"UpdateStack"}, "StackName": {"app"}, "TemplateBody": {secretTmpl}},
		{"Action": {"DeleteStack"}, "StackName": {"app"}},
		{"Action": {"CreateChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}, "TemplateBody": {secretTmpl}},
		{"Action": {"ExecuteChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}},
	} {
		if w := cfnServe(h, form); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("a reader's %s must be denied up front: %d %s", form.Get("Action"), w.Code, w.Body.String())
		}
	}
	if _, found, _ := h.applierForIdentityMust(t).GetStack(context.Background(), "new"); found {
		t.Fatal("a denied CreateStack must create nothing")
	}
}

func (h *cfnDoorway) applierForIdentityMust(t *testing.T) *impersonatingApplier {
	ap, err := h.applierForIdentity("openinfra:tester", testUser.Groups)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// A User's data-plane policy is enforced on stack actions (it can only tighten RBAC).
func TestCFN_UserDataPlaneDenyEnforced(t *testing.T) {
	h, _ := cfnServeDoorway(t)
	h.authz = userPolicy(dpAllow([]string{"cloudformation:*"}, "*"), dpDeny([]string{"cloudformation:GetTemplate"}, "Stack::app"))
	if w := cfnServe(h, url.Values{"Action": {"GetTemplate"}, "StackName": {"app"}}); w.Code != http.StatusForbidden {
		t.Fatalf("GetTemplate on a denied stack must be refused: %d %s", w.Code, w.Body.String())
	}
	if w := cfnServe(h, url.Values{"Action": {"DescribeStacks"}, "StackName": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("DescribeStacks is still allowed: %d %s", w.Code, w.Body.String())
	}
}

// DescribeStacks shows a NoEcho parameter as "****" — also on a record written before NoEcho values were
// kept apart; the template summary and ValidateTemplate report NoEcho.
func TestCFN_NoEchoMasked(t *testing.T) {
	h, _ := cfnServeDoorway(t)
	w := cfnServe(h, url.Values{"Action": {"DescribeStacks"}, "StackName": {"app"}})
	body := w.Body.String()
	if strings.Contains(body, "legacy-plaintext") || !strings.Contains(body, "<ParameterKey>DbPassword</ParameterKey><ParameterValue>****</ParameterValue>") {
		t.Fatalf("NoEcho value not masked:\n%s", body)
	}
	if !strings.Contains(body, "<ParameterValue>prod</ParameterValue>") {
		t.Fatalf("a plain parameter is shown as is:\n%s", body)
	}
	for _, action := range []string{"GetTemplateSummary", "ValidateTemplate"} {
		// (ValidateTemplate plans without parameter values, so here DbPassword has a default)
		tmpl := strings.Replace(secretTmpl, "NoEcho: true }", "NoEcho: true, Default: x }", 1)
		w := cfnServe(h, url.Values{"Action": {action}, "TemplateBody": {tmpl}})
		b := w.Body.String()
		if !strings.Contains(b, "<ParameterKey>DbPassword</ParameterKey>") || !strings.Contains(b, "<NoEcho>true</NoEcho>") || !strings.Contains(b, "<NoEcho>false</NoEcho>") {
			t.Errorf("%s must report DbPassword NoEcho true and Env false:\n%s", action, b)
		}
	}
}

// The full round trip: a NoEcho value goes to a Secret, never into the stack or change-set ConfigMaps;
// UsePreviousValue on an update and on a change set gets it back from there; the stack's creator is
// recorded as its owner; deleting the stack removes the Secrets.
func TestCFN_NoEchoRoundTripAndOwner(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0003")
	cs := h.cs.(*fake.Clientset)
	h.noecho = &noEchoSecrets{cs: cs, ns: "open-infra-aws-shim"}
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	post := func(action string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var rr *httptest.ResponseRecorder
		rr = cfnPost(t, h, ap, form, func(w http.ResponseWriter, r *http.Request) {
			switch action {
			case "create":
				h.createStack(w, r, ap, "req")
			case "update":
				h.updateStack(w, r, ap, "req")
			case "changeset":
				h.createChangeSet(w, r, ap, "req")
			case "execute":
				h.executeChangeSet(w, r, ap, "req")
			case "delete":
				h.deleteStack(w, r, ap, "req")
			}
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", action, rr.Code, rr.Body.String())
		}
		h.ops.drain(10 * time.Second)
		return rr
	}
	noSecretInConfigMaps := func(when string) {
		t.Helper()
		for k, o := range fa.objs {
			if b, _ := json.Marshal(o); strings.Contains(string(b), "s3cret-value") {
				t.Fatalf("%s: the NoEcho value is in %s", when, k)
			}
		}
	}
	secretValue := func() string {
		s, err := cs.CoreV1().Secrets("open-infra-aws-shim").Get(context.Background(), "noecho-cfn-stack-app", metav1.GetOptions{})
		if err != nil {
			return ""
		}
		return string(s.Data["DbPassword"])
	}

	post("create", url.Values{"StackName": {"app"}, "TemplateBody": {secretTmpl},
		"Parameters.member.1.ParameterKey": {"DbPassword"}, "Parameters.member.1.ParameterValue": {"s3cret-value"}})
	rec, _ := recordIn(t, fa, "app")
	if rec == nil || rec.Status != "CREATE_COMPLETE" || rec.Owner != alice.User {
		t.Fatalf("want CREATE_COMPLETE owned by %s: %+v", alice.User, rec)
	}
	noSecretInConfigMaps("after create")
	if secretValue() != "s3cret-value" {
		t.Fatal("the NoEcho value must be kept in its Secret")
	}

	prev := url.Values{"StackName": {"app"}, "TemplateBody": {strings.Replace(secretTmpl, "k1", "k2", 1)},
		"Parameters.member.1.ParameterKey": {"DbPassword"}, "Parameters.member.1.UsePreviousValue": {"true"}}
	post("update", prev)
	rec, _ = recordIn(t, fa, "app")
	if rec.Status != "UPDATE_COMPLETE" || rec.Owner != alice.User {
		t.Fatalf("UsePreviousValue of a NoEcho parameter must update (owner kept): %+v", rec)
	}
	noSecretInConfigMaps("after update")
	if secretValue() != "s3cret-value" {
		t.Fatal("the update must keep the previous NoEcho value")
	}

	csForm := url.Values{"StackName": {"app"}, "ChangeSetName": {"cs1"}, "ChangeSetType": {"UPDATE"},
		"TemplateBody":                     {strings.Replace(secretTmpl, "k1", "k3", 1)},
		"Parameters.member.1.ParameterKey": {"DbPassword"}, "Parameters.member.1.UsePreviousValue": {"true"}}
	post("changeset", csForm)
	noSecretInConfigMaps("after create-change-set")
	post("execute", url.Values{"StackName": {"app"}, "ChangeSetName": {"cs1"}})
	rec, _ = recordIn(t, fa, "app")
	if rec.Status != "UPDATE_COMPLETE" || !strings.Contains(rec.Template, "k3") {
		t.Fatalf("the change set (NoEcho value from its Secret) must execute: %+v", rec)
	}
	noSecretInConfigMaps("after execute")

	post("delete", url.Values{"StackName": {"app"}})
	list, _ := cs.CoreV1().Secrets("open-infra-aws-shim").List(context.Background(), metav1.ListOptions{})
	if len(list.Items) != 0 {
		t.Fatalf("deleting the stack must delete its NoEcho Secrets, %d left", len(list.Items))
	}
}

// DeleteStack checks the caller may delete everything before anything happens: a caller who may not run
// a custom resource's Function (its Delete event runs with the shim's authority) or delete one of the
// stack's objects changes nothing, not even the record.
func TestCFN_DeleteStackPreflight(t *testing.T) {
	for name, deny := range map[string]func(a *authzv1.ResourceAttributes) bool{
		"custom resource Function": func(a *authzv1.ResourceAttributes) bool { return a.Resource == "functions" },
		// (the test RESTMapper's guessed plural is "encryptionkeies"; a cluster's comes from discovery)
		"kubernetes object": func(a *authzv1.ResourceAttributes) bool {
			return strings.HasPrefix(a.Resource, "encryptionke") && a.Verb == "delete"
		},
		"REST v1 API": func(a *authzv1.ResourceAttributes) bool {
			return a.Resource == "applications" && a.Verb == "delete" && a.Name == "api123"
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, ap := cfnTestDoorway(t, "")
			h.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return !deny(a) })
			h.invoker = &http.Client{Timeout: 100 * time.Millisecond} // only reached if the preflight let it through
			ctx := context.Background()
			if err := ap.putRecord(ctx, &cfn.StackRecord{Name: "victim", Namespace: "default", Status: "CREATE_COMPLETE", Owner: "openinfra:someone",
				Resources: []cfn.StackResource{
					{LogicalID: "Key", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "victim-key"},
					{LogicalID: "Api", APIVersion: "cfn.openinfra.dev/v1", Kind: "ApiGatewayRestV1Provision", Name: "api", ProvisionedID: "api123"},
					{LogicalID: "Custom", APIVersion: "cfn.openinfra.dev/v1", Kind: "CustomResourceInvoke", Name: "custom",
						Spec: map[string]any{"function": "handler"}},
				}}); err != nil {
				t.Fatal(err)
			}
			ap.user, ap.groups = "openinfra:tester", testUser.Groups
			rr := cfnPost(t, h, ap, url.Values{"StackName": {"victim"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req") })
			if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "AccessDenied") {
				t.Fatalf("want AccessDenied: %d %s", rr.Code, rr.Body.String())
			}
			rec, found, _ := ap.GetStack(ctx, "victim")
			if !found || rec.Status != "CREATE_COMPLETE" || len(rec.Resources) != 3 {
				t.Fatalf("a refused delete must leave the record as it was: %+v", rec)
			}
		})
	}
}

// Every shim-authority hook checks the caller first, on every path (create, update, execute, recovery).
func TestCFN_ShimAuthorityHooksCheckTheCaller(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	ap.user, ap.groups = "openinfra:tester", testUser.Groups
	invoked, deprovisioned := 0, 0
	base := cfn.DeployOptions{
		Invoke:             func(context.Context, string, string, []byte) (map[string]any, error) { invoked++; return nil, nil },
		DeprovisionRestAPI: func(context.Context, string) error { deprovisioned++; return nil },
	}
	h.cs = csWithSAR(false)
	o := h.asCaller(base, ap)
	if o.Owner != "openinfra:tester" {
		t.Fatalf("owner = %q", o.Owner)
	}
	if _, err := o.Invoke(context.Background(), "default", "fn", nil); err == nil || invoked != 0 {
		t.Fatal("an unauthorized caller's custom resource must not be invoked")
	}
	if err := o.DeprovisionRestAPI(context.Background(), "api1"); err == nil || deprovisioned != 0 {
		t.Fatal("an unauthorized caller's REST API must not be deleted")
	}
	h.cs = csWithSAR(true)
	o = h.asCaller(base, ap)
	if _, err := o.Invoke(context.Background(), "default", "fn", nil); err != nil || invoked != 1 {
		t.Fatalf("an authorized caller's custom resource is invoked: %v", err)
	}
	if err := o.DeprovisionRestAPI(context.Background(), "api1"); err != nil || deprovisioned != 1 {
		t.Fatalf("an authorized caller's REST API is deleted: %v", err)
	}
}

// Change-set records: names are unambiguous, a record is used only for the stack and change set it
// names (also one found under the old, ambiguous name), and a "." in a name is refused.
func TestCFN_ChangeSetNamesUnambiguous(t *testing.T) {
	if changeSetCMName("a", "b-c") == changeSetCMName("a-b", "c") {
		t.Fatal("two different (stack, change set) pairs share a record name")
	}
	h, ap := cfnTestDoorway(t, "")
	ctx := context.Background()
	// A legacy record of stack "a-b", change set "c" — its old name is also what "a" + "b-c" gave.
	data, _ := json.Marshal(changeSet{StackName: "a-b", Name: "c", Type: "UPDATE"})
	st := h.recs()
	legacy := st.object(legacyChangeSetCMName("a-b", "c"), map[string]any{"app.kubernetes.io/managed-by": "cfn"}, nil,
		map[string]string{"changeset.json": string(data)})
	if _, err := st.client().Create(ctx, legacy, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.getChangeSet(ctx, "a", "b-c"); err == nil {
		t.Fatal("stack a must not see stack a-b's change set")
	}
	if cs, err := h.getChangeSet(ctx, "a-b", "c"); err != nil || cs.StackName != "a-b" {
		t.Fatalf("the legacy record is still found for its own stack: %v", err)
	}
	cfnPost(t, h, ap, url.Values{"StackName": {"a"}, "ChangeSetName": {"b-c"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteChangeSet(w, r, ap, "req") })
	if _, err := h.getChangeSet(ctx, "a-b", "c"); err != nil {
		t.Fatal("deleting a's change set must not delete a-b's")
	}
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"a"}, "ChangeSetName": {"b.c"}, "TemplateBody": {secretTmpl}},
		func(w http.ResponseWriter, r *http.Request) { h.createChangeSet(w, r, ap, "req") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "ValidationError") {
		t.Fatalf("a change-set name with a dot must be refused: %d %s", rr.Code, rr.Body.String())
	}
}
