package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/dynamic"
)

// A REST v1 plan with a Lambda proxy integration to another principal's Function and no authorization —
// what a template can ask CreateStack to build.
func victimRestPlan() map[string]any {
	plan := cfn.RestAPIPlan{LogicalID: "Api", Name: "open-api",
		Methods: []cfn.RestMethodPlan{{Resource: "<root>", HTTPMethod: "ANY", AuthorizationType: "NONE",
			Integration: &cfn.RestIntegrationPlan{Type: "AWS_PROXY",
				URI: "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:victim-fn/invocations"}}},
		Stages: []cfn.RestStagePlan{{StageName: "prod"}}}
	b, _ := json.Marshal(plan)
	var spec map[string]any
	_ = json.Unmarshal(b, &spec)
	return spec
}

// CreateStack's REST v1 API is built with the shim's authority, so the caller is first checked as the API
// Gateway front door checks it: CreateRestApi and each later call, and — for an integration that invokes a
// Lambda — that the caller may itself invoke that Function (the PutIntegration fence).
func TestCFN_ProvisionRestAPIChecksTheCaller(t *testing.T) {
	for name, tc := range map[string]struct {
		sar    func(a *authzv1.ResourceAttributes) bool
		authz  *dataplaneauthz.Checker
		claims *iam.Claims
		want   bool
	}{
		"allowed":                       {sar: func(*authzv1.ResourceAttributes) bool { return true }, want: true},
		"may not create the API (RBAC)": {sar: func(a *authzv1.ResourceAttributes) bool { return a.Resource != "applications" }},
		"may not invoke the Function (RBAC)": {sar: func(a *authzv1.ResourceAttributes) bool {
			return !(a.Resource == "functions" && a.Name == "victim-fn")
		}},
		"policy denies invoking the Function": {sar: func(*authzv1.ResourceAttributes) bool { return true },
			authz: userPolicy(dpAllow([]string{"apigateway:*", "lambda:*"}, "*"), dpDeny([]string{"lambda:InvokeFunction"}, "Function::victim-fn"))},
		"policy denies CreateRestApi": {sar: func(*authzv1.ResourceAttributes) bool { return true },
			authz: userPolicy(dpDeny([]string{"apigateway:CreateRestApi"}, "*"))},
		"role allowed only CreateStack": {sar: func(*authzv1.ResourceAttributes) bool { return true },
			authz:  roleChecker(dpAllow([]string{"cloudformation:CreateStack"}, "*")),
			claims: ptrClaims(ecrRoleClaims())},
		"role allowed the API and the Function": {sar: func(*authzv1.ResourceAttributes) bool { return true },
			authz:  roleChecker(dpAllow([]string{"apigateway:*", "lambda:InvokeFunction"}, "*")),
			claims: ptrClaims(ecrRoleClaims()), want: true},
	} {
		t.Run(name, func(t *testing.T) {
			h, ap := cfnTestDoorway(t, "")
			ap.user, ap.groups = "openinfra:tester", testUser.Groups
			ap.claims = ptrClaims(testUser)
			if tc.claims != nil {
				ap.claims = tc.claims
			}
			h.cs = csWithSARFunc(tc.sar)
			h.authz = tc.authz
			provisioned := 0
			o := h.asCaller(cfn.DeployOptions{ProvisionRestAPI: func(context.Context, map[string]any) (string, error) {
				provisioned++
				return "api1", nil
			}}, ap)
			_, err := o.ProvisionRestAPI(context.Background(), victimRestPlan())
			if tc.want {
				if err != nil || provisioned != 1 {
					t.Fatalf("an authorized caller's API is built: %v", err)
				}
				return
			}
			if err == nil || provisioned != 0 || !cfn.IsUnauthorized(err) {
				t.Fatalf("an unauthorized caller's API must not be built (err %v, provisioned %d)", err, provisioned)
			}
		})
	}
}

// A custom resource's Function, and a REST API's delete, are checked against the caller's data-plane
// policy as well as RBAC: a policy Deny on lambda:InvokeFunction or apigateway:DeleteRestApi holds.
func TestCFN_HooksHonorTheCallersPolicy(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	ap.user, ap.groups, ap.claims = "openinfra:tester", testUser.Groups, ptrClaims(testUser)
	h.authz = userPolicy(dpAllow([]string{"lambda:*", "apigateway:*"}, "*"),
		dpDeny([]string{"lambda:InvokeFunction"}, "Function::handler"), dpDeny([]string{"apigateway:DeleteRestApi"}, "Api::api123"))
	invoked, deleted := 0, 0
	o := h.asCaller(cfn.DeployOptions{
		Invoke:             func(context.Context, string, string, []byte) (map[string]any, error) { invoked++; return nil, nil },
		DeprovisionRestAPI: func(context.Context, string) error { deleted++; return nil },
	}, ap)
	if _, err := o.Invoke(context.Background(), "default", "handler", nil); !cfn.IsUnauthorized(err) || invoked != 0 {
		t.Fatalf("a Function the policy denies is not invoked: %v", err)
	}
	if _, err := o.Invoke(context.Background(), "default", "other", nil); err != nil || invoked != 1 {
		t.Fatalf("another Function is: %v", err)
	}
	if err := o.DeprovisionRestAPI(context.Background(), "api123"); !cfn.IsUnauthorized(err) || deleted != 0 {
		t.Fatalf("an API the policy denies deleting is not deleted: %v", err)
	}
	// DeleteStack's preflight runs the same checks: nothing is touched.
	ctx := context.Background()
	if err := ap.putRecord(ctx, &cfn.StackRecord{Name: "victim", Namespace: "default", Status: "CREATE_COMPLETE",
		Resources: []cfn.StackResource{{LogicalID: "Api", APIVersion: "cfn.openinfra.dev/v1", Kind: "ApiGatewayRestV1Provision", Name: "api", ProvisionedID: "api123"}}}); err != nil {
		t.Fatal(err)
	}
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"victim"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req") })
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "apigateway:DeleteRestApi") {
		t.Fatalf("want AccessDenied naming the denied action: %d %s", rr.Code, rr.Body.String())
	}
	if rec, _, _ := ap.GetStack(ctx, "victim"); rec == nil || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("a refused delete leaves the record as it was: %+v", rec)
	}
}

// An action that names no stack is checked on Stack::* for a User too, as AWS evaluates it on Resource
// "*"; DescribeStacks of every stack leaves out a stack the caller's policy denies describing.
func TestCFN_UnnamedStackActionsCheckedOnAnyStack(t *testing.T) {
	h, ap := cfnServeDoorway(t)
	if err := ap.putRecord(context.Background(), &cfn.StackRecord{Name: "secret", Namespace: "default", Status: "CREATE_COMPLETE",
		Outputs: []cfn.StackOutput{{OutputKey: "Conn", OutputValue: "secret-output"}}}); err != nil {
		t.Fatal(err)
	}
	h.authz = userPolicy(dpAllow([]string{"cloudformation:*"}, "Stack::app"))
	for _, form := range []url.Values{{"Action": {"ListStacks"}}, {"Action": {"DescribeStacks"}}, {"Action": {"ListExports"}}} {
		if w := cfnServe(h, form); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("%v with a grant on one stack only must be denied: %d %s", form, w.Code, w.Body.String())
		}
	}
	if w := cfnServe(h, url.Values{"Action": {"DescribeStacks"}, "StackName": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("the granted stack is described: %d %s", w.Code, w.Body.String())
	}
	h.authz = userPolicy(dpAllow([]string{"cloudformation:*"}, "*"), dpDeny([]string{"cloudformation:DescribeStacks"}, "Stack::secret"))
	w := cfnServe(h, url.Values{"Action": {"DescribeStacks"}})
	b := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(b, "<StackName>app</StackName>") {
		t.Fatalf("every stack the caller may describe is listed: %d %s", w.Code, b)
	}
	if strings.Contains(b, "secret") {
		t.Fatalf("a stack the caller may not describe shows nothing of itself: %s", b)
	}
}

// Executing an UPDATE change set needs UpdateStack's verb, not only ExecuteChangeSet's.
func TestCFN_ExecuteUpdateChangeSetNeedsUpdate(t *testing.T) {
	h, ap := cfnServeDoorway(t)
	ctx := context.Background()
	if err := h.putChangeSet(ctx, &changeSet{StackName: "app", Name: "cs1", TemplateBody: secretTmpl, Type: "UPDATE"}); err != nil {
		t.Fatal(err)
	}
	h.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return a.Verb != "update" })
	w := cfnServe(h, url.Values{"Action": {"ExecuteChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("an UPDATE change set without the update verb must be denied: %d %s", w.Code, w.Body.String())
	}
	if rec, _, _ := ap.GetStack(ctx, "app"); rec == nil || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("a denied execute changes nothing: %+v", rec)
	}
}

// An assumed-role caller is recorded with its role, so a recovery's checks run for the same principal.
func TestCFN_RecordedCallerKeepsTheAssumedRole(t *testing.T) {
	h, _ := cfnTestDoorway(t, "")
	h.callerDyn = func(string, []string) (dynamic.Interface, error) { return h.shimDyn, nil }
	ap, err := h.applierFor(ecrRoleClaims())
	if err != nil {
		t.Fatal(err)
	}
	rc := ap.identity()
	if rc.AssumedRole != ecrTestRole {
		t.Fatalf("recorded caller = %+v", rc)
	}
	back, _ := h.applierForIdentity(rc.User, rc.Groups)
	back.assumedRole = rc.AssumedRole
	if c := back.callerClaims(); c.PrincipalType() != "Role" || c.PrincipalID() != ecrTestRole {
		t.Fatalf("a recovery's checks must run for the role: %+v", c)
	}
}

func ptrClaims(c iam.Claims) *iam.Claims { return &c }
