package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// noopApplier is a cfn.Applier that provisions nothing — BuildChangeSet only reads (GetStack) and runs
// the pure plan+translate gates, so this lets the translate gate's refusals be asserted without a cluster.
type noopApplier struct{}

func (noopApplier) Apply(context.Context, []byte) error                  { return nil }
func (noopApplier) Delete(context.Context, string, string, string) error { return nil }
func (noopApplier) WaitReady(context.Context, string, string, string, time.Duration) error {
	return nil
}
func (noopApplier) WaitGone(context.Context, string, string, string, time.Duration) error { return nil }
func (noopApplier) GetStack(context.Context, string) (*cfn.StackRecord, bool, error) {
	return nil, false, nil
}
func (noopApplier) GetSpec(context.Context, string, string, string) (map[string]any, bool, error) {
	return nil, false, nil
}

func simpleTD() map[string]any {
	return map[string]any{
		"family": "app",
		"containerDefinitions": []any{
			map[string]any{
				"name":         "app",
				"image":        "registry/app:1",
				"portMappings": []any{map[string]any{"containerPort": 8080}},
				"environment":  []any{map[string]any{"name": "TIER", "value": "prod"}},
			},
		},
	}
}

// (a) The adapter synthesizes a CloudFormation template the cfn engine ACCEPTS for a plain
// single-container service — proving the camelCase->PascalCase mapping lands on the translator's
// `known` property names and the TaskDefinition !Ref resolves in-stack.
func TestECS_SpecScalingMinReadsInt64(t *testing.T) {
	// Regression: unstructured.NestedMap (live-object reads) surfaces JSON integers as int64, so
	// DescribeServices read desiredCount=0 until toInt handled int64. Lock the exact path.
	spec := map[string]any{"scaling": map[string]any{"min": int64(3), "max": int64(3)}}
	if got := specScalingMin(spec); got != 3 {
		t.Fatalf("specScalingMin with int64 min = %d, want 3 (toInt must handle int64 from unstructured)", got)
	}
	if got := toInt(int64(5)); got != 5 {
		t.Fatalf("toInt(int64(5)) = %d, want 5", got)
	}
}

func TestECS_AdapterAcceptsSimpleService(t *testing.T) {
	svc := map[string]any{"serviceName": "web", "taskDefinition": "app:1", "desiredCount": 3}
	tmpl, err := buildECSTemplate("web", svc, simpleTD())
	if err != nil {
		t.Fatalf("buildECSTemplate: %v", err)
	}
	plan, err := cfn.BuildPlan(tmpl, nil, "web")
	if err != nil {
		t.Fatalf("BuildPlan: %v (template: %s)", err, tmpl)
	}
	if plan.Verdict == cfn.Rejected {
		t.Fatalf("a simple single-container service must be accepted; blockers: %v\ntemplate: %s", plan.Blockers, tmpl)
	}
}

// (b1) A Fargate service with a raw/opaque awsvpc subnet is REFUSED by the synchronous translate gate
// (BuildChangeSet applies nothing) — never silently mapped. This is the exact refusal BuildPlan alone
// would miss (BuildPlan does not run translators), so the gate must include the translate pass.
func TestECS_AdapterRefusesFargateRawSubnet(t *testing.T) {
	svc := map[string]any{
		"serviceName":    "web",
		"taskDefinition": "app:1",
		"desiredCount":   1,
		"launchType":     "FARGATE",
		"networkConfiguration": map[string]any{
			"awsvpcConfiguration": map[string]any{
				"subnets":        []any{"subnet-0123456789abcdef0"},
				"securityGroups": []any{"sg-01"},
			},
		},
	}
	tmpl, err := buildECSTemplate("web", svc, simpleTD())
	if err != nil {
		t.Fatalf("buildECSTemplate: %v", err)
	}
	if _, _, _, cerr := cfn.BuildChangeSet(context.Background(), tmpl, cfn.DeployOptions{StackName: "web", Namespace: "default"}, noopApplier{}); cerr == nil {
		t.Fatalf("a Fargate service with a raw awsvpc subnet must be refused by the translate gate\ntemplate: %s", tmpl)
	}
}

// (b2) An unsupported volume type (EFS) must be refused, NOT silently mapped to an ephemeral emptyDir.
// This proves the EFSVolumeConfiguration acronym override lands on the key the translator checks.
func TestECS_AdapterRefusesEFSVolume(t *testing.T) {
	td := simpleTD()
	td["volumes"] = []any{map[string]any{"name": "data", "efsVolumeConfiguration": map[string]any{"fileSystemId": "fs-1"}}}
	td["containerDefinitions"].([]any)[0].(map[string]any)["mountPoints"] = []any{map[string]any{"sourceVolume": "data", "containerPath": "/data"}}
	svc := map[string]any{"serviceName": "web", "taskDefinition": "app:1", "desiredCount": 1}
	tmpl, err := buildECSTemplate("web", svc, td)
	if err != nil {
		t.Fatalf("buildECSTemplate: %v", err)
	}
	if _, _, _, cerr := cfn.BuildChangeSet(context.Background(), tmpl, cfn.DeployOptions{StackName: "web", Namespace: "default"}, noopApplier{}); cerr == nil {
		t.Fatalf("an EFS task volume must be refused (never silently mapped to emptyDir)\ntemplate: %s", tmpl)
	}
}

func ecsTestDoorway(allowed bool) *ecsDoorway {
	return &ecsDoorway{
		cs:      csWithSAR(allowed),
		authz:   nil, // deniedByDataPlane is a no-op on a nil checker
		authzNS: "default",
		account: "open-infra",
		region:  "us-east-1",
		ns:      "default",
		logger:  discardLogger(),
	}
}

func ecsRequest(target, body string) *http.Request {
	req := httptest.NewRequest("POST", "http://ecs/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerServiceV20141113."+target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	return req
}

func assertECSErrorType(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantType string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status=%d want %d; body=%s", w.Code, wantStatus, w.Body.String())
	}
	var body struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	if body.Type != wantType {
		t.Fatalf("__type=%q want %q (message=%q)", body.Type, wantType, body.Message)
	}
}

// (c) The coarse authorization gate denies when the caller cannot create applications — the same
// impersonated SubjectAccessReview every front door funnels through — before any resource is touched.
func TestECS_AuthzGateDenies(t *testing.T) {
	h := ecsTestDoorway(false)
	w := httptest.NewRecorder()
	h.serve(w, ecsRequest("CreateService", `{"serviceName":"web","taskDefinition":"app:1"}`),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-deny")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
}

// RunTask is refused honestly: a one-off task has no long-lived kind: Application form.
func TestECS_RunTaskRefused(t *testing.T) {
	h := ecsTestDoorway(true)
	w := httptest.NewRecorder()
	h.serve(w, ecsRequest("RunTask", `{"taskDefinition":"app:1"}`),
		iam.Claims{Sub: "erin", Groups: []string{"openinfra:powerusers", "openinfra:users"}}, "req-run")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidParameterException")
}

// An operation the shim does not implement is refused, never faked.
func TestECS_UnsupportedOpRefused(t *testing.T) {
	h := ecsTestDoorway(true)
	w := httptest.NewRecorder()
	h.serve(w, ecsRequest("PutAccountSetting", `{}`),
		iam.Claims{Sub: "erin", Groups: []string{"openinfra:powerusers", "openinfra:users"}}, "req-unsup")
	assertECSErrorType(t, w, http.StatusBadRequest, "ClientException")
}

// The auth-failure dialect is ECS's JSON 1.1 InvalidSignatureException (what an SDK expects for a bad
// signature), so a rejected request is parseable before any operation runs.
func TestECS_AuthFailureDialect(t *testing.T) {
	h := ecsTestDoorway(true)
	w := httptest.NewRecorder()
	h.authFailure(w, ecsRequest("CreateService", `{}`), "req-authfail")
	assertECSErrorType(t, w, http.StatusForbidden, "InvalidSignatureException")
}
