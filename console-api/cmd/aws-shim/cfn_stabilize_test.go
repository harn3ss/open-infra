package main

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func testDeploymentObj(gen int64, spec, observed, replicas, updated, available int64) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "acct"},
		"spec":     map[string]any{"replicas": spec},
		"status": map[string]any{"observedGeneration": observed, "replicas": replicas, "updatedReplicas": updated,
			"availableReplicas": available}}}
	u.SetGeneration(gen)
	return u
}

// A service is steady once its Deployment has taken its spec and runs every desired task on its current
// revision, ready, with none of an earlier one — what ECS calls a steady state.
func TestCFNStabilize_SteadyState(t *testing.T) {
	for _, c := range []struct {
		name    string
		dep     *unstructured.Unstructured
		desired int
		steady  bool
	}{
		{"all running", testDeploymentObj(2, 7, 2, 7, 7, 7), 7, true},
		{"short of its count (placement refused)", testDeploymentObj(2, 7, 2, 4, 4, 4), 7, false},
		{"an earlier revision still running", testDeploymentObj(3, 2, 3, 3, 2, 2), 2, false},
		{"not yet taken its new spec", testDeploymentObj(3, 2, 2, 2, 2, 2), 2, false},
		{"its count not yet the service's", testDeploymentObj(2, 1, 2, 1, 1, 1), 7, false},
		{"no fixed count known", testDeploymentObj(2, 3, 2, 3, 3, 3), -1, true},
	} {
		if got, state := deploymentSteady(c.dep, c.desired); got != c.steady {
			t.Errorf("%s: steady %v (%s), want %v", c.name, got, state, c.steady)
		}
	}
}

// waitServiceStable returns once the service is steady, and fails, saying where it stands, if it is not by
// the deadline.
func TestCFNStabilize_WaitsAndTimesOut(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: "DeploymentList"},
		testDeploymentObj(2, 7, 2, 4, 4, 4))
	a := &impersonatingApplier{shim: dyn, caller: dyn, ns: "acct"}
	err := a.waitServiceStable(context.Background(), "web", 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not reach a steady state") || !strings.Contains(err.Error(), "running 4 of 7") {
		t.Fatalf("a service short of its count: %v", err)
	}
	if _, err := dyn.Resource(gvr).Namespace("acct").Update(context.Background(), testDeploymentObj(2, 7, 2, 7, 7, 7), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.waitServiceStable(context.Background(), "web", time.Second); err != nil {
		t.Fatalf("a steady service: %v", err)
	}
}

// DeploymentConfig.Mode is STANDARD (the default) or EXPRESS; anything else is AWS's validation error.
func TestCFNStabilize_DeploymentMode(t *testing.T) {
	for in, want := range map[string]string{"": "STANDARD", "STANDARD": "STANDARD", "EXPRESS": "EXPRESS"} {
		if got, ok := deploymentMode(url.Values{"DeploymentConfig.Mode": {in}}); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	if _, ok := deploymentMode(url.Values{"DeploymentConfig.Mode": {"FAST"}}); ok {
		t.Error("an unknown mode must be refused")
	}
	h, _ := cfnServeDoorway(t)
	w := cfnServe(h, url.Values{"Action": {"CreateStack"}, "StackName": {"x"}, "TemplateBody": {secretTmpl}, "DeploymentConfig.Mode": {"FAST"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "ValidationError") {
		t.Fatalf("CreateStack with an unknown mode: %d %s", w.Code, w.Body.String())
	}
}
