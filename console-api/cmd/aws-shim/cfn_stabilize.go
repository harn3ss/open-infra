package main

// In CloudFormation's default (STANDARD) deployment mode a resource is complete only once it has fully
// stabilized: an ECS service (AWS::ECS::Service, a kind: Application here) once it has reached a steady
// state, every desired task running on its current revision and no earlier one left. A service that never
// gets there fails the resource after three hours, as AWS's does, and the operation rolls back. In EXPRESS
// mode (DeploymentConfig.Mode) the operation completes once the resource's configuration is applied, and the
// service keeps rolling out in the background, as AWS documents.

import (
	"context"
	"fmt"
	"net/url"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ecsStabilizeTimeout is how long a stack waits for an ECS service to reach a steady state before the
// resource fails, as AWS's does.
const ecsStabilizeTimeout = 3 * time.Hour

var deploymentGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

// deploymentMode is a stack operation's DeploymentConfig.Mode: STANDARD (the default) or EXPRESS. ok is false
// for any other value.
func deploymentMode(form url.Values) (mode string, ok bool) {
	switch m := form.Get("DeploymentConfig.Mode"); m {
	case "", "STANDARD":
		return "STANDARD", true
	case "EXPRESS":
		return "EXPRESS", true
	default:
		return m, false
	}
}

// waitServiceStable waits until the Application app's service is steady: its Deployment has taken its
// current spec, runs as many tasks as the service desires, every one of them on its current revision and
// ready, and none of an earlier one. It reads the Deployment with the shim's own client.
func (a *impersonatingApplier) waitServiceStable(ctx context.Context, app string, timeout time.Duration) error {
	desired := -1
	if gvr, err := a.gvrFor(ecsAppAPIVersion, "Application"); err == nil {
		if u, err := a.caller.Resource(gvr).Namespace(a.ns).Get(ctx, app, metav1.GetOptions{}); err == nil {
			lo, okLo, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "scaling", "min")
			hi, okHi, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "scaling", "max")
			if okLo && okHi && toInt(lo) == toInt(hi) {
				desired = toInt(lo) // a fixed count: the service's desiredCount
			}
		}
	}
	deadline := time.Now().Add(timeout)
	last := "its tasks have not started"
	for {
		if u, err := a.shim.Resource(deploymentGVR).Namespace(a.ns).Get(ctx, app, metav1.GetOptions{}); err == nil {
			steady, state := deploymentSteady(u, desired)
			if steady {
				return nil
			}
			last = state
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the ECS service did not reach a steady state within %s (%s)", timeout, last)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the ECS service did not reach a steady state (%s): %w", last, ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

// deploymentSteady reports whether a Deployment is steady for desired tasks (-1: as many as it asks for), and
// where it stands.
func deploymentSteady(u *unstructured.Unstructured, desired int) (bool, string) {
	num := func(path ...string) int {
		v, _, _ := unstructured.NestedFieldNoCopy(u.Object, path...)
		return toInt(v)
	}
	spec, replicas := num("spec", "replicas"), num("status", "replicas")
	updated, available := num("status", "updatedReplicas"), num("status", "availableReplicas")
	state := fmt.Sprintf("running %d of %d", available, spec)
	if desired >= 0 && spec != desired {
		return false, fmt.Sprintf("taking its desired count %d (now %d)", desired, spec)
	}
	if num("status", "observedGeneration") < int(u.GetGeneration()) {
		return false, "taking its new configuration"
	}
	return updated == spec && available == spec && replicas == spec, state
}
