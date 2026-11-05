package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const webID = "i-0123456789abcdef0"

// ec2Stopped is a second, stopped instance.
func ec2Stopped() *unstructured.Unstructured {
	return ec2Obj("VirtualMachine", "s-db", map[string]any{"os": "ubuntu-24.04", "running": false},
		map[string]any{"instanceId": "i-0fedcba9876543210", "powerState": "Stopped"}, nil)
}

func claimRunning(t *testing.T, dyn *dynamicfake.FakeDynamicClient, name string) (bool, bool) {
	t.Helper()
	u, err := dyn.Resource(vmClaimGVR).Namespace(ec2TestNS).Get(t.Context(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	v, found, _ := unstructured.NestedBool(u.Object, "spec", "running")
	return v, found
}

// StopInstances and StartInstances flip the claim's spec.running and answer EC2's state transitions; a
// stopped instance stopped again (or a running one started) is EC2's no-op, unchanged.
func TestEC2_StopStartInstances(t *testing.T) {
	h, dyn := ec2Fixture(t, ec2Web(), ec2Stopped())
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}})
	if w.Code != 200 {
		t.Fatalf("StopInstances: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"<StopInstancesResponse", "<instancesSet><item><instanceId>" + webID + "</instanceId>",
		"<currentState><code>64</code><name>stopping</name></currentState>", "<previousState><code>16</code><name>running</name></previousState>"} {
		if !strings.Contains(body, want) {
			t.Errorf("StopInstances must contain %s: %s", want, body)
		}
	}
	if running, found := claimRunning(t, dyn, "s-web"); !found || running {
		t.Error("the stopped instance's claim must have spec.running false")
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"StartInstances"}, "InstanceId.1": {"i-0fedcba9876543210"}})
	if !strings.Contains(w.Body.String(), "<currentState><code>0</code><name>pending</name></currentState><previousState><code>80</code><name>stopped</name></previousState>") {
		t.Errorf("StartInstances of a stopped instance: %s", w.Body.String())
	}
	if running, _ := claimRunning(t, dyn, "s-db"); !running {
		t.Error("the started instance's claim must have spec.running true")
	}
	// A stopped instance stopped again: the no-op, its state unchanged both sides.
	h2, dyn2 := ec2Fixture(t, ec2Stopped())
	w = ec2Call(h2, ec2Alice, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {"i-0fedcba9876543210"}})
	if !strings.Contains(w.Body.String(), "<currentState><code>80</code><name>stopped</name></currentState><previousState><code>80</code><name>stopped</name></previousState>") {
		t.Errorf("stopping a stopped instance is a no-op: %s", w.Body.String())
	}
	for _, a := range dyn2.Actions() {
		if a.GetVerb() == "patch" {
			t.Errorf("a no-op must change nothing: %v", a)
		}
	}
}

// TerminateInstances deletes the claim (shutting-down), and refuses one whose DisableApiTermination is set.
func TestEC2_TerminateInstances(t *testing.T) {
	view, _ := cfnViewJSON(cfn.AWSView{DisableApiTermination: true})
	protected := ec2Obj("VirtualMachine", "s-keep", map[string]any{"os": "ubuntu-24.04"},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaaa1", "powerState": "Running"}, map[string]string{cfn.AWSViewAnnotation: view})
	h, dyn := ec2Fixture(t, ec2Web(), protected)
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {"i-0aaaaaaaaaaaaaaa1"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "OperationNotPermitted") || !strings.Contains(w.Body.String(), "disableApiTermination") {
		t.Errorf("a protected instance must be refused: %d %s", w.Code, w.Body.String())
	}
	if _, err := dyn.Resource(vmClaimGVR).Namespace(ec2TestNS).Get(t.Context(), "s-keep", metav1.GetOptions{}); err != nil {
		t.Errorf("the protected instance must survive: %v", err)
	}
	// Both named, one protected: nothing is terminated.
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {webID}, "InstanceId.2": {"i-0aaaaaaaaaaaaaaa1"}})
	if w.Code != 400 {
		t.Errorf("one protected instance refuses the request: %d", w.Code)
	}
	if _, err := dyn.Resource(vmClaimGVR).Namespace(ec2TestNS).Get(t.Context(), "s-web", metav1.GetOptions{}); err != nil {
		t.Errorf("nothing may be terminated when one instance is refused: %v", err)
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {webID}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<currentState><code>32</code><name>shutting-down</name></currentState><previousState><code>16</code><name>running</name></previousState>") {
		t.Fatalf("TerminateInstances: %d %s", w.Code, w.Body.String())
	}
	if _, err := dyn.Resource(vmClaimGVR).Namespace(ec2TestNS).Get(t.Context(), "s-web", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("the terminated instance's claim must be gone: %v", err)
	}
}

// RebootInstances records the request on the claim as the caller, then restarts the VM; only a running
// instance can be rebooted.
func TestEC2_RebootInstances(t *testing.T) {
	h, dyn := ec2Fixture(t, ec2Web(), ec2Stopped())
	var restarted []string
	h.restartVM = func(_ context.Context, ns, name string) error { restarted = append(restarted, ns+"/"+name); return nil }
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"RebootInstances"}, "InstanceId.1": {webID}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<return>true</return>") {
		t.Fatalf("RebootInstances: %d %s", w.Code, w.Body.String())
	}
	if len(restarted) != 1 || restarted[0] != ec2TestNS+"/s-web" {
		t.Errorf("the VM must be restarted once: %v", restarted)
	}
	u, _ := dyn.Resource(vmClaimGVR).Namespace(ec2TestNS).Get(t.Context(), "s-web", metav1.GetOptions{})
	if _, err := time.Parse(time.RFC3339, u.GetAnnotations()[rebootAnnotation]); err != nil {
		t.Errorf("the reboot must be recorded on the claim: %v", u.GetAnnotations())
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"RebootInstances"}, "InstanceId.1": {"i-0fedcba9876543210"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "IncorrectInstanceState") || len(restarted) != 1 {
		t.Errorf("a stopped instance cannot be rebooted: %d %s (restarts %v)", w.Code, w.Body.String(), restarted)
	}
}

// The request's ids: missing, malformed or unknown is EC2's error, and nothing is changed.
func TestEC2_InstanceStateRequestErrors(t *testing.T) {
	h, dyn := ec2Fixture(t, ec2Web())
	for _, c := range []struct {
		form url.Values
		code string
	}{
		{url.Values{"Action": {"StopInstances"}}, "MissingParameter"},
		{url.Values{"Action": {"StopInstances"}, "InstanceId.1": {"s-web"}}, "InvalidInstanceID.Malformed"},
		{url.Values{"Action": {"StartInstances"}, "InstanceId.1": {"i-00000000000000000"}}, "InvalidInstanceID.NotFound"},
		{url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {webID}, "InstanceId.2": {"i-00000000000000000"}}, "InvalidInstanceID.NotFound"},
		{url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}, "Hibernate": {"true"}}, "UnsupportedHibernationConfiguration"},
	} {
		w := ec2Call(h, ec2Alice, c.form)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") {
			t.Errorf("%v: want %s, got %d %s", c.form, c.code, w.Code, w.Body.String())
		}
	}
	for _, a := range dyn.Actions() {
		if v := a.GetVerb(); v == "patch" || v == "delete" {
			t.Errorf("a refused request must change nothing: %v", a)
		}
	}
}

// Authorization per instance: an assumed role needs ec2:<Action> on that instance (a grant on another is
// not enough), a User's explicit Deny refuses it, RBAC refusing the patch refuses it, and DryRun answers
// DryRunOperation only when it would be authorized, changing nothing.
func TestEC2_InstanceStateAuthorization(t *testing.T) {
	roleChecker := func(resource string) *dataplaneauthz.Checker {
		return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "ops", AppliesTo: []string{"Role::ops"},
				Statements: []policyengine.Statement{{Effect: policyengine.Allow, Actions: []string{"ec2:StopInstances", "ec2:DescribeInstances"}, Resources: []string{resource}}}}}}, nil
		}, time.Minute)
	}
	role := iam.Claims{Sub: "assumed-role/ops/s", AssumedRole: "ops"}

	h, dyn := ec2Fixture(t, ec2Web())
	h.door.authz = roleChecker("Instance::i-0ffffffffffffffff")
	if w := ec2Call(h, role, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("a grant on another instance must not stop this one: %d %s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, role, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}, "DryRun": {"true"}}); w.Code != 403 {
		t.Errorf("DryRun of an unauthorized call must be UnauthorizedOperation: %d %s", w.Code, w.Body.String())
	}
	h.door.authz = roleChecker("Instance::" + webID)
	if w := ec2Call(h, role, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}, "DryRun": {"true"}}); w.Code != 412 || !strings.Contains(w.Body.String(), "DryRunOperation") {
		t.Errorf("DryRun of an authorized call: %d %s", w.Code, w.Body.String())
	}
	if running, found := claimRunning(t, dyn, "s-web"); found && !running {
		t.Error("DryRun must change nothing")
	}
	if w := ec2Call(h, role, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}}); w.Code != 200 {
		t.Errorf("a grant on the instance must stop it: %d %s", w.Code, w.Body.String())
	}

	h, _ = ec2Fixture(t, ec2Web())
	h.door.authz = checkerFor(policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"ec2:TerminateInstances"}, Resources: []string{"*"}})
	if w := ec2Call(h, iam.Claims{Sub: "tester"}, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {webID}}); w.Code != 403 {
		t.Errorf("a User's Deny must refuse TerminateInstances: %d %s", w.Code, w.Body.String())
	}

	h, dyn = ec2Fixture(t, ec2Web())
	dyn.PrependReactor("patch", "virtualmachines", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(vmClaimGVR.GroupResource(), "s-web", errors.New("RBAC"))
	})
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {webID}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("the caller's RBAC refusing the change must refuse it: %d %s", w.Code, w.Body.String())
	}
}
