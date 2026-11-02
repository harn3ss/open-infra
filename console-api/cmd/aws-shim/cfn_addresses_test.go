package main

import (
	"context"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

const testEIPAlloc = "eipalloc-0123456789abcdef0"

func addressApplier(t *testing.T, allow func(*authzv1.ResourceAttributes) bool) (*impersonatingApplier, *dynamicfake.FakeDynamicClient, *[]authzv1.ResourceAttributes) {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{serviceGVR: "ServiceList"})
	var sars []authzv1.ResourceAttributes
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(act ktesting.Action) (bool, runtime.Object, error) {
		sar := act.(ktesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		sars = append(sars, *sar.Spec.ResourceAttributes)
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allow(sar.Spec.ResourceAttributes)}}, nil
	})
	door := &cfnDoorway{shimDyn: dyn, ns: "open-infra-cfn", cs: cs, authzNS: "default", logger: discardLogger()}
	return &impersonatingApplier{shim: dyn, ns: "open-infra-cfn", door: door, user: "openinfra:alice", groups: []string{"openinfra:admins"}}, dyn, &sars
}

func lanService(name, alloc string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": "open-infra-cfn", "annotations": map[string]any{eipShareKey: alloc}},
		"spec":     map[string]any{"type": "LoadBalancer"},
	}}
}

func vmNaming(name, alloc string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "VirtualMachine",
		"metadata": map[string]any{"name": name},
		"spec":     map[string]any{"elasticIp": map[string]any{"allocationId": alloc}},
	}}
}

// An allocation is a holder Service MetalLB keeps an address on: shared by key, selected by the allocation
// label, one placeholder port; its address is read back once assigned.
func TestAddress_HolderAndItsAddress(t *testing.T) {
	ctx := context.Background()
	a, dyn, _ := addressApplier(t, func(*authzv1.ResourceAttributes) bool { return true })
	if err := a.addressCreate(ctx, testEIPAlloc, ""); err != nil {
		t.Fatal(err)
	}
	u, err := dyn.Resource(serviceGVR).Namespace("open-infra-cfn").Get(ctx, testEIPAlloc, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if u.GetLabels()[eipHolderLabel] != "true" || u.GetAnnotations()[eipShareKey] != testEIPAlloc {
		t.Fatalf("holder labels/annotations = %v %v", u.GetLabels(), u.GetAnnotations())
	}
	sel, _, _ := unstructured.NestedStringMap(u.Object, "spec", "selector")
	etp, _, _ := unstructured.NestedString(u.Object, "spec", "externalTrafficPolicy")
	if sel[eipSelectorLabel] != testEIPAlloc || etp != "Local" {
		t.Fatalf("holder selector %v / eTP %q: it must match the VM LAN Service's for MetalLB to share", sel, etp)
	}
	if ok, err := a.addressExists(ctx, testEIPAlloc); !ok || err != nil {
		t.Fatalf("exists = %v %v", ok, err)
	}
	if ip := a.addressIP(ctx, testEIPAlloc); ip != "" {
		t.Fatalf("no address assigned yet, got %q", ip)
	}
	_ = unstructured.SetNestedSlice(u.Object, []any{map[string]any{"ip": "192.0.2.80"}}, "status", "loadBalancer", "ingress")
	if _, err := dyn.Resource(serviceGVR).Namespace("open-infra-cfn").Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if ip := a.addressIP(ctx, testEIPAlloc); ip != "192.0.2.80" {
		t.Fatalf("address = %q", ip)
	}

	// A Service that is not a holder is never taken for one.
	other := lanService(strings.Replace(testEIPAlloc, "0123", "4567", 1), "")
	if _, err := dyn.Resource(serviceGVR).Namespace("open-infra-cfn").Create(ctx, other, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.addressExists(ctx, other.GetName()); ok || err == nil {
		t.Fatalf("a non-holder Service must not count as an allocation: %v %v", ok, err)
	}
}

// Releasing an associated allocation is refused (InvalidIPAddress.InUse); once nothing shares it, it goes.
func TestAddress_ReleaseRefusedWhileAssociated(t *testing.T) {
	ctx := context.Background()
	a, dyn, _ := addressApplier(t, func(*authzv1.ResourceAttributes) bool { return true })
	if err := a.addressCreate(ctx, testEIPAlloc, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := dyn.Resource(serviceGVR).Namespace("open-infra-cfn").Create(ctx, lanService("web-lan", testEIPAlloc), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.addressDelete(ctx, testEIPAlloc); err == nil || !strings.Contains(err.Error(), "InvalidIPAddress.InUse") || !strings.Contains(err.Error(), "web-lan") {
		t.Fatalf("release while associated must refuse, naming the association: %v", err)
	}
	if err := dyn.Resource(serviceGVR).Namespace("open-infra-cfn").Delete(ctx, "web-lan", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.addressDelete(ctx, testEIPAlloc); err != nil {
		t.Fatalf("release once disassociated: %v", err)
	}
	if ok, _ := a.addressExists(ctx, testEIPAlloc); ok {
		t.Fatal("the holder must be gone")
	}
}

// A VM naming an allocation: the caller must be allowed to associate it, it must exist, and no other VM may
// have it. A VM naming none is not checked.
func TestAddress_AssociationChecks(t *testing.T) {
	ctx := context.Background()
	allowAll := func(*authzv1.ResourceAttributes) bool { return true }

	a, dyn, sars := addressApplier(t, allowAll)
	plain := vmNaming("web", "")
	unstructured.RemoveNestedField(plain.Object, "spec", "elasticIp")
	if err := a.checkAddressAssociation(ctx, plain); err != nil {
		t.Fatalf("a VM without spec.elasticIp: %v", err)
	}
	if err := a.checkAddressAssociation(ctx, vmNaming("web", testEIPAlloc)); err == nil || !strings.Contains(err.Error(), "InvalidAllocationID.NotFound") {
		t.Fatalf("an allocation that does not exist: %v", err)
	}
	if err := a.addressCreate(ctx, testEIPAlloc, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.checkAddressAssociation(ctx, vmNaming("web", testEIPAlloc)); err != nil {
		t.Fatalf("an allowed association of a free allocation: %v", err)
	}
	asked := false
	for _, s := range *sars {
		asked = asked || (s.Verb == "update" && s.Resource == "applications" && s.Name == testEIPAlloc)
	}
	if !asked {
		t.Fatalf("ec2:AssociateAddress must be checked as the caller: %+v", *sars)
	}
	// Its own LAN Service already sharing the address (a re-apply) is fine; another VM's is not.
	if _, err := dyn.Resource(serviceGVR).Namespace("open-infra-cfn").Create(ctx, lanService("web-lan", testEIPAlloc), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.checkAddressAssociation(ctx, vmNaming("web", testEIPAlloc)); err != nil {
		t.Fatalf("re-applying the associated VM: %v", err)
	}
	if err := a.checkAddressAssociation(ctx, vmNaming("other", testEIPAlloc)); err == nil || !strings.Contains(err.Error(), "Resource.AlreadyAssociated") {
		t.Fatalf("a second VM must be refused: %v", err)
	}

	denied, _, _ := addressApplier(t, func(r *authzv1.ResourceAttributes) bool { return r.Verb != "update" })
	if err := denied.checkAddressAssociation(ctx, vmNaming("web", testEIPAlloc)); err == nil || !strings.Contains(err.Error(), "ec2:AssociateAddress") {
		t.Fatalf("a caller who may not associate must be refused: %v", err)
	}
}

func TestAddress_VerbMapping(t *testing.T) {
	for op, want := range map[string]string{"AllocateAddress": "create", "ReleaseAddress": "delete", "DescribeAddresses": "get", "AssociateAddress": "update"} {
		if v, ok := verbForEC2Op(op); !ok || v != want {
			t.Errorf("%s -> %q %v, want %q", op, v, ok, want)
		}
	}
}
