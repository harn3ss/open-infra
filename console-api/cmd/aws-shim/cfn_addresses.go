// A stack's Elastic IP allocations (#347 item 8).
//
// An AWS::EC2::EIP associated with nothing in its stack is an allocation of its own (cfn.KindEC2Address,
// named by its AllocationId): a LAN address held for the stack until the stack deletes it, which an
// AWS::EC2::EIPAssociation in another stack associates with its instance by that AllocationId. The shim
// holds it as a "holder" LoadBalancer Service in the stack namespace, named by the AllocationId and
// labelled openinfra.dev/eip-holder: MetalLB assigns it an address and keeps it. The associated VM's LAN
// Service shares that address (vm-composition.yaml, spec.elasticIp): the same MetalLB sharing key (the
// AllocationId) and the same selector (openinfra.dev/eip-allocation), which MetalLB requires of two
// Services sharing an address with externalTrafficPolicy Local. So the address follows whichever VM names
// the allocation, and stays with the allocation when that VM, or its stack, goes.
//
// As on AWS:
//   - AllocateAddress / ReleaseAddress / DescribeAddresses are checked as the caller (RBAC + data-plane
//     policy, ec2:<Op> on ElasticIp::<AllocationId>);
//   - associating it (a VM naming it, through this front door) is ec2:AssociateAddress on it, and an
//     allocation already associated with another VM is refused (Resource.AlreadyAssociated);
//   - releasing it while it is associated is refused (InvalidIPAddress.InUse), so the stack that owns it
//     fails to delete until the other stack lets go of it.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var serviceGVR = schema.GroupVersionResource{Version: "v1", Resource: "services"}

const (
	eipHolderLabel   = "openinfra.dev/eip-holder"
	eipSelectorLabel = "openinfra.dev/eip-allocation"
	eipShareKey      = "metallb.universe.tf/allow-shared-ip"
	eipHolderPort    = 9 // UDP; the one port a Service must declare (the VM may not publish it, cfn checks)
)

// verbForEC2Op is the RBAC verb an EC2 address operation needs (on applications in the authz namespace,
// as every front door's coarse gate).
func verbForEC2Op(op string) (string, bool) {
	switch op {
	case "DescribeAddresses":
		return "get", true
	case "AllocateAddress":
		return "create", true
	case "AssociateAddress", "DisassociateAddress":
		return "update", true
	case "ReleaseAddress":
		return "delete", true
	}
	return "", false
}

// addressOK reports whether this applier can hold allocations (the shim's own client).
func (a *impersonatingApplier) addressOK() bool { return a.shim != nil }

// holder reads an allocation's holder Service (nil when there is none, or what is there is not one).
func (a *impersonatingApplier) holder(ctx context.Context, alloc string) (*unstructured.Unstructured, error) {
	u, err := a.shim.Resource(serviceGVR).Namespace(a.ns).Get(ctx, alloc, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.GetLabels()[eipHolderLabel] != "true" {
		return nil, fmt.Errorf("service %s in %s exists but is not an Elastic IP allocation's holder", alloc, a.ns)
	}
	return u, nil
}

// addressIP is the address an allocation holds ("" until MetalLB assigns it).
func (a *impersonatingApplier) addressIP(ctx context.Context, alloc string) string {
	u, err := a.holder(ctx, alloc)
	if err != nil || u == nil {
		return ""
	}
	ingress, _, _ := unstructured.NestedSlice(u.Object, "status", "loadBalancer", "ingress")
	if len(ingress) == 0 {
		return ""
	}
	m, _ := ingress[0].(map[string]any)
	ip, _ := m["ip"].(string)
	return ip
}

// addressExists reports whether the allocation is held.
func (a *impersonatingApplier) addressExists(ctx context.Context, alloc string) (bool, error) {
	u, err := a.holder(ctx, alloc)
	return u != nil, err
}

// addressCreate allocates: the holder Service, which MetalLB gives an address and keeps it on.
func (a *impersonatingApplier) addressCreate(ctx context.Context, alloc, stack string) error {
	if !strings.HasPrefix(alloc, "eipalloc-") {
		return fmt.Errorf("%q is not an allocation id", alloc)
	}
	labels := map[string]any{eipHolderLabel: "true", "app.kubernetes.io/managed-by": "cfn"}
	if stack != "" {
		labels["cfn.openinfra.dev/stack"] = stack
	}
	svc := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{
			"name": alloc, "namespace": a.ns, "labels": labels,
			"annotations": map[string]any{eipShareKey: alloc},
		},
		"spec": map[string]any{
			"type":                  "LoadBalancer",
			"externalTrafficPolicy": "Local",
			"selector":              map[string]any{eipSelectorLabel: alloc},
			"ports":                 []any{map[string]any{"name": "hold", "port": int64(eipHolderPort), "protocol": "UDP", "targetPort": int64(eipHolderPort)}},
		},
	}}
	_, err := a.shim.Resource(serviceGVR).Namespace(a.ns).Create(ctx, svc, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// associatedWith lists the Services other than the holder that share the allocation's address: the LAN
// Services of the VMs it is associated with.
func (a *impersonatingApplier) associatedWith(ctx context.Context, alloc string) ([]string, error) {
	list, err := a.shim.Resource(serviceGVR).Namespace(a.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range list.Items {
		if s.GetName() == alloc || s.GetAnnotations()[eipShareKey] != alloc {
			continue
		}
		out = append(out, s.GetName())
	}
	return out, nil
}

// addressDelete releases the allocation, refusing while it is associated (as AWS's ReleaseAddress).
func (a *impersonatingApplier) addressDelete(ctx context.Context, alloc string) error {
	users, err := a.associatedWith(ctx, alloc)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return fmt.Errorf("InvalidIPAddress.InUse: the address of allocation %s is associated (%s); disassociate it (delete or update the stack whose EIPAssociation names it) before releasing it", alloc, strings.Join(users, ", "))
	}
	err = a.shim.Resource(serviceGVR).Namespace(a.ns).Delete(ctx, alloc, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// checkAddressAssociation authorizes a VM that names an Elastic IP allocation (spec.elasticIp): the caller
// may associate it (ec2:AssociateAddress), it exists here, and no other VM has it. Anything else passes.
func (a *impersonatingApplier) checkAddressAssociation(ctx context.Context, obj *unstructured.Unstructured) error {
	if obj.GetKind() != "VirtualMachine" || !strings.HasPrefix(obj.GetAPIVersion(), "openinfra.dev/") {
		return nil
	}
	alloc, _, _ := unstructured.NestedString(obj.Object, "spec", "elasticIp", "allocationId")
	if alloc == "" {
		return nil
	}
	if a.shim == nil || a.door == nil {
		return cfn.Unauthorized("VirtualMachine " + obj.GetName() + " names Elastic IP allocation " + alloc + ", which this deploy path cannot check")
	}
	verb, _ := verbForEC2Op("AssociateAddress")
	if ok, reason := a.door.callerCan(ctx, a, verb, "openinfra.dev", "applications", a.door.authzNS, alloc); !ok {
		return cfn.Unauthorized("not authorized to perform ec2:AssociateAddress on " + alloc + ": " + reason)
	}
	if ok, reason := a.door.callerPolicyAllows(ctx, a, "ec2:AssociateAddress", "ElasticIp", alloc); !ok {
		return cfn.Unauthorized("not authorized to perform ec2:AssociateAddress on " + alloc + ": " + reason)
	}
	ok, err := a.addressExists(ctx, alloc)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("InvalidAllocationID.NotFound: the allocation ID %s does not exist", alloc)
	}
	users, err := a.associatedWith(ctx, alloc)
	if err != nil {
		return err
	}
	own := obj.GetName() + "-lan"
	for _, u := range users {
		if u != own {
			return fmt.Errorf("Resource.AlreadyAssociated: allocation %s is already associated (%s); an Elastic IP is one address on one instance", alloc, u)
		}
	}
	return nil
}
