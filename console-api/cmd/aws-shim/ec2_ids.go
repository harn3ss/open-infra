// EC2 ids for the platform's kinds, shared by the EC2 and SSM front doors and the CloudFormation status
// reader (#347 item 23).
//
// An instance's id is i- and the first 17 hex digits of sha256("<XVirtualMachine uid>-instance"): what the
// guest's instance metadata reports (vm-composition.yaml renders it into the metadata agent's config) and
// what the composite carries as status.instanceId, which Crossplane copies to the claim. A VM whose
// composite was last rendered before status.instanceId existed has none yet; its id is derived here the
// same way from its composite's uid, so every API names an instance by the id its guest reports.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	vmClaimGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "virtualmachines"}
	vmXRGVR    = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "xvirtualmachines"}
)

// instanceIDRe is an instance id as AWS writes one (i- and 8 or 17 hex digits); the platform's are 17.
var instanceIDRe = regexp.MustCompile(`^i-([0-9a-f]{8}|[0-9a-f]{17})$`)

// shortHashID is <prefix> and the first n hex digits of sha256(seed), the shape the composition renders
// with Sprig's sha256sum | trunc.
func shortHashID(prefix, seed string, n int) string {
	sum := sha256.Sum256([]byte(seed))
	return prefix + hex.EncodeToString(sum[:])[:n]
}

// instanceIDForUID is the instance id of the VM whose composite has uid.
func instanceIDForUID(xrUID string) string { return shortHashID("i-", xrUID+"-instance", 17) }

// imageIDForOS is the image id the guest's instance metadata reports for a catalog OS (ami-…).
func imageIDForOS(os string) string { return shortHashID("ami-", os+"-image", 17) }

// vmInstanceID is a VM claim's instance id: its status.instanceId, else derived from its composite's uid
// (read with xr, the shim's own client: a composite is cluster-scoped). "" while the claim has no composite.
func vmInstanceID(ctx context.Context, claim *unstructured.Unstructured, xr dynamic.Interface) string {
	if id, _, _ := unstructured.NestedString(claim.Object, "status", "instanceId"); id != "" {
		return id
	}
	ref, _, _ := unstructured.NestedString(claim.Object, "spec", "resourceRef", "name")
	if ref == "" || xr == nil {
		return ""
	}
	u, err := xr.Resource(vmXRGVR).Get(ctx, ref, metav1.GetOptions{})
	if err != nil || string(u.GetUID()) == "" {
		return ""
	}
	return instanceIDForUID(string(u.GetUID()))
}
