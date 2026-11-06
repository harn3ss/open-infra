package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// EC2 keeps each account's resources apart: a member account's instances, volumes, security groups, VPCs,
// subnets and addresses are in its home namespace, beside the management account's (in the stack
// namespace) of the same names; each account sees, changes and deletes its own alone, and the OwnerId and
// ARNs it is answered with name it.

const memberWebID = "i-0aaaaaaaaaaaaaaa1"

var ec2Bob = iam.Claims{Sub: "bob", Account: testMember}

// inNS is u in namespace ns.
func inNS(u *unstructured.Unstructured, ns string) *unstructured.Unstructured {
	u.SetNamespace(ns)
	return u
}

// ec2AccountsFixture: the management account's web instance (its s-data volume attached), group, VPC,
// subnet and address in the stack namespace; the member account's instance, volume, group, VPC, subnet and
// address of the same names in its home. IAM policy decides (enforce): alice and bob may do anything.
func ec2AccountsFixture(t *testing.T) (*ec2Handler, runtime.Object) {
	t.Helper()
	memberVM := inNS(ec2Obj("VirtualMachine", "s-web", map[string]any{"os": "ubuntu-24.04", "subnet": "s-a", "instanceRole": "s-role"},
		map[string]any{"instanceId": memberWebID, "ip": "10.99.0.5", "powerState": "Running"}, nil), memberHome)
	objs := []runtime.Object{
		ec2Web(),
		ec2Obj("Volume", "s-data", map[string]any{"size": "10Gi"}, map[string]any{"phase": "Bound"}, nil),
		ec2Obj("SecurityGroup", "s-sg", map[string]any{"ingress": []any{map[string]any{"ports": []any{int64(22)},
			"from": []any{map[string]any{"cidr": "10.1.0.0/16"}}}}}, nil, nil),
		ec2Obj("Vpc", "s-vpc", map[string]any{}, map[string]any{"ready": true}, nil),
		ec2Obj("Subnet", "s-a", map[string]any{"cidr": "10.20.0.0/24", "vpc": "s-vpc"}, map[string]any{"ready": true}, nil),
		eipHolder("eipalloc-mgmt", ec2TestNS, "198.51.100.10"),
		memberVM,
		inNS(ec2Obj("Volume", "s-data", map[string]any{"size": "30Gi", "encrypted": true, "encryptionKey": "mk"}, map[string]any{"phase": "Bound"}, nil), memberHome),
		inNS(ec2Obj("SecurityGroup", "s-sg", map[string]any{"ingress": []any{map[string]any{"ports": []any{int64(443)},
			"from": []any{map[string]any{"cidr": "10.99.0.0/16"}}}}}, nil, nil), memberHome),
		inNS(ec2Obj("Vpc", "s-vpc", map[string]any{}, map[string]any{"ready": true}, nil), memberHome),
		inNS(ec2Obj("Subnet", "s-a", map[string]any{"cidr": "10.99.0.0/24", "vpc": "s-vpc"}, map[string]any{"ready": true}, nil), memberHome),
		eipHolder("eipalloc-member", memberHome, "198.51.100.20"),
	}
	h, _ := ec2Fixture(t, objs...)
	h.door.authz = doorAccountsAuthz(t)
	return h, memberVM
}

// eipHolder is an Elastic IP allocation's holder Service in ns (cfn_addresses.go).
func eipHolder(name, ns, ip string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{eipHolderLabel: "true"}},
		"status":   map[string]any{"loadBalancer": map[string]any{"ingress": []any{map[string]any{"ip": ip}}}}}}
}

// ec2CallIn is ec2Call on a request acting in ctx's account, as the router marks an account-scoped door's.
func ec2CallIn(h *ec2Handler, ctx context.Context, claims iam.Claims, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(form.Encode())).WithContext(inAccountScope(ctx))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	return w
}

func mustHave(t *testing.T, what, body string, want, notWant []string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(body, s) {
			t.Errorf("%s must contain %s: %.600s", what, s, body)
		}
	}
	for _, s := range notWant {
		if strings.Contains(body, s) {
			t.Errorf("%s must not contain %s: %.600s", what, s, body)
		}
	}
}

func TestEC2Accounts_DoorIsAccountScoped(t *testing.T) {
	if !accountScopedServices["ec2"] {
		t.Fatal("the EC2 door keeps each account's resources apart, so it is listed as account-scoped")
	}
}

// Each account's Describe* reads its own namespace: the member account's instance, volume, group, VPC,
// subnet and address, never the management account's of the same name, and the other way round.
func TestEC2Accounts_DescribesAreTheCallersAccounts(t *testing.T) {
	h, _ := ec2AccountsFixture(t)
	member, mgmt := memberCtx(), context.Background()
	const mgmtAcct = "123456789012" // the fixture door's (the install's) account

	w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeInstances"}})
	if w.Code != 200 {
		t.Fatalf("member DescribeInstances: %d %s", w.Code, w.Body.String())
	}
	mustHave(t, "the member account's instances", w.Body.String(),
		[]string{"<instanceId>" + memberWebID + "</instanceId>", "<ownerId>" + testMember + "</ownerId>",
			"arn:aws:iam::" + testMember + ":instance-profile/s-role", "<privateIpAddress>10.99.0.5</privateIpAddress>"},
		[]string{webID, mgmtAcct})
	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeInstances"}, "Filter.1.Name": {"owner-id"}, "Filter.1.Value.1": {testMember}})
	mustHave(t, "the member account's owner-id filter", w.Body.String(), []string{memberWebID}, nil)
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {webID}}); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "InvalidInstanceID.NotFound") {
		t.Errorf("the management account's instance is no instance of the member account: %d %s", w.Code, w.Body.String())
	}
	w = ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeInstances"}})
	mustHave(t, "the management account's instances", w.Body.String(),
		[]string{"<instanceId>" + webID + "</instanceId>", "<ownerId>" + mgmtAcct + "</ownerId>", "arn:aws:iam::" + mgmtAcct + ":instance-profile/s-role"},
		[]string{memberWebID, testMember})

	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeVolumes"}})
	mustHave(t, "the member account's volumes", w.Body.String(),
		[]string{"<volumeId>s-data</volumeId><size>30</size>", "<kmsKeyId>arn:aws:kms:us-east-1:" + testMember + ":key/mk</kmsKeyId>",
			"<status>available</status>", "<instanceId>" + memberWebID + "</instanceId>"},
		[]string{"<size>10</size>", webID})
	w = ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeVolumes"}})
	mustHave(t, "the management account's volumes", w.Body.String(), []string{"<volumeId>s-data</volumeId><size>10</size>"},
		[]string{"<size>30</size>", testMember, memberWebID})

	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeSecurityGroups"}, "GroupId.1": {"s-sg"}})
	mustHave(t, "the member account's group", w.Body.String(),
		[]string{"<ownerId>" + testMember + "</ownerId>", "<cidrIp>10.99.0.0/16</cidrIp>",
			"<securityGroupArn>arn:aws:ec2:us-east-1:" + testMember + ":security-group/s-sg</securityGroupArn>"},
		[]string{"10.1.0.0/16", mgmtAcct})
	w = ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeSecurityGroups"}})
	mustHave(t, "the management account's group", w.Body.String(), []string{"<cidrIp>10.1.0.0/16</cidrIp>", "<ownerId>" + mgmtAcct + "</ownerId>"},
		[]string{"10.99.0.0/16", testMember})

	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeVpcs"}})
	mustHave(t, "the member account's VPCs", w.Body.String(), []string{"<vpcId>s-vpc</vpcId><ownerId>" + testMember + "</ownerId>"}, []string{mgmtAcct})
	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeSubnets"}})
	mustHave(t, "the member account's subnets", w.Body.String(),
		[]string{"<subnetArn>arn:aws:ec2:us-east-1:" + testMember + ":subnet/s-a</subnetArn>", "<cidrBlock>10.99.0.0/24</cidrBlock>"},
		[]string{"10.20.0.0/24", mgmtAcct})
	w = ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeSubnets"}})
	mustHave(t, "the management account's subnets", w.Body.String(), []string{"<cidrBlock>10.20.0.0/24</cidrBlock>", ":" + mgmtAcct + ":subnet/s-a"},
		[]string{"10.99.0.0/24", testMember})

	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAddresses"}})
	mustHave(t, "the member account's addresses", w.Body.String(), []string{"eipalloc-member", "198.51.100.20"}, []string{"eipalloc-mgmt"})
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAddresses"}, "AllocationId.1": {"eipalloc-mgmt"}}); !strings.Contains(w.Body.String(), "InvalidAllocationID.NotFound") {
		t.Errorf("the management account's address is not the member account's: %s", w.Body.String())
	}
	w = ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeAddresses"}})
	mustHave(t, "the management account's addresses", w.Body.String(), []string{"eipalloc-mgmt"}, []string{"eipalloc-member"})

	// The catalog is the platform's in every account: its images' owner is the install's account.
	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeImages"}})
	mustHave(t, "the catalog, for a member account", w.Body.String(), []string{"<imageOwnerId>" + mgmtAcct + "</imageOwnerId>"}, []string{testMember})
}

// A member account deletes, stops and reboots its own volume and instance, in its home, and never the
// management account's of the same name.
func TestEC2Accounts_WritesAreTheCallersAccounts(t *testing.T) {
	h, _ := ec2AccountsFixture(t)
	member := memberCtx()
	dyn := h.door.shimDyn
	get := func(kind, ns, name string) (*unstructured.Unstructured, error) {
		gvr := vmClaimGVR
		if kind == "volumes" {
			gvr = volumeGVR
		}
		return dyn.Resource(gvr).Namespace(ns).Get(t.Context(), name, metav1.GetOptions{})
	}

	// DeleteVolume: the member's s-data is available, and goes; the management account's, attached to its
	// instance, is untouched (it is in use there, and not the member's at all).
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-data"}}); w.Code != 200 {
		t.Fatalf("member DeleteVolume of its own volume: %d %s", w.Code, w.Body.String())
	}
	if _, err := get("volumes", memberHome, "s-data"); !apierrors.IsNotFound(err) {
		t.Errorf("the member account's volume must be gone: %v", err)
	}
	if _, err := get("volumes", ec2TestNS, "s-data"); err != nil {
		t.Errorf("the management account's volume of the same name must be untouched: %v", err)
	}
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-data"}}); !strings.Contains(w.Body.String(), "InvalidVolume.NotFound") {
		t.Errorf("deleted, the member account has no such volume (the management account's is not its): %s", w.Body.String())
	}

	// StopInstances: the member's own instance's claim, in its home.
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"StopInstances"}, "InstanceId.1": {memberWebID}}); w.Code != 200 {
		t.Fatalf("member StopInstances: %d %s", w.Code, w.Body.String())
	}
	u, _ := get("vms", memberHome, "s-web")
	if running, found, _ := unstructured.NestedBool(u.Object, "spec", "running"); !found || running {
		t.Error("the member account's instance must be stopped")
	}
	u, _ = get("vms", ec2TestNS, "s-web")
	if _, found, _ := unstructured.NestedBool(u.Object, "spec", "running"); found {
		t.Error("the management account's instance of the same name must be untouched")
	}
	// The management account's instance is no instance of the member account's to stop or terminate.
	for _, op := range []string{"StopInstances", "TerminateInstances", "RebootInstances"} {
		if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {op}, "InstanceId.1": {webID}}); !strings.Contains(w.Body.String(), "InvalidInstanceID.NotFound") {
			t.Errorf("member %s of the management account's instance: %d %s", op, w.Code, w.Body.String())
		}
	}
	if _, err := get("vms", ec2TestNS, "s-web"); err != nil {
		t.Errorf("the management account's instance must still exist: %v", err)
	}

	// RebootInstances restarts the member's VM, in its home.
	if err := dyn.Resource(vmClaimGVR).Namespace(memberHome).Delete(t.Context(), "s-web", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	running := inNS(ec2Obj("VirtualMachine", "s-web", map[string]any{"os": "ubuntu-24.04"},
		map[string]any{"instanceId": memberWebID, "powerState": "Running"}, nil), memberHome)
	if _, err := dyn.Resource(vmClaimGVR).Namespace(memberHome).Create(t.Context(), running, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	var restarted string
	h.restartVM = func(_ context.Context, ns, name string) error { restarted = ns + "/" + name; return nil }
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"RebootInstances"}, "InstanceId.1": {memberWebID}}); w.Code != 200 {
		t.Fatalf("member RebootInstances: %d %s", w.Code, w.Body.String())
	}
	if restarted != memberHome+"/s-web" {
		t.Errorf("the member account's reboot restarted %q, want its own VM", restarted)
	}
	u, _ = get("vms", memberHome, "s-web")
	if u.GetAnnotations()[rebootAnnotation] == "" {
		t.Error("the reboot is recorded on the member account's claim")
	}
	u, _ = get("vms", ec2TestNS, "s-web")
	if u.GetAnnotations()[rebootAnnotation] != "" {
		t.Error("the management account's claim must not record the member's reboot")
	}

	// TerminateInstances deletes the member's claim alone.
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {memberWebID}}); w.Code != 200 {
		t.Fatalf("member TerminateInstances: %d %s", w.Code, w.Body.String())
	}
	if _, err := get("vms", memberHome, "s-web"); !apierrors.IsNotFound(err) {
		t.Errorf("the member account's instance must be gone: %v", err)
	}
	if _, err := get("vms", ec2TestNS, "s-web"); err != nil {
		t.Errorf("the management account's instance must be untouched: %v", err)
	}
}

// A member request whose account has no home reaches no namespace at all, never the stack namespace.
func TestEC2Accounts_MemberWithoutHomeReachesNothing(t *testing.T) {
	h, _ := ec2AccountsFixture(t)
	noHome := context.Background()
	noHome = withAccount(noHome, testMember, "")
	if w := ec2CallIn(h, noHome, ec2Bob, url.Values{"Action": {"DescribeInstances"}}); strings.Contains(w.Body.String(), webID) {
		t.Errorf("a member request with no home read the management account's instances: %s", w.Body.String())
	}
}
