package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const ec2TestNS = "open-infra-cfn"

func ec2Obj(kind, name string, spec, status map[string]any, ann map[string]string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": ec2TestNS}, "spec": spec}}
	if status != nil {
		u.Object["status"] = status
	}
	if ann != nil {
		u.SetAnnotations(ann)
	}
	u.SetUID(types.UID(name + "-uid"))
	return u
}

func ec2Fixture(t *testing.T, objs ...runtime.Object) (*ec2Handler, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	lists := map[schema.GroupVersionResource]string{
		vmClaimGVR: "VirtualMachineList", vmXRGVR: "XVirtualMachineList", volumeGVR: "VolumeList",
		securityGroupGVR: "SecurityGroupList", vpcGVR: "VpcList", subnetGVR: "SubnetList", serviceGVR: "ServiceList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), lists, objs...)
	door := &cfnDoorway{shimDyn: dyn, ns: ec2TestNS, account: "123456789012", region: "us-east-1", cs: csWithSAR(true), authzNS: "authz",
		callerDyn: func(string, []string) (dynamic.Interface, error) { return dyn, nil },
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil))}
	return newEC2Handler(door, nil, door.logger), dyn
}

func ec2Call(h *ec2Handler, claims iam.Claims, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	return w
}

var ec2Alice = iam.Claims{Sub: "alice", Groups: []string{"openinfra:admins"}}

func ec2Web() *unstructured.Unstructured {
	view, _ := cfnViewJSON(cfn.AWSView{InstanceType: "t3.small", KeyName: "ops", Tags: map[string]string{"Name": "web"}})
	return ec2Obj("VirtualMachine", "s-web", map[string]any{"os": "ubuntu-22.04", "cpu": int64(2), "memory": "2Gi", "subnet": "s-a",
		"securityGroups": []any{"s-sg"}, "instanceRole": "s-role", "volumes": []any{map[string]any{"name": "s-data", "deviceName": "/dev/sdf"}}},
		map[string]any{"instanceId": "i-0123456789abcdef0", "ip": "10.16.0.21", "lanIp": "192.0.2.50", "powerState": "Running"},
		map[string]string{cfn.AWSViewAnnotation: view})
}

func cfnViewJSON(v cfn.AWSView) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// #350 item T / #347 item 23: DescribeInstances reports the platform's VMs by the i- id the guest reports,
// with AWS's shape and filters; an id it does not have is InvalidInstanceID.NotFound.
func TestEC2_DescribeInstances(t *testing.T) {
	h, _ := ec2Fixture(t, ec2Web(),
		ec2Obj("Subnet", "s-a", map[string]any{"cidr": "10.20.0.0/24", "vpc": "s-vpc"}, nil, nil),
		// A VM rendered before status.instanceId: its id is derived from its composite's uid.
		ec2Obj("VirtualMachine", "s-old", map[string]any{"os": "debian-12", "resourceRef": map[string]any{"name": "s-old-x"}}, map[string]any{"powerState": "Stopped"}, nil),
		&unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "XVirtualMachine", "metadata": map[string]any{"name": "s-old-x", "uid": "xr-uid"}}})
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}})
	body := w.Body.String()
	oldID := instanceIDForUID("xr-uid")
	for _, want := range []string{"<instanceId>i-0123456789abcdef0</instanceId>", "<instanceId>" + oldID + "</instanceId>",
		"<name>running</name>", "<name>stopped</name>", "<instanceType>t3.small</instanceType>", "<keyName>ops</keyName>",
		"<vpcId>s-vpc</vpcId>", "<subnetId>s-a</subnetId>", "<ipAddress>192.0.2.50</ipAddress>", "<key>Name</key><value>web</value>",
		"<imageId>" + imageIDForOS("ubuntu-22.04") + "</imageId>", "<volumeId>s-data</volumeId>", "instance-profile/s-role"} {
		if !strings.Contains(body, want) {
			t.Errorf("DescribeInstances must contain %s; got %s", want, body)
		}
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {"w*"}})
	if !strings.Contains(w.Body.String(), "i-0123456789abcdef0") || strings.Contains(w.Body.String(), oldID) {
		t.Errorf("tag:Name=w* must select web only: %s", w.Body.String())
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {"i-00000000000000000"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "InvalidInstanceID.NotFound") {
		t.Errorf("an unknown id: %d %s", w.Code, w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {"s-web"}}); !strings.Contains(w.Body.String(), "InvalidInstanceID.Malformed") {
		t.Errorf("a name is not an instance id: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "Filter.1.Name": {"bogus"}, "Filter.1.Value.1": {"x"}}); !strings.Contains(w.Body.String(), "InvalidParameterValue") {
		t.Errorf("an unknown filter: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"RunInstances"}}); w.Code != 501 || !strings.Contains(w.Body.String(), "<Code>NotImplemented</Code>") {
		t.Errorf("an unserved operation: %d %s", w.Code, w.Body.String())
	}
}

// Authorization: RBAC (the caller's own list) and the data-plane policy (an assumed role is default-deny;
// a User's explicit Deny on the resource wins).
func TestEC2_AuthorizationRefusals(t *testing.T) {
	h, dyn := ec2Fixture(t, ec2Web())
	role := iam.Claims{Sub: "assumed-role/r/s", AssumedRole: "r"}
	h.door.authz = checkerFor(policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"ec2:DeleteVolume"}, Resources: []string{"*"}})
	if w := ec2Call(h, role, url.Values{"Action": {"DescribeInstances"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("an assumed role with no policy must be refused: %d %s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, iam.Claims{Sub: "tester"}, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-data"}}); w.Code != 403 {
		t.Errorf("a User's Deny on ec2:DeleteVolume must refuse it: %d %s", w.Code, w.Body.String())
	}
	dyn.PrependReactor("list", "virtualmachines", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(vmClaimGVR.GroupResource(), "", errors.New("RBAC"))
	})
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("a caller RBAC refuses must be refused: %d %s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeKeyPairs"}, "DryRun": {"true"}}); w.Code != 412 {
		t.Errorf("DryRun of an allowed call: %d", w.Code)
	}
}

// In enforce, IAM policy alone decides a read: once it has allowed ec2:Describe*, the kinds are read with the
// shim's own client in the account namespace, so a caller whose Kubernetes identity has no RBAC (the IAM
// compiler has not generated it yet) still reads exactly what its policy allows. In legacy the caller's RBAC
// still is its read permission. A write acts as the caller in both, so it needs the caller's RBAC.
func TestEC2_EnforceReadsWhatIAMPolicyAllowed(t *testing.T) {
	forbidden := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		vmClaimGVR: "VirtualMachineList", volumeGVR: "VolumeList", subnetGVR: "SubnetList", vpcGVR: "VpcList"})
	forbidden.PrependReactor("*", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: a.GetResource().Group, Resource: a.GetResource().Resource}, "", errors.New("no RBAC"))
	})
	vol := ec2Obj("Volume", "s-kept", map[string]any{"size": "20Gi"}, map[string]any{"phase": "Bound"}, nil)
	setup := func(mode string, stmts ...policyengine.Statement) *ec2Handler {
		h, _ := ec2Fixture(t, ec2Web(), vol)
		h.door.callerDyn = func(string, []string) (dynamic.Interface, error) { return forbidden, nil }
		h.door.authz = checkerInMode(t, mode, userDoc(stmts...))
		return h
	}
	user := iam.Claims{Sub: "tester"}
	h := setup("enforce", dpAllow([]string{"ec2:DescribeInstances", "ec2:DescribeVolumes"}, "*"))
	if w := ec2Call(h, user, url.Values{"Action": {"DescribeInstances"}}); w.Code != 200 || !strings.Contains(w.Body.String(), "<instanceId>i-0123456789abcdef0</instanceId>") {
		t.Errorf("enforce: DescribeInstances IAM policy allows must read the account's instances: %d %.300s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, user, url.Values{"Action": {"DescribeVolumes"}}); w.Code != 200 || !strings.Contains(w.Body.String(), "<volumeId>s-kept</volumeId>") {
		t.Errorf("enforce: DescribeVolumes IAM policy allows must read the account's volumes: %d %.300s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, user, url.Values{"Action": {"DescribeVpcs"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("enforce: a Describe IAM policy does not allow is refused: %d %.300s", w.Code, w.Body.String())
	}
	h = setup("enforce", dpAllow([]string{"ec2:DescribeVolumes", "ec2:DeleteVolume"}, "*"))
	if w := ec2Call(h, user, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-kept"}}); w.Code != 403 {
		t.Errorf("enforce: a delete still acts as the caller, whose RBAC refuses it: %d %.300s", w.Code, w.Body.String())
	}
	h = setup("legacy")
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("legacy: the caller's RBAC is its read permission: %d %.300s", w.Code, w.Body.String())
	}
}

// DeleteVolume removes a volume an instance kept, and refuses one a VM still has (VolumeInUse) or a VM's own disk.
func TestEC2_DeleteVolume(t *testing.T) {
	h, dyn := ec2Fixture(t, ec2Web(),
		ec2Obj("Volume", "s-data", map[string]any{"size": "10Gi"}, map[string]any{"phase": "Bound"}, nil),
		ec2Obj("Volume", "s-kept", map[string]any{"size": "20Gi", "encrypted": true, "encryptionKey": "k"}, map[string]any{"phase": "Bound"}, nil))
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVolumes"}, "Filter.1.Name": {"status"}, "Filter.1.Value.1": {"available"}})
	if !strings.Contains(w.Body.String(), "<volumeId>s-kept</volumeId>") || strings.Contains(w.Body.String(), "<volumeId>s-data</volumeId>") {
		t.Errorf("available volumes: %s", w.Body.String())
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVolumes"}, "Filter.1.Name": {"attachment.instance-id"}, "Filter.1.Value.1": {"i-0123456789abcdef0"}})
	if !strings.Contains(w.Body.String(), "<device>/dev/sda1</device>") || !strings.Contains(w.Body.String(), "<volumeId>s-data</volumeId>") {
		t.Errorf("an instance's volumes include its root and its attached volume: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-data"}}); !strings.Contains(w.Body.String(), "VolumeInUse") {
		t.Errorf("an attached volume: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-kept"}}); w.Code != 200 {
		t.Fatalf("a kept volume: %d %s", w.Code, w.Body.String())
	}
	if _, err := dyn.Resource(volumeGVR).Namespace(ec2TestNS).Get(t.Context(), "s-kept", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("the kept volume must be gone: %v", err)
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"s-nope"}}); !strings.Contains(w.Body.String(), "InvalidVolume.NotFound") {
		t.Errorf("an unknown volume: %s", w.Body.String())
	}
}

// Images, regions and zones are the catalog and the install's one region and zone.
func TestEC2_CatalogRegionsZones(t *testing.T) {
	h, _ := ec2Fixture(t)
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeImages"}, "Filter.1.Name": {"name"}, "Filter.1.Value.1": {"ubuntu-*"}})
	if !strings.Contains(w.Body.String(), imageIDForOS("ubuntu-24.04")) || strings.Contains(w.Body.String(), "windows") {
		t.Errorf("images: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeAvailabilityZones"}}); !strings.Contains(w.Body.String(), "<zoneName>us-east-1a</zoneName><zoneId>use1-az1</zoneId>") {
		t.Errorf("zones: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRegions"}, "RegionName.1": {"eu-west-1"}}); w.Code != 400 {
		t.Errorf("another region: %d", w.Code)
	}
}

// Key pairs against a real store: import, the fingerprint AWS reports, duplicate refusal, describe, delete.
func TestServicesPG_EC2KeyPairs(t *testing.T) {
	db := freshPGDB(t)
	st := &ec2KeyStore{db: db}
	if err := st.ensureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	h, _ := ec2Fixture(t)
	h.keys = st
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOqR0Jm8b2Y2c6JkqfQm0R0nq0nKc1pV0b9b1o0tK3Yv ops@example"
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"ImportKeyPair"}, "KeyName": {"ops"}, "PublicKeyMaterial": {base64.StdEncoding.EncodeToString([]byte(pub))}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<keyPairId>key-") {
		t.Fatalf("ImportKeyPair: %d %s", w.Code, w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"ImportKeyPair"}, "KeyName": {"ops"}, "PublicKeyMaterial": {base64.StdEncoding.EncodeToString([]byte(pub))}}); !strings.Contains(w.Body.String(), "InvalidKeyPair.Duplicate") {
		t.Errorf("a duplicate: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"ImportKeyPair"}, "KeyName": {"bad"}, "PublicKeyMaterial": {"not a key"}}); !strings.Contains(w.Body.String(), "InvalidKey.Format") {
		t.Errorf("a bad key: %s", w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"made"}}); !strings.Contains(w.Body.String(), "BEGIN RSA PRIVATE KEY") {
		t.Errorf("CreateKeyPair returns the private key once: %s", w.Body.String())
	}
	keys, _ := st.publicKeys(t.Context())
	if keys["ops"] != pub[:strings.LastIndex(pub, " ")] || !strings.HasPrefix(keys["made"], "ssh-rsa ") {
		t.Errorf("the CloudFormation front door's key pairs: %v", keys)
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeKeyPairs"}, "KeyName.1": {"missing"}}); !strings.Contains(w.Body.String(), "InvalidKeyPair.NotFound") {
		t.Errorf("an unknown key: %s", w.Body.String())
	}
	h.door.cs = csWithSAR(false)
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DeleteKeyPair"}, "KeyName": {"ops"}}); w.Code != 403 {
		t.Errorf("a caller RBAC refuses cannot delete a key pair: %d", w.Code)
	}
	h.door.cs = csWithSAR(true)
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DeleteKeyPair"}, "KeyName": {"ops"}}); w.Code != 200 {
		t.Errorf("DeleteKeyPair: %d %s", w.Code, w.Body.String())
	}
}
