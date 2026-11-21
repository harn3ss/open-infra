package main

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// An account's EC2 images (ec2_images.go): made from an instance (its root disk copied into the platform's
// image namespace), shared by launch permission, copied, described with the catalog, and deregistered — each
// account seeing its own and those it may launch, and only the owner changing one.

const (
	testImagesNS = "openinfra-images"
	mgmtAcct     = "123456789012" // the fixture door's (the install's) account
	otherAcct    = "444455556666"
)

// imageFixture is ec2Fixture with the image namespace configured, and root disks for the instances named.
func imageFixture(t *testing.T, roots map[string]string, objs ...runtime.Object) (*ec2Handler, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	h, dyn := ec2Fixture(t, objs...)
	h.imagesNS = testImagesNS
	for key, size := range roots {
		ns, name, _ := strings.Cut(key, "/")
		mode := corev1.PersistentVolumeFilesystem
		pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: corev1.PersistentVolumeClaimSpec{VolumeMode: &mode,
				Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)}}}}
		if _, err := h.door.cs.CoreV1().PersistentVolumeClaims(ns).Create(context.Background(), pvc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return h, dyn
}

func imageDV(t *testing.T, dyn *dynamicfake.FakeDynamicClient, id string) *unstructured.Unstructured {
	t.Helper()
	u, err := dyn.Resource(dataVolumeGVR).Namespace(testImagesNS).Get(context.Background(), id, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("image %s's disk: %v", id, err)
	}
	return u
}

// copyDone marks image id's copy finished (CDI's phase).
func copyDone(t *testing.T, dyn *dynamicfake.FakeDynamicClient, id, phase string) {
	t.Helper()
	u := imageDV(t, dyn, id)
	_ = unstructured.SetNestedField(u.Object, phase, "status", "phase")
	if _, err := dyn.Resource(dataVolumeGVR).Namespace(testImagesNS).Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// madeImageID is the imageId a CreateImage or CopyImage answered.
func madeImageID(t *testing.T, body string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, "<imageId>")
	id, _, ok2 := strings.Cut(rest, "</imageId>")
	if !ok || !ok2 || !accountImageIDRe.MatchString(id) {
		t.Fatalf("no image id in %s", body)
	}
	return id
}

func createImage(t *testing.T, h *ec2Handler, ctx context.Context, claims iam.Claims, form url.Values) string {
	t.Helper()
	form.Set("Action", "CreateImage")
	w := ec2CallIn(h, ctx, claims, form)
	if w.Code != 200 {
		t.Fatalf("CreateImage %v: %d %s", form, w.Code, w.Body.String())
	}
	return madeImageID(t, w.Body.String())
}

// CreateImage copies the instance's root disk into an image in the platform's image namespace, records the
// image's EC2 record on it, stops the running instance while its disk is copied, and answers the image id at
// once, pending; once the copy is done the image is available and the instance runs again.
func TestEC2Images_CreateImage(t *testing.T) {
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "22817013760"}, ec2Web())
	ctx := context.Background()
	id := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"build tools (1.0)"},
		"Description": {"compilers and SDKs"}, "TagSpecification.1.ResourceType": {"image"},
		"TagSpecification.1.Tag.1.Key": {"team"}, "TagSpecification.1.Tag.1.Value": {"builds"},
		"TagSpecification.2.ResourceType": {"snapshot"}, "TagSpecification.2.Tag.1.Key": {"ignored"}})
	if catalogOSOf(id) != "" {
		t.Fatalf("an account image's id is never a catalog image's: %s", id)
	}
	dv := imageDV(t, dyn, id)
	src, _, _ := unstructured.NestedStringMap(dv.Object, "spec", "source", "pvc")
	pvc, _, _ := unstructured.NestedMap(dv.Object, "spec", "pvc")
	if src["namespace"] != ec2TestNS || src["name"] != "s-web-root" {
		t.Errorf("the image is a copy of the instance's root disk: %v", src)
	}
	if pvc["storageClassName"] != "longhorn" || pvc["volumeMode"] != "Filesystem" ||
		pvc["resources"].(map[string]any)["requests"].(map[string]any)["storage"] != "24Gi" {
		t.Errorf("the image's disk is the root's size and volume mode, on the image class: %v", pvc)
	}
	ann, labels := dv.GetAnnotations(), dv.GetLabels()
	for k, want := range map[string]string{annImageName: "build tools (1.0)", annImageDescription: "compilers and SDKs",
		annImageOS: "ubuntu-22.04", annImageRootSize: "24", annImageSourceInst: webID, annImageSourceVM: ec2TestNS + "/s-web",
		annImageRestart: "pending", annImageState: "pending", annImageTags: `{"team":"builds"}`, cdiDeleteAfterComplet: "false",
		cdiUsePopulator: "false"} {
		if ann[k] != want {
			t.Errorf("record %s = %q, want %q", k, ann[k], want)
		}
	}
	if labels[imageLabel] != "true" || labels[imageOwnerLabel] != mgmtAcct {
		t.Errorf("the image's labels: %v", labels)
	}
	if running, _ := claimRunning(t, dyn, "s-web"); running {
		t.Error("the running instance must be stopped while its disk is copied")
	}
	body := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeImages"}, "ImageId.1": {id}}).Body.String()
	mustHave(t, "a pending image", body, []string{"<imageState>pending</imageState>", "<imageOwnerId>" + mgmtAcct + "</imageOwnerId>",
		"<name>build tools (1.0)</name>", "<isPublic>false</isPublic>", "<platformDetails>Linux/UNIX</platformDetails>",
		"<usageOperation>RunInstances</usageOperation>", "<volumeSize>24</volumeSize>", "<sourceInstanceId>" + webID + "</sourceInstanceId>",
		"<imageLocation>" + mgmtAcct + "/build tools (1.0)</imageLocation>", "<key>team</key><value>builds</value>"},
		[]string{"<platform>", "ignored", "imageOwnerAlias"})

	// The copy finishes: the image is available, and the instance is started again, once.
	copyDone(t, dyn, id, "Succeeded")
	h.reconcileImages(ctx)
	if running, _ := claimRunning(t, dyn, "s-web"); !running {
		t.Error("the instance must run again once its image is made")
	}
	if a := imageDV(t, dyn, id).GetAnnotations(); a[annImageState] != "available" || a[annImageRestart] != "done" {
		t.Errorf("the record must say available and the start done: %v", a)
	}
	body = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeImages"}, "Owner.1": {"self"}}).Body.String()
	mustHave(t, "an available image", body, []string{"<imageId>" + id + "</imageId>", "<imageState>available</imageState>"},
		[]string{"open-infra catalog image"})
	// The reconciler is idempotent: a stopped instance is not started twice.
	_ = h.setVMRunning(ctx, ec2TestNS, "s-web", false)
	h.reconcileImages(ctx)
	if running, _ := claimRunning(t, dyn, "s-web"); running {
		t.Error("an image whose instance was started must not start it again")
	}
}

// With NoReboot the instance is not stopped; the image waits for it to stop (a disk in use cannot be
// copied). A stopped instance is imaged as it is, and is not started after. While its disk is copied, the
// instance is not started.
func TestEC2Images_NoRebootAndStoppedInstances(t *testing.T) {
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi", ec2TestNS + "/s-db-root": "20Gi"}, ec2Web(), ec2Stopped())
	ctx := context.Background()
	id := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"web-noreboot"}, "NoReboot": {"true"}})
	if running, found := claimRunning(t, dyn, "s-web"); found && !running {
		t.Error("NoReboot must not stop the instance")
	}
	if a := imageDV(t, dyn, id).GetAnnotations(); a[annImageRestart] != "" || a[annImageNoReboot] != "true" {
		t.Errorf("a NoReboot image starts nothing after: %v", a)
	}
	dbID := "i-0fedcba9876543210"
	sid := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {dbID}, "Name": {"db-image"}})
	if a := imageDV(t, dyn, sid).GetAnnotations(); a[annImageRestart] != "" {
		t.Errorf("a stopped instance is not started after its image: %v", a)
	}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"StartInstances"}, "InstanceId.1": {dbID}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "IncorrectInstanceState") || !strings.Contains(w.Body.String(), sid) {
		t.Errorf("an instance whose disk is being copied must not start: %d %s", w.Code, w.Body.String())
	}
	copyDone(t, dyn, sid, "Succeeded")
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"StartInstances"}, "InstanceId.1": {dbID}}); w.Code != 200 {
		t.Errorf("once its image is made, the instance starts: %d %s", w.Code, w.Body.String())
	}
	// A failed copy: the image is failed, with a state reason, and its instance is started again.
	h2, dyn2 := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi"}, ec2Web())
	fid := createImage(t, h2, ctx, ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"broken"}})
	copyDone(t, dyn2, fid, "Failed")
	h2.reconcileImages(ctx)
	if running, _ := claimRunning(t, dyn2, "s-web"); !running {
		t.Error("an instance whose image failed must run again")
	}
	body := ec2Call(h2, ec2Alice, url.Values{"Action": {"DescribeImages"}, "Filter.1.Name": {"state"}, "Filter.1.Value.1": {"failed"}}).Body.String()
	mustHave(t, "a failed image", body, []string{"<imageId>" + fid + "</imageId>", "<imageState>failed</imageState>",
		"<stateReason><code>Server.InternalError</code>"}, nil)
}

// CreateImage refuses what EC2 refuses, and changes nothing.
func TestEC2Images_CreateImageRefusals(t *testing.T) {
	enc := ec2Obj("VirtualMachine", "s-enc", map[string]any{"os": "ubuntu-24.04", "rootDisk": map[string]any{"encrypted": true, "encryptionKey": "k"}},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaaa7", "powerState": "Running"}, nil)
	norootVM := ec2Obj("VirtualMachine", "s-new", map[string]any{"os": "ubuntu-24.04"},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaaa8", "powerState": "Stopped"}, nil)
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi"}, ec2Web(), enc, norootVM)
	createImage(t, h, context.Background(), ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"taken"}, "NoReboot": {"true"}})
	before := len(dyn.Actions())
	for _, c := range []struct {
		form url.Values
		code string
	}{
		{url.Values{"Name": {"x-image"}}, "MissingParameter"},
		{url.Values{"InstanceId": {"s-web"}, "Name": {"x-image"}}, "InvalidInstanceID.Malformed"},
		{url.Values{"InstanceId": {webID}}, "MissingParameter"},
		{url.Values{"InstanceId": {webID}, "Name": {"no"}}, "InvalidAMIName.Malformed"},
		{url.Values{"InstanceId": {webID}, "Name": {"bad*name"}}, "InvalidAMIName.Malformed"},
		{url.Values{"InstanceId": {webID}, "Name": {"taken"}}, "InvalidAMIName.Duplicate"},
		{url.Values{"InstanceId": {"i-00000000000000000"}, "Name": {"x-image"}}, "InvalidInstanceID.NotFound"},
		{url.Values{"InstanceId": {webID}, "Name": {"x-image"}, "BlockDeviceMapping.1.DeviceName": {"/dev/sdf"}}, "InvalidParameterValue"},
		{url.Values{"InstanceId": {webID}, "Name": {"x-image"}, "Description": {strings.Repeat("d", 256)}}, "InvalidParameterValue"},
		{url.Values{"InstanceId": {"i-0aaaaaaaaaaaaaaa7"}, "Name": {"x-image"}}, "UnsupportedOperation"},
		{url.Values{"InstanceId": {"i-0aaaaaaaaaaaaaaa8"}, "Name": {"x-image"}}, "IncorrectInstanceState"},
	} {
		c.form.Set("Action", "CreateImage")
		w := ec2Call(h, ec2Alice, c.form)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") {
			t.Errorf("%v: want %s, got %d %s", c.form, c.code, w.Code, w.Body.String())
		}
	}
	for _, a := range dyn.Actions()[before:] {
		if v := a.GetVerb(); v == "create" || v == "patch" || v == "delete" {
			t.Errorf("a refused CreateImage must change nothing: %v", a)
		}
	}
	// Without the image namespace, images are not served (DescribeImages lists the catalog alone).
	h.imagesNS = ""
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"CreateImage"}, "InstanceId": {webID}, "Name": {"x-image"}}); w.Code != 503 {
		t.Errorf("CreateImage without the image namespace: %d %s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeImages"}}); w.Code != 200 || strings.Contains(w.Body.String(), "taken") {
		t.Errorf("DescribeImages without the image namespace: %d %s", w.Code, w.Body.String())
	}
}

// sharedFixture: the management account's available image of its web instance.
func sharedFixture(t *testing.T) (*ec2Handler, *dynamicfake.FakeDynamicClient, string) {
	t.Helper()
	h, _ := ec2AccountsFixture(t)
	dyn := h.door.shimDyn.(*dynamicfake.FakeDynamicClient)
	h.imagesNS = testImagesNS
	mode := corev1.PersistentVolumeFilesystem
	_, _ = h.door.cs.CoreV1().PersistentVolumeClaims(ec2TestNS).Create(context.Background(), &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "s-web-root", Namespace: ec2TestNS}, Spec: corev1.PersistentVolumeClaimSpec{VolumeMode: &mode,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("30Gi")}}}}, metav1.CreateOptions{})
	id := createImage(t, h, context.Background(), ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"golden-build"}, "NoReboot": {"true"}})
	copyDone(t, dyn, id, "Succeeded")
	return h, dyn, id
}

// An image is its owner's: another account does not see it until its launch permission names that account
// (or "all"); it then describes it and may launch it, but cannot change, read the attributes of, or
// deregister it (AuthFailure). Removing the permission hides it again.
func TestEC2Images_SharingByLaunchPermission(t *testing.T) {
	h, _, id := sharedFixture(t)
	member, mgmt := memberCtx(), context.Background()
	describe := func(form url.Values) string {
		form.Set("Action", "DescribeImages")
		return ec2CallIn(h, member, ec2Bob, form).Body.String()
	}
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeImages"}, "ImageId.1": {id}}); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "InvalidAMIID.NotFound") {
		t.Errorf("an image not shared with the account does not exist for it: %d %s", w.Code, w.Body.String())
	}
	if b := describe(url.Values{}); strings.Contains(b, id) || !strings.Contains(b, imageIDForOS("ubuntu-24.04")) {
		t.Errorf("the member account sees the catalog, not the unshared image: %.400s", b)
	}
	if imgs, _ := h.launchableImages(member); len(imgs) != 0 {
		t.Errorf("the member account may launch none of the management account's images: %v", imgs)
	}
	for _, c := range []url.Values{
		{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.UserId": {testMember}},
		{"Action": {"DeregisterImage"}, "ImageId": {id}},
		{"Action": {"DescribeImageAttribute"}, "ImageId": {id}, "Attribute": {"launchPermission"}},
	} {
		if w := ec2CallIn(h, member, ec2Bob, c); !strings.Contains(w.Body.String(), "InvalidAMIID.NotFound") {
			t.Errorf("%s on an image the account cannot see: %d %s", c.Get("Action"), w.Code, w.Body.String())
		}
	}

	// The owner shares it with the member account (AWS CLI: --launch-permission "Add=[{UserId=…}]").
	if w := ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id},
		"LaunchPermission.Add.1.UserId": {testMember}}); w.Code != 200 || !strings.Contains(w.Body.String(), "<return>true</return>") {
		t.Fatalf("ModifyImageAttribute add: %d %s", w.Code, w.Body.String())
	}
	mustHave(t, "the shared image", describe(url.Values{"ImageId.1": {id}}),
		[]string{"<imageOwnerId>" + mgmtAcct + "</imageOwnerId>", "<isPublic>false</isPublic>", "<imageState>available</imageState>"}, nil)
	mustHave(t, "ExecutableBy self", describe(url.Values{"ExecutableBy.1": {"self"}}), []string{id}, []string{"open-infra catalog image"})
	if b := describe(url.Values{"Owner.1": {"self"}}); strings.Contains(b, id) {
		t.Errorf("Owner=self is the account's own images, not those shared with it: %.300s", b)
	}
	mustHave(t, "Owner=<the owner>", describe(url.Values{"Owner.1": {mgmtAcct}}), []string{id}, nil)
	if imgs, _ := h.launchableImages(member); imgs[id].State != "available" || imgs[id].OS != "ubuntu-22.04" || imgs[id].RootGiB != 32 {
		t.Errorf("the member account may launch the shared image: %v", imgs)
	}
	for _, c := range []url.Values{
		{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "Description.Value": {"mine now"}},
		{"Action": {"DeregisterImage"}, "ImageId": {id}},
		{"Action": {"DescribeImageAttribute"}, "ImageId": {id}, "Attribute": {"launchPermission"}},
		{"Action": {"ResetImageAttribute"}, "ImageId": {id}, "Attribute": {"launchPermission"}},
	} {
		w := ec2CallIn(h, member, ec2Bob, c)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>AuthFailure</Code>") || !strings.Contains(w.Body.String(), "Not authorized for image:"+id) {
			t.Errorf("%s by an account the image is shared with: %d %s", c.Get("Action"), w.Code, w.Body.String())
		}
	}
	// The owner reads the permission; removes it (the OperationType form): hidden again.
	mustHave(t, "the launch permission", ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id},
		"Attribute": {"launchPermission"}}).Body.String(), []string{"<launchPermission><item><userId>" + testMember + "</userId></item></launchPermission>"}, nil)
	if w := ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "Attribute": {"launchPermission"},
		"OperationType": {"remove"}, "UserId.1": {testMember}}); w.Code != 200 {
		t.Fatalf("ModifyImageAttribute remove: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(describe(url.Values{}), id) {
		t.Error("an image no longer shared with the account must be hidden from it")
	}
	// Public (UserGroup all): every account sees and may launch it.
	if w := ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "OperationType": {"add"},
		"UserGroup.1": {"all"}}); w.Code != 200 {
		t.Fatalf("ModifyImageAttribute public: %d %s", w.Code, w.Body.String())
	}
	mustHave(t, "a public image", describe(url.Values{"ImageId.1": {id}}), []string{"<isPublic>true</isPublic>"}, nil)
	mustHave(t, "ExecutableBy all", describe(url.Values{"ExecutableBy.1": {"all"}, "Filter.1.Name": {"is-public"}, "Filter.1.Value.1": {"true"}}), []string{id}, nil)
	mustHave(t, "the public permission", ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id},
		"Attribute": {"launchPermission"}}).Body.String(), []string{"<item><group>all</group></item>"}, nil)
	// ResetImageAttribute: private again.
	if w := ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"ResetImageAttribute"}, "ImageId": {id}, "Attribute": {"launchPermission"}}); w.Code != 200 {
		t.Fatalf("ResetImageAttribute: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(describe(url.Values{}), id) {
		t.Error("a reset image must be the owner's alone")
	}
	mustHave(t, "a reset permission", ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id},
		"Attribute": {"launchPermission"}}).Body.String(), []string{"<launchPermission/>"}, nil)
}

// The attribute operations' own parameters: description, boot mode, the value checks, and the attributes
// that cannot be reset or are unknown. The catalog's images are no account's to change.
func TestEC2Images_Attributes(t *testing.T) {
	h, _, id := sharedFixture(t)
	call := func(form url.Values) (int, string) {
		w := ec2Call(h, ec2Alice, form)
		return w.Code, w.Body.String()
	}
	if c, b := call(url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "Description.Value": {"tools v2"}}); c != 200 {
		t.Fatalf("description: %d %s", c, b)
	}
	_, b := call(url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id}, "Attribute": {"description"}})
	mustHave(t, "the description", b, []string{"<imageId>" + id + "</imageId>", "<description><value>tools v2</value></description>"}, nil)
	_, b = call(url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "Attribute": {"description"}, "Value": {"tools v3"}})
	mustHave(t, "description by Attribute/Value", b, []string{"<return>true</return>"}, nil)
	_, b = call(url.Values{"Action": {"DescribeImages"}, "Filter.1.Name": {"description"}, "Filter.1.Value.1": {"tools v3"}})
	mustHave(t, "the new description", b, []string{id}, nil)
	_, b = call(url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id}, "Attribute": {"bootMode"}})
	mustHave(t, "the boot mode", b, []string{"<bootMode><value>legacy-bios</value></bootMode>"}, nil)
	// Both forms of launch permission, several accounts at once, the owner's own id ignored.
	_, b = call(url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.UserId": {otherAcct},
		"LaunchPermission.Add.2.UserId": {testMember}, "LaunchPermission.Add.3.UserId": {mgmtAcct}})
	mustHave(t, "two accounts added", b, []string{"<return>true</return>"}, nil)
	_, b = call(url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id}, "Attribute": {"launchPermission"}})
	mustHave(t, "both accounts", b, []string{"<userId>" + otherAcct + "</userId>", "<userId>" + testMember + "</userId>"}, []string{"<userId>" + mgmtAcct})
	_, b = call(url.Values{"Action": {"DescribeImages"}, "ExecutableBy.1": {otherAcct}})
	mustHave(t, "ExecutableBy another account", b, []string{id}, nil)
	for _, c := range []struct {
		form url.Values
		code string
	}{
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}}, "InvalidParameterCombination"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.UserId": {"12345"}}, "InvalidAMIAttributeItemValue"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.Group": {"everyone"}}, "InvalidAMIAttributeItemValue"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "OperationType": {"grant"}, "UserId.1": {otherAcct}}, "InvalidParameterValue"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.OrganizationArn": {"arn:aws:organizations::111122223333:organization/o-abc"}}, "InvalidParameterValue"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.UserId": {otherAcct}, "Description.Value": {"x"}}, "InvalidParameterCombination"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "Attribute": {"kernel"}, "Value": {"x"}}, "InvalidParameterValue"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {"ami-123"}, "Description.Value": {"x"}}, "InvalidAMIID.Malformed"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "Description.Value": {"x"}}, "MissingParameter"},
		{url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id}}, "MissingParameter"},
		{url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {id}, "Attribute": {"colour"}}, "InvalidParameterValue"},
		{url.Values{"Action": {"ResetImageAttribute"}, "ImageId": {id}, "Attribute": {"description"}}, "InvalidParameterValue"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {imageIDForOS("ubuntu-24.04")}, "Description.Value": {"x"}}, "AuthFailure"},
		{url.Values{"Action": {"DeregisterImage"}, "ImageId": {imageIDForOS("windows-server-2022")}}, "AuthFailure"},
		{url.Values{"Action": {"DescribeImageAttribute"}, "ImageId": {"ami-0fffffffffffffff9"}, "Attribute": {"description"}}, "InvalidAMIID.NotFound"},
	} {
		if code, body := call(c.form); code != 400 || !strings.Contains(body, "<Code>"+c.code+"</Code>") {
			t.Errorf("%v: want %s, got %d %s", c.form, c.code, code, body)
		}
	}
	for _, c := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "OperationType": {"add"}, "UserId.1": {"all"}}, "all&#34; for userId item type"},
		{url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "OperationType": {"add"}, "UserGroup.1": {otherAcct}}, otherAcct + "&#34; for group item type"},
	} {
		if _, body := call(c.form); !strings.Contains(body, c.want) {
			t.Errorf("%v: want %s, got %s", c.form, c.want, body)
		}
	}
}

// CopyImage makes a new image of the caller's account from one it may launch, in this region alone; the copy
// is pending until its disk is copied, and is the caller's to share and deregister.
func TestEC2Images_CopyImage(t *testing.T) {
	h, dyn, id := sharedFixture(t)
	member, mgmt := memberCtx(), context.Background()
	copyForm := func(src string) url.Values {
		return url.Values{"Action": {"CopyImage"}, "SourceImageId": {src}, "SourceRegion": {"us-east-1"}, "Name": {"my copy"}}
	}
	if w := ec2CallIn(h, member, ec2Bob, copyForm(id)); w.Code != 400 || !strings.Contains(w.Body.String(), "InvalidAMIID.NotFound") {
		t.Errorf("an image not shared with the account cannot be copied by it: %d %s", w.Code, w.Body.String())
	}
	_ = h.patchImage(mgmt, id, map[string]any{annImageLaunch: testMember, annImageTags: `{"team":"builds"}`})
	w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "SourceRegion": {"us-east-1"},
		"Name": {"my copy"}, "Description": {"for the member's builds"}, "CopyImageTags": {"true"}})
	if w.Code != 200 {
		t.Fatalf("CopyImage of a shared image: %d %s", w.Code, w.Body.String())
	}
	cid := madeImageID(t, w.Body.String())
	dv := imageDV(t, dyn, cid)
	src, _, _ := unstructured.NestedStringMap(dv.Object, "spec", "source", "pvc")
	if src["namespace"] != testImagesNS || src["name"] != id || dv.GetLabels()[imageOwnerLabel] != testMember ||
		dv.GetAnnotations()[annImageSourceImage] != id || dv.GetAnnotations()[annImageOS] != "ubuntu-22.04" {
		t.Errorf("the copy is the member account's, of the source image's disk: %v %v %v", src, dv.GetLabels(), dv.GetAnnotations())
	}
	if dv.GetAnnotations()[annImageTags] != "{}" {
		t.Errorf("CopyImageTags copies only the caller's own image's tags: %s", dv.GetAnnotations()[annImageTags])
	}
	b := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeImages"}, "Owner.1": {"self"}}).Body.String()
	mustHave(t, "the member's copy", b, []string{"<imageId>" + cid + "</imageId>", "<imageState>pending</imageState>",
		"<imageOwnerId>" + testMember + "</imageOwnerId>", "<sourceImageId>" + id + "</sourceImageId>"}, []string{"<imageId>" + id + "</imageId>"})
	if strings.Contains(ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeImages"}}).Body.String(), cid) {
		t.Error("the member account's copy is not the management account's to see")
	}
	for _, c := range []struct {
		form url.Values
		code string
	}{
		{url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "SourceRegion": {"eu-west-1"}, "Name": {"x-copy"}}, "InvalidParameterValue"},
		{url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "Name": {"x-copy"}}, "MissingParameter"},
		{url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "SourceRegion": {"us-east-1"}}, "MissingParameter"},
		{url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "SourceRegion": {"us-east-1"}, "Name": {"my copy"}}, "InvalidAMIName.Duplicate"},
		{url.Values{"Action": {"CopyImage"}, "SourceImageId": {cid}, "SourceRegion": {"us-east-1"}, "Name": {"copy of copy"}}, "IncorrectState"},
		{url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "SourceRegion": {"us-east-1"}, "Name": {"enc"}, "Encrypted": {"true"}}, "InvalidParameterValue"},
		{copyForm(imageIDForOS("debian-12")), "InvalidParameterValue"},
	} {
		if w := ec2CallIn(h, member, ec2Bob, c.form); w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") {
			t.Errorf("%v: want %s, got %d %s", c.form, c.code, w.Code, w.Body.String())
		}
	}
}

// DeregisterImage deletes the owner's image and its disk (no snapshot remains); an instance launched from it
// keeps running. Deregistering an image whose instance waits to be started again starts it.
func TestEC2Images_DeregisterImage(t *testing.T) {
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi"}, ec2Web())
	ctx := context.Background()
	id := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"short-lived"}})
	if running, _ := claimRunning(t, dyn, "s-web"); running {
		t.Fatal("CreateImage must stop the instance")
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DeregisterImage"}, "ImageId": {id}}); w.Code != 200 || !strings.Contains(w.Body.String(), "<return>true</return>") {
		t.Fatalf("DeregisterImage: %d %s", w.Code, w.Body.String())
	}
	if _, err := dyn.Resource(dataVolumeGVR).Namespace(testImagesNS).Get(ctx, id, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("a deregistered image's disk must be deleted: %v", err)
	}
	if running, _ := claimRunning(t, dyn, "s-web"); !running {
		t.Error("an image deregistered while its instance waited must start the instance")
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeImages"}, "ImageId.1": {id}}); !strings.Contains(w.Body.String(), "InvalidAMIID.NotFound") {
		t.Errorf("a deregistered image does not exist: %s", w.Body.String())
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DeregisterImage"}, "ImageId": {id}}); !strings.Contains(w.Body.String(), "InvalidAMIID.NotFound") {
		t.Errorf("deregistering it again: %s", w.Body.String())
	}
}

// DescribeImages: the catalog beside the account's images, the Owner and ExecutableBy scopes, the filters,
// the ids AWS refuses, and pages.
func TestEC2Images_DescribeImages(t *testing.T) {
	win := ec2Obj("VirtualMachine", "s-win", map[string]any{"os": "windows-server-2022"},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaab1", "powerState": "Stopped"}, nil)
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi", ec2TestNS + "/s-win-root": "113816633344"}, ec2Web(), win)
	ctx := context.Background()
	lin := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"linux-build"}, "NoReboot": {"true"}})
	wid := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {"i-0aaaaaaaaaaaaaab1"}, "Name": {"windows-build"},
		"TagSpecification.1.ResourceType": {"image"}, "TagSpecification.1.Tag.1.Key": {"os"}, "TagSpecification.1.Tag.1.Value": {"windows"}})
	copyDone(t, dyn, wid, "Succeeded")
	call := func(form url.Values) (int, string) {
		form.Set("Action", "DescribeImages")
		w := ec2Call(h, ec2Alice, form)
		return w.Code, w.Body.String()
	}
	_, b := call(url.Values{"ImageId.1": {wid}})
	mustHave(t, "a Windows image", b, []string{"<platform>windows</platform>", "<platformDetails>Windows</platformDetails>",
		"<usageOperation>RunInstances:0002</usageOperation>", "<volumeSize>112</volumeSize>", "<creationDate>", "<rootDeviceType>ebs</rootDeviceType>"}, nil)
	_, b = call(url.Values{})
	mustHave(t, "everything", b, []string{lin, wid, imageIDForOS("ubuntu-24.04"), "<imageOwnerAlias>openinfra</imageOwnerAlias>"}, nil)
	for _, c := range []struct {
		form          url.Values
		want, notWant []string
	}{
		{url.Values{"Owner.1": {"amazon"}}, []string{imageIDForOS("debian-12")}, []string{lin, wid}},
		{url.Values{"Owner.1": {"self"}}, []string{lin, wid}, []string{imageIDForOS("debian-12")}},
		{url.Values{"Owner.1": {"self"}, "Owner.2": {"openinfra"}}, []string{lin, imageIDForOS("debian-12")}, nil},
		{url.Values{"Filter.1.Name": {"platform"}, "Filter.1.Value.1": {"windows"}, "Filter.2.Name": {"owner-id"}, "Filter.2.Value.1": {mgmtAcct}},
			[]string{wid, imageIDForOS("windows-server-2022")}, []string{lin, imageIDForOS("debian-12")}},
		{url.Values{"Filter.1.Name": {"name"}, "Filter.1.Value.1": {"*-build"}}, []string{lin, wid}, []string{imageIDForOS("debian-12")}},
		{url.Values{"Filter.1.Name": {"state"}, "Filter.1.Value.1": {"pending"}}, []string{lin}, []string{wid}},
		{url.Values{"Filter.1.Name": {"tag:os"}, "Filter.1.Value.1": {"windows"}}, []string{wid}, []string{lin}},
		{url.Values{"Filter.1.Name": {"is-public"}, "Filter.1.Value.1": {"false"}}, []string{lin, wid}, []string{imageIDForOS("debian-12")}},
		{url.Values{"Filter.1.Name": {"source-instance-id"}, "Filter.1.Value.1": {webID}}, []string{lin}, []string{wid}},
		{url.Values{"Filter.1.Name": {"architecture"}, "Filter.1.Value.1": {"x86_64"}, "Filter.2.Name": {"root-device-type"}, "Filter.2.Value.1": {"ebs"}}, []string{lin, wid}, nil},
		{url.Values{"ImageId.1": {lin}, "ImageId.2": {imageIDForOS("fedora-40")}}, []string{lin, imageIDForOS("fedora-40")}, []string{wid}},
	} {
		code, body := call(c.form)
		if code != 200 {
			t.Errorf("%v: %d %s", c.form, code, body)
			continue
		}
		mustHave(t, c.form.Encode(), body, c.want, c.notWant)
	}
	for _, c := range []struct {
		form url.Values
		code string
	}{
		{url.Values{"ImageId.1": {"ami-0fffffffffffffff9"}}, "InvalidAMIID.NotFound"},
		{url.Values{"ImageId.1": {"image-1"}}, "InvalidAMIID.Malformed"},
		{url.Values{"Owner.1": {"someone"}}, "InvalidUserID.Malformed"},
		{url.Values{"ExecutableBy.1": {"nobody"}}, "InvalidUserID.Malformed"},
		{url.Values{"Filter.1.Name": {"colour"}, "Filter.1.Value.1": {"x"}}, "InvalidParameterValue"},
		{url.Values{"ImageId.1": {lin}, "MaxResults": {"5"}}, "InvalidParameterCombination"},
		{url.Values{"MaxResults": {"2"}}, "InvalidParameterValue"},
	} {
		if code, body := call(c.form); code != 400 || !strings.Contains(body, "<Code>"+c.code+"</Code>") {
			t.Errorf("%v: want %s, got %d %s", c.form, c.code, code, body)
		}
	}
	// Pages: the catalog's eight and the two images, five at a time.
	_, b = call(url.Values{"MaxResults": {"5"}})
	_, tok, _ := strings.Cut(b, "<nextToken>")
	tok, _, _ = strings.Cut(tok, "</nextToken>")
	if strings.Count(b, "<imageId>") != 5 || tok == "" {
		t.Fatalf("a first page of five, with a token: %s", b)
	}
	_, b2 := call(url.Values{"MaxResults": {"5"}, "NextToken": {tok}})
	if strings.Count(b2, "<imageId>") != 5 || strings.Contains(b2, "<nextToken>") {
		t.Errorf("the last page: %s", b2)
	}
}

// IAM decides each operation with the one evaluator, as AWS does: CreateImage on the instance (and
// ec2:CreateTags on the new image when it is tagged), the attribute operations on the image's ARN.
func TestEC2Images_IAMDecides(t *testing.T) {
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi"}, ec2Web())
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:users"}}
	create := url.Values{"Action": {"CreateImage"}, "InstanceId": {webID}, "Name": {"denied-image"}}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:DescribeImages", "ec2:DescribeInstances"}, "*")))
	if w := ec2Call(h, user, create); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") ||
		!strings.Contains(w.Body.String(), "ec2:CreateImage") {
		t.Errorf("a principal without ec2:CreateImage must be refused: %d %s", w.Code, w.Body.String())
	}
	for _, a := range dyn.Actions() {
		if v := a.GetVerb(); v == "create" || v == "patch" {
			t.Errorf("a refused CreateImage must change nothing: %v", a)
		}
	}
	// A grant on another instance does not reach this one.
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:CreateImage"}, "Instance::i-0ffffffffffffffff")))
	if w := ec2Call(h, user, create); w.Code != 403 {
		t.Errorf("a grant on another instance must not image this one: %d %s", w.Code, w.Body.String())
	}
	// Tagging the new image is ec2:CreateTags on it.
	tagged := url.Values{"Action": {"CreateImage"}, "InstanceId": {webID}, "Name": {"tagged-image"}, "NoReboot": {"true"},
		"TagSpecification.1.ResourceType": {"image"}, "TagSpecification.1.Tag.1.Key": {"k"}, "TagSpecification.1.Tag.1.Value": {"v"}}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:CreateImage"}, "Instance::"+webID)))
	if w := ec2Call(h, user, tagged); w.Code != 403 || !strings.Contains(w.Body.String(), "ec2:CreateTags") {
		t.Errorf("tagging the image without ec2:CreateTags must be refused: %d %s", w.Code, w.Body.String())
	}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:CreateImage"}, "Instance::"+webID), dpAllow([]string{"ec2:CreateTags"}, "Image::*")))
	if w := ec2Call(h, user, tagged); w.Code != 200 {
		t.Errorf("with ec2:CreateImage on the instance and ec2:CreateTags on the image: %d %s", w.Code, w.Body.String())
	}
	imgs, _ := h.listImages(context.Background())
	if len(imgs) != 1 || imgs[0].name != "tagged-image" || imgs[0].tags["k"] != "v" {
		t.Fatalf("the tagged image: %+v", imgs)
	}
	id := imgs[0].id
	// The attribute operations are decided on the image's ARN: a grant on another image does not reach it.
	modify := url.Values{"Action": {"ModifyImageAttribute"}, "ImageId": {id}, "LaunchPermission.Add.1.UserId": {otherAcct}}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:ModifyImageAttribute"}, "Image::ami-0fffffffffffffff9")))
	if w := ec2Call(h, user, modify); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("a grant on another image must not share this one: %d %s", w.Code, w.Body.String())
	}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:ModifyImageAttribute"}, "Image::"+id)))
	if w := ec2Call(h, user, modify); w.Code != 200 {
		t.Errorf("a grant on the image shares it: %d %s", w.Code, w.Body.String())
	}
	// An explicit Deny on deregistering wins over an Allow.
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:*"}, "*"), dpDeny([]string{"ec2:DeregisterImage"}, "Image::*")))
	if w := ec2Call(h, user, url.Values{"Action": {"DeregisterImage"}, "ImageId": {id}}); w.Code != 403 {
		t.Errorf("an explicit Deny on DeregisterImage must refuse it: %d %s", w.Code, w.Body.String())
	}
	// An assumed role with no policy: nothing.
	h.door.authz = checkerInMode(t, "enforce")
	if w := ec2Call(h, ecrRoleClaims(), url.Values{"Action": {"CopyImage"}, "SourceImageId": {id}, "SourceRegion": {"us-east-1"}, "Name": {"c"}}); w.Code != 403 {
		t.Errorf("a role with no policy must be refused CopyImage: %d %s", w.Code, w.Body.String())
	}
}

// An image's record is read back as it was written: a restarted shim sees every image, its state from its
// copy, and finishes the start an image still waits for.
func TestEC2Images_RecordSurvivesARestart(t *testing.T) {
	h, dyn := imageFixture(t, map[string]string{ec2TestNS + "/s-web-root": "20Gi"}, ec2Web())
	ctx := context.Background()
	id := createImage(t, h, ctx, ec2Alice, url.Values{"InstanceId": {webID}, "Name": {"survivor"}})
	copyDone(t, dyn, id, "Succeeded")
	// A new handler over the same cluster: nothing kept in memory.
	fresh := newEC2Handler(h.door, nil, h.logger)
	fresh.imagesNS = testImagesNS
	imgs, err := fresh.listImages(ctx)
	if err != nil || len(imgs) != 1 || imgs[0].id != id || imgs[0].state != "available" || imgs[0].name != "survivor" || imgs[0].owner != mgmtAcct {
		t.Fatalf("the record read back: %v %+v", err, imgs)
	}
	stop := make(chan struct{})
	rctx, cancel := context.WithCancel(ctx)
	go func() { fresh.runImageReconciler(rctx, time.Hour); close(stop) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if running, _ := claimRunning(t, dyn, "s-web"); running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the restarted shim must start the instance its image stopped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-stop
	// A record the shim did not write (the catalog's disks) is no account image.
	other := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "cdi.kubevirt.io/v1beta1", "kind": "DataVolume",
		"metadata": map[string]any{"name": "windows-server-2022-golden", "namespace": testImagesNS}}}
	if _, ok := imageOf(other); ok {
		t.Error("a catalog disk is no account image")
	}
	raw, _ := json.Marshal(imgs[0].tags)
	if string(raw) != "null" && string(raw) != "{}" {
		t.Errorf("an untagged image has no tags: %s", raw)
	}
}

// Launching: DescribeInstances and the instance identity document report the account image an instance was
// launched from.
func TestEC2Images_InstanceReportsItsImage(t *testing.T) {
	vm := ec2Obj("VirtualMachine", "s-from", map[string]any{"os": "windows-server-2022", "imageId": "ami-0aaaaaaaaaaaaaaa1"},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaac1", "powerState": "Running", "imageLaunched": true}, nil)
	waiting := ec2Obj("VirtualMachine", "s-wait", map[string]any{"os": "ubuntu-24.04", "imageId": "ami-0bbbbbbbbbbbbbbb2"},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaac2", "powerState": "Stopped"}, nil)
	h, _ := imageFixture(t, nil, vm, waiting)
	b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "Filter.1.Name": {"image-id"}, "Filter.1.Value.1": {"ami-0aaaaaaaaaaaaaaa1"}}).Body.String()
	mustHave(t, "an instance launched from an image", b, []string{"<imageId>ami-0aaaaaaaaaaaaaaa1</imageId>", "<platform>windows</platform>",
		"<name>running</name>"}, []string{imageIDForOS("windows-server-2022"), "i-0aaaaaaaaaaaaaac2"})
	// One whose image its account may not launch yet (or not yet available) waits, pending, not stopped.
	b = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {"i-0aaaaaaaaaaaaaac2"}}).Body.String()
	mustHave(t, "an instance waiting for its image", b, []string{"<imageId>ami-0bbbbbbbbbbbbbbb2</imageId>", "<name>pending</name>"},
		[]string{"InstanceInitiatedShutdown"})
	if got := identityFieldsOf(&boundVM{claim: vm, xr: &unstructured.Unstructured{}}, mgmtAcct, "us-east-1").ImageID; got != "ami-0aaaaaaaaaaaaaaa1" {
		t.Errorf("the identity document's imageId: %s", got)
	}
}

// An image's disk holds its root's: a Block root's size, a filesystem root's with room for the image class's
// filesystem overhead; an instance launched from it has a root of at least that size.
func TestEC2Images_DiskSize(t *testing.T) {
	for _, c := range []struct {
		root int64
		mode string
		want int64
	}{{20, "Filesystem", 21}, {22, "Filesystem", 24}, {106, "Filesystem", 112}, {100, "Block", 100}, {30, "", 32}} {
		if got := imageDiskGiB(c.root, c.mode); got != c.want {
			t.Errorf("imageDiskGiB(%d, %q) = %d, want %d", c.root, c.mode, got, c.want)
		}
	}
	// A Block root (a highly available instance's) is imaged as Block, at its size.
	vm := ec2Obj("VirtualMachine", "s-ha", map[string]any{"os": "ubuntu-24.04", "highAvailability": true},
		map[string]any{"instanceId": "i-0aaaaaaaaaaaaaad1", "powerState": "Stopped"}, nil)
	h, dyn := ec2Fixture(t, vm)
	h.imagesNS = testImagesNS
	block := corev1.PersistentVolumeBlock
	_, _ = h.door.cs.CoreV1().PersistentVolumeClaims(ec2TestNS).Create(context.Background(), &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "s-ha-root", Namespace: ec2TestNS}, Spec: corev1.PersistentVolumeClaimSpec{VolumeMode: &block,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("20Gi")}}}}, metav1.CreateOptions{})
	id := createImage(t, h, context.Background(), ec2Alice, url.Values{"InstanceId": {"i-0aaaaaaaaaaaaaad1"}, "Name": {"ha-image"}})
	pvc, _, _ := unstructured.NestedMap(imageDV(t, dyn, id).Object, "spec", "pvc")
	if pvc["volumeMode"] != "Block" || pvc["resources"].(map[string]any)["requests"].(map[string]any)["storage"] != "20Gi" {
		t.Errorf("a Block root's image: %v", pvc)
	}
}

// The image operations are served, and the catalog's ids stay its own.
func TestEC2Images_Served(t *testing.T) {
	for _, op := range []string{"CreateImage", "CopyImage", "DeregisterImage", "DescribeImageAttribute", "ModifyImageAttribute", "ResetImageAttribute"} {
		if _, ok := ec2Ops[op]; !ok || !ec2ImageOp(op) || !ec2StoreOp(op) {
			t.Errorf("%s must be served as an image operation", op)
		}
	}
	taken := []ec2Image{{id: imageIDForOS("ubuntu-24.04")}}
	for i := 0; i < 50; i++ {
		if id := newImageID(taken); !accountImageIDRe.MatchString(id) || catalogOSOf(id) != "" || len(id) != 21 {
			t.Fatalf("a new image id: %s", id)
		}
	}
}
