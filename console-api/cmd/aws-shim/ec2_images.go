// EC2 images an account makes, shares and launches from (the EC2 front door, ec2.go): CreateImage,
// CopyImage, DescribeImages (the catalog, and the images the caller's account owns or may launch),
// DescribeImageAttribute, ModifyImageAttribute, ResetImageAttribute and DeregisterImage.
//
// An account image is a disk in the platform's image namespace (EC2_IMAGES_NAMESPACE, openinfra-images),
// named by its ami- id: a CDI DataVolume cloned from an instance's root disk (CreateImage) or from another
// image (CopyImage), whose labels and annotations are the image's EC2 record — its owner, name,
// description, base OS (which decides Windows or Linux), architecture, root size, creation date, launch
// permissions and tags. Its state is the copy's: pending while the disk is copied, available once the copy
// has succeeded, failed if it failed. The record lives with the disk, so a restarted shim reads every image
// back as it was, and finishes what an image still waits for (imageReconciler).
//
// As on AWS:
//   - each operation is decided by the one evaluator: ec2:CreateImage on the instance it images (and
//     ec2:CreateTags on the new image when it is tagged), ec2:CopyImage on the new image, and
//     ec2:DescribeImageAttribute, ec2:ModifyImageAttribute, ec2:ResetImageAttribute and ec2:DeregisterImage
//     on the image (arn:aws:ec2:<region>::image/<ami-id>, an ARN that names no account);
//   - an account sees the images it owns, those whose launch permission names it, and public ones (the
//     catalog, and any shared with "all"); only the owner reads or changes an image's attributes, or
//     deregisters it — another account that can see it is refused (AuthFailure), one that cannot is told it
//     does not exist (InvalidAMIID.NotFound);
//   - CreateImage stops the instance first (unless NoReboot) and starts it again once its image is made;
//   - an instance launched from an image keeps running when the image is deregistered.
//
// Where it differs (docs/aws-shim.md): an image holds the instance's root volume only, and is no snapshot
// (DeregisterImage deletes its disk; no snapshot remains); its disk is copied whole, so an instance CreateImage
// stopped stays stopped until the copy is done (on AWS it restarts once its snapshots begin), and with NoReboot
// the image stays pending until the instance is stopped (a disk in use cannot be copied). The instance, the
// copy and the image's disk are the platform's work, done with the shim's own authority once IAM has decided
// the call.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// dataVolumeGVR is CDI's DataVolume: an account image's disk, and the copy that fills it.
var dataVolumeGVR = schema.GroupVersionResource{Group: "cdi.kubevirt.io", Version: "v1beta1", Resource: "datavolumes"}

// defaultImagesNS is the platform's image namespace, where the catalog's Windows images are too.
const defaultImagesNS = "openinfra-images"

// imageStorageClass is the class an image's disk is stored on: replicated, so an image outlives any one node
// (the catalog's Windows images are there too).
const imageStorageClass = "longhorn"

// An image's EC2 record, on its DataVolume. The composition that launches an instance from an image reads
// the owner, the launch permission and the copy's phase (vm-composition.yaml), so their names are fixed.
const (
	imageLabel            = "openinfra.dev/ec2-image" // "true" on every account image
	imageOwnerLabel       = "openinfra.dev/image-owner"
	annImageName          = "openinfra.dev/image-name"
	annImageDescription   = "openinfra.dev/image-description"
	annImageOS            = "openinfra.dev/image-os"
	annImageArch          = "openinfra.dev/image-architecture"
	annImageRootSize      = "openinfra.dev/image-root-size" // GiB
	annImageBootMode      = "openinfra.dev/image-boot-mode" // uefi, or "" (BIOS)
	annImageCreated       = "openinfra.dev/image-created"
	annImageState         = "openinfra.dev/image-state" // pending | available | failed, as last recorded
	annImageStateReason   = "openinfra.dev/image-state-reason"
	annImageLaunch        = "openinfra.dev/image-launch-permission" // account ids and "all", comma-separated
	annImageTags          = "openinfra.dev/image-tags"              // JSON object
	annImageSourceInst    = "openinfra.dev/image-source-instance"
	annImageSourceVM      = "openinfra.dev/image-source-vm" // <namespace>/<name> of the instance's VM
	annImageSourceImage   = "openinfra.dev/image-source-image"
	annImageNoReboot      = "openinfra.dev/image-no-reboot"
	annImageRestart       = "openinfra.dev/image-restart" // "pending": start the source instance once the copy ends; "done"
	cdiDeleteAfterComplet = "cdi.kubevirt.io/storage.deleteAfterCompletion"
)

// accountImageIDRe is an image id as AWS writes one (ami- and 8 or 17 hex digits); the platform's are 17.
var accountImageIDRe = regexp.MustCompile(`^ami-([0-9a-f]{8}|[0-9a-f]{17})$`)

// amiNameRe is AWS's AMI name: 3–128 letters, numbers, ( ) [ ] space . / - ' @ _.
var amiNameRe = regexp.MustCompile(`^[A-Za-z0-9()\[\] ./\-'@_]{3,128}$`)

const amiNameRule = "AMI names must be between 3 and 128 characters long, and may contain letters, numbers, '(', ')', '[', ']', ' ', '.', '/', '-', ''', '@' and '_'"

// ec2ImageOp reports whether op is one of an account image's write or attribute operations.
func ec2ImageOp(op string) bool {
	switch op {
	case "CreateImage", "CopyImage", "DeregisterImage", "DescribeImageAttribute", "ModifyImageAttribute", "ResetImageAttribute":
		return true
	}
	return false
}

// ec2Image is an account image, from its record.
type ec2Image struct {
	id, owner, name, description, os, arch, bootMode string
	rootGiB                                          int64
	created                                          time.Time
	state, stateReason                               string
	sourceInstance, sourceVM, sourceImage, restart   string
	noReboot                                         bool
	launch                                           []string // account ids, and "all" for a public image
	tags                                             map[string]string
	diskSize                                         string // the disk's requested size (a quantity)
	volumeMode                                       string
	recordedState                                    string // the state the record last said
}

func (img ec2Image) public() bool { return contains(img.launch, "all") }

// launchableBy reports whether account may launch the image: it owns it, or its launch permission names the
// account or "all".
func (img ec2Image) launchableBy(account string) bool {
	return img.owner == account || img.public() || contains(img.launch, account)
}

// imageOf reads an image from its DataVolume; ok=false for anything else in the namespace (the catalog's
// disks) and for an image being deleted (deregistered).
func imageOf(u *unstructured.Unstructured) (ec2Image, bool) {
	if u.GetLabels()[imageLabel] != "true" || !accountImageIDRe.MatchString(u.GetName()) || u.GetDeletionTimestamp() != nil {
		return ec2Image{}, false
	}
	a := u.GetAnnotations()
	img := ec2Image{id: u.GetName(), owner: u.GetLabels()[imageOwnerLabel], name: a[annImageName], description: a[annImageDescription],
		os: a[annImageOS], arch: a[annImageArch], bootMode: a[annImageBootMode], sourceInstance: a[annImageSourceInst],
		sourceVM: a[annImageSourceVM], sourceImage: a[annImageSourceImage], restart: a[annImageRestart],
		noReboot: a[annImageNoReboot] == "true", recordedState: a[annImageState], stateReason: a[annImageStateReason]}
	if img.arch == "" {
		img.arch = "x86_64"
	}
	img.rootGiB, _ = strconv.ParseInt(a[annImageRootSize], 10, 64)
	if t, err := time.Parse(time.RFC3339Nano, a[annImageCreated]); err == nil {
		img.created = t
	} else {
		img.created = u.GetCreationTimestamp().Time
	}
	for _, p := range strings.Split(a[annImageLaunch], ",") {
		if p = strings.TrimSpace(p); p != "" {
			img.launch = append(img.launch, p)
		}
	}
	if s := a[annImageTags]; s != "" {
		_ = json.Unmarshal([]byte(s), &img.tags)
	}
	img.diskSize, _, _ = unstructured.NestedString(u.Object, "spec", "pvc", "resources", "requests", "storage")
	img.volumeMode, _, _ = unstructured.NestedString(u.Object, "spec", "pvc", "volumeMode")
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	switch {
	case img.recordedState == "failed" || phase == "Failed":
		img.state = "failed"
		if img.stateReason == "" {
			img.stateReason = "the image's disk could not be copied"
		}
	case phase == "Succeeded":
		img.state = "available"
	default:
		img.state = "pending"
	}
	return img, true
}

// imagesOn reports whether this shim keeps account images (EC2_IMAGES_NAMESPACE, the shim's clients).
func (h *ec2Handler) imagesOn() bool {
	return h.imagesNS != "" && h.door != nil && h.door.shimDyn != nil
}

// listImages reads every account image, with the shim's own client (the caller's account decides which it
// sees: visibleImages).
func (h *ec2Handler) listImages(ctx context.Context) ([]ec2Image, error) {
	if !h.imagesOn() {
		return nil, nil
	}
	l, err := h.door.shimDyn.Resource(dataVolumeGVR).Namespace(h.imagesNS).List(ctx, metav1.ListOptions{LabelSelector: imageLabel + "=true"})
	if apierrors.IsNotFound(err) {
		return nil, nil // CDI is not installed: there are none
	}
	if err != nil {
		return nil, err
	}
	out := make([]ec2Image, 0, len(l.Items))
	for i := range l.Items {
		if img, ok := imageOf(&l.Items[i]); ok {
			out = append(out, img)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// visibleImages are the account images account sees: its own, and those it may launch.
func visibleImages(all []ec2Image, account string) []ec2Image {
	var out []ec2Image
	for _, img := range all {
		if img.launchableBy(account) {
			out = append(out, img)
		}
	}
	return out
}

// newImageID is a fresh image id: ami- and 17 random hex digits, never a catalog image's or another image's.
func newImageID(taken []ec2Image) string {
	used := map[string]bool{}
	for _, img := range taken {
		used[img.id] = true
	}
	for _, os := range cfn.CatalogOSes() {
		used[imageIDForOS(os)] = true
	}
	for {
		b := make([]byte, 9)
		_, _ = rand.Read(b)
		id := "ami-" + hex.EncodeToString(b)[:17]
		if !used[id] {
			return id
		}
	}
}

// catalogOSOf is the catalog OS whose image id is id ("" for any other id).
func catalogOSOf(id string) string {
	for _, os := range cfn.CatalogOSes() {
		if imageIDForOS(os) == id {
			return os
		}
	}
	return ""
}

func (h *ec2Handler) imagesOff(w http.ResponseWriter, requestID string) {
	writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID,
		"EC2 images are not configured on this shim (it needs the image namespace, EC2_IMAGES_NAMESPACE, and its cluster client)")
}

func (h *ec2Handler) imagesFailed(w http.ResponseWriter, requestID string, err error) {
	if h.logger != nil {
		h.logger.Warn("ec2: reading images failed", "error", err.Error())
	}
	writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "The images could not be read; retry.")
}

func imageNotFound(w http.ResponseWriter, requestID, id string) {
	writeEC2Error(w, http.StatusBadRequest, "InvalidAMIID.NotFound", requestID, "The image id '["+id+"]' does not exist")
}

// imageIDParam reads and checks the ImageId parameter; ok=false once answered.
func imageIDParam(w http.ResponseWriter, form url.Values, param, requestID string) (string, bool) {
	id := form.Get(param)
	if id == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter "+param)
		return "", false
	}
	if !accountImageIDRe.MatchString(id) {
		writeEC2Error(w, http.StatusBadRequest, "InvalidAMIID.Malformed", requestID, "Invalid id: \""+id+"\" (expecting \"ami-...\")")
		return "", false
	}
	return id, true
}

// ownedImage finds image id for an operation only its owner may make: one the caller's account cannot see
// does not exist; one it sees but does not own (another account's, or the catalog's) is not its to change.
func (h *ec2Handler) ownedImage(ctx context.Context, w http.ResponseWriter, id, requestID string) (ec2Image, bool) {
	all, err := h.listImages(ctx)
	if err != nil {
		h.imagesFailed(w, requestID, err)
		return ec2Image{}, false
	}
	if catalogOSOf(id) != "" {
		writeEC2Error(w, http.StatusBadRequest, "AuthFailure", requestID, "Not authorized for image:"+id)
		return ec2Image{}, false
	}
	acct := h.ownerAccount(ctx)
	for _, img := range all {
		if img.id != id {
			continue
		}
		if img.owner == acct {
			return img, true
		}
		if img.launchableBy(acct) {
			writeEC2Error(w, http.StatusBadRequest, "AuthFailure", requestID, "Not authorized for image:"+id)
			return ec2Image{}, false
		}
	}
	imageNotFound(w, requestID, id)
	return ec2Image{}, false
}

// checkImageName refuses a name AWS refuses (InvalidAMIName.Malformed) or one the account already gave
// another image (InvalidAMIName.Duplicate); ok=false once answered.
func checkImageName(w http.ResponseWriter, all []ec2Image, account, name, requestID string) bool {
	if name == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter Name")
		return false
	}
	if !amiNameRe.MatchString(name) {
		writeEC2Error(w, http.StatusBadRequest, "InvalidAMIName.Malformed", requestID, amiNameRule)
		return false
	}
	for _, img := range all {
		if img.owner == account && img.name == name {
			writeEC2Error(w, http.StatusBadRequest, "InvalidAMIName.Duplicate", requestID, "AMI name "+name+" is already in use by AMI "+img.id)
			return false
		}
	}
	return true
}

func checkImageDescription(w http.ResponseWriter, desc, requestID string) bool {
	if len(desc) > 255 {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Value for parameter description is invalid. Length must be at most 255 characters.")
		return false
	}
	return true
}

// authorizeImageTags decides ec2:CreateTags on the new image, as AWS does when a create tags what it makes.
func (h *ec2Handler) authorizeImageTags(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, op, id string, tags map[string]string, requestID string) bool {
	if len(tags) == 0 {
		return true
	}
	if ok, reason := decide(ctx, r, h.door.authz, claims, "ec2:CreateTags", "Image", id,
		dataPlaneOnly(ctx, r, h.door.authz, claims, "ec2:CreateTags", "Image", id)); !ok {
		h.audit(ctx, op, id, reason)
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
		return false
	}
	return true
}

// imageRecord is the labels and annotations of a new image's DataVolume.
func imageRecord(img ec2Image) (map[string]any, map[string]any) {
	tags, _ := json.Marshal(img.tags)
	if len(img.tags) == 0 {
		tags = []byte("{}")
	}
	labels := map[string]any{imageLabel: "true", imageOwnerLabel: img.owner}
	ann := map[string]any{
		cdiDeleteAfterComplet: "false", // the disk is the image: CDI must never collect it
		annImageName:          img.name, annImageDescription: img.description, annImageOS: img.os, annImageArch: img.arch,
		annImageRootSize: strconv.FormatInt(img.rootGiB, 10), annImageCreated: img.created.UTC().Format("2006-01-02T15:04:05.000Z"),
		annImageState: "pending", annImageLaunch: strings.Join(img.launch, ","), annImageTags: string(tags),
	}
	for k, v := range map[string]string{annImageBootMode: img.bootMode, annImageSourceInst: img.sourceInstance,
		annImageSourceVM: img.sourceVM, annImageSourceImage: img.sourceImage, annImageRestart: img.restart} {
		if v != "" {
			ann[k] = v
		}
	}
	if img.noReboot {
		ann[annImageNoReboot] = "true"
	}
	return labels, ann
}

// imageDiskGiB is the size of an image's disk, in whole GiB, for a root disk of rootGiB: a Block disk's own
// size, and a filesystem disk's with 5% more, so the root's disk image fits beside the filesystem's own
// overhead (which the image's class may reserve more of than the root's). An instance launched from the
// image has a root of at least this size (cfn.AccountImage.RootGiB), which the copy into it needs.
func imageDiskGiB(rootGiB int64, volumeMode string) int64 {
	if volumeMode == string(corev1.PersistentVolumeBlock) {
		return rootGiB
	}
	return (rootGiB*105 + 99) / 100
}

// createImageDisk makes a new image's DataVolume: a copy of PVC srcNS/srcName, of the same size and volume
// mode, on the image class.
func (h *ec2Handler) createImageDisk(ctx context.Context, img ec2Image, srcNS, srcName string) error {
	labels, ann := imageRecord(img)
	mode := img.volumeMode
	if mode == "" {
		mode = string(corev1.PersistentVolumeFilesystem)
	}
	dv := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cdi.kubevirt.io/v1beta1", "kind": "DataVolume",
		"metadata": map[string]any{"name": img.id, "namespace": h.imagesNS, "labels": labels, "annotations": ann},
		"spec": map[string]any{
			"source": map[string]any{"pvc": map[string]any{"namespace": srcNS, "name": srcName}},
			// The pvc form, not storage: the copy is exactly the source's size, with no filesystem overhead
			// added, so an instance launched with a root of the image's size holds it.
			"pvc": map[string]any{
				"accessModes": []any{"ReadWriteOnce"}, "volumeMode": mode, "storageClassName": imageStorageClass,
				"resources": map[string]any{"requests": map[string]any{"storage": img.diskSize}},
			},
		},
	}}
	_, err := h.door.shimDyn.Resource(dataVolumeGVR).Namespace(h.imagesNS).Create(ctx, dv, metav1.CreateOptions{})
	return err
}

// patchImage merges annotations into image id's record.
func (h *ec2Handler) patchImage(ctx context.Context, id string, ann map[string]any) error {
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": ann}})
	_, err := h.door.shimDyn.Resource(dataVolumeGVR).Namespace(h.imagesNS).Patch(ctx, id, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// setVMRunning sets VM claim ns/name's spec.running with the shim's own authority: CreateImage's stop of the
// instance it images, and the start once the image is made. The caller proved its authority over the
// instance (ec2:CreateImage on it) before the stop.
func (h *ec2Handler) setVMRunning(ctx context.Context, ns, name string, running bool) error {
	patch, _ := json.Marshal(map[string]any{"spec": map[string]any{"running": running}})
	_, err := h.door.shimDyn.Resource(vmClaimGVR).Namespace(ns).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// --- CreateImage ---

func (h *ec2Handler) createImage(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if !h.imagesOn() || h.door.cs == nil {
		h.imagesOff(w, requestID)
		return
	}
	iid := r.Form.Get("InstanceId")
	if iid == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter InstanceId")
		return
	}
	if !instanceIDRe.MatchString(iid) {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.Malformed", requestID, "Invalid id: \""+iid+"\"")
		return
	}
	name, desc := r.Form.Get("Name"), r.Form.Get("Description")
	if !checkImageDescription(w, desc, requestID) {
		return
	}
	for k := range r.Form {
		if strings.HasPrefix(k, "BlockDeviceMapping.") {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
				"BlockDeviceMapping is not supported by the open-infra shim: an image holds its instance's root volume, as it is")
			return
		}
	}
	all, denied, err := h.instancesForCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "instances", denied, err)
		return
	}
	var in *ec2Instance
	for i := range all {
		if all[i].id == iid {
			in = &all[i]
		}
	}
	if in == nil {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance ID '"+iid+"' does not exist")
		return
	}
	if in.state != "running" && in.state != "stopped" {
		writeEC2Error(w, http.StatusBadRequest, "IncorrectInstanceState", requestID, "The instance '"+iid+"' is not in a state from which an image can be created ("+in.state+").")
		return
	}
	spec, _, _ := unstructured.NestedMap(in.claim.Object, "spec")
	if rd, _ := spec["rootDisk"].(map[string]any); rd != nil && rd["encrypted"] == true {
		writeEC2Error(w, http.StatusBadRequest, "UnsupportedOperation", requestID,
			"The instance '"+iid+"' has an encrypted root volume: the open-infra shim does not make images of encrypted volumes")
		return
	}
	images, err := h.listImages(ctx)
	if err != nil {
		h.imagesFailed(w, requestID, err)
		return
	}
	acct := h.ownerAccount(ctx)
	if !checkImageName(w, images, acct, name, requestID) {
		return
	}
	ns := h.accountNS(ctx)
	vm := in.claim.GetName()
	rootPVC := vm + "-root"
	if adopted, _ := spec["existingRootClaim"].(string); adopted != "" {
		rootPVC = adopted
	}
	pvc, err := h.door.cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, rootPVC, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			writeEC2Error(w, http.StatusBadRequest, "IncorrectInstanceState", requestID, "The instance '"+iid+"' has no root volume yet.")
			return
		}
		h.readFailed(w, requestID, "instance's root volume", false, err)
		return
	}
	q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	img := ec2Image{id: newImageID(images), owner: acct, name: name, description: desc, os: in.os, arch: in.arch,
		created: time.Now(), sourceInstance: iid, sourceVM: ns + "/" + vm, noReboot: r.Form.Get("NoReboot") == "true",
		tags: ec2TagSpec(r.Form, "image"), volumeMode: string(corev1.PersistentVolumeFilesystem)}
	if pvc.Spec.VolumeMode != nil {
		img.volumeMode = string(*pvc.Spec.VolumeMode)
	}
	img.rootGiB = imageDiskGiB(sizeGiB(q.String()), img.volumeMode)
	img.diskSize = strconv.FormatInt(img.rootGiB, 10) + "Gi"
	if fw, _ := spec["firmware"].(map[string]any); fw != nil && fw["mode"] == "uefi" {
		img.bootMode = "uefi"
	}
	if !h.authorizeImageTags(ctx, w, r, claims, "CreateImage", img.id, img.tags, requestID) {
		return
	}
	// As AWS does by default, the instance is stopped while its disk is copied, and started again after.
	if !img.noReboot && in.state == "running" {
		if err := h.setVMRunning(ctx, ns, vm, false); err != nil {
			h.imageWriteFailed(w, requestID, "CreateImage", iid, err)
			return
		}
		img.restart = "pending"
	}
	if err := h.createImageDisk(ctx, img, ns, rootPVC); err != nil {
		if img.restart == "pending" {
			_ = h.setVMRunning(ctx, ns, vm, true)
		}
		h.imageWriteFailed(w, requestID, "CreateImage", iid, err)
		return
	}
	writeEC2(w, requestID, "CreateImage", xtag("imageId", img.id))
}

func (h *ec2Handler) imageWriteFailed(w http.ResponseWriter, requestID, op, what string, err error) {
	if h.logger != nil {
		h.logger.Warn("ec2: "+op+" failed", "resource", what, "error", err.Error())
	}
	writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, op+" could not be completed; retry.")
}

// --- CopyImage ---

func (h *ec2Handler) copyImage(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if !h.imagesOn() {
		h.imagesOff(w, requestID)
		return
	}
	src, ok := imageIDParam(w, r.Form, "SourceImageId", requestID)
	if !ok {
		return
	}
	region := r.Form.Get("SourceRegion")
	if region == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter SourceRegion")
		return
	}
	if region != h.region() {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"Value ("+region+") for parameter sourceRegion is invalid: the open-infra shim serves one region, "+h.region())
		return
	}
	if r.Form.Get("Encrypted") == "true" || r.Form.Get("KmsKeyId") != "" {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Encrypted copies are not supported by the open-infra shim")
		return
	}
	name, desc := r.Form.Get("Name"), r.Form.Get("Description")
	if !checkImageDescription(w, desc, requestID) {
		return
	}
	if catalogOSOf(src) != "" {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"The image '"+src+"' is one of the platform's catalog images, which every account launches by its id: it is not copied")
		return
	}
	images, err := h.listImages(ctx)
	if err != nil {
		h.imagesFailed(w, requestID, err)
		return
	}
	acct := h.ownerAccount(ctx)
	var source *ec2Image
	for i := range images {
		if images[i].id == src && images[i].launchableBy(acct) {
			source = &images[i]
		}
	}
	if source == nil {
		imageNotFound(w, requestID, src)
		return
	}
	if source.state != "available" {
		writeEC2Error(w, http.StatusBadRequest, "IncorrectState", requestID, "The image '"+src+"' is not in a valid state for this operation ("+source.state+").")
		return
	}
	if !checkImageName(w, images, acct, name, requestID) {
		return
	}
	tags := map[string]string{}
	if r.Form.Get("CopyImageTags") == "true" && source.owner == acct {
		for k, v := range source.tags {
			tags[k] = v
		}
	}
	for k, v := range ec2TagSpec(r.Form, "image") {
		tags[k] = v
	}
	img := ec2Image{id: newImageID(images), owner: acct, name: name, description: desc, os: source.os, arch: source.arch,
		bootMode: source.bootMode, rootGiB: source.rootGiB, created: time.Now(), sourceImage: src, sourceInstance: source.sourceInstance,
		tags: tags, diskSize: source.diskSize, volumeMode: source.volumeMode}
	if !h.authorizeImageTags(ctx, w, r, claims, "CopyImage", img.id, img.tags, requestID) {
		return
	}
	if err := h.createImageDisk(ctx, img, h.imagesNS, src); err != nil {
		h.imageWriteFailed(w, requestID, "CopyImage", src, err)
		return
	}
	writeEC2(w, requestID, "CopyImage", xtag("imageId", img.id))
}

// --- DeregisterImage ---

func (h *ec2Handler) deregisterImage(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if !h.imagesOn() {
		h.imagesOff(w, requestID)
		return
	}
	id, ok := imageIDParam(w, r.Form, "ImageId", requestID)
	if !ok {
		return
	}
	img, ok := h.ownedImage(ctx, w, id, requestID)
	if !ok {
		return
	}
	// An image deregistered while its instance waits to be started again: the instance is started now.
	if img.restart == "pending" {
		h.restartSource(ctx, img)
	}
	policy := metav1.DeletePropagationBackground
	err := h.door.shimDyn.Resource(dataVolumeGVR).Namespace(h.imagesNS).Delete(ctx, id, metav1.DeleteOptions{PropagationPolicy: &policy})
	if err != nil && !apierrors.IsNotFound(err) {
		h.imageWriteFailed(w, requestID, "DeregisterImage", id, err)
		return
	}
	writeEC2(w, requestID, "DeregisterImage", "<return>true</return>")
}

// --- attributes ---

// launchPermissionChange reads ModifyImageAttribute's launch permission changes in both of AWS's forms:
// LaunchPermission.Add.N / .Remove.N with UserId or Group, and OperationType with UserId.N / UserGroup.N.
// msg is AWS's error for a bad value or an unsupported one.
func launchPermissionChange(form url.Values) (add, remove []string, code, msg string) {
	const orgs = "Sharing an image with an organization or organizational unit is not supported by the open-infra shim: share it with each account (UserId)"
	// put checks one item — an account id (a userId item) or "all" (the one group item) — and files it.
	put := func(adding bool, v string, group bool) bool {
		switch {
		case group && v != "all":
			code, msg = "InvalidAMIAttributeItemValue", "Invalid attribute item value \""+v+"\" for group item type."
			return false
		case !group && !accountIDRe.MatchString(v):
			code, msg = "InvalidAMIAttributeItemValue", "Invalid attribute item value \""+v+"\" for userId item type."
			return false
		case adding:
			add = append(add, v)
		default:
			remove = append(remove, v)
		}
		return true
	}
	for _, dir := range []string{"Add", "Remove"} {
		for i := 1; i <= 1000; i++ {
			p := "LaunchPermission." + dir + "." + strconv.Itoa(i)
			u, g := form.Get(p+".UserId"), form.Get(p+".Group")
			if form.Get(p+".OrganizationArn") != "" || form.Get(p+".OrganizationalUnitArn") != "" {
				return nil, nil, "InvalidParameterValue", orgs
			}
			if u == "" && g == "" {
				break
			}
			if (u != "" && !put(dir == "Add", u, false)) || (g != "" && !put(dir == "Add", g, true)) {
				return nil, nil, code, msg
			}
		}
	}
	if len(ec2List(form, "OrganizationArn")) > 0 || len(ec2List(form, "OrganizationalUnitArn")) > 0 {
		return nil, nil, "InvalidParameterValue", orgs
	}
	if op := form.Get("OperationType"); op != "" {
		if op != "add" && op != "remove" {
			return nil, nil, "InvalidParameterValue", "Value (" + op + ") for parameter operationType is invalid. Valid values are add and remove."
		}
		for _, u := range ec2List(form, "UserId") {
			if !put(op == "add", u, false) {
				return nil, nil, code, msg
			}
		}
		for _, g := range ec2List(form, "UserGroup") {
			if !put(op == "add", g, true) {
				return nil, nil, code, msg
			}
		}
	}
	return add, remove, "", ""
}

func (h *ec2Handler) modifyImageAttribute(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if !h.imagesOn() {
		h.imagesOff(w, requestID)
		return
	}
	id, ok := imageIDParam(w, r.Form, "ImageId", requestID)
	if !ok {
		return
	}
	attr := r.Form.Get("Attribute")
	add, remove, code, msg := launchPermissionChange(r.Form)
	if code != "" {
		writeEC2Error(w, http.StatusBadRequest, code, requestID, msg)
		return
	}
	desc, hasDesc := r.Form["Description.Value"]
	if attr == "description" {
		desc, hasDesc = r.Form["Value"], true
	}
	if len(ec2List(r.Form, "ProductCode")) > 0 || (attr != "" && attr != "launchPermission" && attr != "description") {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"Value ("+attr+") for parameter attribute is invalid: the open-infra shim modifies an image's launchPermission and description")
		return
	}
	launch := len(add) > 0 || len(remove) > 0
	switch {
	case !launch && !hasDesc:
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, "No attributes specified.")
		return
	case launch && hasDesc:
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, "Only one attribute can be modified at a time.")
		return
	}
	img, ok := h.ownedImage(ctx, w, id, requestID)
	if !ok {
		return
	}
	ann := map[string]any{}
	if launch {
		set := map[string]bool{}
		for _, p := range img.launch {
			set[p] = true
		}
		for _, p := range add {
			if p != img.owner {
				set[p] = true
			}
		}
		for _, p := range remove {
			delete(set, p)
		}
		ann[annImageLaunch] = strings.Join(sortedSet(set), ",")
	} else {
		d := ""
		if len(desc) > 0 {
			d = desc[0]
		}
		if !checkImageDescription(w, d, requestID) {
			return
		}
		ann[annImageDescription] = d
	}
	if err := h.patchImage(ctx, id, ann); err != nil {
		h.imageWriteFailed(w, requestID, "ModifyImageAttribute", id, err)
		return
	}
	writeEC2(w, requestID, "ModifyImageAttribute", "<return>true</return>")
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// launchPermissionXML is an image's launch permission as EC2 answers it: one item per account, and a group
// item for a public image.
func launchPermissionXML(launch []string) string {
	items := make([]string, 0, len(launch))
	for _, p := range launch {
		if p == "all" {
			items = append(items, xtag("group", "all"))
		} else {
			items = append(items, xtag("userId", p))
		}
	}
	return xset("launchPermission", items)
}

func (img ec2Image) bootModeValue() string {
	if img.bootMode == "uefi" {
		return "uefi"
	}
	return "legacy-bios"
}

func (h *ec2Handler) describeImageAttribute(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if !h.imagesOn() {
		h.imagesOff(w, requestID)
		return
	}
	id, ok := imageIDParam(w, r.Form, "ImageId", requestID)
	if !ok {
		return
	}
	attr := r.Form.Get("Attribute")
	if attr == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter Attribute")
		return
	}
	switch attr {
	case "launchPermission", "description", "bootMode", "productCodes", "kernel", "ramdisk":
	default:
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Value ("+attr+") for parameter attribute is invalid. Unknown attribute.")
		return
	}
	img, ok := h.ownedImage(ctx, w, id, requestID)
	if !ok {
		return
	}
	out := xtag("imageId", id)
	switch attr {
	case "launchPermission":
		out += launchPermissionXML(img.launch)
	case "description":
		out += "<description>" + xtag("value", img.description) + "</description>"
	case "bootMode":
		out += "<bootMode>" + xtag("value", img.bootModeValue()) + "</bootMode>"
	case "productCodes":
		out += "<productCodes/>"
	case "kernel", "ramdisk":
		out += "<" + attr + "/>"
	}
	writeEC2(w, requestID, "DescribeImageAttribute", out)
}

func (h *ec2Handler) resetImageAttribute(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if !h.imagesOn() {
		h.imagesOff(w, requestID)
		return
	}
	id, ok := imageIDParam(w, r.Form, "ImageId", requestID)
	if !ok {
		return
	}
	switch attr := r.Form.Get("Attribute"); attr {
	case "":
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter Attribute")
		return
	case "launchPermission":
	default:
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Value ("+attr+") for parameter attribute is invalid. Only launchPermission can be reset.")
		return
	}
	if _, ok := h.ownedImage(ctx, w, id, requestID); !ok {
		return
	}
	if err := h.patchImage(ctx, id, map[string]any{annImageLaunch: ""}); err != nil {
		h.imageWriteFailed(w, requestID, "ResetImageAttribute", id, err)
		return
	}
	writeEC2(w, requestID, "ResetImageAttribute", "<return>true</return>")
}

// --- DescribeImages ---

// ec2ImageItem is one image as DescribeImages answers it, and as its filters see it.
type ec2ImageItem struct {
	rec ec2Record
	xml string
}

var imageFilters = []string{"image-id", "name", "state", "architecture", "platform", "platform-details", "usage-operation",
	"owner-alias", "owner-id", "is-public", "image-type", "root-device-type", "root-device-name", "virtualization-type",
	"hypervisor", "description", "creation-date", "block-device-mapping.device-name", "block-device-mapping.volume-size",
	"block-device-mapping.volume-type", "block-device-mapping.delete-on-termination", "block-device-mapping.encrypted",
	"ena-support", "boot-mode", "source-instance-id", "source-image-id", "state-reason-code", "state-reason-message"}

// An image's billing usage operation, as EC2 reports it (a value, not an operation this front door serves).
const (
	usageOperationLinux   = "RunInstances"
	usageOperationWindows = usageOperationLinux + ":0002"
)

// platformOf is an image's platform (windows, or none for Linux), its platform details and usage operation.
func platformOf(os string) (platform, details, usage string) {
	if strings.HasPrefix(os, "windows-") {
		return "windows", "Windows", usageOperationWindows
	}
	return "", "Linux/UNIX", usageOperationLinux
}

// catalogItem is a catalog OS's image: public, the platform's (owner alias openinfra), the same in every
// account, its owner the install's own account whoever asks (as a public AMI's owner is its publisher's).
func (h *ec2Handler) catalogItem(os string) ec2ImageItem {
	id := imageIDForOS(os)
	platform, details, usage := platformOf(os)
	desc := "open-infra catalog image " + os
	rec := ec2Record{fields: map[string][]string{"image-id": {id}, "name": {os}, "state": {"available"}, "architecture": {"x86_64"},
		"platform": {platform}, "platform-details": {details}, "usage-operation": {usage}, "owner-alias": {"openinfra"},
		"owner-id": {h.account()}, "is-public": {"true"}, "image-type": {"machine"}, "root-device-type": {"ebs"},
		"root-device-name": {"/dev/sda1"}, "virtualization-type": {"hvm"}, "hypervisor": {"xen"}, "description": {desc},
		"ena-support": {"true"}, "boot-mode": {"legacy-bios"}}}
	item := xtag("imageId", id) + xtag("imageLocation", "openinfra/"+os) + "<imageState>available</imageState>" + xtag("imageOwnerId", h.account()) +
		"<isPublic>true</isPublic><architecture>x86_64</architecture><imageType>machine</imageType>"
	if platform != "" {
		item += xtag("platform", platform)
	}
	item += xtag("platformDetails", details) + xtag("usageOperation", usage) + xtag("imageOwnerAlias", "openinfra") + xtag("name", os) + xtag("description", desc) +
		"<rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping/><virtualizationType>hvm</virtualizationType>" +
		"<hypervisor>xen</hypervisor><enaSupport>true</enaSupport><bootMode>legacy-bios</bootMode>"
	return ec2ImageItem{rec: rec, xml: item}
}

// accountItem is an account image as DescribeImages answers it.
func accountItem(img ec2Image) ec2ImageItem {
	platform, details, usage := platformOf(img.os)
	created := ec2Time(img.created)
	size := strconv.FormatInt(img.rootGiB, 10)
	f := map[string][]string{"image-id": {img.id}, "name": {img.name}, "state": {img.state}, "architecture": {img.arch},
		"platform": {platform}, "platform-details": {details}, "usage-operation": {usage}, "owner-id": {img.owner},
		"is-public": {strconv.FormatBool(img.public())}, "image-type": {"machine"}, "root-device-type": {"ebs"},
		"root-device-name": {"/dev/sda1"}, "virtualization-type": {"hvm"}, "hypervisor": {"xen"}, "description": {img.description},
		"creation-date": {created}, "block-device-mapping.device-name": {"/dev/sda1"}, "block-device-mapping.volume-size": {size},
		"block-device-mapping.volume-type": {"gp3"}, "block-device-mapping.delete-on-termination": {"true"},
		"block-device-mapping.encrypted": {"false"}, "ena-support": {"true"}, "boot-mode": {img.bootModeValue()},
		"source-instance-id": {img.sourceInstance}, "source-image-id": {img.sourceImage}}
	b := xtag("imageId", img.id) + xtag("imageLocation", img.owner+"/"+img.name) + xtag("imageState", img.state) + xtag("imageOwnerId", img.owner) +
		xtag("creationDate", created) + xbool("isPublic", img.public()) + xtag("architecture", img.arch) + "<imageType>machine</imageType>"
	if platform != "" {
		b += xtag("platform", platform)
	}
	b += xtag("platformDetails", details) + xtag("usageOperation", usage) + xtag("name", img.name) + xtag("description", img.description) +
		"<rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/sda1</rootDeviceName>" +
		xset("blockDeviceMapping", []string{"<deviceName>/dev/sda1</deviceName><ebs><deleteOnTermination>true</deleteOnTermination><volumeSize>" +
			size + "</volumeSize><volumeType>gp3</volumeType><encrypted>false</encrypted></ebs>"}) +
		"<virtualizationType>hvm</virtualizationType>" + xtags(img.tags) + "<hypervisor>xen</hypervisor><enaSupport>true</enaSupport>" +
		xtag("bootMode", img.bootModeValue()) + xtag("sourceInstanceId", img.sourceInstance) + xtag("sourceImageId", img.sourceImage)
	if img.state == "failed" {
		f["state-reason-code"] = []string{"Server.InternalError"}
		f["state-reason-message"] = []string{img.stateReason}
		b += "<stateReason><code>Server.InternalError</code><message>" + xesc("Server.InternalError: "+img.stateReason) + "</message></stateReason>"
	}
	return ec2ImageItem{rec: ec2Record{fields: f, tags: img.tags}, xml: b}
}

func (h *ec2Handler) describeImages(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, imageFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	ids := ec2List(r.Form, "ImageId")
	for _, id := range ids {
		if !accountImageIDRe.MatchString(id) {
			writeEC2Error(w, http.StatusBadRequest, "InvalidAMIID.Malformed", requestID, "Invalid id: \""+id+"\" (expecting \"ami-...\")")
			return
		}
	}
	if len(ids) > 0 && r.Form.Get("MaxResults") != "" {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, "The parameter imagesSet cannot be used with the parameter maxResults")
		return
	}
	acct := h.ownerAccount(ctx)
	owners := ec2List(r.Form, "Owner")
	for _, o := range owners {
		switch {
		case o == "self", o == "amazon", o == "openinfra", o == "aws-marketplace", o == "aws-backup-vault", accountIDRe.MatchString(o):
		default:
			writeEC2Error(w, http.StatusBadRequest, "InvalidUserID.Malformed", requestID, "Invalid user id: \""+o+"\"")
			return
		}
	}
	execBy := ec2List(r.Form, "ExecutableBy")
	for _, e := range execBy {
		if e != "self" && e != "all" && !accountIDRe.MatchString(e) {
			writeEC2Error(w, http.StatusBadRequest, "InvalidUserID.Malformed", requestID, "Invalid user id: \""+e+"\"")
			return
		}
	}
	all, err := h.listImages(ctx)
	if err != nil {
		h.imagesFailed(w, requestID, err)
		return
	}
	// Owner.N: self is the caller's account's images, amazon and openinfra the catalog's, an account id that
	// account's (and the catalog's, for the install's own account, which owns it).
	ownerOK := func(catalog bool, owner string) bool {
		if len(owners) == 0 {
			return true
		}
		for _, o := range owners {
			switch {
			case o == "amazon" || o == "openinfra":
				if catalog {
					return true
				}
			case o == "self":
				if !catalog && owner == acct {
					return true
				}
			case o == owner:
				return true
			}
		}
		return false
	}
	// ExecutableBy.N: self (or the caller's own id) is what it owns and what is shared with it; another
	// account's id, what is shared with that account; all, the public images.
	execOK := func(catalog bool, img ec2Image) bool {
		if len(execBy) == 0 {
			return true
		}
		for _, e := range execBy {
			switch {
			case e == "all":
				if catalog || img.public() {
					return true
				}
			case e == "self" || e == acct:
				if !catalog && (img.owner == acct || contains(img.launch, acct)) {
					return true
				}
			default:
				if !catalog && contains(img.launch, e) {
					return true
				}
			}
		}
		return false
	}
	want, found := setOf(ids), map[string]bool{}
	var sel []ec2ImageItem
	for _, os := range cfn.CatalogOSes() {
		id := imageIDForOS(os)
		if len(ids) > 0 && !want[id] {
			continue
		}
		found[id] = true
		if !ownerOK(true, h.account()) || !execOK(true, ec2Image{}) {
			continue
		}
		if it := h.catalogItem(os); it.rec.matches(fs) {
			sel = append(sel, it)
		}
	}
	for _, img := range visibleImages(all, acct) {
		if len(ids) > 0 && !want[img.id] {
			continue
		}
		found[img.id] = true
		if !ownerOK(false, img.owner) || !execOK(false, img) {
			continue
		}
		if it := accountItem(img); it.rec.matches(fs) {
			sel = append(sel, it)
		}
	}
	var missing []string
	for _, id := range ids {
		if !found[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		writeEC2Error(w, http.StatusBadRequest, "InvalidAMIID.NotFound", requestID, "The image id '["+strings.Join(missing, ", ")+"]' does not exist")
		return
	}
	start, end, next, msg, ok := ec2Page(r.Form, len(sel), 5, 1000)
	if !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	items := make([]string, 0, end-start)
	for _, it := range sel[start:end] {
		items = append(items, it.xml)
	}
	writeEC2(w, requestID, "DescribeImages", xset("imagesSet", items)+xtag("nextToken", next))
}

// --- launching, and the instance an image is made from ---

// launchableImages are the account images the request's account may launch, for an instance's ImageId
// (cfn.Capabilities.Images): its own, those shared with it, and public ones.
func (h *ec2Handler) launchableImages(ctx context.Context) (map[string]cfn.AccountImage, error) {
	all, err := h.listImages(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]cfn.AccountImage{}
	for _, img := range visibleImages(all, h.ownerAccount(ctx)) {
		out[img.id] = cfn.AccountImage{OS: img.os, State: img.state, RootGiB: int(img.rootGiB), BootMode: img.bootMode}
	}
	return out, nil
}

// imageInProgress is the pending image being made from instance id ("" for none): the instance is not
// started while its disk is copied (a disk in use cannot be copied whole).
func (h *ec2Handler) imageInProgress(ctx context.Context, id string) string {
	all, err := h.listImages(ctx)
	if err != nil {
		return ""
	}
	for _, img := range all {
		if img.sourceInstance == id && img.sourceImage == "" && img.state == "pending" {
			return img.id
		}
	}
	return ""
}

// imageInstanceID is the image id an instance reports: the account image it was launched from
// (spec.imageId), else its catalog OS's.
func imageInstanceID(claim *unstructured.Unstructured, os string) string {
	if id, _, _ := unstructured.NestedString(claim.Object, "spec", "imageId"); id != "" {
		return id
	}
	return imageIDForOS(os)
}

// --- finishing what an image waits for ---

// restartSource starts the instance CreateImage stopped to image it, with the shim's own authority, and
// records that it did. An instance terminated meanwhile has nothing to start.
func (h *ec2Handler) restartSource(ctx context.Context, img ec2Image) {
	ns, name, ok := strings.Cut(img.sourceVM, "/")
	if ok && ns != "" && name != "" {
		if err := h.setVMRunning(ctx, ns, name, true); err != nil && !apierrors.IsNotFound(err) {
			if h.logger != nil {
				h.logger.Warn("ec2: starting an imaged instance again failed; retrying", "image", img.id, "instance", img.sourceInstance, "error", err.Error())
			}
			return
		}
	}
	if err := h.patchImage(ctx, img.id, map[string]any{annImageRestart: "done"}); err != nil && !apierrors.IsNotFound(err) && h.logger != nil {
		h.logger.Warn("ec2: recording an imaged instance's start failed", "image", img.id, "error", err.Error())
	}
}

// reconcileImages finishes what each image waits for once its copy is done: the record takes the state
// (available or failed), and an instance CreateImage stopped is started again. It reads only the images'
// records, so a restarted shim picks up where the last one stopped.
func (h *ec2Handler) reconcileImages(ctx context.Context) {
	all, err := h.listImages(ctx)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("ec2: reading images failed", "error", err.Error())
		}
		return
	}
	for _, img := range all {
		if img.state == "pending" {
			continue
		}
		if img.recordedState != img.state {
			ann := map[string]any{annImageState: img.state}
			if img.state == "failed" {
				ann[annImageStateReason] = img.stateReason
			}
			if err := h.patchImage(ctx, img.id, ann); err != nil && h.logger != nil {
				h.logger.Warn("ec2: recording an image's state failed", "image", img.id, "error", err.Error())
			}
		}
		if img.restart == "pending" {
			h.restartSource(ctx, img)
		}
	}
}

// runImageReconciler reconciles the images now and then every interval, until ctx ends.
func (h *ec2Handler) runImageReconciler(ctx context.Context, every time.Duration) {
	if !h.imagesOn() {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.reconcileImages(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
