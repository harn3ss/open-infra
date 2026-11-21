package main

// A Windows instance's metadata service, served outside the guest as EC2's is (vm-composition.yaml,
// $imdsOutside). A mutating admission webhook (platform/aws-shim/instance-metadata-webhook.yaml) sends this
// handler the KubeVirt launcher pod of every VM labelled openinfra.dev/instance-metadata=pod, and it adds:
//
//   - an init container that puts 169.254.169.254/32 on the pod's loopback (NET_ADMIN, nothing else). The
//     guest reaches the pod through its network adapter and default gateway (the launch agent adds the
//     route, as EC2Launch does), so a request for the metadata service leaves the guest through its NIC,
//     where Windows Firewall filters it, and arrives in the pod, where the address is local;
//   - the metadata container: the metadata agent the Linux guests run (the VM's <name>-metadata Secret holds
//     it and its configuration), as the pod's own non-root user, listening on 169.254.169.254:80 (the pod's
//     net.ipv4.ip_unprivileged_port_start lets it bind port 80 without a capability);
//   - its volume: that Secret, the instance's user data and the platform root CA from the launch CD's Secret
//     (<name>-launch), and a token of the VM's ServiceAccount, which /v1/vm-credentials exchanges for the
//     instance role's credentials, as it does for the guest's own agents.
//
// The handler only reads the pod it is sent and answers a patch: it reads and changes nothing else.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	instanceMetadataWebhookPath = "/v1/admission/instance-metadata"
	instanceMetadataLabel       = "openinfra.dev/instance-metadata" // "pod": serve the VM's metadata from its pod
	kubevirtVMNameLabel         = "vm.kubevirt.io/name"
	instanceMetadataContainer   = "instance-metadata"
	instanceMetadataInit        = "instance-metadata-address"
	instanceMetadataVolume      = "openinfra-metadata"
	instanceMetadataDir         = "/etc/openinfra-metadata"
	// instanceMetadataImageDefault runs both containers: Python for the agent, BusyBox ip for the address.
	// INSTANCE_METADATA_IMAGE overrides it (a mirror, in an air-gapped install).
	instanceMetadataImageDefault = "docker.io/library/python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89"
	// launcherUID is the KubeVirt launcher's user, whose group the pod's volumes are readable by (fsGroup).
	launcherUID = int64(107)
)

// vmNameRe is a VM name the patch may carry into Secret names: a DNS label, as the composition makes them.
var vmNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type instanceMetadataWebhook struct {
	image string
}

func newInstanceMetadataWebhook() *instanceMetadataWebhook {
	img := os.Getenv("INSTANCE_METADATA_IMAGE")
	if img == "" {
		img = instanceMetadataImageDefault
	}
	return &instanceMetadataWebhook{image: img}
}

// serve answers an AdmissionReview of a pod with the patch that serves its VM's instance metadata.
func (h *instanceMetadataWebhook) serve(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&review); err != nil || review.Request == nil {
		http.Error(w, "an AdmissionReview with a request is expected", http.StatusBadRequest)
		return
	}
	resp := &admissionv1.AdmissionResponse{UID: review.Request.UID, Allowed: true}
	patch, err := h.patchFor(review.Request)
	if err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
			Message: "instance metadata: " + err.Error()}
	} else if patch != nil {
		pt := admissionv1.PatchTypeJSONPatch
		resp.Patch, resp.PatchType = patch, &pt
	}
	out := admissionv1.AdmissionReview{TypeMeta: review.TypeMeta, Response: resp}
	if out.APIVersion == "" {
		out.APIVersion, out.Kind = "admission.k8s.io/v1", "AdmissionReview"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// patchFor is the JSON patch for the pod a request carries: nil when the pod is not a launcher pod marked for
// it, or already has the metadata container (a reinvocation); an error when the pod is marked but cannot be
// served (it would start an instance with no metadata service).
func (h *instanceMetadataWebhook) patchFor(req *admissionv1.AdmissionRequest) ([]byte, error) {
	if req.Kind.Kind != "Pod" || req.Operation != admissionv1.Create {
		return nil, nil
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return nil, fmt.Errorf("the pod cannot be read: %v", err)
	}
	if pod.Labels[instanceMetadataLabel] != "pod" || pod.Labels["kubevirt.io"] != "virt-launcher" {
		return nil, nil
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == instanceMetadataContainer {
			return nil, nil
		}
	}
	vm := pod.Labels[kubevirtVMNameLabel]
	if !vmNameRe.MatchString(vm) {
		return nil, fmt.Errorf("the launcher pod names no VM (label %s)", kubevirtVMNameLabel)
	}
	var ops []map[string]any
	add := func(path string, v any) { ops = append(ops, map[string]any{"op": "add", "path": path, "value": v}) }

	sysctl := corev1.Sysctl{Name: "net.ipv4.ip_unprivileged_port_start", Value: "80"}
	switch {
	case pod.Spec.SecurityContext == nil:
		add("/spec/securityContext", corev1.PodSecurityContext{Sysctls: []corev1.Sysctl{sysctl}})
	case len(pod.Spec.SecurityContext.Sysctls) == 0:
		add("/spec/securityContext/sysctls", []corev1.Sysctl{sysctl})
	default:
		add("/spec/securityContext/sysctls/-", sysctl)
	}
	if len(pod.Spec.InitContainers) == 0 {
		add("/spec/initContainers", []corev1.Container{h.initContainer()})
	} else {
		add("/spec/initContainers/-", h.initContainer())
	}
	add("/spec/containers/-", h.container())
	if len(pod.Spec.Volumes) == 0 {
		add("/spec/volumes", []corev1.Volume{metadataVolume(vm)})
	} else {
		add("/spec/volumes/-", metadataVolume(vm))
	}
	return json.Marshal(ops)
}

func (h *instanceMetadataWebhook) initContainer() corev1.Container {
	root, no := int64(0), false
	return corev1.Container{
		Name:  instanceMetadataInit,
		Image: h.image,
		// Idempotent: a pod whose network namespace outlived a restart may already have the address.
		Command: []string{"sh", "-c", "ip -4 addr show dev lo | grep -q ' 169.254.169.254/32 ' || ip addr add 169.254.169.254/32 dev lo"},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: &root, RunAsNonRoot: &no, AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: boolPtr(true),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_ADMIN"}},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("32Mi")},
		},
	}
}

func (h *instanceMetadataWebhook) container() corev1.Container {
	uid, no := launcherUID, false
	return corev1.Container{
		Name:    instanceMetadataContainer,
		Image:   h.image,
		Command: []string{"python3", instanceMetadataDir + "/metadata-agent.py", instanceMetadataDir + "/metadata-agent.json"},
		Env:     []corev1.EnvVar{{Name: "PYTHONDONTWRITEBYTECODE", Value: "1"}, {Name: "PYTHONUNBUFFERED", Value: "1"}},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: boolPtr(true), AllowPrivilegeEscalation: &no,
			ReadOnlyRootFilesystem: boolPtr(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: instanceMetadataVolume, MountPath: instanceMetadataDir, ReadOnly: true}},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("48Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
		},
	}
}

// metadataVolume is the metadata container's files: the agent and its configuration (<vm>-metadata), the
// instance's user data and the platform root CA (<vm>-launch: there is no user data key when the instance
// has none), and a token of the pod's ServiceAccount, the VM's.
func metadataVolume(vm string) corev1.Volume {
	mode, optional, expiry := int32(0o440), true, int64(3600)
	return corev1.Volume{Name: instanceMetadataVolume, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
		DefaultMode: &mode,
		Sources: []corev1.VolumeProjection{
			{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: vm + "-metadata"},
				Items: []corev1.KeyToPath{{Key: "metadata-agent.json", Path: "metadata-agent.json"}, {Key: "metadata-agent.py", Path: "metadata-agent.py"}}}},
			{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: vm + "-launch"}, Optional: &optional,
				Items: []corev1.KeyToPath{{Key: "user-data", Path: "user-data"}, {Key: "platform-root-ca.pem", Path: "platform-root-ca.pem"}}}},
			{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expiry}},
		},
	}}}
}
