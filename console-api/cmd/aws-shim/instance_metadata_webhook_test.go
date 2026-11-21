package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// launcherPod is a KubeVirt launcher pod as virt-controller makes it, with the labels the VM's template gives it.
func launcherPod(labels map[string]string) corev1.Pod {
	uid := int64(107)
	return corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "virt-launcher-build-abcde", Namespace: "acct-111122223333", Labels: labels},
		Spec: corev1.PodSpec{
			ServiceAccountName: "vm-build",
			SecurityContext:    &corev1.PodSecurityContext{RunAsUser: &uid, FSGroup: &uid},
			Containers:         []corev1.Container{{Name: "compute", Image: "quay.io/kubevirt/virt-launcher:v1.8.4"}},
			Volumes:            []corev1.Volume{{Name: "private", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		},
	}
}

func markedLabels() map[string]string {
	return map[string]string{"kubevirt.io": "virt-launcher", instanceMetadataLabel: "pod", kubevirtVMNameLabel: "build"}
}

// review sends pod to the webhook and returns its response and, when it patched, the patched pod.
func review(t *testing.T, h *instanceMetadataWebhook, pod corev1.Pod, op admissionv1.Operation) (*admissionv1.AdmissionResponse, *corev1.Pod) {
	t.Helper()
	raw, _ := json.Marshal(pod)
	in := admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{UID: "u-1", Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: op, Object: runtime.RawExtension{Raw: raw}}}
	body, _ := json.Marshal(in)
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest(http.MethodPost, instanceMetadataWebhookPath, bytes.NewReader(body)))
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Response == nil {
		t.Fatalf("the webhook answered %d %s", w.Code, w.Body)
	}
	if out.Response.UID != "u-1" || out.APIVersion != "admission.k8s.io/v1" || out.Kind != "AdmissionReview" {
		t.Fatalf("the response must carry the request's uid and AdmissionReview's kind: %+v", out)
	}
	if out.Response.Patch == nil {
		return out.Response, nil
	}
	p, err := jsonpatch.DecodePatch(out.Response.Patch)
	if err != nil {
		t.Fatalf("the patch does not decode: %v", err)
	}
	patched, err := p.Apply(raw)
	if err != nil {
		t.Fatalf("the patch does not apply to the pod: %v", err)
	}
	var got corev1.Pod
	if err := json.Unmarshal(patched, &got); err != nil {
		t.Fatal(err)
	}
	return out.Response, &got
}

// A launcher pod marked for it gets the metadata service: the address on the pod's loopback (an init container
// with NET_ADMIN and nothing more), the agent as the pod's non-root user with no capability, port 80 bindable
// through the pod's sysctl, and a volume of the VM's own Secrets and ServiceAccount token.
func TestInstanceMetadataWebhook_ServesTheVMsMetadataFromItsPod(t *testing.T) {
	h := &instanceMetadataWebhook{image: "registry.example/python@sha256:0123"}
	resp, pod := review(t, h, launcherPod(markedLabels()), admissionv1.Create)
	if !resp.Allowed || pod == nil || resp.PatchType == nil || *resp.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("a marked launcher pod must be allowed and patched: %+v", resp)
	}
	if n := len(pod.Spec.Containers); n != 2 || pod.Spec.Containers[0].Name != "compute" {
		t.Fatalf("the launcher's containers must be kept, the metadata container added: %+v", pod.Spec.Containers)
	}
	c := pod.Spec.Containers[1]
	sc := c.SecurityContext
	if c.Name != instanceMetadataContainer || c.Image != h.image || sc == nil || *sc.RunAsUser != launcherUID || !*sc.RunAsNonRoot ||
		*sc.AllowPrivilegeEscalation || len(sc.Capabilities.Add) != 0 || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("the metadata container must run the agent as the launcher's non-root user with no capability: %+v", c)
	}
	if strings.Join(c.Command, " ") != "python3 /etc/openinfra-metadata/metadata-agent.py /etc/openinfra-metadata/metadata-agent.json" {
		t.Errorf("the metadata container runs %v", c.Command)
	}
	if len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != instanceMetadataDir || !c.VolumeMounts[0].ReadOnly {
		t.Errorf("the metadata container mounts %+v", c.VolumeMounts)
	}
	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("one init container: %+v", pod.Spec.InitContainers)
	}
	ic := pod.Spec.InitContainers[0]
	isc := ic.SecurityContext
	if ic.Name != instanceMetadataInit || !strings.Contains(strings.Join(ic.Command, " "), "ip addr add 169.254.169.254/32 dev lo") ||
		isc == nil || *isc.AllowPrivilegeEscalation || len(isc.Capabilities.Add) != 1 || isc.Capabilities.Add[0] != "NET_ADMIN" ||
		len(isc.Capabilities.Drop) != 1 || isc.Capabilities.Drop[0] != "ALL" || len(ic.VolumeMounts) != 0 {
		t.Errorf("the init container must add the address with NET_ADMIN alone and mount nothing: %+v", ic)
	}
	if s := pod.Spec.SecurityContext; s == nil || len(s.Sysctls) != 1 || s.Sysctls[0].Name != "net.ipv4.ip_unprivileged_port_start" ||
		s.Sysctls[0].Value != "80" || *s.RunAsUser != launcherUID {
		t.Errorf("the pod's security context keeps the launcher's and lets port 80 be bound: %+v", s)
	}
	if n := len(pod.Spec.Volumes); n != 2 || pod.Spec.Volumes[0].Name != "private" {
		t.Fatalf("the launcher's volumes must be kept, the metadata volume added: %+v", pod.Spec.Volumes)
	}
	v := pod.Spec.Volumes[1].Projected
	if pod.Spec.Volumes[1].Name != instanceMetadataVolume || v == nil || len(v.Sources) != 3 {
		t.Fatalf("the metadata volume: %+v", pod.Spec.Volumes[1])
	}
	if s := v.Sources[0].Secret; s == nil || s.Name != "build-metadata" || (s.Optional != nil && *s.Optional) {
		t.Errorf("the agent and its configuration come from the VM's own metadata Secret, which must exist: %+v", v.Sources[0])
	}
	if s := v.Sources[1].Secret; s == nil || s.Name != "build-launch" || s.Optional == nil || !*s.Optional {
		t.Errorf("the user data and CA come from the VM's launch Secret (no user data key when it has none): %+v", v.Sources[1])
	}
	if tok := v.Sources[2].ServiceAccountToken; tok == nil || tok.Path != "token" || tok.Audience != "" {
		t.Errorf("the VM's ServiceAccount token, for the API server (TokenReview): %+v", v.Sources[2])
	}
}

// A pod that carries no security context or volumes yet is patched with the fields made, not appended to.
func TestInstanceMetadataWebhook_PodWithoutSecurityContextOrVolumes(t *testing.T) {
	pod := launcherPod(markedLabels())
	pod.Spec.SecurityContext, pod.Spec.Volumes = nil, nil
	pod.Spec.InitContainers = []corev1.Container{{Name: "container-disk-binary", Image: "quay.io/kubevirt/virt-launcher:v1.8.4"}}
	_, got := review(t, &instanceMetadataWebhook{image: "img"}, pod, admissionv1.Create)
	if got == nil || got.Spec.SecurityContext == nil || len(got.Spec.SecurityContext.Sysctls) != 1 || len(got.Spec.Volumes) != 1 ||
		len(got.Spec.InitContainers) != 2 || got.Spec.InitContainers[1].Name != instanceMetadataInit {
		t.Fatalf("patched pod: %+v", got)
	}
}

// Only a launcher pod marked for it is changed, once; one that names no VM is refused rather than started with
// no metadata service.
func TestInstanceMetadataWebhook_LeavesOtherPodsAlone(t *testing.T) {
	h := &instanceMetadataWebhook{image: "img"}
	unmarked := markedLabels()
	delete(unmarked, instanceMetadataLabel)
	notLauncher := markedLabels()
	notLauncher["kubevirt.io"] = "virt-handler"
	for name, pod := range map[string]corev1.Pod{"unmarked": launcherPod(unmarked), "not a launcher": launcherPod(notLauncher)} {
		if resp, got := review(t, h, pod, admissionv1.Create); !resp.Allowed || got != nil {
			t.Errorf("%s: must be allowed unchanged: %+v", name, resp)
		}
	}
	served := launcherPod(markedLabels())
	served.Spec.Containers = append(served.Spec.Containers, corev1.Container{Name: instanceMetadataContainer})
	if resp, got := review(t, h, served, admissionv1.Create); !resp.Allowed || got != nil {
		t.Errorf("a pod that already has the metadata container is left as it is: %+v", resp)
	}
	if resp, got := review(t, h, launcherPod(markedLabels()), admissionv1.Update); !resp.Allowed || got != nil {
		t.Errorf("only a pod's creation is patched: %+v", resp)
	}
	for _, vm := range []string{"", "Build", "../x", strings.Repeat("a", 64)} {
		l := markedLabels()
		l[kubevirtVMNameLabel] = vm
		if resp, _ := review(t, h, launcherPod(l), admissionv1.Create); resp.Allowed || resp.Result == nil ||
			!strings.Contains(resp.Result.Message, "names no VM") {
			t.Errorf("VM name %q: a marked pod whose VM cannot be named must be refused: %+v", vm, resp)
		}
	}
}

// The API server calls the webhook over TLS; on the plaintext port it is not found.
func TestInstanceMetadataWebhook_TLSOnly(t *testing.T) {
	served := 0
	h := plaintextVMCredsGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served++ }), true)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, instanceMetadataWebhookPath, strings.NewReader("{}")))
	if w.Code != http.StatusNotFound || served != 0 {
		t.Fatalf("plaintext: %d (served %d), want 404", w.Code, served)
	}
	r := httptest.NewRequest(http.MethodPost, instanceMetadataWebhookPath, strings.NewReader("{}"))
	r.TLS = &tls.ConnectionState{}
	h.ServeHTTP(httptest.NewRecorder(), r)
	if served != 1 {
		t.Fatal("over TLS the webhook is served")
	}
	w = httptest.NewRecorder()
	newInstanceMetadataWebhook().serve(w, httptest.NewRequest(http.MethodPost, instanceMetadataWebhookPath, strings.NewReader("not json")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a body that is no AdmissionReview: %d", w.Code)
	}
}
