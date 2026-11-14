package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func vmConsoleRouter(cs *fake.Clientset) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := chi.NewRouter()
	r.Get("/api/vms/{namespace}/{name}/console-output", handleVMConsoleOutput(cs, logger))
	r.Get("/api/vms/{namespace}/{name}/console-screenshot", handleVMConsoleScreenshot(cs, logger))
	return r
}

func vmLauncher(vm string, containers ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "virt-launcher-" + vm + "-x", Namespace: "acct",
		Labels: map[string]string{"kubevirt.io": "virt-launcher", "vm.kubevirt.io/name": vm}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	for _, c := range containers {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c})
	}
	return p
}

// The system log: the guest's serial output when it is collected, otherwise a note saying why not (the
// instance isn't running, or it started before collection was on), never an error.
func TestVMConsoleOutput(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	sidecar := vmLauncher("web", "compute") // KubeVirt 1.8: the log container is a native sidecar
	sidecar.Spec.InitContainers = []corev1.Container{{Name: "guest-console-log", RestartPolicy: &always}}
	cs := fake.NewSimpleClientset(sidecar, vmLauncher("old", "compute"))
	for _, c := range []struct{ vm, want string }{
		{"web", "fake logs"}, // the fake clientset's log body
		{"old", "next stop and start"},
		{"gone", "isn't running"},
	} {
		w := httptest.NewRecorder()
		vmConsoleRouter(cs).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/vms/acct/"+c.vm+"/console-output", nil))
		var resp vmConsoleOutput
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if w.Code != 200 || !strings.Contains(resp.Output+resp.Note, c.want) {
			t.Errorf("%s: %d %s, want %q", c.vm, w.Code, w.Body.String(), c.want)
		}
	}
}

// A screenshot of an instance that isn't running is a conflict with a plain explanation.
func TestVMConsoleScreenshotNotRunning(t *testing.T) {
	w := httptest.NewRecorder()
	vmConsoleRouter(fake.NewSimpleClientset()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/vms/acct/gone/console-screenshot", nil))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "isn't running") {
		t.Errorf("got %d %s", w.Code, w.Body.String())
	}
}
