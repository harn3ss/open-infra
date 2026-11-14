package vmconsole

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func launcher(name, vm string, phase corev1.PodPhase, created time.Time, containers ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "acct",
		Labels:            map[string]string{"kubevirt.io": "virt-launcher", "vm.kubevirt.io/name": vm},
		CreationTimestamp: metav1.NewTime(created)},
		Status: corev1.PodStatus{Phase: phase}}
	for _, c := range containers {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c})
	}
	return p
}

// The running launcher is the VM's; during a migration the newest of the running ones. A VM with no
// running launcher is not running.
func TestLauncherPod(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	cs := fake.NewSimpleClientset(
		launcher("virt-launcher-web-old", "web", corev1.PodRunning, t0, "compute"),
		launcher("virt-launcher-web-new", "web", corev1.PodRunning, t0.Add(time.Minute), "compute"),
		launcher("virt-launcher-web-done", "web", corev1.PodSucceeded, t0.Add(2*time.Minute), "compute"),
		launcher("virt-launcher-db-x", "db", corev1.PodPending, t0, "compute"),
	)
	p, err := launcherPod(context.Background(), cs, "acct", "web")
	if err != nil || p.Name != "virt-launcher-web-new" {
		t.Fatalf("launcher of web: %v %v, want virt-launcher-web-new", p, err)
	}
	if _, err := launcherPod(context.Background(), cs, "acct", "db"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("a pending launcher: %v, want ErrNotRunning", err)
	}
	if _, err := launcherPod(context.Background(), cs, "acct", "nope"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("no launcher: %v, want ErrNotRunning", err)
	}
}

// A VM started without serial console logging has no log container: ErrNoLog, not an empty log.
func TestOutputWithoutLogging(t *testing.T) {
	cs := fake.NewSimpleClientset(launcher("virt-launcher-web-1", "web", corev1.PodRunning, time.Now(), "compute"))
	if _, err := Output(context.Background(), cs, "acct", "web"); !errors.Is(err, ErrNoLog) {
		t.Errorf("no guest-console-log container: %v, want ErrNoLog", err)
	}
}

// logged marks the pod's log container as started (running), in the status list its kind is in.
func logged(p *corev1.Pod, sidecar bool) *corev1.Pod {
	st := corev1.ContainerStatus{Name: LogContainer, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	if sidecar {
		p.Status.InitContainerStatuses = append(p.Status.InitContainerStatuses, st)
	} else {
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, st)
	}
	return p
}

// KubeVirt 1.8 runs the log container as a native sidecar (an init container that restarts always); the
// log is read from it, as from a plain container.
func TestOutputFromSidecar(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	p := launcher("virt-launcher-web-1", "web", corev1.PodRunning, time.Now(), "compute")
	p.Spec.InitContainers = []corev1.Container{{Name: LogContainer, RestartPolicy: &always}}
	plain := launcher("virt-launcher-db-1", "db", corev1.PodRunning, time.Now(), "compute", LogContainer)
	cs := fake.NewSimpleClientset(logged(p, true), logged(plain, false))
	for _, vm := range []string{"web", "db"} {
		if out, err := Output(context.Background(), cs, "acct", vm); err != nil || len(out) == 0 {
			t.Errorf("%s: %q %v, want the log", vm, out, err)
		}
	}
}

// Once a VM stops, its last output is answered while the pod it ran in remains (EC2 answers a stopped
// instance's last output too); a launcher whose log container hasn't started has nothing yet.
func TestOutputAfterStop(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	done := launcher("virt-launcher-web-1", "web", corev1.PodSucceeded, t0, "compute", LogContainer)
	done.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: LogContainer,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}}}
	starting := launcher("virt-launcher-db-1", "db", corev1.PodPending, t0, "compute", LogContainer)
	cs := fake.NewSimpleClientset(done, starting)
	if out, err := Output(context.Background(), cs, "acct", "web"); err != nil || len(out) == 0 {
		t.Errorf("a stopped VM's last output: %q %v", out, err)
	}
	if _, err := Output(context.Background(), cs, "acct", "db"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("a launcher whose log hasn't started: %v, want ErrNotRunning (nothing buffered)", err)
	}
}

// The tail is at most n bytes and starts on a line, as EC2's last 64 KB of output.
func TestLast(t *testing.T) {
	if got := Last([]byte("short"), 10); string(got) != "short" {
		t.Errorf("short input changed: %q", got)
	}
	b := []byte(strings.Repeat("line of serial output\n", 5000))
	got := Last(b, MaxOutput)
	if len(got) > MaxOutput {
		t.Errorf("tail is %d bytes, over %d", len(got), MaxOutput)
	}
	if !strings.HasPrefix(string(got), "line of serial output\n") {
		t.Errorf("tail doesn't start on a line: %q", got[:30])
	}
	if !bytes.HasSuffix(b, got) {
		t.Error("tail is not the end of the output")
	}
}

// KubeVirt's PNG comes back as a JPEG of the same size, as EC2's ImageData.
func TestToJPEG(t *testing.T) {
	m := image.NewRGBA(image.Rect(0, 0, 64, 48))
	for x := 0; x < 64; x++ {
		m.Set(x, 10, color.RGBA{255, 0, 0, 255})
	}
	var p bytes.Buffer
	_ = png.Encode(&p, m)
	j, err := ToJPEG(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(j))
	if err != nil || cfg.Width != 64 || cfg.Height != 48 {
		t.Errorf("JPEG %v %+v, want a 64x48 JPEG", err, cfg)
	}
	if _, err := ToJPEG([]byte("not an image")); err == nil {
		t.Error("garbage must not encode")
	}
}

// The screenshot is asked for as virt-api serves it: its route declares no media type, so a request that
// does not accept */* is 406 Not Acceptable (as live). wake moves the pointer first; only a Running VMI
// is captured.
func TestScreenshotAcceptsAny(t *testing.T) {
	var p bytes.Buffer
	_ = png.Encode(&p, image.NewRGBA(image.Rect(0, 0, 8, 8)))
	var query string
	phase := "Running"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/apis/kubevirt.io/v1/namespaces/acct/virtualmachineinstances/web":
			if phase == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"kind":"VirtualMachineInstance","status":{"phase":"` + phase + `"}}`))
		case r.URL.Path == "/api/v1/namespaces/acct/pods":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","items":[{"metadata":{"name":"virt-launcher-web-1","namespace":"acct"},"status":{"phase":"Running"}}]}`))
		case r.URL.Path == "/apis/subresources.kubevirt.io/v1/namespaces/acct/virtualmachineinstances/web/vnc/screenshot":
			if !strings.Contains(r.Header.Get("Accept"), "*/*") {
				http.Error(w, "406: Not Acceptable", http.StatusNotAcceptable)
				return
			}
			query = r.URL.RawQuery
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(p.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	j, err := Screenshot(context.Background(), cs, "acct", "web", true)
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}
	if _, err := jpeg.DecodeConfig(bytes.NewReader(j)); err != nil {
		t.Errorf("not a JPEG: %v", err)
	}
	if query != "moveCursor=true" {
		t.Errorf("wake sent %q, want moveCursor=true", query)
	}
	// The launcher outlives a stop for a moment: a VMI that has finished, or is gone, is not running.
	for _, phase = range []string{"Succeeded", ""} {
		if _, err := Screenshot(context.Background(), cs, "acct", "web", false); !errors.Is(err, ErrNotRunning) {
			t.Errorf("VMI phase %q: %v, want ErrNotRunning", phase, err)
		}
	}
}
