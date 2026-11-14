package vmconsole

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

// KubeVirt 1.8 runs the log container as a native sidecar (an init container that restarts always); the
// log is read from it, as from a plain container.
func TestOutputFromSidecar(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	p := launcher("virt-launcher-web-1", "web", corev1.PodRunning, time.Now(), "compute")
	p.Spec.InitContainers = []corev1.Container{{Name: LogContainer, RestartPolicy: &always}}
	plain := launcher("virt-launcher-db-1", "db", corev1.PodRunning, time.Now(), "compute", LogContainer)
	cs := fake.NewSimpleClientset(p, plain)
	for _, vm := range []string{"web", "db"} {
		if out, err := Output(context.Background(), cs, "acct", vm); err != nil || len(out) == 0 {
			t.Errorf("%s: %q %v, want the log", vm, out, err)
		}
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
