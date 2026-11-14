// Package vmconsole reads what an EC2 instance's console shows, for the AWS front door's
// GetConsoleOutput and GetConsoleScreenshot and for the console's "Get system log" and "Get instance
// screenshot": the guest's serial console output, and a still image of its display.
//
// An instance is a KubeVirt VirtualMachine of the same name as its kind: VirtualMachine, in the same
// namespace. Its serial output is what KubeVirt's guest-console-log container (on when the VM is started
// with spec.domain.devices.logSerialConsole) prints in the VM's virt-launcher pod; the screenshot is
// KubeVirt's vnc/screenshot subresource, a PNG, re-encoded as the JPEG EC2 returns.
//
// Callers decide authorization first (the IAM action on the instance); these functions only read.
package vmconsole

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/jpeg"
	_ "image/png" // decode KubeVirt's PNG
	"io"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// MaxOutput is the most console output returned, as EC2's GetConsoleOutput: the last 64 KB.
const MaxOutput = 64 * 1024

// LogContainer is the virt-launcher container that streams the guest's serial console output.
const LogContainer = "guest-console-log"

var (
	// ErrNotRunning: the instance has no running VM (stopped, starting or gone).
	ErrNotRunning = errors.New("the instance is not running")
	// ErrNoLog: the VM is running but was started without serial console logging (it started before
	// logging was turned on, and gets it at its next start).
	ErrNoLog = errors.New("the instance was started without console logging")
)

// launcherPod is the running virt-launcher pod of VM ns/name.
func launcherPod(ctx context.Context, cs kubernetes.Interface, ns, name string) (*corev1.Pod, error) {
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "kubevirt.io=virt-launcher,vm.kubevirt.io/name=" + name,
	})
	if err != nil {
		return nil, err
	}
	var running []corev1.Pod
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			running = append(running, p)
		}
	}
	if len(running) == 0 {
		return nil, ErrNotRunning
	}
	// During a live migration two launchers run; the newest is the VM's.
	sort.Slice(running, func(i, j int) bool {
		return running[j].CreationTimestamp.Before(&running[i].CreationTimestamp)
	})
	return &running[0], nil
}

// Output is the last MaxOutput bytes of VM ns/name's serial console output.
func Output(ctx context.Context, cs kubernetes.Interface, ns, name string) ([]byte, error) {
	pod, err := launcherPod(ctx, cs, ns, name)
	if err != nil {
		return nil, err
	}
	if !hasLogContainer(pod) {
		return nil, ErrNoLog
	}
	// Serial output is mostly short lines; 8,000 lines covers 64 KB, then keep the tail.
	tail := int64(8000)
	stream, err := cs.CoreV1().Pods(ns).GetLogs(pod.Name, &corev1.PodLogOptions{Container: LogContainer, TailLines: &tail}).Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	b, err := io.ReadAll(io.LimitReader(stream, 16*MaxOutput))
	if err != nil {
		return nil, err
	}
	return Last(b, MaxOutput), nil
}

// hasLogContainer: the launcher runs the log container, as a native sidecar (an init container that
// restarts always, as KubeVirt 1.8 does) or as a container.
func hasLogContainer(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.InitContainers {
		if c.Name == LogContainer {
			return true
		}
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == LogContainer {
			return true
		}
	}
	return false
}

// Last is the last n bytes of b, starting at a line boundary when one is within reach, so the output
// doesn't open on half a line.
func Last(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	b = b[len(b)-n:]
	if i := bytes.IndexByte(b, '\n'); i >= 0 && i < 512 {
		b = b[i+1:]
	}
	return b
}

// Screenshot is a JPEG of VM ns/name's display. wake moves the pointer first, so a screen that has
// blanked shows its content (EC2's WakeUp).
func Screenshot(ctx context.Context, cs kubernetes.Interface, ns, name string, wake bool) ([]byte, error) {
	if _, err := launcherPod(ctx, cs, ns, name); err != nil {
		return nil, err
	}
	// virt-api's screenshot route declares no media type, so it answers only a request that accepts any
	// (406 Not Acceptable otherwise): said here, not left to the client's default.
	req := cs.CoreV1().RESTClient().Get().
		AbsPath("/apis/subresources.kubevirt.io/v1/namespaces/"+ns+"/virtualmachineinstances/"+name+"/vnc/screenshot").
		SetHeader("Accept", "image/png, */*")
	if wake {
		req = req.Param("moveCursor", "true")
	}
	png, err := req.DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	return ToJPEG(png)
}

// ToJPEG re-encodes an image (KubeVirt's PNG) as a JPEG.
func ToJPEG(img []byte) ([]byte, error) {
	m, _, err := image.Decode(bytes.NewReader(img))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, m, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
