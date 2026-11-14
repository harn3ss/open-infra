package serialconsole

import (
	"context"
	"errors"
	"testing"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// One session per instance: a second is ErrSessionLimit while the first is open, from either door;
// another instance is unaffected; release frees it.
func TestOneSessionPerInstance(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	release, err := Acquire(ctx, cs, "shim", "i-0123456789abcdef0", "aws-shim")
	if err != nil {
		t.Fatal(err)
	}
	if busy, _ := Busy(ctx, cs, "shim", "i-0123456789abcdef0"); !busy {
		t.Error("an open session reads not busy")
	}
	if _, err := Acquire(ctx, cs, "shim", "i-0123456789abcdef0", "console"); !errors.Is(err, ErrSessionLimit) {
		t.Errorf("a second session: %v, want ErrSessionLimit", err)
	}
	other, err := Acquire(ctx, cs, "shim", "i-0fedcba9876543210", "console")
	if err != nil {
		t.Fatalf("another instance: %v", err)
	}
	other()
	release()
	if busy, _ := Busy(ctx, cs, "shim", "i-0123456789abcdef0"); busy {
		t.Error("a released session reads busy")
	}
	again, err := Acquire(ctx, cs, "shim", "i-0123456789abcdef0", "console")
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}

// A holder that died without releasing frees the instance once its lease lapses.
func TestLapsedSessionIsTaken(t *testing.T) {
	ctx := context.Background()
	old := metav1.NewMicroTime(time.Now().Add(-time.Minute))
	who, dur := "aws-shim/dead", int32(leaseSeconds)
	cs := fake.NewSimpleClientset(&coordv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName("i-0123456789abcdef0"), Namespace: "shim"},
		Spec: coordv1.LeaseSpec{HolderIdentity: &who, LeaseDurationSeconds: &dur, RenewTime: &old}})
	if busy, _ := Busy(ctx, cs, "shim", "i-0123456789abcdef0"); busy {
		t.Error("a lapsed lease reads busy")
	}
	release, err := Acquire(ctx, cs, "shim", "i-0123456789abcdef0", "console")
	if err != nil {
		t.Fatalf("a lapsed session: %v", err)
	}
	release()
}
