package serialconsole

// One serial console session per instance, as EC2 allows: a session holds a Lease in the aws-shim's
// namespace (serial-console-<instance id>) while it is open, renewed as it runs, so a second — through the
// SSH gateway or the console's browser terminal — is refused with EC2's
// SerialConsoleSessionLimitExceededException, and a session whose holder died frees the instance once its
// lease lapses. KubeVirt itself would let the second connection in and silently drop the first.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ErrSessionLimit: the instance has its one session open.
var ErrSessionLimit = errors.New("the instance currently has 1 active serial console session")

// SessionLimitMessage is EC2's message for ErrSessionLimit.
const SessionLimitMessage = "The instance currently has 1 active serial console session. Only 1 session is supported at a time."

const (
	leaseSeconds = 30
	renewEvery   = 10 * time.Second
)

func leaseName(instanceID string) string { return "serial-console-" + instanceID }

// Busy reports whether instanceID has a session open (its lease is held and has not lapsed).
func Busy(ctx context.Context, cs kubernetes.Interface, ns, instanceID string) (bool, error) {
	l, err := cs.CoordinationV1().Leases(ns).Get(ctx, leaseName(instanceID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return held(l, time.Now()), nil
}

func held(l *coordv1.Lease, now time.Time) bool {
	if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity == "" || l.Spec.RenewTime == nil {
		return false
	}
	d := leaseSeconds
	if l.Spec.LeaseDurationSeconds != nil {
		d = int(*l.Spec.LeaseDurationSeconds)
	}
	return now.Before(l.Spec.RenewTime.Add(time.Duration(d) * time.Second))
}

// Acquire opens instanceID's one session for holder (who holds it: "aws-shim", "console"), or answers
// ErrSessionLimit. The lease is renewed until release is called (or ctx ends), and release frees it.
func Acquire(ctx context.Context, cs kubernetes.Interface, ns, instanceID, holder string) (release func(), err error) {
	leases := cs.CoordinationV1().Leases(ns)
	id := holder + "/" + nonce()
	dur := int32(leaseSeconds)
	now := metav1.NewMicroTime(time.Now())
	want := coordv1.LeaseSpec{HolderIdentity: &id, LeaseDurationSeconds: &dur, AcquireTime: &now, RenewTime: &now}
	_, err = leases.Create(ctx, &coordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: leaseName(instanceID), Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/part-of": "open-infra", "app.kubernetes.io/component": "serial-console"}},
		Spec: want}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		l, gerr := leases.Get(ctx, leaseName(instanceID), metav1.GetOptions{})
		if gerr != nil {
			return nil, gerr
		}
		if held(l, time.Now()) {
			return nil, ErrSessionLimit
		}
		l.Spec = want // the last holder's lease lapsed: take it (a conflict means another took it first)
		if _, err = leases.Update(ctx, l, metav1.UpdateOptions{}); apierrors.IsConflict(err) {
			return nil, ErrSessionLimit
		}
	}
	if err != nil {
		return nil, err
	}
	renewCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	go func() {
		t := time.NewTicker(renewEvery)
		defer t.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-t.C:
				l, err := leases.Get(renewCtx, leaseName(instanceID), metav1.GetOptions{})
				if err != nil || l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity != id {
					continue
				}
				rt := metav1.NewMicroTime(time.Now())
				l.Spec.RenewTime = &rt
				_, _ = leases.Update(renewCtx, l, metav1.UpdateOptions{})
			}
		}
	}()
	return func() {
		stop()
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if l, err := leases.Get(bg, leaseName(instanceID), metav1.GetOptions{}); err == nil &&
			l.Spec.HolderIdentity != nil && *l.Spec.HolderIdentity == id {
			_ = leases.Delete(bg, leaseName(instanceID), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &l.ResourceVersion}})
		}
	}, nil
}

func nonce() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
