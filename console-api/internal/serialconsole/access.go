// Package serialconsole is EC2 Serial Console's account setting and what the AWS front door and the
// console share for it: whether an account allows serial console access to its instances (EC2's
// EnableSerialConsoleAccess / DisableSerialConsoleAccess / GetSerialConsoleAccessStatus). As on AWS, an
// account starts with access off, and while it is off no instance of the account can be connected to.
//
// The setting is one ConfigMap in the aws-shim's own namespace, ec2-serial-console-access, whose data holds
// one key per account that allows access ("<account id>": "true"). Callers decide authorization first
// (the IAM action); these functions only read and write the setting.
package serialconsole

import (
	"context"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// ConfigMap is the setting's ConfigMap, in the aws-shim's namespace.
const ConfigMap = "ec2-serial-console-access"

var accountRe = regexp.MustCompile(`^[0-9]{12}$`)

// Enabled reports whether account allows serial console access. No ConfigMap, or no key for the account,
// is off (AWS's default).
func Enabled(ctx context.Context, cs kubernetes.Interface, ns, account string) (bool, error) {
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, ConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return cm.Data[account] == "true", nil
}

// SetEnabled turns account's serial console access on or off.
func SetEnabled(ctx context.Context, cs kubernetes.Interface, ns, account string, on bool) error {
	if !accountRe.MatchString(account) {
		return apierrors.NewBadRequest("not an account id: " + account)
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cms := cs.CoreV1().ConfigMaps(ns)
		cm, err := cms.Get(ctx, ConfigMap, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if !on {
				return nil
			}
			_, err = cms.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: ConfigMap, Namespace: ns,
					Labels: map[string]string{"app.kubernetes.io/part-of": "open-infra", "app.kubernetes.io/component": "aws-shim"}},
				Data: map[string]string{account: "true"},
			}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				return apierrors.NewConflict(corev1.Resource("configmaps"), ConfigMap, err) // made meanwhile: retry
			}
			return err
		}
		if err != nil {
			return err
		}
		if (cm.Data[account] == "true") == on {
			return nil
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		if on {
			cm.Data[account] = "true"
		} else {
			delete(cm.Data, account)
		}
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}
