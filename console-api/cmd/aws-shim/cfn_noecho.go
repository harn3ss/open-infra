package main

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// noEchoSecrets keeps the values of NoEcho template parameters out of the plain stack and change-set
// records (ConfigMaps). They live in Secrets in the shim's own namespace, where the shim already manages
// Secrets, one per record: noecho-<record ConfigMap name>. DescribeStacks shows them as "****"; an
// update reads them back only for UsePreviousValue, and ExecuteChangeSet for the change set it runs.
type noEchoSecrets struct {
	cs kubernetes.Interface
	ns string
}

const labelNoEchoStack = "cfn.openinfra.dev/noecho-stack"

func noEchoSecretName(recordName string) string { return "noecho-" + recordName }

// put replaces the values stored for one record; an empty map removes them. A nil store keeps nothing.
func (s *noEchoSecrets) put(ctx context.Context, recordName, stack string, values map[string]string) error {
	if s == nil {
		return nil
	}
	name := noEchoSecretName(recordName)
	sc := s.cs.CoreV1().Secrets(s.ns)
	if len(values) == 0 {
		if err := sc.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	}
	data := map[string][]byte{}
	for k, v := range values {
		data[k] = []byte(v)
	}
	want := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.ns, Labels: map[string]string{
			"app.kubernetes.io/managed-by": "cfn", labelNoEchoStack: stack}},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	cur, err := sc.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = sc.Create(ctx, want, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	cur.Labels, cur.Data, cur.StringData = want.Labels, want.Data, nil
	_, err = sc.Update(ctx, cur, metav1.UpdateOptions{})
	return err
}

// get returns the values stored for one record (empty when none).
func (s *noEchoSecrets) get(ctx context.Context, recordName string) (map[string]string, error) {
	out := map[string]string{}
	if s == nil {
		return out, nil
	}
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, noEchoSecretName(recordName), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for k, v := range sec.Data {
		out[k] = string(v)
	}
	return out, nil
}

// deleteStack removes every NoEcho Secret of a stack: its record's and its change sets'. (List + delete:
// the shim's Secret Role has no deletecollection.)
func (s *noEchoSecrets) deleteStack(ctx context.Context, stack string) error {
	if s == nil {
		return nil
	}
	sc := s.cs.CoreV1().Secrets(s.ns)
	list, err := sc.List(ctx, metav1.ListOptions{LabelSelector: labelNoEchoStack + "=" + stack})
	if err != nil {
		return err
	}
	for _, it := range list.Items {
		if err := sc.Delete(ctx, it.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
