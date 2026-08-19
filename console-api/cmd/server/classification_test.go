package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// A class that requests no mechanically-checkable requirements must still yield a non-nil slice.
// A nil slice marshals to JSON null, and the console maps over res.checks directly — a null there
// crashed the Data Classification page ("Cannot read properties of null (reading 'length')").
func TestEvaluateWorkloadNeverNil(t *testing.T) {
	cs := fake.NewSimpleClientset()
	got := evaluateWorkload(context.Background(), cs, workload{namespace: "default", name: "x"}, classPolicy{})
	if got == nil {
		t.Fatal("evaluateWorkload returned nil; must be a non-nil (possibly empty) slice so it marshals to []")
	}
	if b, _ := json.Marshal(got); string(b) != "[]" {
		t.Fatalf("empty checks marshalled to %s, want []", b)
	}
}

// The compliance response must always present classes/resources as arrays, never null — the console
// reads .classes.length and .resources.length without a null guard on the happy path.
func TestClassComplianceEmptyMarshalsArrays(t *testing.T) {
	// Mirror exactly what the handler builds when nothing is defined/tagged.
	b, err := json.Marshal(classComplianceResp{
		Classes:   []classSummary{},
		Resources: []classifiedResource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "null") {
		t.Fatalf("empty compliance response contains null: %s", s)
	}
	if !strings.Contains(s, `"classes":[]`) || !strings.Contains(s, `"resources":[]`) {
		t.Fatalf("want classes/resources as []: %s", s)
	}
}

// The encryptionAtRest check must PASS iff every data volume is on an encrypted StorageClass (matched by
// the `encrypted=true` parameter, not a class name), FAIL if any is not, and stay UNKNOWN (never a false
// pass) for a stateless workload or an unreadable class/PVC.
func TestEvalEncryptionAtRest(t *testing.T) {
	sp := func(s string) *string { return &s }
	cs := fake.NewSimpleClientset(
		&storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{Name: "enc"},
			Parameters: map[string]string{"encrypted": "true"},
		},
		&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "plain"}},
		&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "data-enc", Namespace: "default"},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: sp("enc")},
		},
		&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "data-plain", Namespace: "default"},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: sp("plain")},
		},
	)
	ctx := context.Background()
	cases := []struct {
		name   string
		wl     workload
		status string
	}{
		{"deployment on encrypted PVC", workload{namespace: "default", pvcClaims: []string{"data-enc"}}, "pass"},
		{"deployment on plaintext PVC", workload{namespace: "default", pvcClaims: []string{"data-plain"}}, "fail"},
		{"one encrypted, one not", workload{namespace: "default", pvcClaims: []string{"data-enc", "data-plain"}}, "fail"},
		{"statefulset template on encrypted SC", workload{namespace: "default", stsSCs: []string{"enc"}}, "pass"},
		{"statefulset template on plaintext SC", workload{namespace: "default", stsSCs: []string{"plain"}}, "fail"},
		{"stateless (no volumes)", workload{namespace: "default"}, "unknown"},
		{"missing PVC", workload{namespace: "default", pvcClaims: []string{"gone"}}, "unknown"},
		{"unknown StorageClass", workload{namespace: "default", stsSCs: []string{"nonesuch"}}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalEncryptionAtRest(ctx, cs, c.wl)
			if got.Rule != "encryptionAtRest" {
				t.Fatalf("rule = %q, want encryptionAtRest", got.Rule)
			}
			if got.Status != c.status {
				t.Fatalf("status = %q, want %q (detail: %q)", got.Status, c.status, got.Detail)
			}
		})
	}
}
