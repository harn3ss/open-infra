package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Cost Explorer's by-namespace breakdown shows a caller its own account's namespaces, never another
// account's: the pods are read with the console's ServiceAccount across the cluster.
func TestCost_ByNamespaceIsTheCallersAccount(t *testing.T) {
	pod := func(ns string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}
	cs := fake.NewSimpleClientset(pod("team-a"), pod("team-b"))
	serve := func(scope costScopeFunc) []string {
		rec := httptest.NewRecorder()
		handleCost(cs, scope, slog.New(slog.NewTextHandler(io.Discard, nil))).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cost", nil))
		var resp costResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			t.Fatalf("cost: %d %s", rec.Code, rec.Body)
		}
		var names []string
		for _, e := range resp.ByNamespace {
			names = append(names, e.Namespace)
		}
		return names
	}
	if got := serve(nil); len(got) != 2 {
		t.Fatalf("unscoped (the operator): %v, want both namespaces", got)
	}
	teamA := func(*http.Request) func(string) bool { return func(ns string) bool { return ns == "team-a" } }
	if got := serve(teamA); len(got) != 1 || got[0] != "team-a" {
		t.Fatalf("an account holding team-a sees %v, want only team-a", got)
	}
}
