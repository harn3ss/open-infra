package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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
