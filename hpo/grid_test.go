package main

import "testing"

func TestGridCartesian(t *testing.T) {
	params := []Param{
		{Name: "LR", Values: []string{"0.1", "0.01"}},
		{Name: "EPOCHS", Values: []string{"10", "20", "30"}},
	}
	trials := gridTrials(params, 0)
	if len(trials) != 6 {
		t.Fatalf("grid size = %d, want 6", len(trials))
	}
	// every combo present + well-formed
	seen := map[string]bool{}
	for _, tr := range trials {
		if tr["LR"] == "" || tr["EPOCHS"] == "" {
			t.Fatalf("incomplete trial %v", tr)
		}
		seen[tr["LR"]+"/"+tr["EPOCHS"]] = true
	}
	if !seen["0.1/10"] || !seen["0.01/30"] {
		t.Fatalf("missing expected combos: %v", seen)
	}
}

func TestGridTruncate(t *testing.T) {
	params := []Param{{Name: "X", Values: []string{"a", "b", "c", "d"}}}
	if got := len(gridTrials(params, 2)); got != 2 {
		t.Fatalf("truncate to 2 got %d", got)
	}
}

func TestGridSkipsEmptyParam(t *testing.T) {
	params := []Param{{Name: "X", Values: []string{"1", "2"}}, {Name: "Y", Values: nil}}
	trials := gridTrials(params, 0)
	if len(trials) != 2 {
		t.Fatalf("empty-value param should contribute nothing, got %d trials", len(trials))
	}
	if _, ok := trials[0]["Y"]; ok {
		t.Fatalf("Y should be absent")
	}
}

func TestExtractMetricLast(t *testing.T) {
	logs := "epoch 1\nOPENINFRA_METRIC=0.9\nepoch 2\nOPENINFRA_METRIC=0.12\n"
	v, ok := extractMetric(logs, "")
	if !ok || v != "0.12" {
		t.Fatalf("extract = %q ok=%v; want 0.12", v, ok)
	}
	if _, ok := extractMetric("no metric here", ""); ok {
		t.Fatal("expected no match")
	}
	// custom regex
	v, ok = extractMetric("val_auc: 0.87", `val_auc:\s*([0-9.]+)`)
	if !ok || v != "0.87" {
		t.Fatalf("custom regex = %q ok=%v", v, ok)
	}
}

func TestBetter(t *testing.T) {
	if !better("0.1", "0.2", "Minimize") {
		t.Fatal("0.1 should beat 0.2 minimizing")
	}
	if better("0.2", "0.1", "Minimize") {
		t.Fatal("0.2 should not beat 0.1 minimizing")
	}
	if !better("0.9", "0.8", "Maximize") {
		t.Fatal("0.9 should beat 0.8 maximizing")
	}
	if !better("0.5", "nan-ish", "Minimize") {
		t.Fatal("a number should beat a non-number")
	}
	if better("oops", "0.5", "Minimize") {
		t.Fatal("a non-number is never better")
	}
}
