package main

import (
	"reflect"
	"testing"
)

func TestParseFilterPattern(t *testing.T) {
	// plain terms → AND substring terms
	terms, err := parseFilterPattern("ERROR timeout")
	if err != nil || !reflect.DeepEqual(terms, []string{"ERROR", "timeout"}) {
		t.Errorf("plain terms: %v %v", terms, err)
	}
	// quoted phrase is one term
	terms, err = parseFilterPattern(`ERROR "connection refused"`)
	if err != nil || !reflect.DeepEqual(terms, []string{"ERROR", "connection refused"}) {
		t.Errorf("quoted: %v %v", terms, err)
	}
	// empty → no terms (match all)
	if terms, err := parseFilterPattern("   "); err != nil || terms != nil {
		t.Errorf("empty should be nil terms: %v %v", terms, err)
	}
	// unsupported syntaxes are refused, not silently ignored
	for _, bad := range []string{`{ $.level = "ERROR" }`, `[w1, w2]`, `?ERROR ?WARN`, `-INFO`, `$msg`} {
		if _, err := parseFilterPattern(bad); err == nil {
			t.Errorf("pattern %q must be refused", bad)
		}
	}
	if _, err := parseFilterPattern(`"unterminated`); err == nil {
		t.Error("unterminated quote must error")
	}
}

func TestParseCursor(t *testing.T) {
	cases := map[string]int64{"": 0, "f/42": 42, "b/7": 7, "100": 100, "garbage": 0}
	for in, want := range cases {
		if got := parseCursor(in); got != want {
			t.Errorf("parseCursor(%q)=%d want %d", in, got, want)
		}
	}
}

func TestVerbForCWLOp(t *testing.T) {
	cases := map[string]string{
		"PutLogEvents":      "create",
		"CreateLogGroup":    "create",
		"GetLogEvents":      "get",
		"FilterLogEvents":   "get",
		"DescribeLogGroups": "get",
		"DeleteLogGroup":    "delete",
		"DeleteLogStream":   "delete",
	}
	for op, want := range cases {
		if got, ok := verbForCWLOp(op); !ok || got != want {
			t.Errorf("verbForCWLOp(%q)=%q,%v want %q", op, got, ok, want)
		}
	}
	if _, ok := verbForCWLOp("StartQuery"); ok {
		t.Error("StartQuery (Logs Insights) should be unknown to the verb map (refused)")
	}
}

func TestAllowedRetentionDays(t *testing.T) {
	for _, ok := range []int{1, 7, 30, 365, 2557, 3653} {
		if !allowedRetentionDays[ok] {
			t.Errorf("%d should be an allowed retention value", ok)
		}
	}
	for _, bad := range []int{2, 15, 31, 100, 0} {
		if allowedRetentionDays[bad] {
			t.Errorf("%d should NOT be an allowed retention value", bad)
		}
	}
}

func TestToInt64(t *testing.T) {
	if toInt64(float64(1737000000000)) != 1737000000000 {
		t.Error("float64 ms timestamp")
	}
	if toInt64("42") != 42 || toInt64(nil) != 0 {
		t.Error("string / nil")
	}
}

func TestLikeEscape(t *testing.T) {
	if likeEscape("a%b_c") != `a\%b\_c` {
		t.Errorf("likeEscape wrong: %q", likeEscape("a%b_c"))
	}
}
