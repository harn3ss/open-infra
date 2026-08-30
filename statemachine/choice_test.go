package main

import (
	"encoding/json"
	"testing"
)

func rule(t *testing.T, s string) ChoiceRule {
	t.Helper()
	var c ChoiceRule
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatalf("bad rule %q: %v", s, err)
	}
	return c
}

func TestChoiceOperators(t *testing.T) {
	data := mustJSON(t, `{"s":"hello","n":5,"b":true,"t":"2020-01-01T00:00:00Z","nil":null}`)
	cases := []struct {
		rule string
		want bool
	}{
		{`{"Variable":"$.s","StringEquals":"hello","Next":"X"}`, true},
		{`{"Variable":"$.s","StringEquals":"bye","Next":"X"}`, false},
		{`{"Variable":"$.s","StringLessThan":"z","Next":"X"}`, true},
		{`{"Variable":"$.n","NumericEquals":5,"Next":"X"}`, true},
		{`{"Variable":"$.n","NumericGreaterThan":3,"Next":"X"}`, true},
		{`{"Variable":"$.n","NumericLessThanEquals":5,"Next":"X"}`, true},
		{`{"Variable":"$.n","NumericGreaterThan":10,"Next":"X"}`, false},
		{`{"Variable":"$.b","BooleanEquals":true,"Next":"X"}`, true},
		{`{"Variable":"$.missing","IsPresent":false,"Next":"X"}`, true},
		{`{"Variable":"$.s","IsPresent":true,"Next":"X"}`, true},
		{`{"Variable":"$.nil","IsNull":true,"Next":"X"}`, true},
		{`{"Variable":"$.s","IsString":true,"Next":"X"}`, true},
		{`{"Variable":"$.n","IsNumeric":true,"Next":"X"}`, true},
		{`{"Variable":"$.t","IsTimestamp":true,"Next":"X"}`, true},
		{`{"Variable":"$.t","TimestampGreaterThan":"2019-01-01T00:00:00Z","Next":"X"}`, true},
		{`{"Variable":"$.missing","NumericEquals":5,"Next":"X"}`, false},
	}
	for _, c := range cases {
		got, err := rule(t, c.rule).eval(data, nil)
		if err != nil {
			t.Fatalf("eval %s: %v", c.rule, err)
		}
		if got != c.want {
			t.Fatalf("eval %s = %v want %v", c.rule, got, c.want)
		}
	}
}

func TestChoiceComposition(t *testing.T) {
	data := mustJSON(t, `{"n":5,"s":"go"}`)
	and := `{"And":[{"Variable":"$.n","NumericGreaterThan":1},{"Variable":"$.s","StringEquals":"go"}],"Next":"X"}`
	if ok, _ := rule(t, and).eval(data, nil); !ok {
		t.Fatal("And should match")
	}
	or := `{"Or":[{"Variable":"$.n","NumericEquals":999},{"Variable":"$.s","StringEquals":"go"}],"Next":"X"}`
	if ok, _ := rule(t, or).eval(data, nil); !ok {
		t.Fatal("Or should match")
	}
	not := `{"Not":{"Variable":"$.s","StringEquals":"stop"},"Next":"X"}`
	if ok, _ := rule(t, not).eval(data, nil); !ok {
		t.Fatal("Not should match")
	}
}

func TestChoicePathVariant(t *testing.T) {
	data := mustJSON(t, `{"a":5,"b":5,"c":9}`)
	if ok, _ := rule(t, `{"Variable":"$.a","NumericEqualsPath":"$.b","Next":"X"}`).eval(data, nil); !ok {
		t.Fatal("a should equal b via NumericEqualsPath")
	}
	if ok, _ := rule(t, `{"Variable":"$.a","NumericEqualsPath":"$.c","Next":"X"}`).eval(data, nil); ok {
		t.Fatal("a should not equal c")
	}
}
