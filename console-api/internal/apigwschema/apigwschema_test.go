package apigwschema

import (
	"encoding/json"
	"testing"
)

func mustSchema(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad schema: %v", err)
	}
	return m
}

func TestValidateSchema(t *testing.T) {
	s := mustSchema(t, `{
		"type":"object",
		"required":["name","qty"],
		"additionalProperties":false,
		"properties":{
			"name":{"type":"string","minLength":1,"maxLength":10},
			"qty":{"type":"integer","minimum":1,"maximum":100},
			"size":{"type":"string","enum":["S","M","L"]},
			"tags":{"type":"array","items":{"type":"string"}}
		}
	}`)
	cases := []struct {
		name, body string
		wantOK     bool
	}{
		{"valid", `{"name":"widget","qty":5,"size":"M","tags":["a","b"]}`, true},
		{"missing required", `{"name":"widget"}`, false},
		{"wrong type", `{"name":"widget","qty":"five"}`, false},
		{"non-integer", `{"name":"widget","qty":2.5}`, false},
		{"below minimum", `{"name":"widget","qty":0}`, false},
		{"above maximum", `{"name":"widget","qty":101}`, false},
		{"maxLength", `{"name":"this-name-is-too-long","qty":1}`, false},
		{"bad enum", `{"name":"w","qty":1,"size":"XL"}`, false},
		{"additional prop", `{"name":"w","qty":1,"extra":true}`, false},
		{"array item wrong type", `{"name":"w","qty":1,"tags":[1,2]}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v any
			_ = json.Unmarshal([]byte(c.body), &v)
			reason := ValidateSchema(s, v, "body")
			if (reason == "") != c.wantOK {
				t.Errorf("body=%s: ok=%v reason=%q", c.body, reason == "", reason)
			}
		})
	}
}

func TestValidateBody(t *testing.T) {
	s := mustSchema(t, `{"type":"object","required":["x"],"properties":{"x":{"type":"string"}}}`)
	if r := ValidateBody(s, []byte(`{"x":"ok"}`)); r != "" {
		t.Errorf("valid body should pass, got %q", r)
	}
	if r := ValidateBody(s, nil); r == "" {
		t.Errorf("empty body must fail when a schema is set")
	}
	if r := ValidateBody(s, []byte(`{bad json`)); r == "" {
		t.Errorf("invalid JSON must fail")
	}
	if r := ValidateBody(s, []byte(`{"y":1}`)); r == "" {
		t.Errorf("missing required field must fail")
	}
	if r := ValidateBody(nil, nil); r != "" {
		t.Errorf("no schema means no constraint, got %q", r)
	}
}
