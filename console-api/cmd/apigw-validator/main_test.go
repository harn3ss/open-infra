package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func schema(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad schema: %v", err)
	}
	return m
}

func TestValidateSchema(t *testing.T) {
	s := schema(t, `{
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
			reason := validateSchema(s, v, "body")
			if (reason == "") != c.wantOK {
				t.Errorf("body=%s: ok=%v reason=%q", c.body, reason == "", reason)
			}
		})
	}
}

func TestValidateRequest_Params(t *testing.T) {
	r := &route{RequiredHeaders: []string{"x-api-key"}, RequiredQuery: []string{"v"}}

	h := http.Header{}
	if reason := validateRequest(r, h, url.Values{"v": {"1"}}, nil); reason == "" {
		t.Errorf("missing required header must fail")
	}
	h.Set("x-api-key", "k")
	if reason := validateRequest(r, h, url.Values{}, nil); reason == "" {
		t.Errorf("missing required query must fail")
	}
	if reason := validateRequest(r, h, url.Values{"v": {"1"}}, nil); reason != "" {
		t.Errorf("all params present must pass, got %q", reason)
	}
}

func TestMatch_LongestPrefix(t *testing.T) {
	c := &config{Routes: []route{
		{Methods: []string{"POST"}, PathPrefix: "/orders", Upstream: "http://a"},
		{Methods: []string{"POST"}, PathPrefix: "/orders/bulk", Upstream: "http://b"},
	}}
	// loadConfig sorts; emulate by sorting here via the same rule.
	c2, _ := sortedForTest(c)
	if r := c2.match("POST", "/orders/bulk/x"); r == nil || r.Upstream != "http://b" {
		t.Errorf("longest-prefix route should win: %+v", r)
	}
	if r := c2.match("GET", "/orders"); r != nil {
		t.Errorf("method mismatch must not match")
	}
}

// sortedForTest re-applies loadConfig's ordering without touching disk.
func sortedForTest(c *config) (*config, error) {
	b, _ := json.Marshal(c)
	var out config
	_ = json.Unmarshal(b, &out)
	// reuse the production sort by marshalling through loadConfig's logic:
	sortRoutesLongestFirst(&out)
	return &out, nil
}
