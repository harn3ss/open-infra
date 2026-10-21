package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

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
