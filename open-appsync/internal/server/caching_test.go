package server

import (
	"encoding/json"
	"testing"
	"time"
)

// A resolver's caching block round-trips from config.json JSON into the lifecycle CachingConfig, and a
// zero/absent ttl means "no caching" (nil), so the executor leaves the resolver uncached.
func TestBuildCaching_FromConfig(t *testing.T) {
	var rc ResolverConfig
	if err := json.Unmarshal([]byte(`{
	  "type":"Query","field":"getNote","dataSource":"notes",
	  "caching":{"ttlSeconds":30,"keys":["arguments.id","identity.sub"]}
	}`), &rc); err != nil {
		t.Fatal(err)
	}
	c := buildCaching(rc.Caching)
	if c == nil {
		t.Fatal("a caching block with a positive ttl must produce a CachingConfig")
	}
	if c.TTL != 30*time.Second {
		t.Errorf("TTL = %v, want 30s (ttlSeconds carried as seconds)", c.TTL)
	}
	if len(c.Keys) != 2 || c.Keys[0] != "arguments.id" || c.Keys[1] != "identity.sub" {
		t.Errorf("keys = %v, want [arguments.id identity.sub]", c.Keys)
	}

	// Absent block, and a zero/negative ttl, both disable caching (nil).
	if buildCaching(nil) != nil {
		t.Error("absent caching block must be nil (disabled)")
	}
	if buildCaching(&CachingConfig{TTLSeconds: 0, Keys: []string{"arguments.id"}}) != nil {
		t.Error("ttlSeconds:0 must disable caching (nil), even with keys set")
	}
}
