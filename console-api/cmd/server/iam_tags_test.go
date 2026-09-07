package main

import (
	"strings"
	"testing"
)

// tagsFromAnnotations must project only the openinfra.dev/tag-* annotations onto clean keys, leave
// every other annotation out, and never return a nil map (the SPA iterates it).
func TestTagsFromAnnotations(t *testing.T) {
	got := tagsFromAnnotations(map[string]string{
		"openinfra.dev/tag-team":        "payments",
		"openinfra.dev/tag-cost-center": "1234",
		"crossplane.io/composition":     "x", // not a tag
		"openinfra.dev/other":           "y", // openinfra domain but not a tag
		"kubectl.kubernetes.io/last":    "z", // not a tag
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 tags, got %d (%v)", len(got), got)
	}
	if got["team"] != "payments" || got["cost-center"] != "1234" {
		t.Errorf("unexpected tag values: %v", got)
	}

	// nil annotations → empty (non-nil) map, so it serialises as {} not null.
	if m := tagsFromAnnotations(nil); m == nil || len(m) != 0 {
		t.Errorf("nil annotations should yield an empty non-nil map, got %v", m)
	}
}

// validateTags is the AWS-shaped bound: count, key length + charset, value length + charset,
// reserved-prefix keys. Keep it in step with what the SPA lets a user type.
func TestValidateTags(t *testing.T) {
	ok := func(tags map[string]string) {
		t.Helper()
		if msg := validateTags(tags); msg != "" {
			t.Errorf("expected valid, got %q for %v", msg, tags)
		}
	}
	bad := func(want string, tags map[string]string) {
		t.Helper()
		msg := validateTags(tags)
		if msg == "" {
			t.Errorf("expected an error mentioning %q, got none for %v", want, tags)
			return
		}
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}

	ok(map[string]string{})
	ok(map[string]string{"team": "payments"})
	ok(map[string]string{"cost.center_1-2": ""})           // punctuation inside, empty value is fine
	ok(map[string]string{"a": strings.Repeat("v", 256)})   // value at the limit
	ok(map[string]string{"env": "prod value with spaces"}) // spaces are fine in a value

	bad("reserved prefix", map[string]string{"aws:foo": "x"})
	bad("reserved prefix", map[string]string{"openinfra.dev-x": "x"})
	bad("reserved prefix", map[string]string{"kubernetes.io/x": "x"}) // caught as reserved before charset
	bad("invalid", map[string]string{"has space": "x"})               // space in a key
	bad("invalid", map[string]string{"-lead": "x"})                   // must start alphanumeric
	bad("invalid", map[string]string{"trail-": "x"})                  // must end alphanumeric
	bad("too long", map[string]string{strings.Repeat("k", 60): "x"})  // key over 59
	bad("too long", map[string]string{"a": strings.Repeat("v", 257)}) // value over 256
	bad("control character", map[string]string{"a": "x\x00y"})        // NUL in a value

	// count over the AWS 50-tag limit.
	many := map[string]string{}
	for i := 0; i < maxTagsPerResource+1; i++ {
		many["k"+string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
	}
	bad("maximum", many)
}

// cleanTags trims keys and drops blank-keyed rows (an empty editor row), preserving values verbatim.
func TestCleanTags(t *testing.T) {
	got := cleanTags(map[string]string{"  team ": "payments", "": "orphan", "keep": "  spaced  "})
	if len(got) != 2 {
		t.Fatalf("expected 2 tags after cleaning, got %d (%v)", len(got), got)
	}
	if got["team"] != "payments" {
		t.Errorf("key not trimmed: %v", got)
	}
	if got["keep"] != "  spaced  " {
		t.Errorf("value should be preserved verbatim, got %q", got["keep"])
	}
}

// tagAnnotationPatch must add/update new tags, delete removed ones (null), and never touch a
// non-tag annotation (leave it out of the patch entirely).
func TestTagAnnotationPatch(t *testing.T) {
	cur := map[string]string{
		"openinfra.dev/tag-team":  "old",
		"openinfra.dev/tag-stale": "gone",
		"crossplane.io/paved":     "keep-me",
	}
	patch := tagAnnotationPatch(cur, map[string]string{"team": "new", "env": "prod"})

	if patch["openinfra.dev/tag-team"] != "new" {
		t.Errorf("expected team updated to new, got %v", patch["openinfra.dev/tag-team"])
	}
	if patch["openinfra.dev/tag-env"] != "prod" {
		t.Errorf("expected env added, got %v", patch["openinfra.dev/tag-env"])
	}
	v, ok := patch["openinfra.dev/tag-stale"]
	if !ok || v != nil {
		t.Errorf("expected stale tag deleted (null), got %v (present=%v)", v, ok)
	}
	if _, touched := patch["crossplane.io/paved"]; touched {
		t.Errorf("non-tag annotation must not appear in the patch")
	}
}
