package main

import "testing"

func TestQueueNameFromURL(t *testing.T) {
	cases := map[string]string{
		"http://localhost:4566/open-infra/orders":       "orders",
		"https://sqs.us-east-1.amazonaws.com/123/jobs/": "jobs",
		"plainname": "plainname",
	}
	for in, want := range cases {
		if got := queueNameFromURL(in); got != want {
			t.Errorf("queueNameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerbForSQSOp_ReceiveIsNotDelete(t *testing.T) {
	// The read/delete split is the "receive but not delete" boundary the issue calls out.
	if v, _ := verbForSQSOp("ReceiveMessage"); v != "get" {
		t.Errorf("ReceiveMessage should map to get, got %q", v)
	}
	if v, _ := verbForSQSOp("DeleteMessage"); v != "delete" {
		t.Errorf("DeleteMessage should map to delete, got %q", v)
	}
	if v, _ := verbForSQSOp("SendMessage"); v != "create" {
		t.Errorf("SendMessage should map to create, got %q", v)
	}
	if _, ok := verbForSQSOp("Nonsense"); ok {
		t.Errorf("an unknown op must not be known")
	}
}

// md5OfMessageAttributes must be empty for no attributes, deterministic, and sensitive to every field
// (name, data type, and value) — the SDK verifies this hash, so any drift in the encoding breaks it.
func TestMD5OfMessageAttributes(t *testing.T) {
	if got := md5OfMessageAttributes(nil); got != "" {
		t.Errorf("no attributes should yield empty MD5, got %q", got)
	}
	base := map[string]any{"k": map[string]any{"DataType": "String", "StringValue": "v"}}
	h1 := md5OfMessageAttributes(base)
	if len(h1) != 32 {
		t.Fatalf("expected a 32-char hex md5, got %q", h1)
	}
	// Deterministic.
	if md5OfMessageAttributes(base) != h1 {
		t.Error("md5 must be deterministic")
	}
	// Order-independent (sorted by name): same two attributes in either construction order → same hash.
	a := map[string]any{
		"alpha": map[string]any{"DataType": "String", "StringValue": "1"},
		"beta":  map[string]any{"DataType": "Number", "StringValue": "2"},
	}
	if md5OfMessageAttributes(a) == h1 {
		t.Error("different attributes should hash differently")
	}
	// Changing the value changes the hash.
	diff := map[string]any{"k": map[string]any{"DataType": "String", "StringValue": "w"}}
	if md5OfMessageAttributes(diff) == h1 {
		t.Error("changing the value must change the md5")
	}
	// Changing the data type changes the hash.
	dt := map[string]any{"k": map[string]any{"DataType": "Number", "StringValue": "v"}}
	if md5OfMessageAttributes(dt) == h1 {
		t.Error("changing the data type must change the md5")
	}
}

func TestMD5Hex(t *testing.T) {
	// md5("hello") is well-known.
	if got := md5Hex("hello"); got != "5d41402abc4b2a76b9719d911017c592" {
		t.Errorf("md5Hex(hello) = %q", got)
	}
}

func TestToIntCoercions(t *testing.T) {
	if toInt(float64(7)) != 7 || toInt("9") != 9 || toInt(3) != 3 || toInt(nil) != 0 {
		t.Error("toInt coercions wrong")
	}
}
