package main

import (
	"encoding/base64"
	"testing"
)

func TestSecretNameFromID(t *testing.T) {
	cases := map[string]string{
		"my-secret": "my-secret",
		"arn:aws:secretsmanager:us-east-1:open-infra:secret:my-secret-AbCdEf": "my-secret",
		"arn:aws:secretsmanager:us-east-1:open-infra:secret:has-hyphens-in-name-123456": "has-hyphens-in-name",
		"arn:aws:secretsmanager:us-east-1:open-infra:secret:plainname":                 "plainname",
	}
	for in, want := range cases {
		if got := secretNameFromID(in); got != want {
			t.Errorf("secretNameFromID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestArnSuffixShape(t *testing.T) {
	s := arnSuffix([]byte{1, 2, 3, 4, 5, 6})
	if len(s) != 6 {
		t.Errorf("arnSuffix length = %d, want 6", len(s))
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("arnSuffix has a non-alnum char: %q", s)
		}
	}
}

func TestValueFromBodyString(t *testing.T) {
	pt, isBin, ok := valueFromBody(map[string]any{"SecretString": "hunter2"})
	if !ok || isBin {
		t.Fatalf("SecretString should be non-binary present: ok=%v isBin=%v", ok, isBin)
	}
	// pt is base64 of the raw string; render should reproduce it.
	out := map[string]any{}
	renderValue(out, pt, isBin)
	if out["SecretString"] != "hunter2" {
		t.Errorf("round-trip SecretString wrong: %v", out["SecretString"])
	}
	if _, has := out["SecretBinary"]; has {
		t.Error("SecretString round-trip should not set SecretBinary")
	}
}

func TestValueFromBodyBinary(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff, 0xfe}
	b64 := base64.StdEncoding.EncodeToString(raw)
	pt, isBin, ok := valueFromBody(map[string]any{"SecretBinary": b64})
	if !ok || !isBin {
		t.Fatalf("SecretBinary should be binary present: ok=%v isBin=%v", ok, isBin)
	}
	if pt != b64 {
		t.Errorf("binary plaintext should pass base64 through unchanged: %q != %q", pt, b64)
	}
	out := map[string]any{}
	renderValue(out, pt, isBin)
	if out["SecretBinary"] != b64 {
		t.Errorf("binary round-trip wrong: %v", out["SecretBinary"])
	}
}

func TestValueFromBodyMissing(t *testing.T) {
	if _, _, ok := valueFromBody(map[string]any{"Description": "x"}); ok {
		t.Error("no SecretString/SecretBinary should give ok=false")
	}
}

func TestTagsRoundTrip(t *testing.T) {
	tags := tagsFromBody([]any{
		map[string]any{"Key": "env", "Value": "prod"},
		map[string]any{"Key": "team", "Value": "data"},
	})
	if tags["env"] != "prod" || tags["team"] != "data" {
		t.Errorf("tagsFromBody wrong: %v", tags)
	}
	if len(tagList(tags)) != 2 {
		t.Errorf("tagList wrong length: %v", tagList(tags))
	}
}

func TestVerbForSMOp(t *testing.T) {
	cases := map[string]string{
		"GetSecretValue": "get",
		"DescribeSecret": "get",
		"CreateSecret":   "create",
		"PutSecretValue": "create",
		"DeleteSecret":   "delete",
	}
	for op, want := range cases {
		if got, ok := verbForSMOp(op); !ok || got != want {
			t.Errorf("verbForSMOp(%q)=%q,%v want %q", op, got, ok, want)
		}
	}
	if _, ok := verbForSMOp("PutResourcePolicy"); ok {
		t.Error("PutResourcePolicy should be unknown (resource policies refused)")
	}
}
