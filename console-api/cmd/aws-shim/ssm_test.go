package main

import "testing"

func TestParseParamRef(t *testing.T) {
	cases := []struct {
		in      string
		base    string
		version int64
		label   string
	}{
		{"/app/prod/db/host", "/app/prod/db/host", 0, ""},
		{"/app/prod/db/host:3", "/app/prod/db/host", 3, ""},
		{"/app/prod/db/host:release", "/app/prod/db/host", 0, "release"},
		{"flat", "flat", 0, ""},
		{"flat:2", "flat", 2, ""},
		{"arn:aws:ssm:us-east-1:acct:parameter/app/prod/db/host", "/app/prod/db/host", 0, ""},
		{"arn:aws:ssm:us-east-1:acct:parameter/app/prod/db/host:5", "/app/prod/db/host", 5, ""},
		{"/a/b:0", "/a/b", 0, "0"}, // ":0" is not a valid version (>0), treated as a label
	}
	for _, c := range cases {
		base, ver, label := parseParamRef(c.in)
		if base != c.base || ver != c.version || label != c.label {
			t.Errorf("parseParamRef(%q) = (%q,%d,%q), want (%q,%d,%q)", c.in, base, ver, label, c.base, c.version, c.label)
		}
	}
}

func TestSelectorSuffix(t *testing.T) {
	cases := map[string]string{
		"/app/prod":         "",
		"/app/prod:3":       ":3",
		"/app/prod:release": ":release",
		"arn:aws:ssm:us-east-1:acct:parameter/a/b:2": ":2",
		"arn:aws:ssm:us-east-1:acct:parameter/a/b":   "",
	}
	for in, want := range cases {
		if got := selectorSuffix(in); got != want {
			t.Errorf("selectorSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":           "",
		"/":          "/",
		"/app":       "/app",
		"/app/":      "/app",
		"/app/prod/": "/app/prod",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContainsSlash(t *testing.T) {
	if !containsSlash("a/b") {
		t.Error("containsSlash(a/b) should be true")
	}
	if containsSlash("ab") {
		t.Error("containsSlash(ab) should be false")
	}
	if containsSlash("") {
		t.Error("containsSlash(empty) should be false")
	}
}

func TestVerbForSSMOp(t *testing.T) {
	gets := []string{"GetParameter", "GetParameters", "GetParametersByPath", "DescribeParameters", "GetParameterHistory", "ListTagsForResource"}
	for _, op := range gets {
		if v, ok := verbForSSMOp(op); !ok || v != "get" {
			t.Errorf("verbForSSMOp(%q) = (%q,%v), want (get,true)", op, v, ok)
		}
	}
	creates := []string{"PutParameter", "LabelParameterVersion", "AddTagsToResource", "RemoveTagsFromResource"}
	for _, op := range creates {
		if v, ok := verbForSSMOp(op); !ok || v != "create" {
			t.Errorf("verbForSSMOp(%q) = (%q,%v), want (create,true)", op, v, ok)
		}
	}
	for _, op := range []string{"DeleteParameter", "DeleteParameters"} {
		if v, ok := verbForSSMOp(op); !ok || v != "delete" {
			t.Errorf("verbForSSMOp(%q) = (%q,%v), want (delete,true)", op, v, ok)
		}
	}
	if _, ok := verbForSSMOp("NopeOp"); ok {
		t.Error("verbForSSMOp(NopeOp) should be unknown")
	}
}

func TestSSMScopeName(t *testing.T) {
	if got := ssmScopeName("GetParameter", map[string]any{"Name": "/app/a/db:3"}); got != "/app/a/db" {
		t.Errorf("scope for GetParameter = %q, want /app/a/db", got)
	}
	if got := ssmScopeName("GetParametersByPath", map[string]any{"Path": "/app/a/"}); got != "/app/a" {
		t.Errorf("scope for GetParametersByPath = %q, want /app/a", got)
	}
	if got := ssmScopeName("GetParameters", map[string]any{"Names": []any{"/a", "/b"}}); got != "" {
		t.Errorf("scope for batch GetParameters should be empty, got %q", got)
	}
	if got := ssmScopeName("AddTagsToResource", map[string]any{"ResourceType": "Parameter", "ResourceId": "/app/a"}); got != "/app/a" {
		t.Errorf("scope for AddTagsToResource = %q, want /app/a", got)
	}
}

func TestSSMBatchOp(t *testing.T) {
	if !ssmBatchOp("GetParameters") || !ssmBatchOp("DeleteParameters") {
		t.Error("GetParameters/DeleteParameters should be batch ops")
	}
	if ssmBatchOp("GetParameter") {
		t.Error("GetParameter is not a batch op")
	}
}
