package cfn

import (
	"strings"
	"testing"
)

func TestTranslate_S3BucketTags(t *testing.T) {
	m, f := translateS3Bucket("Data", map[string]any{"Tags": []any{
		map[string]any{"Key": "env", "Value": "dev"},
		map[string]any{"Key": "cost-center", "Value": 42},
	}}, nil)
	if len(f) != 0 {
		t.Fatalf("findings: %v", f)
	}
	tags, _ := m.Spec["tags"].(map[string]any)
	if tags["env"] != "dev" || tags["cost-center"] != "42" || len(tags) != 2 {
		t.Errorf("spec.tags = %v", m.Spec["tags"])
	}
	for _, c := range m.Caveats {
		if strings.Contains(c, "Tags dropped") {
			t.Errorf("tags are no longer dropped: %q", c)
		}
	}
}

func TestTranslate_S3BucketTags_Refusals(t *testing.T) {
	for name, tags := range map[string][]any{
		"aws: prefix":   {map[string]any{"Key": "aws:cloudformation:stack-name", "Value": "x"}},
		"empty key":     {map[string]any{"Key": "", "Value": "x"}},
		"long value":    {map[string]any{"Key": "k", "Value": strings.Repeat("v", 257)}},
		"duplicate key": {map[string]any{"Key": "k", "Value": "a"}, map[string]any{"Key": "k", "Value": "b"}},
	} {
		if _, f := translateS3Bucket("Data", map[string]any{"Tags": tags}, nil); len(f) == 0 {
			t.Errorf("%s: not refused", name)
		}
	}
	many := []any{}
	for i := 0; i < 51; i++ {
		many = append(many, map[string]any{"Key": strings.Repeat("k", i+1), "Value": "v"})
	}
	if _, f := translateS3Bucket("Data", map[string]any{"Tags": many}, nil); len(f) == 0 {
		t.Error("51 tags: not refused")
	}
}

// A tag whose value is not known at plan time is dropped with a caveat — the stack still deploys.
func TestTranslate_S3BucketTags_UnresolvedIsDropped(t *testing.T) {
	m, f := translateS3Bucket("Data", map[string]any{"Tags": []any{
		map[string]any{"Key": "owner", "Value": "<ref:SomeResource>"},
		map[string]any{"Key": "env", "Value": "dev"},
	}}, nil)
	if len(f) != 0 {
		t.Fatalf("findings: %v", f)
	}
	tags, _ := m.Spec["tags"].(map[string]any)
	if len(tags) != 1 || tags["env"] != "dev" {
		t.Errorf("spec.tags = %v, want only env", tags)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "Tags[0] dropped") {
		t.Errorf("caveats = %v, want the dropped tag named", m.Caveats)
	}
}
