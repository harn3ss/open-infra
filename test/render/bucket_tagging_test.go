package render

import (
	"strings"
	"testing"
)

func bucketCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{
		"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"name": "data-x7k2p", "creationTimestamp": xrCreated,
				"labels": map[string]any{"crossplane.io/claim-name": "data", "crossplane.io/claim-namespace": "team-a"},
			},
		}},
		"resources": map[string]any{},
	}}
}

// Bucket tags reach MinIO's bucket tagging as a TagSet document — passed as an env value, never inside
// the script — so GetBucketTagging returns them. A claim with no tags renders exactly as before (no env,
// no step, the same Job name), so adding the field re-runs no existing Job.
func TestBucketComposition_Tags(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	plain := render(t, tmpl, bucketCtx(map[string]any{"versioning": true}))
	if strings.Contains(plain, "BUCKET_TAGGING") || strings.Contains(plain, "put-bucket-tagging") {
		t.Errorf("a claim with no tags must render no tagging:\n%s", grepCtx(plain, "TAGGING"))
	}
	tagged := render(t, tmpl, bucketCtx(map[string]any{"versioning": true,
		"tags": map[string]any{"team": "a", "env": "dev", "note": `it's "quoted"; $(id)`}}))
	want := `{"TagSet":[{"Key":"env","Value":"dev"},{"Key":"note","Value":"it's \"quoted\"; $(id)"},{"Key":"team","Value":"a"}]}`
	docs, err := parseYAMLDocs(tagged)
	if err != nil {
		t.Fatalf("tagged render does not parse: %v", err)
	}
	var env string
	var scripts []string
	for _, d := range docs {
		walkEnv(d, func(name, value string) {
			if name == "BUCKET_TAGGING" {
				env = value
			}
		})
		scriptTexts(d, "bucket", &scripts)
	}
	if env != want {
		t.Errorf("BUCKET_TAGGING = %q, want %q", env, want)
	}
	joined := strings.Join(scripts, "\n")
	if !strings.Contains(joined, `put-bucket-tagging --bucket data --tagging "$BUCKET_TAGGING"`) {
		t.Errorf("the setup does not apply the tags:\n%s", grepCtx(tagged, "tagging"))
	}
	if strings.Contains(joined, "quoted") {
		t.Error("a tag value reached the script text")
	}
	if bucketJobName(plain) == bucketJobName(tagged) {
		t.Error("adding tags must mint a new setup Job (the tags are in its hash)")
	}
}

func bucketJobName(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "-bucket-") && strings.Contains(ln, "namespace: minio") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// walkEnv calls fn for every container env entry (name, literal value) in a parsed document.
func walkEnv(v any, fn func(name, value string)) {
	switch t := v.(type) {
	case map[string]any:
		if env, ok := t["env"].([]any); ok {
			for _, e := range env {
				if m, ok := e.(map[string]any); ok {
					n, _ := m["name"].(string)
					val, _ := m["value"].(string)
					fn(n, val)
				}
			}
		}
		for _, c := range t {
			walkEnv(c, fn)
		}
	case []any:
		for _, c := range t {
			walkEnv(c, fn)
		}
	}
}
