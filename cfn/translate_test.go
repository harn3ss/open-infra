package main

import (
	"strings"
	"testing"
)

func findingsText(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Reason)
		b.WriteString("\n")
	}
	return b.String()
}

func TestTranslate_KMSKey_Faithful(t *testing.T) {
	m, fs := translateKMSKey("AppKey", map[string]any{
		"Description":       "app data key",
		"EnableKeyRotation": true,
		"KeySpec":           "SYMMETRIC_DEFAULT",
		"KeyPolicy":         map[string]any{"Version": "2012-10-17"},
	})
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "EncryptionKey" || m.Name != "appkey" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	if m.Spec["description"] != "app data key" || m.Spec["rotationDays"] != 365 || m.Spec["keyType"] != "aes256-gcm96" {
		t.Fatalf("spec not faithful: %#v", m.Spec)
	}
	// KeyPolicy has no equivalent — it must be a declared caveat, not silently dropped.
	if len(m.Caveats) == 0 || !strings.Contains(m.Caveats[0], "KeyPolicy") {
		t.Fatalf("KeyPolicy should surface a caveat, caveats: %v", m.Caveats)
	}
}

func TestTranslate_KMSKey_UnknownPropertyBlocks(t *testing.T) {
	_, fs := translateKMSKey("K", map[string]any{"MultiRegion": true})
	if findingsText(fs) == "" || !strings.Contains(findingsText(fs), "MultiRegion") {
		t.Fatalf("an unhandled property must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_LambdaImage_Faithful(t *testing.T) {
	m, fs := translateLambdaFunction("Api", map[string]any{
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "registry.example/api:1"},
		"MemorySize":  float64(512),
		"Timeout":     float64(30),
		"Environment": map[string]any{"Variables": map[string]any{"LOG": "info", "TIER": "b"}},
		"Role":        "arn:aws:iam::x:role/r",
	})
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Function" || m.Spec["image"] != "registry.example/api:1" {
		t.Fatalf("bad manifest: %+v", m)
	}
	if m.Spec["memory"] != "512Mi" || m.Spec["timeout"] != 30 {
		t.Fatalf("mem/timeout not faithful: %#v", m.Spec)
	}
	env, _ := m.Spec["env"].([]any)
	if len(env) != 2 {
		t.Fatalf("env should have 2 vars, got %#v", m.Spec["env"])
	}
	if len(m.Caveats) == 0 || !strings.Contains(m.Caveats[0], "Role") {
		t.Fatalf("Lambda Role should surface a caveat: %v", m.Caveats)
	}
}

func TestTranslate_LambdaZip_Refused(t *testing.T) {
	_, fs := translateLambdaFunction("Zip", map[string]any{
		"Runtime": "python3.12",
		"Handler": "index.handler",
		"Code":    map[string]any{"S3Bucket": "b", "S3Key": "k"},
	})
	txt := findingsText(fs)
	if !strings.Contains(txt, "PackageType: Image") {
		t.Fatalf("a zip Lambda must be refused (no image to run), findings: %s", txt)
	}
}

// An env var whose value is a cross-resource attribute (no concrete open-infra value) blocks
// rather than being provisioned with a wrong value.
func TestTranslate_Lambda_CrossRefEnvBlocks(t *testing.T) {
	_, fs := translateLambdaFunction("Api", map[string]any{
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "img:1"},
		"Environment": map[string]any{"Variables": map[string]any{"BUCKET": "<ref:Assets>"}},
	})
	if !strings.Contains(findingsText(fs), "BUCKET") {
		t.Fatalf("a cross-resource env value must block, findings: %s", findingsText(fs))
	}
}
