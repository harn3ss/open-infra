package crd

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestNormalize verifies the RJSF normalization: x-kubernetes-* keys are stripped
// at every depth, and `nullable: true` becomes a union with the "null" type.
func TestNormalize(t *testing.T) {
	input := mustJSON(t, `{
		"type": "object",
		"x-kubernetes-preserve-unknown-fields": true,
		"properties": {
			"name": {
				"type": "string",
				"nullable": true,
				"x-kubernetes-validations": [{"rule": "self != ''"}]
			},
			"replicas": {
				"type": "integer",
				"nullable": false
			},
			"items": {
				"type": "array",
				"items": {
					"type": "object",
					"x-kubernetes-int-or-string": true,
					"properties": {
						"value": {"type": "string", "nullable": true}
					}
				}
			},
			"either": {
				"type": ["string", "integer"],
				"nullable": true
			}
		}
	}`)

	Normalize(input)

	want := mustJSON(t, `{
		"type": "object",
		"properties": {
			"name": {
				"type": ["string", "null"]
			},
			"replicas": {
				"type": "integer"
			},
			"items": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"value": {"type": ["string", "null"]}
					}
				}
			},
			"either": {
				"type": ["string", "integer", "null"]
			}
		}
	}`)

	if !reflect.DeepEqual(input, want) {
		gotB, _ := json.MarshalIndent(input, "", "  ")
		wantB, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("Normalize mismatch:\n got: %s\nwant: %s", gotB, wantB)
	}
}

// TestStorageSchema confirms the storage version's schema is selected over other
// served versions.
func TestStorageSchema(t *testing.T) {
	doc := &crdDocument{}
	doc.Spec.Versions = []struct {
		Name    string `json:"name"`
		Storage bool   `json:"storage"`
		Schema  struct {
			OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
		} `json:"schema"`
	}{
		{Name: "v1beta1", Storage: false},
		{Name: "v1", Storage: true},
	}
	doc.Spec.Versions[0].Schema.OpenAPIV3Schema = map[string]any{"title": "old"}
	doc.Spec.Versions[1].Schema.OpenAPIV3Schema = map[string]any{"title": "current"}

	got, err := storageSchema(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["title"] != "current" {
		t.Fatalf("expected storage version schema (title=current), got %v", got["title"])
	}
}

// TestStorageSchemaMissing confirms a CRD with no schema yields a 422 StatusError.
func TestStorageSchemaMissing(t *testing.T) {
	doc := &crdDocument{}
	_, err := storageSchema(doc)
	var se *StatusError
	if err == nil {
		t.Fatal("expected error for schema-less CRD")
	}
	if !asStatusError(err, &se) || se.Code != 422 {
		t.Fatalf("expected 422 StatusError, got %v", err)
	}
}

func asStatusError(err error, target **StatusError) bool {
	se, ok := err.(*StatusError)
	if ok {
		*target = se
	}
	return ok
}

func mustJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad test JSON: %v", err)
	}
	return m
}
