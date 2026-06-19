// Package crd fetches a CustomResourceDefinition's OpenAPI v3 schema and
// normalizes it into a JSON Schema that react-jsonschema-form (RJSF) can render.
//
// Kubernetes CRD schemas are "structural schemas": close to JSON Schema draft-04
// but sprinkled with `x-kubernetes-*` vendor extensions and using `nullable:true`
// rather than a `"null"` type. RJSF wants plain draft-07, so we:
//
//   - recursively strip every `x-kubernetes-*` key,
//   - rewrite `nullable: true` into the draft-07 idiom (add "null" to `type`),
//   - stamp the top level with `$schema: draft-07`.
//
// The CRD is read through the same authenticated transport as everything else,
// so the ServiceAccount's RBAC (it needs get on customresourcedefinitions)
// governs access.
package crd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// draft07 is the JSON Schema dialect RJSF targets.
const draft07 = "http://json-schema.org/draft-07/schema#"

// Fetcher retrieves and normalizes CRD schemas. Construct it with New.
type Fetcher struct {
	host      *url.URL
	transport http.RoundTripper
}

// New returns a Fetcher that reads CRDs from the API server at host using
// transport for authentication.
func New(host *url.URL, transport http.RoundTripper) *Fetcher {
	return &Fetcher{host: host, transport: transport}
}

// crdDocument is the minimal slice of a CustomResourceDefinition we care about:
// the per-version schemas and which version is the storage version.
type crdDocument struct {
	Spec struct {
		Versions []struct {
			Name    string `json:"name"`
			Storage bool   `json:"storage"`
			Schema  struct {
				// OpenAPIV3Schema is kept as a generic map so we can walk and
				// rewrite it without modeling the entire (recursive) schema type.
				OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
			} `json:"schema"`
		} `json:"versions"`
	} `json:"spec"`
}

// Schema fetches the CRD named `name` (e.g. "applications.openinfra.dev"),
// extracts the storage version's openAPIV3Schema, normalizes it for RJSF, and
// returns it as marshaled JSON.
func (f *Fetcher) Schema(ctx context.Context, name string) ([]byte, error) {
	doc, err := f.fetch(ctx, name)
	if err != nil {
		return nil, err
	}

	schema, err := storageSchema(doc)
	if err != nil {
		return nil, err
	}

	Normalize(schema)
	schema["$schema"] = draft07

	out, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("marshaling normalized schema: %w", err)
	}
	return out, nil
}

// fetch GETs the CRD as JSON via the authenticated transport.
func (f *Fetcher) fetch(ctx context.Context, name string) (*crdDocument, error) {
	target := *f.host
	target.Path = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + url.PathEscape(name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building CRD request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("fetching CRD %q: %w", name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, fmt.Errorf("reading CRD response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// fallthrough to decode below
	case http.StatusNotFound:
		return nil, &StatusError{Code: http.StatusNotFound, Msg: fmt.Sprintf("CRD %q not found", name)}
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, &StatusError{Code: resp.StatusCode, Msg: "not authorized to read CustomResourceDefinitions"}
	default:
		return nil, &StatusError{Code: http.StatusBadGateway,
			Msg: fmt.Sprintf("API server returned %d fetching CRD %q", resp.StatusCode, name)}
	}

	var doc crdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding CRD %q: %w", name, err)
	}
	return &doc, nil
}

// storageSchema returns the openAPIV3Schema of the CRD's storage version.
// Exactly one version is marked storage:true; we fall back to the first version
// that carries a schema if (unusually) none is flagged.
func storageSchema(doc *crdDocument) (map[string]any, error) {
	var fallback map[string]any
	for _, v := range doc.Spec.Versions {
		if v.Schema.OpenAPIV3Schema == nil {
			continue
		}
		if v.Storage {
			return cloneMap(v.Schema.OpenAPIV3Schema), nil
		}
		if fallback == nil {
			fallback = v.Schema.OpenAPIV3Schema
		}
	}
	if fallback != nil {
		return cloneMap(fallback), nil
	}
	return nil, &StatusError{Code: http.StatusUnprocessableEntity,
		Msg: "CRD has no openAPIV3Schema on any version"}
}

// Normalize rewrites a CRD OpenAPI v3 schema in place into RJSF-friendly
// draft-07: it strips x-kubernetes-* extensions everywhere and converts
// `nullable: true` into a union with the "null" type.
//
// Exported so it can be unit-tested independently of a live API server.
func Normalize(node any) {
	switch n := node.(type) {
	case map[string]any:
		// Remove vendor extensions at this level.
		for k := range n {
			if isVendorExtension(k) {
				delete(n, k)
			}
		}

		// Convert nullable -> union type. RJSF/draft-07 expresses "may be null"
		// as a type array that includes "null"; the OpenAPI `nullable` keyword is
		// not understood by draft-07 validators.
		if nullable, ok := n["nullable"].(bool); ok {
			delete(n, "nullable")
			if nullable {
				addNullType(n)
			}
		}

		// Recurse into all remaining values (properties, items, allOf, etc.).
		for _, v := range n {
			Normalize(v)
		}

	case []any:
		for _, v := range n {
			Normalize(v)
		}
	}
}

// addNullType folds "null" into a schema's `type`, turning e.g.
// {"type":"string"} into {"type":["string","null"]}. If no type is present we
// leave it alone (an untyped schema already permits null).
func addNullType(n map[string]any) {
	switch t := n["type"].(type) {
	case string:
		if t != "null" {
			n["type"] = []any{t, "null"}
		}
	case []any:
		for _, existing := range t {
			if s, ok := existing.(string); ok && s == "null" {
				return // already includes null
			}
		}
		n["type"] = append(t, "null")
	}
}

// isVendorExtension reports whether a schema key is a Kubernetes vendor
// extension that draft-07 validators / RJSF should not see.
func isVendorExtension(key string) bool {
	const prefix = "x-kubernetes-"
	return len(key) >= len(prefix) && key[:len(prefix)] == prefix
}

// cloneMap deep-copies a decoded JSON map so Normalize never mutates a caller's
// shared structure. JSON round-trip is the simplest correct deep copy here.
func cloneMap(m map[string]any) map[string]any {
	b, err := json.Marshal(m)
	if err != nil {
		return m
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return m
	}
	return out
}

// StatusError carries an HTTP status code so the handler can map fetch failures
// to the right response code.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }
