// A tiny client for the platform's Iceberg REST catalog `/v1` API (polyhedron#179).
//
// The Glue doorway does NOT re-implement a metastore: Glue databases ARE Iceberg namespaces and Glue
// tables ARE Iceberg tables, so rather than keep its own copy we ask the real catalog
// (iceberg-rest.lakehouse) over its standard REST API — the same metastore Trino and DataFlow already
// use. This client is deliberately dependency-free (net/http + encoding/json), bounds every call by the
// caller's context plus its own ~10s timeout, and turns a 404 into a typed sentinel (not a generic
// error) so the doorway can tell "no such database/table" apart from a real backend fault. The catalog
// runs in-cluster with NO auth, so no credential is ever attached.
//
// v1 supports SINGLE-LEVEL namespaces only: a Glue database name is treated as a one-level Iceberg
// namespace. Iceberg's multi-level namespaces (levels joined by %1F in the path) are not addressable as
// a single Glue database name and are omitted from listings — the doorway documents this divergence.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Typed 404/409 sentinels. The doorway maps these to the right Glue exception; any OTHER non-2xx status
// becomes an icebergStatusError (surfaced as InternalServiceException), never mistaken for a clean result.
var (
	errNoSuchNamespace   = errors.New("iceberg: namespace does not exist")
	errNamespaceExists   = errors.New("iceberg: namespace already exists")
	errNamespaceNotEmpty = errors.New("iceberg: namespace is not empty")
	errNoSuchTable       = errors.New("iceberg: table does not exist")
)

// icebergClient speaks the Iceberg REST /v1 API against a single catalog base URL.
type icebergClient struct {
	base string // catalog base URL, no trailing slash (e.g. http://iceberg-rest.lakehouse.svc.cluster.local:8181)
	hc   *http.Client
}

func newIcebergClient(base string) *icebergClient {
	return &icebergClient{
		base: strings.TrimRight(base, "/"),
		hc:   &http.Client{Timeout: 10 * time.Second},
	}
}

// icebergTable captures the facts the Glue table projection needs from an Iceberg table's metadata:
// the table root location (metadata.location), the file that is the current metadata snapshot
// (metadata-location), the CURRENT schema's fields, the active partition spec's fields, and the table
// properties (for the file-format classification).
type icebergTable struct {
	Location         string         // metadata.location — the table's data/metadata root (s3://…)
	MetadataLocation string         // metadata-location — the current metadata JSON file (s3://…)
	Fields           []any          // the current schema's fields (raw Iceberg field objects)
	PartitionFields  []any          // the active partition spec's fields (raw)
	Properties       map[string]any // table properties (e.g. write.format.default)
}

// do issues a /v1 request bounded by the caller's context and the client's own timeout. The catalog is
// unauthenticated in-cluster, so no Authorization header is attached.
func (c *icebergClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.hc.Do(req)
}

// nsPath is the URL path for a single-level namespace. PathEscape keeps a name with reserved characters
// safe as one segment; multi-level namespaces (which would need a %1F-joined segment) are unsupported.
func (c *icebergClient) nsPath(ns string) string {
	return "/v1/namespaces/" + url.PathEscape(ns)
}

// listNamespaces returns the SINGLE-LEVEL namespace names the catalog holds. Multi-level namespaces
// (len(levels) != 1) are skipped — they are not addressable as a single Glue database name.
func (c *icebergClient) listNamespaces(ctx context.Context) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/namespaces", nil)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, c.statusErr("list namespaces", resp.StatusCode)
	}
	var out struct {
		Namespaces [][]string `json:"namespaces"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Namespaces))
	for _, levels := range out.Namespaces {
		if len(levels) == 1 {
			names = append(names, levels[0])
		}
	}
	return names, nil
}

// namespaceExists reports whether a namespace is present (GET /v1/namespaces/{ns}: 200 vs 404).
func (c *icebergClient) namespaceExists(ctx context.Context, ns string) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, c.nsPath(ns), nil)
	if err != nil {
		return false, err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, c.statusErr("get namespace", resp.StatusCode)
}

// createNamespace creates a single-level namespace with the given properties. A 409 is the typed
// errNamespaceExists sentinel (the caller maps it to AlreadyExistsException).
func (c *icebergClient) createNamespace(ctx context.Context, ns string, props map[string]string) error {
	if props == nil {
		props = map[string]string{}
	}
	payload, err := json.Marshal(map[string]any{
		"namespace":  []string{ns},
		"properties": props,
	})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/namespaces", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusConflict:
		return errNamespaceExists
	}
	return c.statusErr("create namespace", resp.StatusCode)
}

// deleteNamespace removes a namespace. 404 -> errNoSuchNamespace; 409 -> errNamespaceNotEmpty (Iceberg
// refuses to drop a namespace that still holds tables), so the caller can give the exact Glue reason.
func (c *icebergClient) deleteNamespace(ctx context.Context, ns string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.nsPath(ns), nil)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return errNoSuchNamespace
	case http.StatusConflict:
		return errNamespaceNotEmpty
	}
	return c.statusErr("delete namespace", resp.StatusCode)
}

// listTables returns the table names in a namespace. A 404 means the NAMESPACE is absent
// (errNoSuchNamespace), which the caller surfaces as EntityNotFoundException — distinct from an empty
// namespace (200 with no identifiers).
func (c *icebergClient) listTables(ctx context.Context, ns string) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, c.nsPath(ns)+"/tables", nil)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoSuchNamespace
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.statusErr("list tables", resp.StatusCode)
	}
	var out struct {
		Identifiers []struct {
			Namespace []string `json:"namespace"`
			Name      string   `json:"name"`
		} `json:"identifiers"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Identifiers))
	for _, id := range out.Identifiers {
		if id.Name != "" {
			names = append(names, id.Name)
		}
	}
	return names, nil
}

// getTable loads a table's metadata. The 404 case is the sentinel (nil, false, nil) for "no such
// table", so a caller iterating a namespace's tables can skip one that vanished between list and load.
func (c *icebergClient) getTable(ctx context.Context, ns, name string) (*icebergTable, bool, error) {
	resp, err := c.do(ctx, http.MethodGet, c.nsPath(ns)+"/tables/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, false, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, c.statusErr("get table", resp.StatusCode)
	}
	// Decode into a generic map so the schema/partition translation (glue_types.go) works on the same
	// shape it is unit-tested against.
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return nil, false, err
	}
	t := &icebergTable{}
	if s, _ := body["metadata-location"].(string); s != "" {
		t.MetadataLocation = s
	}
	if md, ok := body["metadata"].(map[string]any); ok {
		t.Location, _ = md["location"].(string)
		t.Properties, _ = md["properties"].(map[string]any)
		schemas, _ := md["schemas"].([]any)
		currentID, _ := intFromAny(md["current-schema-id"])
		t.Fields = currentSchemaFields(schemas, currentID)
		// Older metadata carries a single "schema" object instead of a "schemas" list.
		if len(t.Fields) == 0 {
			if sch, ok := md["schema"].(map[string]any); ok {
				if f, ok := sch["fields"].([]any); ok {
					t.Fields = f
				}
			}
		}
		specs, _ := md["partition-specs"].([]any)
		t.PartitionFields = firstPartitionSpecFields(specs)
	}
	return t, true, nil
}

// deleteTable drops a table (its metadata from the catalog). 404 -> errNoSuchTable.
func (c *icebergClient) deleteTable(ctx context.Context, ns, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.nsPath(ns)+"/tables/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return errNoSuchTable
	}
	return c.statusErr("delete table", resp.StatusCode)
}

func (c *icebergClient) statusErr(op string, status int) error {
	return &icebergStatusError{op: op, status: status}
}

// icebergStatusError is an unexpected (non-sentinel) catalog status — surfaced to the doorway as an
// InternalServiceException rather than mistaken for a clean/empty result.
type icebergStatusError struct {
	op     string
	status int
}

func (e *icebergStatusError) Error() string {
	return "iceberg catalog " + e.op + ": unexpected status " + itoa(e.status)
}
