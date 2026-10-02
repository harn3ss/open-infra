package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// --- fixtures ---

func newGlueTestHandler(cs kubernetes.Interface, catalogURL string) *glueHandler {
	return newGlueHandler(cs, "default", "open-infra", "us-east-1", catalogURL, discardLogger())
}

func glueClaims() iam.Claims {
	return iam.Claims{Sub: "gail", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
}

func glueRequest(target, body string) *http.Request {
	req := httptest.NewRequest("POST", "http://glue/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", glueTargetPrefix+"."+target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	return req
}

func glueErrorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	return body.Message
}

// fakeIceberg is a minimal in-memory Iceberg REST /v1 catalog for the doorway tests: namespaces, table
// listings, and per-table metadata JSON. It counts hits so a test can prove the authz gate denies BEFORE
// any backend call.
type fakeIceberg struct {
	srv  *httptest.Server
	mu   sync.Mutex
	ns   map[string]bool              // namespace name -> present
	tbls map[string]map[string]string // namespace -> table name -> metadata JSON body
	hits int
}

func newFakeIceberg() *fakeIceberg {
	fi := &fakeIceberg{ns: map[string]bool{}, tbls: map[string]map[string]string{}}
	fi.srv = httptest.NewServer(http.HandlerFunc(fi.handle))
	return fi
}

func (fi *fakeIceberg) addNamespace(name string) { fi.ns[name] = true }

func (fi *fakeIceberg) addTable(ns, name, metadata string) {
	fi.ns[ns] = true
	if fi.tbls[ns] == nil {
		fi.tbls[ns] = map[string]string{}
	}
	fi.tbls[ns][name] = metadata
}

func (fi *fakeIceberg) hitCount() int {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.hits
}

func (fi *fakeIceberg) handle(w http.ResponseWriter, r *http.Request) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.hits++
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/v1/config":
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodGet && p == "/v1/namespaces":
		levels := [][]string{}
		for n := range fi.ns {
			levels = append(levels, []string{n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"namespaces": levels, "next-page-token": nil})
	case r.Method == http.MethodPost && p == "/v1/namespaces":
		var in struct {
			Namespace []string `json:"namespace"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		name := strings.Join(in.Namespace, "\x1f")
		if fi.ns[name] {
			w.WriteHeader(http.StatusConflict)
			return
		}
		fi.ns[name] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"namespace": in.Namespace, "properties": map[string]any{}})
	case strings.HasPrefix(p, "/v1/namespaces/"):
		fi.handleNamespaceScoped(w, r, strings.TrimPrefix(p, "/v1/namespaces/"))
	default:
		http.NotFound(w, r)
	}
}

func (fi *fakeIceberg) handleNamespaceScoped(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.SplitN(rest, "/", 3)
	ns, _ := url.PathUnescape(parts[0])
	switch {
	case len(parts) == 1: // /v1/namespaces/{ns}
		switch r.Method {
		case http.MethodGet:
			if fi.ns[ns] {
				_ = json.NewEncoder(w).Encode(map[string]any{"namespace": []string{ns}, "properties": map[string]any{}})
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodDelete:
			if !fi.ns[ns] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if len(fi.tbls[ns]) > 0 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			delete(fi.ns, ns)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	case len(parts) == 2 && parts[1] == "tables": // list tables
		if !fi.ns[ns] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ids := []map[string]any{}
		for name := range fi.tbls[ns] {
			ids = append(ids, map[string]any{"namespace": []string{ns}, "name": name})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"identifiers": ids, "next-page-token": nil})
	case len(parts) == 3 && parts[1] == "tables": // get/delete a table
		tbl, _ := url.PathUnescape(parts[2])
		switch r.Method {
		case http.MethodGet:
			md, ok := fi.tbls[ns][tbl]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(md))
		case http.MethodDelete:
			if _, ok := fi.tbls[ns][tbl]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(fi.tbls[ns], tbl)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

// a realistic Iceberg table metadata response (as the /v1 get-table endpoint returns it).
const salesMetadata = `{
  "metadata-location":"s3://warehouse/demo/sales/metadata/00001-abc.metadata.json",
  "metadata":{
    "location":"s3://warehouse/demo/sales",
    "current-schema-id":0,
    "schemas":[{"schema-id":0,"fields":[
      {"id":1,"name":"region","required":false,"type":"string","doc":"the sales region"},
      {"id":2,"name":"amount","type":"int"},
      {"id":3,"name":"ts","type":"timestamp"}
    ]}],
    "partition-specs":[{"spec-id":0,"fields":[
      {"source-id":1,"field-id":1000,"transform":"identity","name":"region"}
    ]}],
    "properties":{"write.format.default":"PARQUET"}
  }
}`

// --- glue_types.go: Iceberg -> Glue type translation ---

func TestGlue_TypeMapping(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"boolean", "boolean", "boolean"},
		{"int", "int", "int"},
		{"long", "long", "bigint"},
		{"float", "float", "float"},
		{"double", "double", "double"},
		{"date", "date", "date"},
		{"time", "time", "string"},
		{"timestamp", "timestamp", "timestamp"},
		{"timestamptz", "timestamptz", "timestamp"},
		{"string", "string", "string"},
		{"uuid", "uuid", "string"},
		{"binary", "binary", "binary"},
		{"fixed", "fixed[16]", "binary"},
		{"decimal", "decimal(10,2)", "decimal(10,2)"},
		{"unknown", "someweirdtype", "someweirdtype"},
		{
			"struct",
			map[string]any{"type": "struct", "fields": []any{
				map[string]any{"id": float64(1), "name": "a", "type": "int"},
				map[string]any{"id": float64(2), "name": "b", "type": "string"},
			}},
			"struct<a:int,b:string>",
		},
		{"list", map[string]any{"type": "list", "element": "long"}, "array<bigint>"},
		{"map", map[string]any{"type": "map", "key": "string", "value": "double"}, "map<string,double>"},
		{
			"list-of-struct",
			map[string]any{"type": "list", "element": map[string]any{"type": "struct", "fields": []any{
				map[string]any{"name": "x", "type": "int"},
			}}},
			"array<struct<x:int>>",
		},
		{
			"map-of-decimal",
			map[string]any{"type": "map", "key": "string", "value": "decimal(5,0)"},
			"map<string,decimal(5,0)>",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := glueType(c.in); got != c.want {
				t.Fatalf("glueType(%v) = %q want %q", c.in, got, c.want)
			}
		})
	}
}

func TestGlue_SchemaToColumns(t *testing.T) {
	fields := []any{
		map[string]any{"id": float64(1), "name": "region", "type": "string", "doc": "region doc"},
		map[string]any{"id": float64(2), "name": "amount", "type": "int"},
		map[string]any{"id": float64(3), "name": "price", "type": "decimal(10,2)"},
	}
	cols := icebergColumns(fields)
	if len(cols) != 3 {
		t.Fatalf("columns len = %d want 3", len(cols))
	}
	if cols[0]["Name"] != "region" || cols[0]["Type"] != "string" || cols[0]["Comment"] != "region doc" {
		t.Fatalf("col[0] = %+v", cols[0])
	}
	if cols[1]["Name"] != "amount" || cols[1]["Type"] != "int" {
		t.Fatalf("col[1] = %+v", cols[1])
	}
	if _, hasComment := cols[1]["Comment"]; hasComment {
		t.Fatalf("col[1] should have no Comment; got %+v", cols[1])
	}
	if cols[2]["Type"] != "decimal(10,2)" {
		t.Fatalf("col[2] type = %v want decimal(10,2)", cols[2]["Type"])
	}
}

func TestGlue_CurrentSchemaSelection(t *testing.T) {
	schemas := []any{
		map[string]any{"schema-id": float64(0), "fields": []any{map[string]any{"name": "old", "type": "int"}}},
		map[string]any{"schema-id": float64(2), "fields": []any{map[string]any{"name": "new", "type": "string"}}},
	}
	fields := currentSchemaFields(schemas, 2)
	cols := icebergColumns(fields)
	if len(cols) != 1 || cols[0]["Name"] != "new" {
		t.Fatalf("current schema fields = %+v want the schema-id=2 field 'new'", cols)
	}
	// no matching id -> falls back to the first schema.
	fb := icebergColumns(currentSchemaFields(schemas, 99))
	if len(fb) != 1 || fb[0]["Name"] != "old" {
		t.Fatalf("fallback fields = %+v want the first schema's field 'old'", fb)
	}
}

// --- authz gate ---

// The coarse authorization gate denies before any backend call when the caller cannot act — the same
// impersonated SubjectAccessReview every front door funnels through (mirrors TestECR_AuthzGateDenies).
func TestGlue_AuthzGateDenies(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	h := newGlueTestHandler(csWithSAR(false), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetDatabase", `{"Name":"demo"}`),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-deny")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
	if fi.hitCount() != 0 {
		t.Fatalf("backend was called %d times; the gate must deny before any catalog call", fi.hitCount())
	}
}

// --- databases ---

func TestGlue_GetDatabases(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addNamespace("demo")
	fi.addNamespace("analytics")
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetDatabases", `{}`), glueClaims(), "req-dbs")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		DatabaseList []struct {
			Name      string `json:"Name"`
			CatalogID string `json:"CatalogId"`
		} `json:"DatabaseList"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	got := map[string]string{}
	for _, d := range resp.DatabaseList {
		got[d.Name] = d.CatalogID
	}
	if len(got) != 2 || got["demo"] != "open-infra" || got["analytics"] != "open-infra" {
		t.Fatalf("DatabaseList = %+v want demo+analytics with CatalogId open-infra", resp.DatabaseList)
	}
}

func TestGlue_GetDatabaseNotFound(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetDatabase", `{"Name":"ghost"}`), glueClaims(), "req-404")
	assertECSErrorType(t, w, http.StatusBadRequest, "EntityNotFoundException")
}

func TestGlue_CreateDatabase(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)

	w := httptest.NewRecorder()
	h.serve(w, glueRequest("CreateDatabase", `{"DatabaseInput":{"Name":"sales","Description":"the sales db"}}`), glueClaims(), "req-cd")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	fi.mu.Lock()
	created := fi.ns["sales"]
	fi.mu.Unlock()
	if !created {
		t.Fatalf("CreateDatabase did not reach the catalog (namespace 'sales' absent)")
	}

	// a second create of the same name -> AlreadyExistsException (the fake returns 409).
	w2 := httptest.NewRecorder()
	h.serve(w2, glueRequest("CreateDatabase", `{"DatabaseInput":{"Name":"sales"}}`), glueClaims(), "req-cd2")
	assertECSErrorType(t, w2, http.StatusBadRequest, "AlreadyExistsException")
}

func TestGlue_CreateDatabaseRejectsMissingName(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("CreateDatabase", `{"DatabaseInput":{}}`), glueClaims(), "req-noname")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidInputException")
}

func TestGlue_DeleteDatabaseNotEmpty(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addTable("demo", "sales", salesMetadata)
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("DeleteDatabase", `{"Name":"demo"}`), glueClaims(), "req-dd")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidInputException")
	if msg := glueErrorMessage(t, w); !strings.Contains(msg, "not empty") {
		t.Fatalf("delete-non-empty message = %q want it to mention 'not empty'", msg)
	}
}

// --- tables ---

func TestGlue_GetTables(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addTable("demo", "sales", salesMetadata)
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetTables", `{"DatabaseName":"demo"}`), glueClaims(), "req-gts")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		TableList []glueTableJSON `json:"TableList"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.TableList) != 1 {
		t.Fatalf("TableList len = %d want 1", len(resp.TableList))
	}
	assertSalesTable(t, resp.TableList[0])
}

func TestGlue_GetTable(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addTable("demo", "sales", salesMetadata)
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetTable", `{"DatabaseName":"demo","Name":"sales"}`), glueClaims(), "req-gt")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Table glueTableJSON `json:"Table"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	assertSalesTable(t, resp.Table)
}

func TestGlue_GetTableNotFound(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addNamespace("demo")
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetTable", `{"DatabaseName":"demo","Name":"ghost"}`), glueClaims(), "req-gt404")
	assertECSErrorType(t, w, http.StatusBadRequest, "EntityNotFoundException")
}

func TestGlue_GetTablesOnMissingDatabase(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetTables", `{"DatabaseName":"ghost"}`), glueClaims(), "req-gtsx")
	assertECSErrorType(t, w, http.StatusBadRequest, "EntityNotFoundException")
}

func TestGlue_GetPartitionsEmpty(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addTable("demo", "sales", salesMetadata)
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetPartitions", `{"DatabaseName":"demo","TableName":"sales"}`), glueClaims(), "req-gp")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Partitions []any `json:"Partitions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Partitions) != 0 {
		t.Fatalf("Partitions = %+v want [] (Iceberg manages partitions internally)", resp.Partitions)
	}
}

func TestGlue_DeleteTable(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addTable("demo", "sales", salesMetadata)
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("DeleteTable", `{"DatabaseName":"demo","Name":"sales"}`), glueClaims(), "req-dt")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	fi.mu.Lock()
	_, stillThere := fi.tbls["demo"]["sales"]
	fi.mu.Unlock()
	if stillThere {
		t.Fatalf("table should be gone after DeleteTable")
	}
	// deleting it again -> EntityNotFoundException.
	w2 := httptest.NewRecorder()
	h.serve(w2, glueRequest("DeleteTable", `{"DatabaseName":"demo","Name":"sales"}`), glueClaims(), "req-dt2")
	assertECSErrorType(t, w2, http.StatusBadRequest, "EntityNotFoundException")
}

// --- refusals + unknown ops ---

// A deliberately-refused op returns InvalidInputException naming the op (honest, never faked).
func TestGlue_RefusedCreateTable(t *testing.T) {
	h := newGlueTestHandler(csWithSAR(true), "http://unused")
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("CreateTable", `{"DatabaseName":"demo","TableInput":{"Name":"t"}}`), glueClaims(), "req-ct")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidInputException")
	if msg := glueErrorMessage(t, w); !strings.Contains(msg, "CreateTable") {
		t.Fatalf("refusal message should name the op; got %q", msg)
	}
}

func TestGlue_RefusedCrawler(t *testing.T) {
	h := newGlueTestHandler(csWithSAR(true), "http://unused")
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("CreateCrawler", `{"Name":"c"}`), glueClaims(), "req-cc")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidInputException")
	if msg := glueErrorMessage(t, w); !strings.Contains(msg, "crawler") {
		t.Fatalf("crawler refusal message should mention crawlers; got %q", msg)
	}
}

// An unknown op is refused as not-implemented, never faked.
func TestGlue_UnknownOp(t *testing.T) {
	h := newGlueTestHandler(csWithSAR(true), "http://unused")
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetFloob", `{}`), glueClaims(), "req-unk")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidInputException")
	if msg := glueErrorMessage(t, w); !strings.Contains(msg, "not implemented") {
		t.Fatalf("unknown-op message should say not implemented; got %q", msg)
	}
}

// --- helpers for the table-object assertions ---

type glueTableJSON struct {
	Name              string `json:"Name"`
	DatabaseName      string `json:"DatabaseName"`
	CatalogID         string `json:"CatalogId"`
	TableType         string `json:"TableType"`
	StorageDescriptor struct {
		Columns []struct {
			Name    string `json:"Name"`
			Type    string `json:"Type"`
			Comment string `json:"Comment"`
		} `json:"Columns"`
		Location string `json:"Location"`
	} `json:"StorageDescriptor"`
	PartitionKeys []struct {
		Name string `json:"Name"`
		Type string `json:"Type"`
	} `json:"PartitionKeys"`
	Parameters map[string]string `json:"Parameters"`
}

func assertSalesTable(t *testing.T, tbl glueTableJSON) {
	t.Helper()
	if tbl.Name != "sales" || tbl.DatabaseName != "demo" || tbl.CatalogID != "open-infra" {
		t.Fatalf("identity = %+v want sales/demo/open-infra", tbl)
	}
	if tbl.TableType != "EXTERNAL_TABLE" {
		t.Fatalf("TableType = %q want EXTERNAL_TABLE", tbl.TableType)
	}
	if tbl.StorageDescriptor.Location != "s3://warehouse/demo/sales" {
		t.Fatalf("Location = %q", tbl.StorageDescriptor.Location)
	}
	cols := tbl.StorageDescriptor.Columns
	if len(cols) != 3 {
		t.Fatalf("Columns len = %d want 3 (%+v)", len(cols), cols)
	}
	if cols[0].Name != "region" || cols[0].Type != "string" || cols[0].Comment != "the sales region" {
		t.Fatalf("col[0] = %+v", cols[0])
	}
	if cols[1].Name != "amount" || cols[1].Type != "int" {
		t.Fatalf("col[1] = %+v", cols[1])
	}
	if cols[2].Name != "ts" || cols[2].Type != "timestamp" {
		t.Fatalf("col[2] = %+v", cols[2])
	}
	if len(tbl.PartitionKeys) != 1 || tbl.PartitionKeys[0].Name != "region" || tbl.PartitionKeys[0].Type != "string" {
		t.Fatalf("PartitionKeys = %+v want one identity key region:string", tbl.PartitionKeys)
	}
	if tbl.Parameters["table_type"] != "ICEBERG" {
		t.Fatalf("Parameters.table_type = %q want ICEBERG", tbl.Parameters["table_type"])
	}
	if tbl.Parameters["metadata_location"] != "s3://warehouse/demo/sales/metadata/00001-abc.metadata.json" {
		t.Fatalf("Parameters.metadata_location = %q", tbl.Parameters["metadata_location"])
	}
	if tbl.Parameters["classification"] != "parquet" {
		t.Fatalf("Parameters.classification = %q want parquet", tbl.Parameters["classification"])
	}
}
