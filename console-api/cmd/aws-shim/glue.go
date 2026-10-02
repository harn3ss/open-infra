// AWS Glue Data Catalog front door for the aws-shim (polyhedron#179).
//
// Speaks the AWS Glue API (AWS JSON 1.1, the operation named in X-Amz-Target: AWSGlue.<Op>, which is
// what the Glue SDKs and aws CLI sign for), authenticates through the shared SigV4 path, authorizes with
// the one policy world every front door uses (coarse impersonated SubjectAccessReview + fine-grained
// Cedar dataPlane at DATABASE/TABLE granularity), and answers against the platform's EXISTING Iceberg
// REST catalog (iceberg-rest.lakehouse) — the real metastore Trino and DataFlow already use.
//
// This doorway does NOT re-implement a catalog. The mapping is direct:
//   - a Glue DATABASE is an Iceberg namespace (list/get/create/delete);
//   - a Glue TABLE is an Iceberg table (list/get/delete — plus the schema→Column translation in
//     glue_types.go that makes an Iceberg table legible to the Glue SDK).
//
// Deliberate carve-outs, refused honestly rather than faked (never a silent divergence or a false green):
//   - CreateTable/UpdateTable — a Glue StorageDescriptor cannot faithfully specify an Iceberg table's
//     schema and data layout; Iceberg tables are created via Athena DDL / the query engine, which own
//     that. Half-creating one would be a lie, so it is refused.
//   - partition management — Iceberg partitions tables internally; Hive-style partition CRUD does not
//     apply, and GetPartitions therefore returns an empty set.
//   - crawlers (schema inference by scanning) — the catalog is fronted directly, so there is nothing to
//     crawl.
//   - ETL jobs (Apache Spark) — a different product, not provided by this shim.
//   - everything else Glue (connections, triggers, workflows, ML transforms, registries/schemas, …) —
//     the catch-all not-implemented path.
//
// See docs/aws-shim.md for the full divergence list.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// the AWS JSON 1.1 X-Amz-Target prefix the Glue SDKs and aws CLI sign for.
const glueTargetPrefix = "AWSGlue"

type glueHandler struct {
	cs         kubernetes.Interface
	authzNS    string
	account    string // catalogId, e.g. "open-infra"
	region     string // e.g. "us-east-1"
	catalogURL string // Iceberg REST base, no trailing slash (e.g. http://iceberg-rest.lakehouse.svc.cluster.local:8181)
	authz      *dataplaneauthz.Checker
	logger     *slog.Logger
}

func newGlueHandler(cs kubernetes.Interface, authzNS, account, region, catalogURL string, logger *slog.Logger) *glueHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &glueHandler{
		cs:         cs,
		authzNS:    authzNS,
		account:    account,
		region:     region,
		catalogURL: catalogURL,
		logger:     logger,
	}
}

// --- error dialect (AWS JSON 1.1). Glue surfaces the bare exception name in __type, like KMS/ECR. ---

func writeGlueError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeGlueJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *glueHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	// AWS surfaces a SigV4 mismatch as InvalidSignatureException before the service sees it.
	writeGlueError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForGlueOp maps a Glue operation to the coarse RBAC verb its SubjectAccessReview checks (catalog
// reads -> get, database create -> create, deletions -> delete). Unknown -> not recognized.
func verbForGlueOp(op string) (string, bool) {
	switch op {
	case "GetDatabases", "GetDatabase", "GetTables", "GetTable", "GetPartitions":
		return "get", true
	case "CreateDatabase":
		return "create", true
	case "DeleteDatabase", "DeleteTable":
		return "delete", true
	}
	return "", false
}

// glueResource resolves the (resType, resourceName) an op scopes to, for the authz gates. Database ops
// scope to the database name (resType "Database"); table ops scope to "<db>/<table>" (resType "Table");
// GetTables is a database-scoped listing (resType "Database", the database name). GetDatabases has no
// single resource and returns "" (no fine-grained Cedar scope — the coarse gate still applies).
func (h *glueHandler) glueResource(op string, body map[string]any) (resType, res string) {
	switch op {
	case "GetDatabase", "DeleteDatabase":
		return "Database", firstString(body, "Name")
	case "CreateDatabase":
		return "Database", databaseInputName(body)
	case "GetTables":
		return "Database", firstString(body, "DatabaseName")
	case "GetTable", "DeleteTable":
		db := firstString(body, "DatabaseName")
		tbl := firstString(body, "Name")
		if db == "" && tbl == "" {
			return "Table", ""
		}
		return "Table", db + "/" + tbl
	case "GetPartitions":
		return "Table", firstString(body, "DatabaseName") + "/" + firstString(body, "TableName")
	}
	return "", ""
}

// glueRefusal returns the honest reason an op is deliberately NOT fronted (and true), or "" and false.
// Each message names the op and WHY — a refusal is never a faked success. Only the specific groups below
// get a bespoke message; every other unsupported Glue op falls through to the catch-all not-implemented
// path in serve().
func glueRefusal(op string) (string, bool) {
	switch op {
	case "CreateTable", "UpdateTable":
		return "Glue " + op + " is not supported: table creation is not fronted by Glue; create Iceberg tables via Athena DDL (CREATE TABLE) or the query engine, which own the Iceberg schema and data layout.", true
	case "CreatePartition", "UpdatePartition", "BatchCreatePartition", "DeletePartition", "BatchDeletePartition", "BatchUpdatePartition":
		return "Glue " + op + " is not supported: Iceberg manages partitions internally; Hive-style partition management is not applicable.", true
	case "CreateCrawler", "StartCrawler", "GetCrawler", "GetCrawlers", "DeleteCrawler", "UpdateCrawler", "StopCrawler":
		return "Glue " + op + " is not supported: Glue crawlers (schema inference by scanning) are not implemented; the catalog is fronted directly.", true
	case "CreateJob", "StartJobRun", "GetJob", "GetJobs", "GetJobRun", "GetJobRuns", "DeleteJob", "UpdateJob", "BatchStopJobRun":
		return "Glue " + op + " is not supported: Glue ETL jobs (Apache Spark) are a different product and are not provided by this shim.", true
	}
	return "", false
}

func (h *glueHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeGlueError(w, http.StatusBadRequest, "InvalidInputException", requestID,
			"No operation named in the X-Amz-Target header (expected "+glueTargetPrefix+".<Op>).")
		return
	}

	// Carry the resolved principal on the context so every audit record names *who* (AU-2/AU-9).
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// Deliberately-refused ops are a flat capability statement (not an access decision), so they are
	// refused up front with an honest "why" — before the verb table, which does not list them.
	if reason, refused := glueRefusal(op); refused {
		h.audit(ctx, op, "", "refuse", reason)
		writeGlueError(w, http.StatusBadRequest, "InvalidInputException", requestID, reason)
		return
	}

	verb, known := verbForGlueOp(op)
	if !known {
		writeGlueError(w, http.StatusBadRequest, "InvalidInputException", requestID,
			"Glue "+op+" is not implemented by the open-infra shim.")
		return
	}

	body := readJSONBody(r)
	resType, res := h.glueResource(op, body)

	// One policy world: the coarse impersonated SubjectAccessReview (resource-agnostic, as every front door).
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, res); !allowed {
		h.audit(ctx, op, res, "deny", reason)
		writeGlueError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only tighten. Scoped to the resource when we have one.
	if res != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "glue:"+op, resType, res, r); denied {
			h.audit(ctx, op, res, "deny", reason)
			writeGlueError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
			return
		}
	}

	switch op {
	case "GetDatabases":
		h.getDatabases(ctx, w, requestID)
	case "GetDatabase":
		h.getDatabase(ctx, w, requestID, body)
	case "CreateDatabase":
		h.createDatabase(ctx, w, requestID, body)
	case "DeleteDatabase":
		h.deleteDatabase(ctx, w, requestID, body)
	case "GetTables":
		h.getTables(ctx, w, requestID, body)
	case "GetTable":
		h.getTable(ctx, w, requestID, body)
	case "GetPartitions":
		h.getPartitions(ctx, w, requestID, body)
	case "DeleteTable":
		h.deleteTable(ctx, w, requestID, body)
	default:
		writeGlueError(w, http.StatusBadRequest, "InvalidInputException", requestID,
			"Glue "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- databases (<- Iceberg namespaces) ---

func (h *glueHandler) getDatabases(ctx context.Context, w http.ResponseWriter, requestID string) {
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	names, err := c.listNamespaces(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	list := make([]any, 0, len(names))
	for _, n := range names {
		list = append(list, h.databaseObject(n))
	}
	h.audit(ctx, "GetDatabases", "", "allow", "")
	writeGlueJSON(w, requestID, map[string]any{"DatabaseList": list})
}

func (h *glueHandler) getDatabase(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "Name")
	if name == "" {
		h.invalidInput(w, requestID, "Name is required.")
		return
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	exists, err := c.namespaceExists(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !exists {
		h.entityNotFound(w, requestID, "Database "+name+" not found.")
		return
	}
	h.audit(ctx, "GetDatabase", name, "allow", "")
	writeGlueJSON(w, requestID, map[string]any{"Database": h.databaseObject(name)})
}

func (h *glueHandler) createDatabase(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := databaseInputName(body)
	if !validGlueDatabaseName(name) {
		h.invalidInput(w, requestID,
			"DatabaseInput.Name is required, must be at most 255 characters, and must be a single-level name (no '/' separators).")
		return
	}
	props := map[string]string{}
	if in, ok := body["DatabaseInput"].(map[string]any); ok {
		if desc, _ := in["Description"].(string); desc != "" {
			props["description"] = desc
		}
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	switch err := c.createNamespace(ctx, name, props); {
	case err == errNamespaceExists:
		writeGlueError(w, http.StatusBadRequest, "AlreadyExistsException", requestID,
			"Database already exists: "+name+".")
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateDatabase", name, "allow", "")
	// AWS CreateDatabase returns an empty body on success.
	writeGlueJSON(w, requestID, map[string]any{})
}

func (h *glueHandler) deleteDatabase(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "Name")
	if name == "" {
		h.invalidInput(w, requestID, "Name is required.")
		return
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	switch err := c.deleteNamespace(ctx, name); {
	case err == errNoSuchNamespace:
		h.entityNotFound(w, requestID, "Database "+name+" not found.")
		return
	case err == errNamespaceNotEmpty:
		h.invalidInput(w, requestID,
			"Database "+name+" is not empty; delete its tables before deleting the database.")
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteDatabase", name, "allow", "")
	writeGlueJSON(w, requestID, map[string]any{})
}

// --- tables (<- Iceberg tables; READ + delete only) ---

func (h *glueHandler) getTables(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	db := firstString(body, "DatabaseName")
	if db == "" {
		h.invalidInput(w, requestID, "DatabaseName is required.")
		return
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	names, err := c.listTables(ctx, db)
	if err == errNoSuchNamespace {
		h.entityNotFound(w, requestID, "Database "+db+" not found.")
		return
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	list := make([]any, 0, len(names))
	for _, name := range names {
		t, found, err := c.getTable(ctx, db, name)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !found { // vanished between the list and the load — skip it
			continue
		}
		list = append(list, h.tableObject(db, name, t))
	}
	h.audit(ctx, "GetTables", db, "allow", "")
	writeGlueJSON(w, requestID, map[string]any{"TableList": list})
}

func (h *glueHandler) getTable(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	db := firstString(body, "DatabaseName")
	name := firstString(body, "Name")
	if db == "" || name == "" {
		h.invalidInput(w, requestID, "DatabaseName and Name are required.")
		return
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	t, found, err := c.getTable(ctx, db, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		h.entityNotFound(w, requestID, "Table "+name+" not found in database "+db+".")
		return
	}
	h.audit(ctx, "GetTable", db+"/"+name, "allow", "")
	writeGlueJSON(w, requestID, map[string]any{"Table": h.tableObject(db, name, t)})
}

// getPartitions returns an EMPTY partition set. Iceberg manages partitioning internally (hidden
// transforms over data files); it does not expose Hive-style partition VALUES, so there is nothing
// faithful to return but []. The table must exist, so a wrong table name is still an honest 404.
func (h *glueHandler) getPartitions(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	db := firstString(body, "DatabaseName")
	name := firstString(body, "TableName")
	if db == "" || name == "" {
		h.invalidInput(w, requestID, "DatabaseName and TableName are required.")
		return
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	_, found, err := c.getTable(ctx, db, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		h.entityNotFound(w, requestID, "Table "+name+" not found in database "+db+".")
		return
	}
	h.audit(ctx, "GetPartitions", db+"/"+name, "allow", "")
	writeGlueJSON(w, requestID, map[string]any{"Partitions": []any{}})
}

func (h *glueHandler) deleteTable(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	db := firstString(body, "DatabaseName")
	name := firstString(body, "Name")
	if db == "" || name == "" {
		h.invalidInput(w, requestID, "DatabaseName and Name are required.")
		return
	}
	c, err := h.catalog()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	switch err := c.deleteTable(ctx, db, name); {
	case err == errNoSuchTable:
		h.entityNotFound(w, requestID, "Table "+name+" not found in database "+db+".")
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteTable", db+"/"+name, "allow", "")
	writeGlueJSON(w, requestID, map[string]any{})
}

// --- object shaping ---

func (h *glueHandler) databaseObject(name string) map[string]any {
	return map[string]any{"Name": name, "CatalogId": h.account}
}

// tableObject projects an Iceberg table into the Glue Table shape an SDK/CLI expects. The columns come
// from the current schema (translated in glue_types.go); the Parameters mark it as an Iceberg table and
// carry the current metadata file location, which is how AWS Glue itself represents an Iceberg table.
func (h *glueHandler) tableObject(db, name string, t *icebergTable) map[string]any {
	// classification mirrors the table's default write format (AWS Glue sets it from the file format);
	// default to parquet, the lakehouse default, when the property is absent.
	classification := "parquet"
	if f, _ := t.Properties["write.format.default"].(string); f != "" {
		classification = strings.ToLower(f)
	}
	return map[string]any{
		"Name":         name,
		"DatabaseName": db,
		"CatalogId":    h.account,
		"TableType":    "EXTERNAL_TABLE",
		"StorageDescriptor": map[string]any{
			"Columns":  icebergColumns(t.Fields),
			"Location": t.Location,
		},
		"PartitionKeys": partitionKeys(t.PartitionFields, t.Fields),
		"Parameters": map[string]any{
			"table_type":        "ICEBERG",
			"metadata_location": t.MetadataLocation,
			"classification":    classification,
		},
	}
}

// --- catalog client + helpers ---

// catalog builds an Iceberg REST client for this request. It is an honest error (surfaced as
// InternalServiceException) when no catalog backend is configured on this shim.
func (h *glueHandler) catalog() (*icebergClient, error) {
	if h.catalogURL == "" {
		return nil, fmt.Errorf("the Iceberg REST catalog backend is not configured on this shim")
	}
	return newIcebergClient(h.catalogURL), nil
}

func (h *glueHandler) invalidInput(w http.ResponseWriter, requestID, message string) {
	writeGlueError(w, http.StatusBadRequest, "InvalidInputException", requestID, message)
}

func (h *glueHandler) entityNotFound(w http.ResponseWriter, requestID, message string) {
	writeGlueError(w, http.StatusBadRequest, "EntityNotFoundException", requestID, message)
}

func (h *glueHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("glue backend error", "error", err.Error())
	writeGlueError(w, http.StatusInternalServerError, "InternalServiceException", requestID,
		"The server encountered an internal error.")
}

// audit emits a structured audit record for a Glue operation (AU-2/AU-9): who, which op, which resource
// (a database name, or "<db>/<table>"), the decision, and an optional detail.
func (h *glueHandler) audit(ctx context.Context, op, resource, decision, detail string) {
	args := []any{"service", "glue", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if resource != "" {
		args = append(args, "resource", resource)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "glue audit", args...)
}

// --- pure helpers ---

// databaseInputName pulls the database name out of a CreateDatabase request's DatabaseInput.
func databaseInputName(body map[string]any) string {
	if in, ok := body["DatabaseInput"].(map[string]any); ok {
		if name, _ := in["Name"].(string); name != "" {
			return name
		}
	}
	return ""
}

// validGlueDatabaseName enforces the doorway's single-level-namespace contract: non-empty, at most 255
// characters, and free of the Iceberg multi-level separators ('/' and the %1F unit separator) that a
// single Glue database name cannot represent.
func validGlueDatabaseName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	return !strings.ContainsAny(name, "/\x1f")
}
