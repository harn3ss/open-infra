// AWS Athena front door for the aws-shim (polyhedron#179).
//
// Speaks the Amazon Athena API (AWS JSON 1.1, the operation named in X-Amz-Target: AmazonAthena.<Op>, which
// is what the Athena SDKs and aws CLI sign for), authenticates through the shared SigV4 path, authorizes
// with the one policy world every front door uses (coarse impersonated SubjectAccessReview + fine-grained
// Cedar dataPlane at WORKGROUP granularity), and executes SQL against the platform's Trino engine
// (trino.lakehouse, the /v1/statement REST protocol) over the `iceberg` catalog.
//
// Athena here is query submission + async polling + results: StartQueryExecution scales Trino up (it runs
// scale-to-zero) and launches an async run; GetQueryExecution/GetQueryResults poll and read it back;
// StopQueryExecution cancels it. Query METADATA (databases/tables) is the sibling glue.* doorway's job —
// the Athena catalog-metadata API is deliberately refused here with a pointer to Glue.
//
// Deliberate carve-outs, refused honestly rather than faked (see athenaRefusal), never a silent divergence:
//   - workgroup CUD — only the built-in 'primary' workgroup is provided;
//   - named/saved queries, prepared statements — not implemented;
//   - data-catalog management — a single Iceberg catalog is fronted, not a manageable set;
//   - the Athena catalog-metadata API (Get/ListDatabases, Get/ListTableMetadata) — served by glue.*;
//   - everything else Athena — the catch-all not-implemented path.
//
// Two honest v1 limitations are enforced in the code (see athena_exec.go): executions are IN-MEMORY (lost
// on restart; a TTL reaper bounds growth), and results are returned FROM the engine — the doorway does NOT
// write a result CSV to the S3 OutputLocation (it is echoed; the S3 write is a graduation step). SQL is
// passed to Trino VERBATIM, so Athena-only syntax that Trino cannot parse fails as a FAILED query carrying
// Trino's error. See docs/aws-shim.md for the full divergence list.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// the AWS JSON 1.1 X-Amz-Target prefix the Athena SDKs and aws CLI sign for.
const athenaTargetPrefix = "AmazonAthena"

type athenaHandler struct {
	cs            kubernetes.Interface
	authzNS       string
	account       string
	region        string
	trinoURL      string // Trino base, no trailing slash (http://trino.lakehouse.svc.cluster.local:8080)
	trinoNS       string // "lakehouse"
	trinoDeploy   string // "trino"
	catalog       string // Trino catalog, "iceberg"
	defaultOutput string // default ResultConfiguration.OutputLocation, e.g. s3://lakehouse/athena-results/
	execs         *athenaExecStore
	authz         *dataplaneauthz.Checker
	logger        *slog.Logger
}

func newAthenaHandler(cs kubernetes.Interface, authzNS, account, region, trinoURL, trinoNS, trinoDeploy, catalog, defaultOutput string, logger *slog.Logger) *athenaHandler {
	if region == "" {
		region = "us-east-1"
	}
	if catalog == "" {
		catalog = "iceberg"
	}
	if trinoNS == "" {
		trinoNS = "lakehouse"
	}
	if trinoDeploy == "" {
		trinoDeploy = "trino"
	}
	return &athenaHandler{
		cs:            cs,
		authzNS:       authzNS,
		account:       account,
		region:        region,
		trinoURL:      strings.TrimRight(trinoURL, "/"),
		trinoNS:       trinoNS,
		trinoDeploy:   trinoDeploy,
		catalog:       catalog,
		defaultOutput: defaultOutput,
		execs:         newAthenaExecStore(athenaExecTTL, logger),
		logger:        logger,
	}
}

// --- error dialect (AWS JSON 1.1). Athena surfaces the bare exception name in __type, like Glue/KMS. ---

func writeAthenaError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeAthenaJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *athenaHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	// AWS surfaces a SigV4 mismatch as InvalidSignatureException before the service sees it.
	writeAthenaError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func (h *athenaHandler) invalidRequest(w http.ResponseWriter, requestID, message string) {
	writeAthenaError(w, http.StatusBadRequest, "InvalidRequestException", requestID, message)
}

// verbForAthenaOp maps an Athena operation to the coarse RBAC verb its SubjectAccessReview checks (reads ->
// get, query submission -> create, cancellation -> delete). Unknown -> not recognized.
func verbForAthenaOp(op string) (string, bool) {
	switch op {
	case "GetQueryExecution", "GetQueryResults", "GetWorkGroup", "ListWorkGroups", "BatchGetQueryExecution":
		return "get", true
	case "StartQueryExecution":
		return "create", true
	case "StopQueryExecution":
		return "delete", true
	}
	return "", false
}

// athenaResource resolves the (resType, resource) an op scopes to for the authz gates: the WorkGroup name.
// StartQueryExecution/GetWorkGroup scope to the request's WorkGroup (default "primary"); id-scoped ops scope
// to the referenced execution's WorkGroup (else "primary"); ListWorkGroups has no single resource ("").
func (h *athenaHandler) athenaResource(op string, body map[string]any) (resType, res string) {
	switch op {
	case "StartQueryExecution", "GetWorkGroup":
		wg := firstString(body, "WorkGroup")
		if wg == "" {
			wg = "primary"
		}
		return "WorkGroup", wg
	case "GetQueryExecution", "GetQueryResults", "StopQueryExecution", "BatchGetQueryExecution":
		wg := "primary"
		if id := firstString(body, "QueryExecutionId"); id != "" {
			if ex, ok := h.execs.get(id); ok {
				if s := ex.snapshot(); s.WorkGroup != "" {
					wg = s.WorkGroup
				}
			}
		}
		return "WorkGroup", wg
	case "ListWorkGroups":
		return "", ""
	}
	return "WorkGroup", "primary"
}

// athenaRefusal returns the honest reason an op is deliberately NOT fronted (and true), or "" and false.
// Each message names the op and WHY — a refusal is never a faked success.
func athenaRefusal(op string) (string, bool) {
	switch op {
	case "CreateWorkGroup", "UpdateWorkGroup", "DeleteWorkGroup":
		return "Athena " + op + " is not implemented: only the built-in 'primary' workgroup is provided.", true
	case "CreateNamedQuery", "GetNamedQuery", "ListNamedQueries", "DeleteNamedQuery", "BatchGetNamedQuery":
		return "Athena " + op + " is not implemented: saved/named queries are not implemented.", true
	case "CreatePreparedStatement", "GetPreparedStatement", "ListPreparedStatements", "DeletePreparedStatement":
		return "Athena " + op + " is not implemented: prepared statements are not implemented.", true
	case "CreateDataCatalog", "GetDataCatalog", "ListDataCatalogs", "UpdateDataCatalog", "DeleteDataCatalog":
		return "Athena " + op + " is not implemented: a single Iceberg data catalog is fronted; data-catalog management is not implemented.", true
	case "GetDatabase", "ListDatabases", "GetTableMetadata", "ListTableMetadata":
		return "Athena " + op + " is not implemented: catalog metadata is served by the Glue doorway (glue.*); use it, not the Athena metadata API.", true
	}
	return "", false
}

func (h *athenaHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		h.invalidRequest(w, requestID, "No operation named in the X-Amz-Target header (expected "+athenaTargetPrefix+".<Op>).")
		return
	}

	// Carry the resolved principal on the context so every audit record names *who* (AU-2/AU-9).
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// Deliberately-refused ops are a flat capability statement (not an access decision), so they are refused
	// up front with an honest "why" — before the verb table, which does not list them.
	if reason, refused := athenaRefusal(op); refused {
		h.audit(ctx, op, "", "refuse", reason)
		h.invalidRequest(w, requestID, reason)
		return
	}

	verb, known := verbForAthenaOp(op)
	if !known {
		h.invalidRequest(w, requestID, "Athena "+op+" is not implemented by the open-infra shim.")
		return
	}

	body := readJSONBody(r)
	resType, res := h.athenaResource(op, body)

	// One policy world: the coarse impersonated SubjectAccessReview (resource-agnostic, as every front door).
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, res); !allowed {
		h.audit(ctx, op, res, "deny", reason)
		writeAthenaError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only tighten. Scoped to the workgroup when we have one.
	if res != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "athena:"+op, resType, res, r); denied {
			h.audit(ctx, op, res, "deny", reason)
			writeAthenaError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
			return
		}
	}

	switch op {
	case "StartQueryExecution":
		h.startQueryExecution(ctx, w, requestID, body)
	case "GetQueryExecution":
		h.getQueryExecution(ctx, w, requestID, body)
	case "GetQueryResults":
		h.getQueryResults(ctx, w, requestID, body)
	case "StopQueryExecution":
		h.stopQueryExecution(ctx, w, requestID, body)
	case "GetWorkGroup":
		h.getWorkGroup(ctx, w, requestID, body)
	case "ListWorkGroups":
		h.listWorkGroups(ctx, w, requestID)
	default:
		// A recognized op (e.g. BatchGetQueryExecution) the shim does not front yet — honest, never faked.
		h.invalidRequest(w, requestID, "Athena "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- query submission + polling + results ---

func (h *athenaHandler) startQueryExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	sql := firstString(body, "QueryString")
	if strings.TrimSpace(sql) == "" {
		h.invalidRequest(w, requestID, "QueryString is required and must be non-empty.")
		return
	}
	database, catalog := "", h.catalog
	if qec, ok := body["QueryExecutionContext"].(map[string]any); ok {
		if d, _ := qec["Database"].(string); d != "" {
			database = d
		}
		if c, _ := qec["Catalog"].(string); c != "" {
			catalog = c
		}
	}
	output := h.defaultOutput
	if rc, ok := body["ResultConfiguration"].(map[string]any); ok {
		if o, _ := rc["OutputLocation"].(string); o != "" {
			output = o
		}
	}
	wg := firstString(body, "WorkGroup")
	if wg == "" {
		wg = "primary"
	}

	// Scale Trino up + stamp the autostop activity annotation — a QUICK patch (timeout 0, no readiness wait),
	// so StartQueryExecution returns immediately as AWS does. The cold-start wait is absorbed asynchronously in
	// the run (the query sits QUEUED until Trino is ready). A patch failure (e.g. missing RBAC) surfaces now.
	if err := scaleTrinoUp(ctx, h.cs, h.trinoNS, h.trinoDeploy, 0, h.logger); err != nil {
		h.logger.ErrorContext(ctx, "athena: could not scale trino", "error", err.Error())
		writeAthenaError(w, http.StatusInternalServerError, "InternalServerException", requestID,
			"Could not start the query engine.")
		return
	}

	client := newTrinoClient(h.trinoURL)
	ex := h.execs.start(client, athenaStartParams{
		Query:          sql,
		Database:       database,
		Catalog:        catalog,
		WorkGroup:      wg,
		OutputLocation: output,
		User:           principalFromCtx(ctx),
		CS:             h.cs,
		TrinoNS:        h.trinoNS,
		TrinoDeploy:    h.trinoDeploy,
		ReadyTimeout:   athenaReadyTimeout,
	})
	h.audit(ctx, "StartQueryExecution", wg, "allow", "id="+ex.Id)
	writeAthenaJSON(w, requestID, map[string]any{"QueryExecutionId": ex.Id})
}

func (h *athenaHandler) getQueryExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := firstString(body, "QueryExecutionId")
	ex, ok := h.execs.get(id)
	if id == "" || !ok {
		// Athena uses InvalidRequestException (not ResourceNotFound) for an unknown QueryExecutionId.
		h.invalidRequest(w, requestID, "QueryExecutionId "+id+" was not found.")
		return
	}
	s := ex.snapshot()
	status := map[string]any{
		"State":              s.State,
		"SubmissionDateTime": float64(s.SubmittedAt.Unix()),
	}
	if s.StateReason != "" {
		status["StateChangeReason"] = s.StateReason
	}
	if !s.CompletedAt.IsZero() {
		status["CompletionDateTime"] = float64(s.CompletedAt.Unix())
	}
	qe := map[string]any{
		"QueryExecutionId":      s.Id,
		"Query":                 s.Query,
		"StatementType":         statementType(s.Query),
		"ResultConfiguration":   map[string]any{"OutputLocation": s.OutputLocation},
		"QueryExecutionContext": map[string]any{"Database": s.Database, "Catalog": s.Catalog},
		"Status":                status,
		"Statistics":            map[string]any{"EngineExecutionTimeInMillis": float64(s.EngineMillis)},
		"WorkGroup":             s.WorkGroup,
	}
	h.audit(ctx, "GetQueryExecution", s.WorkGroup, "allow", "id="+s.Id)
	writeAthenaJSON(w, requestID, map[string]any{"QueryExecution": qe})
}

func (h *athenaHandler) getQueryResults(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := firstString(body, "QueryExecutionId")
	ex, ok := h.execs.get(id)
	if id == "" || !ok {
		h.invalidRequest(w, requestID, "QueryExecutionId "+id+" was not found.")
		return
	}
	s := ex.snapshot()
	if s.State != "SUCCEEDED" {
		h.invalidRequest(w, requestID, "Query has not yet finished. Current state: "+s.State)
		return
	}

	offset := 0
	if tok := firstString(body, "NextToken"); tok != "" {
		o, err := decodeAthenaToken(tok)
		if err != nil {
			h.invalidRequest(w, requestID, "Invalid NextToken.")
			return
		}
		offset = o
	}
	max := 1000
	if v, ok := intFromAny(body["MaxResults"]); ok && v > 0 && v < max {
		max = v
	}

	// ColumnInfo (one per result column); Label mirrors Name, as Athena does for an unaliased column.
	colInfo := make([]any, 0, len(s.Columns))
	for _, c := range s.Columns {
		colInfo = append(colInfo, map[string]any{"Name": c.Name, "Type": c.Type, "Label": c.Name})
	}

	// Athena convention: the FIRST Row is the column-name HEADER, then one Row per result row. A NULL cell
	// is an empty Data entry (no VarCharValue key). A zero-column (DDL/UTILITY) result has no header and no
	// rows — an empty ResultSet, returned gracefully.
	allRows := []any{}
	if len(s.Columns) > 0 {
		header := make([]any, len(s.Columns))
		for i, c := range s.Columns {
			header[i] = map[string]any{"VarCharValue": c.Name}
		}
		allRows = append(allRows, map[string]any{"Data": header})
		for _, row := range s.Rows {
			data := make([]any, len(row))
			for i, cell := range row {
				if cell == athenaNullCell {
					data[i] = map[string]any{} // a NULL cell carries no VarCharValue
				} else {
					data[i] = map[string]any{"VarCharValue": cell}
				}
			}
			allRows = append(allRows, map[string]any{"Data": data})
		}
	}

	total := len(allRows)
	if offset > total {
		offset = total
	}
	end := offset + max
	if end > total {
		end = total
	}
	resp := map[string]any{
		"ResultSet": map[string]any{
			"ResultSetMetadata": map[string]any{"ColumnInfo": colInfo},
			"Rows":              allRows[offset:end],
		},
	}
	if end < total {
		resp["NextToken"] = encodeAthenaToken(end)
	}
	h.audit(ctx, "GetQueryResults", s.WorkGroup, "allow", "id="+s.Id)
	writeAthenaJSON(w, requestID, resp)
}

func (h *athenaHandler) stopQueryExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := firstString(body, "QueryExecutionId")
	ex, ok := h.execs.get(id)
	if id == "" || !ok {
		h.invalidRequest(w, requestID, "QueryExecutionId "+id+" was not found.")
		return
	}
	ex.stop() // records CANCELLED and DELETEs the running Trino query (the exec's cancel hook)
	h.audit(ctx, "StopQueryExecution", ex.snapshot().WorkGroup, "allow", "id="+id)
	writeAthenaJSON(w, requestID, map[string]any{})
}

// --- workgroups (only the built-in 'primary' exists) ---

func (h *athenaHandler) getWorkGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "WorkGroup")
	if name == "" {
		name = "primary"
	}
	if name != "primary" {
		writeAthenaError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
			"WorkGroup "+name+" was not found; only the built-in 'primary' workgroup is provided.")
		return
	}
	h.audit(ctx, "GetWorkGroup", "primary", "allow", "")
	writeAthenaJSON(w, requestID, map[string]any{
		"WorkGroup": map[string]any{
			"Name":  "primary",
			"State": "ENABLED",
			"Configuration": map[string]any{
				"ResultConfiguration": map[string]any{"OutputLocation": h.defaultOutput},
			},
		},
	})
}

func (h *athenaHandler) listWorkGroups(ctx context.Context, w http.ResponseWriter, requestID string) {
	h.audit(ctx, "ListWorkGroups", "", "allow", "")
	writeAthenaJSON(w, requestID, map[string]any{
		"WorkGroups": []any{map[string]any{"Name": "primary", "State": "ENABLED"}},
	})
}

// --- audit + token helpers ---

// audit emits a structured audit record for an Athena operation (AU-2/AU-9): who, which op, which workgroup,
// the decision, and an optional detail (e.g. the execution id) — never query results.
func (h *athenaHandler) audit(ctx context.Context, op, workgroup, decision, detail string) {
	args := []any{"service", "athena", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if workgroup != "" {
		args = append(args, "workgroup", workgroup)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "athena audit", args...)
}

// encodeAthenaToken / decodeAthenaToken make an opaque pagination cursor: base64 of the next row offset over
// the (header + data) sequence.
func encodeAthenaToken(offset int) string {
	return base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func decodeAthenaToken(tok string) (int, error) {
	raw, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid pagination token")
	}
	return n, nil
}
