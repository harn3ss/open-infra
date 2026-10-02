// The Athena doorway's execution store, async query runner, and Trino scale cooperation (polyhedron#179).
//
// AWS Athena is asynchronous: StartQueryExecution returns an id immediately and the query runs in the
// background; the client then polls GetQueryExecution and reads GetQueryResults. This file is that engine
// for the shim — an in-memory store of executions, each run to completion by its own goroutine against the
// Trino REST client, with the Trino state machine mapped onto Athena's.
//
// Two honest limitations are baked into the CODE here (the reviewer documents them):
//   - executions are IN-MEMORY, so they are lost on a shim restart; the TTL reaper bounds growth.
//   - results are returned FROM the engine via GetQueryResults; the doorway does not (yet) write a result
//     CSV to the S3 OutputLocation — that is echoed, and the S3 result-file write is a graduation step.
//
// Trino runs scale-to-zero (console/trino_autostop.go scales it 0↔1 by recent engine=trino Query
// activity). This doorway cooperates: on query submission it scales Trino UP and stamps a
// `athena.openinfra.dev/last-query` annotation the autostop reconciler honors, so Trino is not scaled
// down out from under a running Athena query.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	// athenaReadyTimeout bounds the cold-start wait for Trino to become ready before a query is submitted.
	// A cold start is the documented first-query latency (Redshift-Serverless-style).
	athenaReadyTimeout = 90 * time.Second
	// athenaExecTTL is how long a finished/stale execution lingers in the in-memory store before the reaper
	// removes it (mirrors Athena's own query-history retention bound).
	athenaExecTTL = time.Hour

	// the annotation the autostop reconciler honors to keep Trino up while an Athena query is in flight.
	athenaLastQueryAnnotation = "athena.openinfra.dev/last-query"

	// athenaNullCell is the sentinel a stringified result cell holds when the engine returned SQL NULL. The
	// handler emits NO VarCharValue for such a cell (AWS's representation of a null), so a real empty string
	// ("") and a NULL are never conflated.
	athenaNullCell = "\x00athena-null\x00"

	// result-size guardrails: executions are held in memory, so an unbounded result would OOM the shim. A
	// query that exceeds either bound is marked FAILED with a clear reason, never allowed to grow without end.
	athenaMaxRows  = 100000
	athenaMaxBytes = 128 << 20 // 128 MiB of stringified cell data
)

// athenaColumn is one result column projected to Athena's ColumnInfo shape.
type athenaColumn struct {
	Name string
	Type string
}

// athenaExec is one query execution's full lifecycle record. All mutable fields are guarded by mu; the
// handler reads a consistent copy via snapshot().
type athenaExec struct {
	mu sync.Mutex

	Id             string
	Query          string
	Database       string
	Catalog        string
	WorkGroup      string
	OutputLocation string

	State        string // QUEUED | RUNNING | SUCCEEDED | FAILED | CANCELLED
	StateReason  string
	SubmittedAt  time.Time
	CompletedAt  time.Time
	Columns      []athenaColumn
	Rows         [][]string // each cell already stringified; a NULL cell holds athenaNullCell
	EngineMillis int64

	curURI string // the live nextUri (so a cancel can DELETE the running query); guarded by mu
	cancel func() // cancels the run goroutine and best-effort DELETEs the running Trino query
}

// athenaExecSnapshot is a lock-free value copy of the fields the handler needs to render a response.
type athenaExecSnapshot struct {
	Id             string
	Query          string
	Database       string
	Catalog        string
	WorkGroup      string
	OutputLocation string
	State          string
	StateReason    string
	SubmittedAt    time.Time
	CompletedAt    time.Time
	Columns        []athenaColumn
	Rows           [][]string
	EngineMillis   int64
}

func (ex *athenaExec) snapshot() athenaExecSnapshot {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	return athenaExecSnapshot{
		Id: ex.Id, Query: ex.Query, Database: ex.Database, Catalog: ex.Catalog,
		WorkGroup: ex.WorkGroup, OutputLocation: ex.OutputLocation,
		State: ex.State, StateReason: ex.StateReason,
		SubmittedAt: ex.SubmittedAt, CompletedAt: ex.CompletedAt,
		Columns: ex.Columns, Rows: ex.Rows, EngineMillis: ex.EngineMillis,
	}
}

func (ex *athenaExec) toRunning() {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.State == "QUEUED" {
		ex.State = "RUNNING"
	}
}

// setProgress moves an in-flight exec between QUEUED/RUNNING as Trino's state advances; it never overwrites
// a terminal state (a cancel that won the race, or an already-recorded success/failure).
func (ex *athenaExec) setProgress(state string) {
	if state != "QUEUED" && state != "RUNNING" {
		return
	}
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.State == "QUEUED" || ex.State == "RUNNING" {
		ex.State = state
	}
}

func (ex *athenaExec) setCurURI(uri string) {
	ex.mu.Lock()
	ex.curURI = uri
	ex.mu.Unlock()
}

func (ex *athenaExec) currentURI() string {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	return ex.curURI
}

func (ex *athenaExec) isCancelled() bool {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	return ex.State == "CANCELLED"
}

// stop cancels a non-terminal execution (StopQueryExecution): it records CANCELLED and fires the run's
// cancel hook (which DELETEs the running Trino query). An already-finished query is left untouched.
func (ex *athenaExec) stop() {
	ex.mu.Lock()
	if ex.State == "SUCCEEDED" || ex.State == "FAILED" || ex.State == "CANCELLED" {
		ex.mu.Unlock()
		return
	}
	ex.State = "CANCELLED"
	ex.StateReason = "Query cancelled by StopQueryExecution."
	ex.CompletedAt = time.Now()
	cancel := ex.cancel
	ex.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// athenaExecStore is the in-memory execution map plus a TTL reaper. Lost on restart (documented); the
// reaper bounds growth.
type athenaExecStore struct {
	mu     sync.Mutex
	m      map[string]*athenaExec
	ttl    time.Duration
	logger *slog.Logger
}

// newAthenaExecStore builds the store and starts its TTL reaper goroutine.
func newAthenaExecStore(ttl time.Duration, logger *slog.Logger) *athenaExecStore {
	if ttl <= 0 {
		ttl = athenaExecTTL
	}
	s := &athenaExecStore{m: map[string]*athenaExec{}, ttl: ttl, logger: logger}
	go s.reap()
	return s
}

func (s *athenaExecStore) reap() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.reapOnce(time.Now())
	}
}

func (s *athenaExecStore) reapOnce(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ex := range s.m {
		sub := ex.snapshot().SubmittedAt
		if now.Sub(sub) > s.ttl {
			delete(s.m, id)
		}
	}
}

func (s *athenaExecStore) put(ex *athenaExec) {
	s.mu.Lock()
	s.m[ex.Id] = ex
	s.mu.Unlock()
}

func (s *athenaExecStore) get(id string) (*athenaExec, bool) {
	s.mu.Lock()
	ex, ok := s.m[id]
	s.mu.Unlock()
	return ex, ok
}

// athenaStartParams carries everything a query execution needs to run.
type athenaStartParams struct {
	Query          string
	Database       string // the Trino schema the query runs under
	Catalog        string
	WorkGroup      string
	OutputLocation string
	User           string // the principal, carried as X-Trino-User
	// Trino readiness is awaited in the async run (so StartQueryExecution returns immediately): the query
	// sits QUEUED until Trino reports ready. Nil CS skips the wait (unit tests that point straight at a fake).
	CS           kubernetes.Interface
	TrinoNS      string
	TrinoDeploy  string
	ReadyTimeout time.Duration
}

// start creates a QUEUED execution with a fresh UUID and launches its run goroutine. The goroutine runs on
// a BACKGROUND context (not the request's — the request returns immediately) bounded by a generous timeout.
func (s *athenaExecStore) start(client *trinoClient, p athenaStartParams) *athenaExec {
	ex := &athenaExec{
		Id:             uuidLike(),
		Query:          p.Query,
		Database:       p.Database,
		Catalog:        p.Catalog,
		WorkGroup:      p.WorkGroup,
		OutputLocation: p.OutputLocation,
		State:          "QUEUED",
		SubmittedAt:    time.Now(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	ex.cancel = func() {
		cancel() // abort any in-flight submit/advance
		if uri := ex.currentURI(); uri != "" {
			dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer dcancel()
			_ = client.cancel(dctx, uri, p.User)
		}
	}
	s.put(ex)
	go func() {
		rctx, rcancel := context.WithTimeout(ctx, 10*time.Minute)
		defer rcancel()
		s.runExec(rctx, ex, client, p)
	}()
	return ex
}

// runExec drives one query to completion against Trino: submit, then follow nextUri pages until there is
// none, accumulating columns (kept from the first non-empty set) and rows (stringified, bounded). It is
// synchronous and deterministic so a test can call it directly. Terminal with no nextUri is success unless
// an error object appeared; any transport/engine error is a FAILED exec with a clear reason.
func (s *athenaExecStore) runExec(ctx context.Context, ex *athenaExec, client *trinoClient, p athenaStartParams) {
	start := time.Now()

	// Absorb the Trino cold start HERE (not in StartQueryExecution, which returned immediately): the query
	// sits QUEUED until Trino reports ready, exactly as AWS Athena queues while the engine warms. A real
	// readiness timeout is an honest FAILED exec, not a fabricated result.
	if p.CS != nil {
		if err := waitTrinoReady(ctx, p.CS, p.TrinoNS, p.TrinoDeploy, p.ReadyTimeout); err != nil {
			if ctx.Err() != nil && ex.isCancelled() {
				return
			}
			s.fail(ex, "Trino did not become ready: "+err.Error(), start)
			return
		}
	}

	q, err := client.submit(ctx, p.Query, p.User, p.Catalog, p.Database)
	if err != nil {
		if ctx.Err() != nil && ex.isCancelled() {
			return // a StopQueryExecution cancelled the submit; CANCELLED already recorded
		}
		s.fail(ex, "Trino query submission failed: "+err.Error(), start)
		return
	}
	ex.toRunning()

	var cols []athenaColumn
	rows := [][]string{}
	var bytesUsed int64

	page := q.page()
	cols = mergeColumns(cols, page.Columns)
	state := page.State
	errMsg := page.ErrMsg
	if ok := appendStringRows(&rows, page.Rows, &bytesUsed); !ok {
		s.failTooLarge(ex, client, q.nextURI(), p.User, start)
		return
	}
	ex.setCurURI(q.nextURI())
	uri := q.nextURI()

	for uri != "" {
		if ctx.Err() != nil {
			if ex.isCancelled() {
				return
			}
			s.fail(ex, "Trino query aborted: "+ctx.Err().Error(), start)
			return
		}
		page, err = client.advance(ctx, uri, p.User)
		if err != nil {
			if ctx.Err() != nil && ex.isCancelled() {
				return
			}
			s.fail(ex, "Trino query failed: "+err.Error(), start)
			return
		}
		cols = mergeColumns(cols, page.Columns)
		if page.State != "" {
			state = page.State
		}
		if page.ErrMsg != "" {
			errMsg = page.ErrMsg
		}
		if ok := appendStringRows(&rows, page.Rows, &bytesUsed); !ok {
			s.failTooLarge(ex, client, page.NextURI, p.User, start)
			return
		}
		ex.setCurURI(page.NextURI)
		uri = page.NextURI
		ex.setProgress(mapTrinoState(state))
	}

	// Terminal: nextUri absent. An error object anywhere in the stream means the query FAILED.
	if errMsg != "" {
		s.fail(ex, "Trino query failed: "+errMsg, start)
		return
	}
	s.succeed(ex, cols, rows, start)
}

func (s *athenaExecStore) succeed(ex *athenaExec, cols []athenaColumn, rows [][]string, start time.Time) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.State == "CANCELLED" { // a cancel won the race — honor it
		return
	}
	ex.State = "SUCCEEDED"
	ex.Columns = cols
	ex.Rows = rows
	ex.CompletedAt = time.Now()
	ex.EngineMillis = time.Since(start).Milliseconds()
}

func (s *athenaExecStore) fail(ex *athenaExec, reason string, start time.Time) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.State == "CANCELLED" {
		return
	}
	ex.State = "FAILED"
	ex.StateReason = reason
	ex.CompletedAt = time.Now()
	ex.EngineMillis = time.Since(start).Milliseconds()
}

// failTooLarge marks an exec FAILED for exceeding the result-size guardrails and best-effort cancels the
// still-running Trino query so it stops producing rows nobody will read.
func (s *athenaExecStore) failTooLarge(ex *athenaExec, client *trinoClient, uri, user string, start time.Time) {
	if uri != "" {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = client.cancel(dctx, uri, user)
		cancel()
	}
	s.fail(ex, fmt.Sprintf("Query result exceeded the doorway limit (%d rows / %d bytes); narrow the query or write results to S3.",
		athenaMaxRows, athenaMaxBytes), start)
}

// scaleTrinoUp cooperates with the Trino autostop: it ALWAYS stamps the last-query annotation (so the
// reconciler keeps Trino up while this query runs) and flips replicas 0→1 when Trino is scaled to zero,
// then waits (bounded by timeout) for Trino to report a ready replica before the caller submits. A
// timeout<=0 skips the readiness wait (patch only). A real readiness timeout is an honest error the caller
// surfaces as InternalServerException.
func scaleTrinoUp(ctx context.Context, cs kubernetes.Interface, ns, deploy string, timeout time.Duration, logger *slog.Logger) error {
	dep, err := cs.AppsV1().Deployments(ns).Get(ctx, deploy, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get trino deployment %s/%s: %w", ns, deploy, err)
	}
	var cur int32 = 1
	if dep.Spec.Replicas != nil {
		cur = *dep.Spec.Replicas
	}
	patch := map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{athenaLastQueryAnnotation: time.Now().UTC().Format(time.RFC3339)},
		},
	}
	if cur == 0 {
		patch["spec"] = map[string]any{"replicas": 1}
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	if _, err := cs.AppsV1().Deployments(ns).Patch(ctx, deploy, types.StrategicMergePatchType, raw, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("scale/annotate trino %s/%s: %w", ns, deploy, err)
	}
	if logger != nil && cur == 0 {
		logger.InfoContext(ctx, "athena: scaled trino up for a query", "namespace", ns, "deployment", deploy)
	}

	if timeout <= 0 {
		return nil
	}
	return waitTrinoReady(ctx, cs, ns, deploy, timeout)
}

// waitTrinoReady polls until the Trino Deployment reports a ready replica, bounded by timeout. It is called
// from the async run (not StartQueryExecution), so a cold-start query simply sits QUEUED until Trino warms —
// StartQueryExecution returns immediately, as AWS Athena does.
func waitTrinoReady(ctx context.Context, cs kubernetes.Interface, ns, deploy string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = athenaReadyTimeout
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		d, derr := cs.AppsV1().Deployments(ns).Get(wctx, deploy, metav1.GetOptions{})
		if derr == nil && d.Status.ReadyReplicas >= 1 {
			return nil
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("Trino did not become ready within %s", timeout)
		case <-time.After(2 * time.Second):
		}
	}
}

// --- pure helpers ---

// mapTrinoState maps a Trino query state onto an Athena execution state. Intermediate states only; a
// query's terminal success/failure is decided by the runner (nextUri absence + any error object), not by
// this mapping alone.
func mapTrinoState(s string) string {
	switch strings.ToUpper(s) {
	case "RUNNING", "FINISHING":
		return "RUNNING"
	case "FINISHED":
		return "SUCCEEDED"
	case "FAILED":
		return "FAILED"
	default: // QUEUED, PLANNING, STARTING, WAITING_FOR_RESOURCES, DISPATCHING, …
		return "QUEUED"
	}
}

// mergeColumns keeps the FIRST non-empty column set seen (Trino sends columns once, mid-stream).
func mergeColumns(have []athenaColumn, got []trinoColumn) []athenaColumn {
	if len(have) > 0 || len(got) == 0 {
		return have
	}
	out := make([]athenaColumn, len(got))
	for i, c := range got {
		out[i] = athenaColumn{Name: c.Name, Type: c.Type}
	}
	return out
}

// appendStringRows stringifies and appends a page of rows to dst, accumulating the byte budget. It returns
// false the moment either guardrail (row count or byte budget) would be exceeded — WITHOUT appending the
// offending row — so the runner can fail the exec instead of growing memory without bound.
func appendStringRows(dst *[][]string, src [][]any, bytesUsed *int64) bool {
	for _, r := range src {
		if len(*dst) >= athenaMaxRows {
			return false
		}
		row := make([]string, len(r))
		for i, cell := range r {
			cs := stringifyCell(cell)
			if cs != athenaNullCell {
				*bytesUsed += int64(len(cs))
			}
			row[i] = cs
		}
		if *bytesUsed > athenaMaxBytes {
			return false
		}
		*dst = append(*dst, row)
	}
	return true
}

// stringifyCell renders a JSON result cell as the string Athena carries in a VarCharValue: a string as-is,
// a bool as "true"/"false", an integral number without a decimal point (42.0 → "42"), a non-integral with
// the shortest round-tripping form, and a SQL NULL as the athenaNullCell sentinel (the handler then emits
// no VarCharValue for it).
func stringifyCell(v any) string {
	switch t := v.(type) {
	case nil:
		return athenaNullCell
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if !math.IsInf(t, 0) && !math.IsNaN(t) && t == math.Trunc(t) {
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// statementType is Athena's best-effort classification from the SQL's first keyword: SELECT/WITH/VALUES/
// SHOW/DESCRIBE → DML, CREATE/DROP/ALTER → DDL, everything else → UTILITY.
func statementType(sql string) string {
	switch firstSQLKeyword(sql) {
	case "SELECT", "WITH", "VALUES", "SHOW", "DESCRIBE", "DESC":
		return "DML"
	case "CREATE", "DROP", "ALTER":
		return "DDL"
	}
	return "UTILITY"
}

// firstSQLKeyword returns the upper-cased first word of a statement, ignoring leading whitespace and a
// leading open paren (a parenthesized subquery).
func firstSQLKeyword(sql string) string {
	s := strings.TrimLeft(sql, " \t\r\n(")
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(strings.TrimRight(fields[0], "("))
}
