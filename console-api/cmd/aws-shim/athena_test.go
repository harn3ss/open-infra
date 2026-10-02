package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	appsv1 "k8s.io/api/apps/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// --- fixtures ---

// athenaCS is csWithSAR plus any seeded objects (e.g. the trino Deployment for the scale test).
func athenaCS(allowed bool, objs ...runtime.Object) *fake.Clientset {
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	return cs
}

func newAthenaTestHandler(cs kubernetes.Interface, trinoURL string) *athenaHandler {
	return newAthenaHandler(cs, "default", "open-infra", "us-east-1", trinoURL, "lakehouse", "trino",
		"iceberg", "s3://lakehouse/athena-results/", discardLogger())
}

func athenaClaims() iam.Claims {
	return iam.Claims{Sub: "amy", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
}

func athenaRequest(target, body string) *http.Request {
	req := httptest.NewRequest("POST", "http://athena/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", athenaTargetPrefix+"."+target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	return req
}

func athenaErrorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	return body.Message
}

// trinoDeploy builds a trino Deployment object for the fake clientset. A scaled-to-zero Trino has
// replicas=0; readyReplicas is seeded so scaleTrinoUp's readiness gate is pre-satisfied in the test (a real
// scaled-to-zero Trino reports readyReplicas=0 and the gate actually waits) — the test asserts the PATCH.
func trinoDeploy(replicas, ready int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "trino", Namespace: "lakehouse"},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: ready},
	}
}

// fakeTrino serves a minimal /v1/statement surface: the POST returns a first page with a nextUri (state
// QUEUED, no data), and the nextUri GET returns the columns + a page of data with NO nextUri (state
// FINISHED). It counts hits so a test can prove the authz gate denies BEFORE any backend call.
type fakeTrino struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits int
}

func newFakeTrino() *fakeTrino {
	ft := &fakeTrino{}
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, _ *http.Request) {
		ft.mu.Lock()
		ft.hits++
		ft.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "q-1",
			"infoUri": base + "/ui/query.html?q-1",
			"nextUri": base + "/v1/statement/q-1/1",
			"stats":   map[string]any{"state": "QUEUED"},
		})
	})
	mux.HandleFunc("/v1/statement/q-1/1", func(w http.ResponseWriter, _ *http.Request) {
		ft.mu.Lock()
		ft.hits++
		ft.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "q-1",
			"columns": []map[string]any{
				{"name": "n", "type": "integer"},
				{"name": "label", "type": "varchar"},
			},
			"data":  [][]any{{1, "one"}, {2, nil}}, // second row's label is SQL NULL
			"stats": map[string]any{"state": "FINISHED"},
		})
	})
	ft.srv = httptest.NewServer(mux)
	base = ft.srv.URL
	return ft
}

func (ft *fakeTrino) count() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.hits
}

// waitForState polls the store for an execution to reach a terminal state, bounded (no arbitrary sleeps).
func waitForState(t *testing.T, h *athenaHandler, id, want string) athenaExecSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ex, ok := h.execs.get(id); ok {
			s := ex.snapshot()
			if s.State == want {
				return s
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ex, ok := h.execs.get(id); ok {
		t.Fatalf("exec %s did not reach %s; last state=%s reason=%q", id, want, ex.snapshot().State, ex.snapshot().StateReason)
	}
	t.Fatalf("exec %s never appeared in the store", id)
	return athenaExecSnapshot{}
}

// --- Trino client + runner ---

// The runner drives a query to completion against Trino: it submits, follows the nextUri, keeps the first
// non-empty column set, appends every page's rows, and stringifies each cell (a SQL NULL → the sentinel).
func TestAthena_RunnerAccumulatesColumnsAndRows(t *testing.T) {
	ft := newFakeTrino()
	defer ft.srv.Close()
	store := newAthenaExecStore(time.Hour, discardLogger())
	client := newTrinoClient(ft.srv.URL)
	ex := &athenaExec{Id: "ex-run", Query: "SELECT n, label FROM t", State: "QUEUED", SubmittedAt: time.Now()}
	store.put(ex)

	store.runExec(context.Background(), ex, client, athenaStartParams{Query: "SELECT n, label FROM t", Catalog: "iceberg", User: "amy"})

	s := ex.snapshot()
	if s.State != "SUCCEEDED" {
		t.Fatalf("state=%s reason=%q want SUCCEEDED", s.State, s.StateReason)
	}
	if len(s.Columns) != 2 || s.Columns[0].Name != "n" || s.Columns[1].Name != "label" {
		t.Fatalf("columns = %+v", s.Columns)
	}
	if len(s.Rows) != 2 {
		t.Fatalf("rows = %+v want 2", s.Rows)
	}
	if s.Rows[0][0] != "1" || s.Rows[0][1] != "one" {
		t.Fatalf("row0 = %+v want [1 one]", s.Rows[0])
	}
	if s.Rows[1][0] != "2" || s.Rows[1][1] != athenaNullCell {
		t.Fatalf("row1 = %+v want [2 <null-sentinel>]", s.Rows[1])
	}
	if ft.count() != 2 { // one POST + one nextUri GET
		t.Fatalf("backend hits = %d want 2", ft.count())
	}
}

// --- authz gate ---

// The coarse authorization gate denies before ANY backend call when the caller cannot act — the same
// impersonated SubjectAccessReview every front door funnels through.
func TestAthena_AuthzGateDenies(t *testing.T) {
	ft := newFakeTrino()
	defer ft.srv.Close()
	h := newAthenaTestHandler(athenaCS(false, trinoDeploy(0, 1)), ft.srv.URL)
	w := httptest.NewRecorder()
	h.serve(w, athenaRequest("StartQueryExecution", `{"QueryString":"SELECT 1"}`),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-deny")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
	if ft.count() != 0 {
		t.Fatalf("Trino was called despite a denied authz gate (hits=%d)", ft.count())
	}
}

// --- StartQueryExecution: scale-up cooperation + id ---

// StartQueryExecution scales the trino Deployment up (replicas 0→1) and stamps the autostop annotation, then
// returns a QueryExecutionId and runs the query to completion against Trino.
func TestAthena_StartQueryExecutionScalesTrinoAndRuns(t *testing.T) {
	ft := newFakeTrino()
	defer ft.srv.Close()
	cs := athenaCS(true, trinoDeploy(0, 1))
	h := newAthenaTestHandler(cs, ft.srv.URL)

	w := httptest.NewRecorder()
	h.serve(w, athenaRequest("StartQueryExecution", `{"QueryString":"SELECT n, label FROM t"}`), athenaClaims(), "req-start")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		QueryExecutionId string `json:"QueryExecutionId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.QueryExecutionId == "" {
		t.Fatalf("empty QueryExecutionId")
	}

	// The Deployment was scaled up and annotated for the autostop reconciler.
	dep, err := cs.AppsV1().Deployments("lakehouse").Get(context.Background(), "trino", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get trino deployment: %v", err)
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
		t.Fatalf("replicas = %v want 1", dep.Spec.Replicas)
	}
	if dep.Annotations[athenaLastQueryAnnotation] == "" {
		t.Fatalf("missing %s annotation; annotations=%v", athenaLastQueryAnnotation, dep.Annotations)
	}

	// The async run reaches SUCCEEDED against the fake Trino.
	s := waitForState(t, h, resp.QueryExecutionId, "SUCCEEDED")
	if len(s.Rows) != 2 {
		t.Fatalf("rows = %+v want 2", s.Rows)
	}
}

// scaleTrinoUp always stamps the annotation and flips replicas 0→1; an unready Trino with a tiny timeout is
// an honest readiness error (never a hang).
func TestAthena_ScaleTrinoUpReadinessTimeout(t *testing.T) {
	cs := athenaCS(true, trinoDeploy(0, 0)) // scaled to zero, never becomes ready
	err := scaleTrinoUp(context.Background(), cs, "lakehouse", "trino", 50*time.Millisecond, discardLogger())
	if err == nil {
		t.Fatalf("want a readiness-timeout error")
	}
	// The patch still landed (replicas→1 + annotation) even though readiness timed out.
	dep, _ := cs.AppsV1().Deployments("lakehouse").Get(context.Background(), "trino", metav1.GetOptions{})
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
		t.Fatalf("replicas = %v want 1", dep.Spec.Replicas)
	}
	if dep.Annotations[athenaLastQueryAnnotation] == "" {
		t.Fatalf("missing last-query annotation")
	}
}

// --- GetQueryResults shaping ---

func TestAthena_GetQueryResults(t *testing.T) {
	h := newAthenaTestHandler(athenaCS(true), "")

	// Before completion → InvalidRequestException naming the current state.
	h.execs.put(&athenaExec{Id: "ex-queued", Query: "SELECT 1", State: "QUEUED", WorkGroup: "primary", SubmittedAt: time.Now()})
	w := httptest.NewRecorder()
	h.serve(w, athenaRequest("GetQueryResults", `{"QueryExecutionId":"ex-queued"}`), athenaClaims(), "req-early")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidRequestException")
	if msg := athenaErrorMessage(t, w); !strings.Contains(msg, "QUEUED") {
		t.Fatalf("message should name the state QUEUED; got %q", msg)
	}

	// After completion → header row + data rows + ColumnInfo; a NULL cell → an empty Data entry.
	h.execs.put(&athenaExec{
		Id: "ex-done", Query: "SELECT a, b", State: "SUCCEEDED", WorkGroup: "primary",
		SubmittedAt: time.Now(), CompletedAt: time.Now(),
		Columns: []athenaColumn{{Name: "a", Type: "varchar"}, {Name: "b", Type: "integer"}},
		Rows:    [][]string{{"x", athenaNullCell}, {"y", "2"}},
	})
	w2 := httptest.NewRecorder()
	h.serve(w2, athenaRequest("GetQueryResults", `{"QueryExecutionId":"ex-done"}`), athenaClaims(), "req-res")
	if w2.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w2.Code, w2.Body.String())
	}
	var resp struct {
		ResultSet struct {
			ResultSetMetadata struct {
				ColumnInfo []struct {
					Name, Type, Label string
				} `json:"ColumnInfo"`
			} `json:"ResultSetMetadata"`
			Rows []struct {
				Data []map[string]string `json:"Data"`
			} `json:"Rows"`
		} `json:"ResultSet"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w2.Body.String())
	}
	ci := resp.ResultSet.ResultSetMetadata.ColumnInfo
	if len(ci) != 2 || ci[0].Name != "a" || ci[0].Label != "a" || ci[1].Type != "integer" {
		t.Fatalf("ColumnInfo = %+v", ci)
	}
	rows := resp.ResultSet.Rows
	if len(rows) != 3 { // header + 2 data rows
		t.Fatalf("rows = %d want 3 (header + 2)", len(rows))
	}
	if rows[0].Data[0]["VarCharValue"] != "a" || rows[0].Data[1]["VarCharValue"] != "b" {
		t.Fatalf("header row = %+v want column names", rows[0].Data)
	}
	if rows[1].Data[0]["VarCharValue"] != "x" {
		t.Fatalf("row1[0] = %+v", rows[1].Data[0])
	}
	if _, present := rows[1].Data[1]["VarCharValue"]; present {
		t.Fatalf("a NULL cell must carry no VarCharValue key; got %+v", rows[1].Data[1])
	}
	if rows[2].Data[1]["VarCharValue"] != "2" {
		t.Fatalf("row2[1] = %+v", rows[2].Data[1])
	}
}

// --- workgroups ---

func TestAthena_GetWorkGroup(t *testing.T) {
	h := newAthenaTestHandler(athenaCS(true), "")

	w := httptest.NewRecorder()
	h.serve(w, athenaRequest("GetWorkGroup", `{"WorkGroup":"primary"}`), athenaClaims(), "req-wg")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		WorkGroup struct {
			Name          string `json:"Name"`
			State         string `json:"State"`
			Configuration struct {
				ResultConfiguration struct {
					OutputLocation string `json:"OutputLocation"`
				} `json:"ResultConfiguration"`
			} `json:"Configuration"`
		} `json:"WorkGroup"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.WorkGroup.Name != "primary" || resp.WorkGroup.State != "ENABLED" {
		t.Fatalf("workgroup = %+v", resp.WorkGroup)
	}
	if resp.WorkGroup.Configuration.ResultConfiguration.OutputLocation != "s3://lakehouse/athena-results/" {
		t.Fatalf("output location = %q", resp.WorkGroup.Configuration.ResultConfiguration.OutputLocation)
	}

	// Any other name → ResourceNotFoundException (only the built-in primary exists).
	w2 := httptest.NewRecorder()
	h.serve(w2, athenaRequest("GetWorkGroup", `{"WorkGroup":"team-analytics"}`), athenaClaims(), "req-wg2")
	assertECSErrorType(t, w2, http.StatusBadRequest, "ResourceNotFoundException")
}

// --- refusals + unknown op ---

func TestAthena_RefusedAndUnknownOps(t *testing.T) {
	h := newAthenaTestHandler(athenaCS(true), "")

	// A deliberately-refused op names the op (honest, never faked).
	w := httptest.NewRecorder()
	h.serve(w, athenaRequest("CreateNamedQuery", `{"Name":"q","Database":"d","QueryString":"SELECT 1"}`), athenaClaims(), "req-nq")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidRequestException")
	if msg := athenaErrorMessage(t, w); !strings.Contains(msg, "CreateNamedQuery") {
		t.Fatalf("refusal should name the op; got %q", msg)
	}

	// The Athena catalog-metadata API points at the Glue doorway.
	w2 := httptest.NewRecorder()
	h.serve(w2, athenaRequest("GetDatabase", `{"CatalogName":"iceberg","DatabaseName":"d"}`), athenaClaims(), "req-gd")
	assertECSErrorType(t, w2, http.StatusBadRequest, "InvalidRequestException")
	if msg := athenaErrorMessage(t, w2); !strings.Contains(msg, "glue.*") {
		t.Fatalf("GetDatabase should point at Glue; got %q", msg)
	}

	// An unknown op is not-implemented, never faked.
	w3 := httptest.NewRecorder()
	h.serve(w3, athenaRequest("FloobQuery", `{}`), athenaClaims(), "req-unk")
	assertECSErrorType(t, w3, http.StatusBadRequest, "InvalidRequestException")
	if msg := athenaErrorMessage(t, w3); !strings.Contains(msg, "not implemented") {
		t.Fatalf("unknown op should say not implemented; got %q", msg)
	}
}

// --- StatementType + cell stringify ---

func TestAthena_StatementType(t *testing.T) {
	cases := map[string]string{
		"SELECT 1":                               "DML",
		"  with x as (select 1) select * from x": "DML",
		"VALUES (1),(2)":                         "DML",
		"SHOW TABLES":                            "DML",
		"DESCRIBE t":                             "DML",
		"CREATE TABLE t (a int)":                 "DDL",
		"drop table t":                           "DDL",
		"ALTER TABLE t ADD COLUMN b int":         "DDL",
		"INSERT INTO t VALUES (1)":               "UTILITY",
		"":                                       "UTILITY",
	}
	for sql, want := range cases {
		if got := statementType(sql); got != want {
			t.Errorf("statementType(%q) = %q want %q", sql, got, want)
		}
	}
}

func TestAthena_StringifyCell(t *testing.T) {
	if got := stringifyCell(float64(42)); got != "42" { // integral float → no decimal point
		t.Errorf("stringifyCell(42.0) = %q want 42", got)
	}
	if got := stringifyCell(float64(1000)); got != "1000" {
		t.Errorf("stringifyCell(1000.0) = %q want 1000", got)
	}
	if got := stringifyCell(float64(42.5)); got != "42.5" {
		t.Errorf("stringifyCell(42.5) = %q want 42.5", got)
	}
	if got := stringifyCell(true); got != "true" {
		t.Errorf("stringifyCell(true) = %q want true", got)
	}
	if got := stringifyCell(false); got != "false" {
		t.Errorf("stringifyCell(false) = %q want false", got)
	}
	if got := stringifyCell(nil); got != athenaNullCell {
		t.Errorf("stringifyCell(nil) = %q want the null sentinel", got)
	}
	if got := stringifyCell("hello"); got != "hello" {
		t.Errorf("stringifyCell(\"hello\") = %q want hello", got)
	}
}
