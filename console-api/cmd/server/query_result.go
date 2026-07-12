package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The Athena result-reader: given a kind: Query, return its state/stats + result
// rows by reading the run's output from MinIO — the GetQueryExecution +
// GetQueryResults of our Athena. The engine (query/run.sh) writes, per query id,
// a <qid>.csv (results) and a <qid>.metadata.json (state/row_count/exec_ms/error)
// to the output bucket; this reads both back. No engine coupling — swapping DuckDB
// for Trino in Phase 2 doesn't touch this.

const queryPreviewRows = 1000

// resultKey is the object key prefix the composition writes results under:
// "<ns>/<name>" (→ .csv + .metadata.json). Plain concat, identical on both sides.
func resultKey(ns, name string) string { return ns + "/" + name }

// jobName mirrors the composition's Job name for the run (used only as a fallback
// to detect a failed run when no metadata was written).
func jobName(ns, name string) string {
	n := "q-" + ns + "-" + name
	if len(n) > 63 {
		n = n[:63]
	}
	return n
}

type queryResultResp struct {
	State           string     `json:"state"` // RUNNING | SUCCEEDED | FAILED
	RowCount        int64      `json:"rowCount"`
	ExecutionTimeMs int64      `json:"executionTimeMs"`
	Error           string     `json:"error,omitempty"`
	ResultLocation  string     `json:"resultLocation,omitempty"`
	Columns         []string   `json:"columns,omitempty"`
	Rows            [][]string `json:"rows,omitempty"`
	Truncated       bool       `json:"truncated,omitempty"`
}

func handleQueryResult(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		bucket := r.URL.Query().Get("bucket")
		if bucket == "" {
			bucket = "query-results"
		}
		key := resultKey(ns, name)

		cl, err := minioClient(cs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Default to RUNNING until the metadata.json exists (query hasn't finished).
		res := queryResultResp{State: "RUNNING"}
		if obj, err := cl.GetObject(r.Context(), bucket, key+".metadata.json", minio.GetObjectOptions{}); err == nil {
			if b, err := io.ReadAll(io.LimitReader(obj, 1<<20)); err == nil && len(b) > 0 {
				var meta struct {
					State           string `json:"state"`
					RowCount        int64  `json:"row_count"`
					ExecutionTimeMs int64  `json:"execution_time_ms"`
					Error           string `json:"error"`
					ResultLocation  string `json:"result_location"`
				}
				if json.Unmarshal(b, &meta) == nil && meta.State != "" {
					res.State = meta.State
					res.RowCount = meta.RowCount
					res.ExecutionTimeMs = meta.ExecutionTimeMs
					res.Error = meta.Error
					res.ResultLocation = meta.ResultLocation
				}
			}
			_ = obj.Close()
		}

		// Fallback: if there's no metadata yet, the run may have crashed before
		// writing it — surface a failed run Job so the UI never spins forever.
		if res.State == "RUNNING" {
			if job, err := cs.BatchV1().Jobs("minio").Get(r.Context(), jobName(ns, name), metav1.GetOptions{}); err == nil {
				for _, c := range job.Status.Conditions {
					if c.Type == "Failed" && c.Status == "True" {
						res.State = "FAILED"
						res.Error = "query run failed before writing results — check the query engine logs"
					}
				}
			}
		}

		if res.State == "SUCCEEDED" {
			if obj, err := cl.GetObject(r.Context(), bucket, key+".csv", minio.GetObjectOptions{}); err == nil {
				rd := csv.NewReader(obj)
				rd.FieldsPerRecord = -1
				for n := 0; ; n++ {
					rec, err := rd.Read()
					if err != nil {
						break
					}
					switch {
					case n == 0:
						res.Columns = rec
					case n <= queryPreviewRows:
						res.Rows = append(res.Rows, rec)
					default:
						res.Truncated = true
					}
					if res.Truncated {
						break
					}
				}
				_ = obj.Close()
			}
		}
		writeJSON(w, http.StatusOK, res)
	}
}
