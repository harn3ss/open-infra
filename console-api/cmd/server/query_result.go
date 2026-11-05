package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
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

// managedQueryResults is the platform's result bucket — Athena's managed query results: every Query
// writes there under its own "<ns>/<name>" key unless it declares another output location, and the
// caller needs only athena:GetQueryResults on the Query to read its results back.
const managedQueryResults = "query-results"

// objectOpener reads one object from object storage.
type objectOpener func(ctx context.Context, bucket, key string) (io.ReadCloser, error)

// minioOpener opens objects with the console's MinIO client.
func minioOpener(cs kubernetes.Interface) (objectOpener, error) {
	cl, err := minioClient(cs)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
		return cl.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	}, nil
}

// queryOutputBucket reads the output location a kind: Query declares (spec.outputBucket, default
// query-results). The results are read from there and nowhere else: a caller never names the bucket.
func queryOutputBucket(ctx context.Context, cs kubernetes.Interface, ns, name string) (string, error) {
	rc := cs.CoreV1().RESTClient()
	if rc == nil {
		return "", errors.New("no REST client")
	}
	if v := reflect.ValueOf(rc); v.Kind() == reflect.Ptr && v.IsNil() {
		return "", errors.New("no REST client")
	}
	raw, err := rc.Get().AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/queries/" + name).DoRaw(ctx)
	if err != nil {
		return "", err
	}
	var q struct {
		Spec struct {
			OutputBucket string `json:"outputBucket"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		return "", err
	}
	if q.Spec.OutputBucket == "" {
		return managedQueryResults, nil
	}
	return q.Spec.OutputBucket, nil
}

// handleQueryResult is Athena's GetQueryExecution + GetQueryResults for a kind: Query. The route's
// gate has already decided athena:GetQueryResults on the Query. The results are read from the output
// location the Query declares, never from a bucket the caller names (the console reads object storage
// with its own credentials, which reach every bucket). As in AWS, results in a customer output location
// also need s3:GetObject on that location, decided for the signed-in user; the managed location
// (query-results, keyed by the Query's own namespace and name) needs nothing more. A Query never reads
// its results from another platform bucket.
func handleQueryResult(cs kubernetes.Interface, buckets *bucketAuthz, logger *slog.Logger) http.HandlerFunc {
	return serveQueryResult(cs, buckets, func() (objectOpener, error) { return minioOpener(cs) })
}

func serveQueryResult(cs kubernetes.Interface, buckets *bucketAuthz, open func() (objectOpener, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		key := resultKey(ns, name)

		bucket, err := queryOutputBucket(r.Context(), cs, ns, name)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "query not found"})
			return
		}
		if bucket != managedQueryResults {
			if s3authz.IsPlatformBucket(bucket) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: a query's output location is never a platform bucket"})
				return
			}
			if !buckets.allow(w, r, s3authz.Request{Action: "s3:GetObject", Verb: "get", Bucket: bucket, Key: key + ".csv", Object: true}) {
				return
			}
		}

		get, err := open()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Default to RUNNING until the metadata.json exists (query hasn't finished).
		res := queryResultResp{State: "RUNNING"}
		if obj, err := get(r.Context(), bucket, key+".metadata.json"); err == nil {
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
			if obj, err := get(r.Context(), bucket, key+".csv"); err == nil {
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
