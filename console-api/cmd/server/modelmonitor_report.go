package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	"k8s.io/client-go/kubernetes"
)

// Drift report reader for kind: ModelMonitor — the SageMaker Model Monitor "Reports" view.
//
// The monitor CronJob writes, under spec.output.{bucket,prefix}, a report-<ts>.json per run
// plus a rolling latest.json (see modelmonitor-composition.yaml). This endpoint reads the
// latest report back and lists prior runs so the console can render per-feature drift and the
// violations table instead of just linking an s3:// URL.
//
// SECURITY (the db-stats SSRF lesson): the bucket and prefix are resolved from the ModelMonitor
// CR's own spec — NEVER from a client query parameter. A caller cannot point this at an
// arbitrary bucket. Objects are read via the scoped console MinIO client (minioClient), not root.
//
// Honest-empty: if no report has been written yet, returns {runs:[], latest:null,
// reason:"no reports written yet"} with 200. It never fabricates a report.

type reportRun struct {
	Key          string `json:"key"`
	LastModified string `json:"lastModified"`
	// Time is derived from the report-<ts>.json key when it matches the composition's
	// naming; omitted when it can't be parsed (LastModified is always authoritative).
	Time string `json:"time,omitempty"`
}

type modelMonitorReportResp struct {
	Runs   []reportRun     `json:"runs"`
	Latest json.RawMessage `json:"latest"` // parsed report JSON, or null
	Reason string          `json:"reason,omitempty"`
	Bucket string          `json:"bucket,omitempty"`
	Prefix string          `json:"prefix,omitempty"`
}

// reportRunTime reconstructs an RFC3339 timestamp from a report object key of the form
// "<prefix>report-2006-01-02T150405Z.json" (the composition writes the run time with colons
// stripped). Returns "" if the key doesn't match — never guesses.
func reportRunTime(key string) string {
	base := strings.TrimSuffix(path.Base(key), ".json")
	base = strings.TrimPrefix(base, "report-")
	if t, err := time.Parse("2006-01-02T150405Z", base); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return ""
}

const modelMonitorReportMaxBytes = 4 << 20 // 4 MiB — a drift report is small JSON

func handleModelMonitorReport(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		ctx := r.Context()

		// Resolve the reports location from the CR spec (bucket/prefix), never from the client.
		raw, err := cs.CoreV1().RESTClient().Get().
			AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/modelmonitors/" + name).DoRaw(ctx)
		if err != nil {
			logger.Warn("modelmonitor report: read CR", slog.String("ns", ns),
				slog.String("name", name), slog.Any("err", err))
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "model monitor not found: " + name})
			return
		}
		var mm struct {
			Spec struct {
				Output struct {
					Bucket string `json:"bucket"`
					Prefix string `json:"prefix"`
				} `json:"output"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &mm); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "parse model monitor"})
			return
		}
		bucket, prefix := mm.Spec.Output.Bucket, mm.Spec.Output.Prefix
		if bucket == "" {
			writeJSON(w, http.StatusOK, modelMonitorReportResp{
				Runs:   []reportRun{},
				Latest: nil,
				Reason: "model monitor has no reports location (spec.output.bucket is empty)",
			})
			return
		}

		cl, err := minioClient(cs)
		if err != nil {
			// Object storage unreachable, or the scoped console MinIO identity can't read the
			// secret — surface honestly (empty) rather than 500. See the RBAC/policy caveat.
			logger.Warn("modelmonitor report: minio client", slog.Any("err", err))
			writeJSON(w, http.StatusOK, modelMonitorReportResp{
				Runs:   []reportRun{},
				Latest: nil,
				Bucket: bucket,
				Prefix: prefix,
				Reason: "object storage unavailable: " + err.Error(),
			})
			return
		}

		// List every report object under the prefix. latest.json is the rolling pointer;
		// report-<ts>.json are the historical runs.
		type rawRun struct {
			key string
			lm  time.Time
		}
		var runsRaw []rawRun
		haveLatest := false
		var listErr string
		for obj := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
			if obj.Err != nil {
				listErr = obj.Err.Error()
				break
			}
			if !strings.HasSuffix(obj.Key, ".json") {
				continue
			}
			if path.Base(obj.Key) == "latest.json" {
				haveLatest = true
				continue
			}
			runsRaw = append(runsRaw, rawRun{key: obj.Key, lm: obj.LastModified})
		}

		// Newest first.
		sort.Slice(runsRaw, func(i, j int) bool { return runsRaw[i].lm.After(runsRaw[j].lm) })
		runs := make([]reportRun, 0, len(runsRaw))
		for _, rr := range runsRaw {
			runs = append(runs, reportRun{
				Key:          rr.key,
				LastModified: rr.lm.UTC().Format(time.RFC3339),
				Time:         reportRunTime(rr.key),
			})
		}

		// Pick the report to return as "latest": prefer latest.json, else the newest run.
		// The composition writes the pointer at exactly `prefix + "latest.json"` (the prefix
		// is used verbatim, no separator inserted), so mirror that here.
		readKey := ""
		if haveLatest {
			readKey = prefix + "latest.json"
		} else if len(runsRaw) > 0 {
			readKey = runsRaw[0].key
		}

		resp := modelMonitorReportResp{Runs: runs, Bucket: bucket, Prefix: prefix}
		if readKey != "" {
			if obj, err := cl.GetObject(ctx, bucket, readKey, minio.GetObjectOptions{}); err == nil {
				if b, err := io.ReadAll(io.LimitReader(obj, modelMonitorReportMaxBytes)); err == nil &&
					len(b) > 0 && json.Valid(b) {
					resp.Latest = json.RawMessage(b)
				}
				_ = obj.Close()
			}
		}

		switch {
		case listErr != "":
			resp.Reason = "could not list reports: " + listErr
		case resp.Latest == nil && len(runs) == 0:
			resp.Reason = "no reports written yet"
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
