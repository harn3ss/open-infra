package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// Best-effort resource time-series for a batch Job's pods, from Prometheus — the loss/
// utilization charts a SageMaker training/processing job page is expected to show, sourced
// from the same cAdvisor + DCGM series kube-prometheus-stack already scrapes.
//
// Modeled on nodes_metrics.go (prometheusBaseURL / promInstant); this adds promRange for
// query_range. It is strictly honest: if Prometheus is unreachable, the Job has no pods, or
// no series exist yet, it returns {available:false, reason:"…"} with 200 and NEVER invents
// points. CPU/memory come from cAdvisor; GPU util (DCGM) is included only if the series exists.

// promRangeSample is one entry of a range-query result matrix. Each Values element is
// [ <ts float seconds>, "<value string>" ], same encoding as an instant sample's Value.
type promRangeSample struct {
	Metric map[string]string `json:"metric"`
	Values [][2]any          `json:"values"`
}

// promRange runs a PromQL range query (GET /api/v1/query_range) and returns its result matrix.
// Analogous to promInstant in nodes_metrics.go.
func promRange(ctx context.Context, query string, start, end time.Time, step time.Duration) ([]promRangeSample, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start.Unix(), 10))
	q.Set("end", strconv.FormatInt(end.Unix(), 10))
	q.Set("step", strconv.Itoa(int(step.Seconds())))
	endpoint := prometheusBaseURL() + "/api/v1/query_range?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return nil, fmt.Errorf("prometheus %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Result []promRangeSample `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Status != "success" {
		return nil, fmt.Errorf("prometheus query status %q", out.Status)
	}
	return out.Data.Result, nil
}

// firstSeriesPoints converts the first result series of a range query into [[tsSeconds, value], …].
// Returns nil when there is no series (honest empty). Queries here aggregate to a single series,
// so taking result[0] is intentional.
func firstSeriesPoints(res []promRangeSample) [][2]float64 {
	if len(res) == 0 {
		return nil
	}
	vals := res[0].Values
	pts := make([][2]float64, 0, len(vals))
	for _, v := range vals {
		ts, ok := v[0].(float64)
		if !ok {
			continue
		}
		str, ok := v[1].(string)
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(str, 64)
		if err != nil {
			continue
		}
		pts = append(pts, [2]float64{ts, f})
	}
	return pts
}

// promEscape escapes a value for safe inclusion inside a double-quoted PromQL label matcher.
func promEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

type metricSeries struct {
	Name   string       `json:"name"`  // cpu | memory | gpu
	Unit   string       `json:"unit"`  // cores | bytes | percent
	Points [][2]float64 `json:"points"`
}

type jobMetricsResp struct {
	Available bool           `json:"available"`
	Reason    string         `json:"reason,omitempty"`
	Series    []metricSeries `json:"series,omitempty"`
}

// handleJobMetrics returns CPU/memory (and GPU, if present) time-series for a batch Job's pods.
//
//	GET /api/jobs/{namespace}/{name}/metrics
//
// It resolves the Job's pods, builds a pod=~"…" matcher, and range-queries Prometheus over the
// pods' run window. Fails soft to {available:false, reason:"…"} — never fabricates data.
func handleJobMetrics(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		ctx := r.Context()

		pods := jobPods(ctx, cs, ns, name, logger)
		if len(pods) == 0 {
			writeJSON(w, http.StatusOK, jobMetricsResp{
				Available: false,
				Reason:    "no pods found for this job yet — metrics appear once it starts running",
			})
			return
		}

		// Use the pods' own (API-server-trusted) namespace and names to build the query,
		// so nothing caller-controlled reaches PromQL unescaped. Pod names are DNS-1123
		// (regex-safe); the namespace is escaped defensively anyway.
		podNS := promEscape(pods[0].Namespace)
		names := make([]string, 0, len(pods))
		for i := range pods {
			names = append(names, pods[i].Name)
		}
		podRe := strings.Join(names, "|")

		// Run window: from the earliest pod start (padded) to now. cAdvisor series simply
		// stop when a pod terminates, so a finished job yields the samples it produced.
		end := time.Now()
		start := end.Add(-1 * time.Hour) // fallback lookback if no start time is known
		var earliest time.Time
		for i := range pods {
			if st := pods[i].Status.StartTime; st != nil {
				if earliest.IsZero() || st.Time.Before(earliest) {
					earliest = st.Time
				}
			}
		}
		if !earliest.IsZero() {
			start = earliest.Add(-1 * time.Minute)
		}
		// Aim for ~120 points; never step finer than 15s.
		step := end.Sub(start) / 120
		if step < 15*time.Second {
			step = 15 * time.Second
		}

		podSel := fmt.Sprintf(`namespace="%s",pod=~"%s"`, podNS, podRe)
		cpuQ := fmt.Sprintf(`sum(rate(container_cpu_usage_seconds_total{%s,container!="",container!="POD"}[2m]))`, podSel)
		memQ := fmt.Sprintf(`sum(container_memory_working_set_bytes{%s,container!="",container!="POD"})`, podSel)
		gpuQ := fmt.Sprintf(`max(DCGM_FI_DEV_GPU_UTIL{%s})`, podSel)

		// CPU is the probe query: if it errors, Prometheus is unreachable/misconfigured →
		// report unavailable rather than a partial/empty chart.
		cpu, err := promRange(ctx, cpuQ, start, end, step)
		if err != nil {
			logger.Warn("job metrics: cpu query failed", slog.String("ns", ns),
				slog.String("job", name), slog.Any("err", err))
			writeJSON(w, http.StatusOK, jobMetricsResp{
				Available: false,
				Reason:    "metrics backend unavailable: " + err.Error(),
			})
			return
		}

		series := make([]metricSeries, 0, 3)
		if pts := firstSeriesPoints(cpu); len(pts) > 0 {
			series = append(series, metricSeries{Name: "cpu", Unit: "cores", Points: pts})
		}
		if mem, err := promRange(ctx, memQ, start, end, step); err == nil {
			if pts := firstSeriesPoints(mem); len(pts) > 0 {
				series = append(series, metricSeries{Name: "memory", Unit: "bytes", Points: pts})
			}
		} else {
			logger.Warn("job metrics: memory query failed", slog.Any("err", err))
		}
		// GPU util — included ONLY if the DCGM series exists for these pods (a CPU-only job
		// or a cluster without DCGM simply omits it; never a zero/placeholder series).
		if gpu, err := promRange(ctx, gpuQ, start, end, step); err == nil {
			if pts := firstSeriesPoints(gpu); len(pts) > 0 {
				series = append(series, metricSeries{Name: "gpu", Unit: "percent", Points: pts})
			}
		}

		if len(series) == 0 {
			writeJSON(w, http.StatusOK, jobMetricsResp{
				Available: false,
				Reason:    "no metric series for this job's pods yet — cAdvisor may not have scraped them, or they've been garbage-collected",
			})
			return
		}
		writeJSON(w, http.StatusOK, jobMetricsResp{Available: true, Series: series})
	}
}
