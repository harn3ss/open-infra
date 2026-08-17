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

	"k8s.io/client-go/kubernetes"
)

// Node metrics — the missing "disk" column on the Nodes page.
//
// The Kubernetes Node object carries capacity (allocatable cores, memory, pods) but not live
// utilization; kubelet does not expose per-node filesystem *usage*. That lives in Prometheus,
// scraped from node-exporter. So this endpoint queries Prometheus directly (same shape as the
// Loki-backed Audit view) and hands the UI a small usage map.
//
// node-exporter identifies a node by its `instance` label — "<node-IP>:9100" — not by node name.
// We strip the port and key the response by IP; the frontend matches that against each Node's
// InternalIP (nodeInternalIP). That keeps the join in the UI, where the Node objects already live,
// instead of round-tripping kube-state-metrics here.

func prometheusBaseURL() string {
	return strings.TrimRight(
		getenv("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		"/",
	)
}

// promSample is one entry of a Prometheus instant-query result vector. Value is [ <ts float>, "<val string>" ].
type promSample struct {
	Metric map[string]string `json:"metric"`
	Value  [2]any            `json:"value"`
}

func (s promSample) float() float64 {
	str, ok := s.Value[1].(string)
	if !ok {
		return 0
	}
	f, _ := strconv.ParseFloat(str, 64)
	return f
}

// promInstant runs an instant PromQL query and returns its result vector.
func promInstant(ctx context.Context, query string) ([]promSample, error) {
	endpoint := prometheusBaseURL() + "/api/v1/query?query=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
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
			Result []promSample `json:"result"`
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

// instanceIP strips the :port off a node-exporter instance label ("10.0.0.1:9100" -> "10.0.0.1").
func instanceIP(instance string) string {
	if i := strings.LastIndex(instance, ":"); i >= 0 {
		return instance[:i]
	}
	return instance
}

type nodeDisk struct {
	SizeBytes   float64 `json:"sizeBytes"`
	UsedBytes   float64 `json:"usedBytes"`
	AvailBytes  float64 `json:"availBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

// handleNodeDisk returns each node's root-filesystem usage from Prometheus, keyed by node IP.
//
// It fails soft: if Prometheus is unreachable or has no data (e.g. node-exporter not installed),
// it returns an empty map with 200 so the Nodes page simply omits the disk row rather than erroring.
func handleNodeDisk(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A user who can list nodes (i.e. can see the Nodes page) may read node utilization.
		if !authorize(w, r, cs, auth, logger, "list", "", "nodes", "", "") {
			return
		}

		// Real root filesystem only — exclude pseudo/overlay/read-only image filesystems.
		const rootFS = `mountpoint="/",fstype!~"tmpfs|overlay|squashfs|iso9660|ramfs|autofs"`
		sizes, err := promInstant(r.Context(), `node_filesystem_size_bytes{`+rootFS+`}`)
		if err != nil {
			logger.Warn("node disk: prometheus size query failed", slog.Any("err", err))
			writeJSON(w, http.StatusOK, map[string]nodeDisk{})
			return
		}
		avails, err := promInstant(r.Context(), `node_filesystem_avail_bytes{`+rootFS+`}`)
		if err != nil {
			logger.Warn("node disk: prometheus avail query failed", slog.Any("err", err))
			avails = nil
		}

		availByIP := make(map[string]float64, len(avails))
		for _, a := range avails {
			availByIP[instanceIP(a.Metric["instance"])] = a.float()
		}

		out := make(map[string]nodeDisk, len(sizes))
		for _, s := range sizes {
			ip := instanceIP(s.Metric["instance"])
			size := s.float()
			if size <= 0 || ip == "" {
				continue
			}
			avail := availByIP[ip]
			used := size - avail
			if used < 0 {
				used = 0
			}
			out[ip] = nodeDisk{
				SizeBytes:   size,
				UsedBytes:   used,
				AvailBytes:  avail,
				UsedPercent: used / size * 100,
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}
