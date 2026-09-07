package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Pod logs for a batch Job — the "kubectl logs -n … job/…" dead-end the SageMaker
// job family (TrainingJob / ProcessingJob / BatchTransform) pointed users at, brought
// in-console. Given the backing batch/v1 Job name, resolve its pods and tail each one's
// logs via the Kubernetes API (pods/log — a right the console SA already holds).
//
// Honest-empty: if the Job hasn't created a pod yet (or was garbage-collected), this
// returns {"pods": []} with 200 rather than a 500 — the UI shows "no logs yet", not an
// error. It never fabricates output.

const (
	jobLogsDefaultTail = 1000
	jobLogsMaxTail     = 5000
	// Per-pod byte cap so a single very chatty pod can't exhaust memory. tailLines
	// already bounds the line count; this bounds total bytes as a backstop.
	jobLogsMaxBytesPerPod = 8 << 20 // 8 MiB
)

// jobPods resolves the pods backing a batch/v1 Job by label selector. Kubernetes moved
// the pod→job label from the legacy `job-name` to `batch.kubernetes.io/job-name`; we try
// the current one first, then fall back, so this works on old and new clusters alike.
// Returns an empty slice (not an error) when the Job has no pods yet.
func jobPods(ctx context.Context, cs kubernetes.Interface, ns, name string, logger *slog.Logger) []corev1.Pod {
	for _, sel := range []string{
		"batch.kubernetes.io/job-name=" + name,
		"job-name=" + name,
	} {
		list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			if logger != nil {
				logger.Warn("job pods: list failed", slog.String("ns", ns), slog.String("job", name),
					slog.String("selector", sel), slog.Any("err", err))
			}
			continue
		}
		if len(list.Items) > 0 {
			return list.Items
		}
	}
	return nil
}

type podLog struct {
	Pod       string `json:"pod"`
	Container string `json:"container"`
	Logs      string `json:"logs"`
}

type jobLogsResp struct {
	Pods []podLog `json:"pods"`
}

// handleJobLogs tails the logs of every pod backing the named batch/v1 Job.
//
//	GET /api/jobs/{namespace}/{name}/logs?tailLines=&container=
//
// tailLines defaults to 1000 and is capped at 5000; container selects a specific
// container (default: the pod's first container). Aggregated across all of the Job's pods.
func handleJobLogs(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")

		tail := int64(jobLogsDefaultTail)
		if v := r.URL.Query().Get("tailLines"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				tail = n
			}
		}
		if tail > jobLogsMaxTail {
			tail = jobLogsMaxTail
		}
		container := r.URL.Query().Get("container")

		ctx := r.Context()
		out := jobLogsResp{Pods: []podLog{}}

		pods := jobPods(ctx, cs, ns, name, logger)
		for i := range pods {
			pod := &pods[i]

			// Choose the container: caller-specified, else the pod's first container.
			c := container
			if c == "" && len(pod.Spec.Containers) > 0 {
				c = pod.Spec.Containers[0].Name
			}

			opts := &corev1.PodLogOptions{TailLines: &tail}
			if c != "" {
				opts.Container = c
			}
			stream, err := cs.CoreV1().Pods(ns).GetLogs(pod.Name, opts).Stream(ctx)
			if err != nil {
				// A pod that is still ContainerCreating (or whose container has no logs
				// yet) can't be streamed — surface that honestly per-pod, keep going.
				logger.Warn("job logs: open stream failed", slog.String("ns", ns),
					slog.String("pod", pod.Name), slog.Any("err", err))
				out.Pods = append(out.Pods, podLog{
					Pod:       pod.Name,
					Container: c,
					Logs:      "— logs unavailable for this pod: " + err.Error(),
				})
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(stream, jobLogsMaxBytesPerPod))
			_ = stream.Close()
			out.Pods = append(out.Pods, podLog{Pod: pod.Name, Container: c, Logs: string(b)})
		}

		writeJSON(w, http.StatusOK, out)
	}
}
