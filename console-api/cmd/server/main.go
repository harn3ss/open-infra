// Command server is the open-infra console backend-for-frontend (BFF).
//
// It is a single container that:
//   - serves the embedded React SPA at "/",
//   - exposes runtime config at /api/config (read from env, not baked into JS),
//   - reverse-proxies the Kubernetes API at /api/k8s/* using the pod's
//     ServiceAccount, so the browser never holds cluster credentials,
//   - streams Kubernetes watches to the browser as SSE at /api/watch,
//   - serves RJSF-normalized CRD schemas at /api/crd-schema.
//
// Authorization for all cluster operations is the ServiceAccount's RBAC — this
// process performs no authorization of its own. The SA MUST be narrowly scoped.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/elemenopyunome/open-infra/console-api/internal/crd"
	"github.com/elemenopyunome/open-infra/console-api/internal/k8s"
	"github.com/elemenopyunome/open-infra/console-api/internal/proxy"
	"github.com/elemenopyunome/open-infra/console-api/internal/watch"
)

// version is the build version, overridden at link time via
// -ldflags "-X main.version=<tag>". It is surfaced through /api/config.
var version = "dev"

// k8sPrefix is the router mount point for the Kubernetes reverse proxy; it is
// stripped before requests are forwarded upstream.
const k8sPrefix = "/api/k8s"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevelFromEnv(),
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("server exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// run wires up dependencies and the HTTP server, then blocks until a shutdown
// signal arrives and the server has drained.
func run(logger *slog.Logger) error {
	addr := getenv("LISTEN_ADDR", ":8080")

	// Resolve cluster credentials: in-cluster ServiceAccount in production, or a
	// kubeconfig ($KUBECONFIG / ~/.kube/config) for local development.
	client, err := k8s.New(getenv("KUBECONFIG", ""))
	if err != nil {
		return err
	}
	logger.Info("connected to Kubernetes API", slog.String("host", client.Host.String()))

	router := newRouter(client, logger)

	srv := &http.Server{
		Addr:    addr,
		Handler: router,
		// Generous header timeout, but no global write timeout: /api/watch is a
		// long-lived SSE stream and a WriteTimeout would sever it. Per-request
		// deadlines for the short endpoints are enforced via context elsewhere.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Run the listener in the background so main can wait on signals.
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("console-api listening",
			slog.String("addr", addr), slog.String("version", version))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Block until we either fail to serve or receive SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	}

	// Graceful shutdown: stop accepting new connections and give in-flight
	// requests up to 15s to finish. SSE streams are tied to their request
	// context and unblock when the server closes.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("shutdown complete")
	return nil
}

// newRouter assembles the chi router with middleware and all routes.
func newRouter(client *k8s.Client, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Standard middleware: request id, structured access logging via slog,
	// panic recovery, and a default per-request timeout. The timeout is scoped
	// so it does NOT wrap the watch/proxy routes, which are mounted on their own
	// sub-router below to avoid cutting off long-lived streams.
	r.Use(middleware.RequestID)
	r.Use(requestLogger(logger))
	r.Use(middleware.Recoverer)

	// --- Health ---
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// --- API ---
	r.Route("/api", func(api chi.Router) {
		// Runtime config: read from env on every request so a redeploy or
		// ConfigMap change is picked up without rebuilding the SPA.
		api.Get("/config", handleConfig)

		// Grafana dashboard list (server-side proxy to Grafana's /api/search) so
		// the SPA can populate a dashboard picker without hitting CORS. Read-only.
		api.With(middleware.Timeout(15*time.Second)).
			Get("/grafana/dashboards", handleGrafanaDashboards(logger))

		// CRD schema (short-lived): wrap with a request timeout.
		api.With(middleware.Timeout(15*time.Second)).
			Get("/crd-schema", handleCRDSchema(crd.New(client.Host, client.Transport), logger))

		// MinIO object storage (S3 browser) + NATS JetStream (queues). These talk
		// to in-cluster MinIO/NATS rather than the k8s API, so they're their own
		// endpoints (not the /k8s proxy).
		api.With(middleware.Timeout(15*time.Second)).
			Get("/buckets", handleBuckets(*client.Clientset, logger))
		api.With(middleware.Timeout(20*time.Second)).
			Get("/buckets/{bucket}/objects", handleBucketObjects(*client.Clientset, logger))
		api.With(middleware.Timeout(10*time.Second)).
			Get("/queues", handleQueues(logger))

		// Resource interactions: bucket/object writes, model chat (playground),
		// queue publish/purge. Upload/download have no request timeout (large
		// transfers); chat allows a long timeout for generation.
		api.With(middleware.Timeout(10*time.Second)).
			Post("/buckets", handleCreateBucket(*client.Clientset, logger))
		api.With(middleware.Timeout(10*time.Second)).
			Delete("/buckets/{bucket}", handleDeleteBucket(*client.Clientset, logger))
		api.Put("/buckets/{bucket}/object", handleUploadObject(*client.Clientset, logger))
		api.Get("/buckets/{bucket}/object", handleDownloadObject(*client.Clientset, logger))
		api.With(middleware.Timeout(10*time.Second)).
			Delete("/buckets/{bucket}/object", handleDeleteObject(*client.Clientset, logger))
		api.With(middleware.Timeout(125*time.Second)).
			Post("/models/{namespace}/{name}/chat", handleModelChat(*client.Clientset, logger))
		api.With(middleware.Timeout(65*time.Second)).
			Post("/functions/{namespace}/{name}/invoke", handleFunctionInvoke(*client.Clientset, logger))
		api.With(middleware.Timeout(10*time.Second)).
			Post("/queues/publish", handleQueuePublish(logger))
		api.With(middleware.Timeout(15*time.Second)).
			Post("/queues/{stream}/purge", handleQueuePurge(logger))

		// Watch (long-lived SSE): NO request timeout — the stream must stay open.
		api.Get("/watch", watch.New(client.Host, client.Transport, logger).ServeHTTP)

		// Kubernetes reverse proxy (CRUD). Mounted under /api/k8s and stripped
		// before forwarding. No write timeout so large applies / log follows are
		// not cut off; the SA's RBAC is the authorization.
		api.Handle("/k8s", proxy.New(client.Host, client.Transport, k8sPrefix, logger))
		api.Handle("/k8s/*", proxy.New(client.Host, client.Transport, k8sPrefix, logger))
	})

	// --- Grafana reverse proxy (same-origin embedding) ---
	// When GRAFANA_PROXY_TARGET is set, proxy /grafana/* to the in-cluster
	// Grafana (which must serve_from_sub_path under /grafana). Same-origin means
	// the console can iframe dashboards with no CORS / cross-origin cookies and
	// no site-specific URL. No request timeout: Grafana has live/streaming calls.
	if gt := getenv("GRAFANA_PROXY_TARGET", ""); gt != "" {
		if gp, err := newGrafanaProxy(gt, logger); err != nil {
			logger.Error("invalid GRAFANA_PROXY_TARGET", slog.String("error", err.Error()))
		} else {
			r.Handle("/grafana", gp)
			r.Handle("/grafana/*", gp)
			logger.Info("grafana reverse proxy enabled", slog.String("target", gt))
		}
	}

	// --- SPA (fallback for everything else) ---
	spa, err := newSPAHandler()
	if err != nil {
		// An embed failure is a build-time bug; fail loudly at startup.
		logger.Error("failed to initialize SPA handler", slog.String("error", err.Error()))
		os.Exit(1)
	}
	r.NotFound(spa.ServeHTTP)

	return r
}

// configResponse is the runtime configuration handed to the browser.
type configResponse struct {
	ClusterName    string `json:"clusterName"`
	GrafanaBaseURL string `json:"grafanaBaseUrl"`
	Version        string `json:"version"`
}

// handleConfig returns runtime config read from the environment. This is the
// "runtime config" pattern: values are NOT compiled into the SPA, so the same
// image runs in any cluster by varying env / ConfigMap.
func handleConfig(w http.ResponseWriter, _ *http.Request) {
	resp := configResponse{
		ClusterName:    os.Getenv("CLUSTER_NAME"),
		GrafanaBaseURL: os.Getenv("GRAFANA_BASE_URL"),
		Version:        version,
	}
	writeJSON(w, http.StatusOK, resp)
}

// newGrafanaProxy builds a reverse proxy to an in-cluster Grafana that serves
// from the /grafana subpath. The path (including the /grafana prefix) is passed
// through unchanged. Frame-blocking headers are dropped so the console can embed
// dashboards same-origin in an iframe.
func newGrafanaProxy(target string, logger *slog.Logger) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("GRAFANA_PROXY_TARGET must be an absolute URL")
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("Content-Security-Policy")
		return nil
	}
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
		logger.Warn("grafana proxy error", slog.String("error", e.Error()))
		http.Error(w, "grafana upstream unavailable", http.StatusBadGateway)
	}
	return rp, nil
}

// grafanaSearchURL returns the absolute Grafana dashboard-search URL for
// server-side calls: the in-cluster proxy target (Grafana under /grafana) when
// set, else a direct absolute base URL (Grafana at root). Empty if neither is
// usable server-side (e.g. a relative GRAFANA_BASE_URL like "/grafana").
func grafanaSearchURL() string {
	const q = "/api/search?type=dash-db&limit=500"
	if t := strings.TrimRight(os.Getenv("GRAFANA_PROXY_TARGET"), "/"); t != "" {
		return t + "/grafana" + q
	}
	if b := strings.TrimRight(os.Getenv("GRAFANA_BASE_URL"), "/"); strings.HasPrefix(b, "http") {
		return b + q
	}
	return ""
}

// handleGrafanaDashboards proxies Grafana's dashboard search to the SPA. The
// browser can't call Grafana directly (CORS), so the BFF fetches it server-side.
// Returns an empty list when Grafana isn't configured/reachable so the Monitoring
// page degrades gracefully rather than erroring.
func handleGrafanaDashboards(logger *slog.Logger) http.HandlerFunc {
	cl := &http.Client{Timeout: 10 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		endpoint := grafanaSearchURL()
		if endpoint == "" {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
		if err != nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		resp, err := cl.Do(req)
		if err != nil {
			logger.Warn("grafana dashboard search failed", slog.String("error", err.Error()))
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// handleCRDSchema serves a CRD's storage-version schema, normalized for
// react-jsonschema-form. The CRD name is required, e.g.
// /api/crd-schema?name=applications.openinfra.dev
func handleCRDSchema(fetcher *crd.Fetcher, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "missing required query parameter: name", http.StatusBadRequest)
			return
		}

		schema, err := fetcher.Schema(r.Context(), name)
		if err != nil {
			var se *crd.StatusError
			if errors.As(err, &se) {
				http.Error(w, se.Msg, se.Code)
				return
			}
			logger.Error("crd schema fetch failed",
				slog.String("name", name), slog.String("error", err.Error()))
			http.Error(w, "failed to fetch CRD schema", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(schema)
	}
}

// writeJSON encodes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Headers are already sent; nothing actionable but log via default.
		slog.Default().Error("failed to encode JSON response", slog.String("error", err.Error()))
	}
}

// requestLogger is a chi middleware that emits one structured access-log line per
// request using slog, including method, path, status, byte count, and latency.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()
			defer func() {
				logger.Info("http request",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.Duration("duration", time.Since(start)),
					slog.String("request_id", middleware.GetReqID(r.Context())),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

// getenv returns the value of key, or def when unset/empty.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// logLevelFromEnv maps LOG_LEVEL (debug|info|warn|error) to an slog level,
// defaulting to info.
func logLevelFromEnv() slog.Level {
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
