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
	"log/slog"
	"net/http"
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

		// CRD schema (short-lived): wrap with a request timeout.
		api.With(middleware.Timeout(15*time.Second)).
			Get("/crd-schema", handleCRDSchema(crd.New(client.Host, client.Transport), logger))

		// Watch (long-lived SSE): NO request timeout — the stream must stay open.
		api.Get("/watch", watch.New(client.Host, client.Transport, logger).ServeHTTP)

		// Kubernetes reverse proxy (CRUD). Mounted under /api/k8s and stripped
		// before forwarding. No write timeout so large applies / log follows are
		// not cut off; the SA's RBAC is the authorization.
		api.Handle("/k8s", proxy.New(client.Host, client.Transport, k8sPrefix, logger))
		api.Handle("/k8s/*", proxy.New(client.Host, client.Transport, k8sPrefix, logger))
	})

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
