// Command server is the open-infra console backend-for-frontend (BFF).
//
// It is a single container that:
// - serves the embedded React SPA at "/",
// - exposes runtime config at /api/config (read from env, not baked into JS),
// - reverse-proxies the Kubernetes API at /api/k8s/* using the pod's
// ServiceAccount, so the browser never holds cluster credentials,
// - streams Kubernetes watches to the browser as SSE at /api/watch,
// - serves RJSF-normalized CRD schemas at /api/crd-schema.
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

	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/crd"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"github.com/harn3ss/open-infra/console-api/internal/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

	// Reap JetStream streams/DLQ orphaned by deleted DataFlows (storage hygiene).
	startDataFlowGC(client.Host, client.Transport, logger)

	// Keep running VMs' launcher-pod SecurityGroup labels in sync with their spec,
	// so editing a VM's securityGroups takes effect live — no restart (like AWS).
	startSGSync(client.Host, client.Transport, logger)

	// Idle-stop the Trino coordinator (kind: Query's "Catalog" engine): scale to 0
	// when no engine=trino query has run recently, up to 1 when one appears.
	startTrinoAutostop(client.Host, client.Transport, *client.Clientset, logger)

	// Console authentication (AUTH_MODE: local | none; ldap/oidc reserved). On a fresh
	// install this bootstraps the console-auth Secret and prints root credentials once.
	auth, err := newAuthStore(*client.Clientset, logger)
	if err != nil {
		return err
	}
	logger.Info("console auth", slog.String("mode", auth.mode))

	// Distributed tracing (#67): opt-in via OTEL_EXPORTER_OTLP_ENDPOINT (Tempo).
	shutdownTracing, err := tracing.Init(context.Background(), "console-api")
	if err != nil {
		logger.Warn("tracing init failed; continuing without traces", slog.String("error", err.Error()))
	} else {
		defer func() { _ = shutdownTracing(context.Background()) }()
	}

	router := newRouter(client, auth, logger)

	srv := &http.Server{
		Addr:    addr,
		Handler: otelhttp.NewHandler(router, "console-api"),
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
func newRouter(client *k8s.Client, auth *authStore, logger *slog.Logger) http.Handler {
	r, _ := buildRouter(client, auth, logger)
	return r
}

// buildRouter is newRouter, also returning the console's IAM gate (its route registry), so a test can
// check that every route the router serves has an IAM action.
func buildRouter(client *k8s.Client, auth *authStore, logger *slog.Logger) (*chi.Mux, *consoleAuthz) {
	r := chi.NewRouter()

	// Standard middleware: request id, structured access logging via slog,
	// panic recovery, and a default per-request timeout. The timeout is scoped
	// so it does NOT wrap the watch/proxy routes, which are mounted on their own
	// sub-router below to avoid cutting off long-lived streams.
	r.Use(middleware.RequestID)
	r.Use(requestLogger(logger))
	r.Use(middleware.Recoverer)

	// One policy world: the bucket browser's object-storage check and every route's IAM gate read the
	// same IAM policy cache (iam_authz.go).
	checker := newPolicyChecker(client, logger)
	z := newConsoleAuthz(*client.Clientset, auth, checker, logger)
	consoleIAM = z
	logger.Info("console authorization", slog.String("iam_authz", string(z.eval.Mode())))

	// --- Health ---
	z.public(http.MethodGet, "/healthz", "liveness probe")
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// --- API ---
	r.Route("/api", func(api chi.Router) {
		// Authentication gate. Everything under /api requires a valid session cookie
		// except /api/auth/* — WITHOUT this, /api/k8s/* proxies the Kubernetes API
		// using the pod's ServiceAccount to any anonymous caller.
		api.Use(auth.requireAuth)

		// Read-only users may not invoke the BFF's own mutating endpoints (legacy and shadow; with IAM
		// policy deciding, writes are IAM actions like any other).
		api.Use(func(next http.Handler) http.Handler { return requireWrite(auth, next) })

		// Every route, with the IAM action it is and the resource it acts on (routes.go).
		registerAPIRoutes(api, z, client, auth, newBucketAuthzWith(*client.Clientset, auth, checker, logger), logger)
	})

	// --- Grafana reverse proxy (same-origin embedding) ---
	// When GRAFANA_PROXY_TARGET is set, proxy /grafana/* to the in-cluster
	// Grafana (which must serve_from_sub_path under /grafana). Same-origin means
	// the console can iframe dashboards with no CORS / cross-origin cookies and
	// no site-specific URL. No request timeout: Grafana has live/streaming calls.
	//
	// Behind requireSignedIn: Grafana runs with anonymous Viewer access for the
	// kiosk, so WITHOUT this gate anyone who can reach the console — including an
	// unauthenticated caller on an internet-exposed one — could read every
	// dashboard/metric/log here. A session check (not full requireAuth) so Grafana's
	// own POST /api/ds/query panel calls, which lack our CSRF header, still work.
	// With IAM policy deciding, it is CloudWatch's read surface: cloudwatch:GetDashboard.
	if gt := getenv("GRAFANA_PROXY_TARGET", ""); gt != "" {
		if gp, err := newGrafanaProxy(gt, logger); err != nil {
			logger.Error("invalid GRAFANA_PROXY_TARGET", slog.String("error", err.Error()))
		} else {
			z.perRequest(allMethods, "/grafana", "cloudwatch:GetDashboard (the dashboards proxy)")
			z.perRequest(allMethods, "/grafana/*", "cloudwatch:GetDashboard (the dashboards proxy)")
			r.With(auth.requireSignedIn, z.grafanaGate).Handle("/grafana", gp)
			r.With(auth.requireSignedIn, z.grafanaGate).Handle("/grafana/*", gp)
			logger.Info("grafana reverse proxy enabled (auth-gated)", slog.String("target", gt))
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

	return r, z
}

// configResponse is the runtime configuration handed to the browser.
type configResponse struct {
	ClusterName    string `json:"clusterName"`
	GrafanaBaseURL string `json:"grafanaBaseUrl"`
	Version        string `json:"version"`
	// AuthMode lets the SPA warn, persistently and visibly, when the console is
	// running unauthenticated (AUTH_MODE=none) — the startup log alone is invisible
	// to anyone using the UI.
	AuthMode string `json:"authMode"`
	// ChaosUIEnabled gates the fault-injection surface in the console. It is OFF by
	// default (least functionality, NIST CM-7): a deliberately-break-things tool is a
	// non-essential, privileged capability that a hardened/government deployment should
	// not surface. A non-production cluster opts in with CHAOS_UI_ENABLED=true.
	ChaosUIEnabled bool `json:"chaosUiEnabled"`
}

// handleConfig returns runtime config read from the environment. This is the
// "runtime config" pattern: values are NOT compiled into the SPA, so the same
// image runs in any cluster by varying env / ConfigMap.
func handleConfig(w http.ResponseWriter, _ *http.Request) {
	resp := configResponse{
		ClusterName:    os.Getenv("CLUSTER_NAME"),
		GrafanaBaseURL: os.Getenv("GRAFANA_BASE_URL"),
		Version:        version,
		AuthMode:       authMode(),
		ChaosUIEnabled: getenv("CHAOS_UI_ENABLED", "") == "true",
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

// writeJSON encodes v as JSON with the given status code. An error answer ({"error": …}, status 400 and
// up) is said in AWS's terms: a Kubernetes or Crossplane message the handler passed through is rewritten
// by awserr.Clean (the original is logged), and the AWS error code is added as "errorCode".
func writeJSON(w http.ResponseWriter, status int, v any) {
	if m, ok := v.(map[string]string); ok && status >= 400 {
		if msg, has := m["error"]; has {
			out := make(map[string]string, len(m)+1)
			for k, val := range m {
				out[k] = val
			}
			if clean := awserr.Clean(msg); clean != msg {
				out["error"] = clean
				slog.Default().Info("kubernetes error answered in AWS terms", slog.Int("status", status), slog.String("original", msg))
			}
			if _, set := out["errorCode"]; !set {
				out["errorCode"] = awserr.Code(status, "", msg)
			}
			v = out
		}
	}
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

			// Who-did-what: the auth middleware runs deeper in the chain, so its
			// context can't propagate back out here. Share a pointer it can fill
			// in, and read it when the request completes — otherwise every log
			// line is anonymous and you cannot answer "who deleted that VM?".
			id := &requestIdentity{}
			r = r.WithContext(context.WithValue(r.Context(), ctxIdentity{}, id))

			defer func() {
				attrs := []any{
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.Duration("duration", time.Since(start)),
					slog.String("request_id", middleware.GetReqID(r.Context())),
					slog.String("remote", r.RemoteAddr),
				}
				if id.user != "" {
					attrs = append(attrs,
						slog.String("user", id.user),
						slog.String("role", id.role))
				}
				logger.Info("http request", attrs...)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

// requestIdentity is filled in by the auth middleware so the access log can name
// the signed-in user. Pointer, because the logger holds the outer request.
type requestIdentity struct{ user, role string }

type ctxIdentity struct{}

// noteIdentity records the signed-in user for this request's access-log line.
func noteIdentity(r *http.Request, user, role string) {
	if id, ok := r.Context().Value(ctxIdentity{}).(*requestIdentity); ok {
		id.user, id.role = user, role
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
