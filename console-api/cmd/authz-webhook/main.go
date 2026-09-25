// authz-webhook is a spike of the open-infra control-plane authorization webhook: it implements the
// Kubernetes authorization-webhook contract (a SubjectAccessReview in, an allow/deny/no-opinion out)
// and decides via the Cedar policy engine over kind: Policy spec.controlPlane. See
// docs/authz-webhook.md.
//
// SPIKE — NOT wired to any live API server. It defaults to SHADOW mode: it computes and logs the
// Cedar decision but always returns "no opinion", so a real chain still decides with RBAC. This is
// how divergence is measured before anything is enforced. AUTHZ_MODE=enforce returns the Cedar
// decision (default-deny) — only for a cluster whose implicit principals already have explicit
// grants. Serving TLS with the FIPS-validated modules is a deployment concern (the webhook is a
// control-plane network service); this spike serves plain HTTP for offline testing.
package main

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	mode := Shadow
	if os.Getenv("AUTHZ_MODE") == "enforce" {
		mode = Enforce
	}

	cfg, err := restConfig()
	if err != nil {
		logger.Error("cannot build a kube client config", "err", err)
		os.Exit(1)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error("cannot build a dynamic client", "err", err)
		os.Exit(1)
	}
	checker := controlplaneauthz.New(controlplaneauthz.K8sLoader(dyn), 30*time.Second)
	h := &webhookHandler{checker: checker, mode: mode, logger: logger,
		breakGlass: breakGlassGroups(), breakGlassUsers: breakGlassUsers()}
	if mode == Enforce {
		logger.Info("break-glass floor active (corpus-independent)",
			"groups", keysOf(h.breakGlass), "users", keysOf(h.breakGlassUsers))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", h.serve)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	// The API server connects over TLS. Serve HTTPS when a cert/key are provided (the deployed
	// path); fall back to plain HTTP only when they are absent (local runs / offline testing).
	cert, key := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if cert != "" && key != "" {
		logger.Info("control-plane authz webhook (TLS)", "mode", mode, "addr", addr)
		if err := srv.ListenAndServeTLS(cert, key); err != nil {
			logger.Error("server exited", "err", err)
			os.Exit(1)
		}
		return
	}
	logger.Warn("control-plane authz webhook (PLAINTEXT — no TLS_CERT_FILE/TLS_KEY_FILE; for local use only)", "mode", mode, "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func restConfig() (*rest.Config, error) {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}
	return rest.InClusterConfig()
}

// breakGlassGroups is the set of GROUPS always allowed in enforce, independent of the Cedar corpus —
// the recovery floor so removing RBAC can never lock out cluster-admin. Defaults to system:masters
// (the admin kubeconfig group); override with BREAK_GLASS_GROUPS (comma-separated).
func breakGlassGroups() map[string]bool {
	groups := os.Getenv("BREAK_GLASS_GROUPS")
	if groups == "" {
		groups = "system:masters"
	}
	out := map[string]bool{}
	for _, g := range strings.Split(groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out[g] = true
		}
	}
	return out
}

// breakGlassUsers is the set of exact USERS always allowed in enforce. It ALWAYS includes the
// webhook's own ServiceAccount (auto-derived from its projected token, below): the authorizer's own
// identity MUST be authorizable without the authorizer, or it deadlocks loading its corpus on the
// first enforce request. This replaces break-glassing the whole open-infra-authz namespace (which also
// covered the corpus-auditor SA — that one is granted by the corpus like any other principal, so it
// no longer needs a bypass). Extend with BREAK_GLASS_USERS (comma-separated) if ever needed.
func breakGlassUsers() map[string]bool {
	out := map[string]bool{}
	if self := selfServiceAccountUser(); self != "" {
		out[self] = true
	}
	for _, u := range strings.Split(os.Getenv("BREAK_GLASS_USERS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			out[u] = true
		}
	}
	return out
}

// selfServiceAccountUser returns the webhook's own ServiceAccount username
// ("system:serviceaccount:<ns>:<name>") from the "sub" claim of its projected SA token — its own
// token, so the claim is read, not verified. Returns "" off-cluster (e.g. unit tests / local runs).
func selfServiceAccountUser() string {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
