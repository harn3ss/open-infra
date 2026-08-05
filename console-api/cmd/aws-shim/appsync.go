package main

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// appsyncHandler fronts AWS AppSync's data plane (managed GraphQL) over a real GraphQL engine
// (Hasura, over the managed Postgres). AppSync's data plane IS GraphQL-over-HTTPS: an SDK/Amplify
// client with IAM auth signs a `POST {query, variables}` with SigV4 (service "appsync"); the shim
// verifies that signature, then forwards the GraphQL body to the engine's /v1/graphql and returns
// its response verbatim. GraphQL response shape (`{data, errors}`) is identical between AppSync and
// the engine, so a GraphQL client can't tell the difference.
//
// Authorization model (honest about the split): the SHIM authenticates (SigV4 → principal) and runs
// a coarse platform-membership gate; the ENGINE authorizes per operation. The shim presents the
// engine's admin secret (proving it is the trusted gateway) AND a NON-admin x-hasura-role derived
// from the principal plus x-hasura-user-id — so the engine applies that role's row/column
// permissions. The shim never lets a caller act as the engine admin. Per-role mapping and the
// AppSync *management* API (schema/resolver CRUD) are the flagged graduations; v1 is the data plane.
type appsyncHandler struct {
	cs          kubernetes.Interface
	client      *http.Client
	endpoint    string // GraphQL engine base URL (…/v1/graphql is appended)
	adminSecret string // engine admin secret; presented so the engine trusts our x-hasura-* headers
	authzNS     string // namespace the coarse platform-membership gate is evaluated in
	logger      *slog.Logger
}

func newAppsyncHandler(cs kubernetes.Interface, endpoint, adminSecret, authzNS string, logger *slog.Logger) *appsyncHandler {
	return &appsyncHandler{
		cs:          cs,
		client:      &http.Client{Timeout: 30 * time.Second},
		endpoint:    endpoint,
		adminSecret: adminSecret,
		authzNS:     authzNS,
		logger:      logger,
	}
}

func (h *appsyncHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeAppsyncError(w, http.StatusUnauthorized, "UnauthorizedException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func (h *appsyncHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if r.Method != http.MethodPost {
		writeAppsyncError(w, http.StatusBadRequest, "BadRequestException", requestID, "GraphQL requests must be POST")
		return
	}

	// Coarse platform-membership gate via the shared impersonated SubjectAccessReview — one policy
	// world. Fine-grained (per-type/row) authorization is delegated to the engine via x-hasura-role.
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "get", "openinfra.dev", "applications", h.authzNS, ""); !allowed {
		h.logger.Warn("appsync denied", "user", claims.Sub, "reason", reason)
		writeAppsyncError(w, http.StatusForbidden, "UnauthorizedException", requestID,
			"not authorized to use the GraphQL API")
		return
	}

	target := strings.TrimRight(h.endpoint, "/") + "/v1/graphql"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, r.Body)
	if err != nil {
		writeAppsyncError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not build upstream request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Present the admin secret so the engine trusts the identity headers, then act AS a non-admin
	// role scoped to this principal — the engine enforces that role's permissions.
	if h.adminSecret != "" {
		req.Header.Set("x-hasura-admin-secret", h.adminSecret)
	}
	req.Header.Set("x-hasura-role", hasuraRole(claims))
	req.Header.Set("x-hasura-user-id", claims.Sub)

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Warn("appsync upstream unreachable", "endpoint", h.endpoint, "error", err.Error())
		writeAppsyncError(w, http.StatusBadGateway, "InternalFailure", requestID, "the GraphQL engine is unreachable")
		return
	}
	defer resp.Body.Close()

	// GraphQL responses ({data, errors}) pass through unchanged.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hasuraRole maps an open-infra principal onto a GraphQL-engine role. v1 deliberately NEVER returns
// the engine's admin role — every shim caller acts as a bounded role, so no principal can gain
// admin over the engine through the shim. Per-group role mapping is a flagged graduation.
func hasuraRole(_ iam.Claims) string {
	return "user"
}

// writeAppsyncError writes AppSync's error dialect: a GraphQL-style JSON `errors` array carrying an
// AWS `errorType`, which both GraphQL clients and the AppSync SDK can parse.
func writeAppsyncError(w http.ResponseWriter, status int, errorType, requestID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-ErrorType", errorType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	// Minimal hand-rolled JSON to avoid a struct just for errors; message/errorType are controlled.
	_, _ = io.WriteString(w, `{"errors":[{"errorType":"`+errorType+`","message":"`+jsonEscape(message)+`"}]}`)
}

// jsonEscape escapes the few characters that could break the inline error JSON above.
func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
