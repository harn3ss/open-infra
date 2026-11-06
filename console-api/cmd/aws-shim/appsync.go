package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// appsyncHandler fronts AWS AppSync's data plane over open-infra's own AppSync engine, "open-appsync"
// (opt-in component `openAppsync`). open-appsync is resolver-first and VTL-faithful — the authoring
// model AppSync-locked teams actually depend on — NOT a GraphQL-over-tables engine wearing a mask.
// (An earlier drop fronted a GraphQL-over-tables placeholder here; it was the wrong model for
// resolver fidelity and has been removed.)
//
// An SDK/Amplify client with IAM auth signs a `POST {query, variables}` with SigV4 (service
// `appsync`); the shim verifies that signature (router), runs the coarse platform-membership gate,
// and forwards the GraphQL body to the engine. Three disciplines are load-bearing:
// - the SigV4 verification + the impersonated coarse IAM gate ("one policy world, four front doors");
// - the fresh-upstream-request discipline: a brand-new request is built so NO client header is ever
// forwarded to the engine (an attacker can't smuggle an identity/role/secret header);
// - component-gating: engine absent → 502; OFF unless explicitly enabled.
// open-appsync is our OWN engine, so the shim conveys the verified principal as its auth context
// (X-OpenInfra-User) and open-appsync enforces fine-grained authz internally against the same
// principals — no foreign admin secret, no vendor-specific role header.
type appsyncHandler struct {
	cs       kubernetes.Interface
	client   *http.Client
	endpoint string   // open-appsync engine base URL (…/graphql is appended)
	authzNS  string   // namespace the coarse platform-membership gate is evaluated in
	apis     apiStore // Stage-2 management: read-modify-write of GraphQLApi claims
	// authz is the data-plane engine: an assumed role's GraphQL requests and API management are
	// default-deny under it. nil = no engine — a role is then denied.
	authz  *dataplaneauthz.Checker
	logger *slog.Logger
	// account and region make an API's ARN in the management reads (appsync_read.go).
	account, region string
	// accounts names the account each namespace belongs to (internal/accounts.Directory): the management
	// plane reaches the caller's account's APIs alone (appsync_accounts.go). nil: a member account's APIs
	// are those in its home alone, and the management account reaches every namespace, as before accounts.
	accounts appsyncAccounts
}

func newAppsyncHandler(cs kubernetes.Interface, endpoint, authzNS string, logger *slog.Logger) *appsyncHandler {
	return &appsyncHandler{
		cs:       cs,
		client:   &http.Client{Timeout: 30 * time.Second},
		endpoint: endpoint,
		authzNS:  authzNS,
		apis:     restAPIStore{cs: cs},
		logger:   logger,
	}
}

// restAPIStore reads/writes GraphQLApi claims via the cluster REST client (the same AbsPath mechanism
// the owner-resolver uses for iam Users), so the shim needs no extra client — its ServiceAccount RBAC
// is the authority.
type restAPIStore struct{ cs kubernetes.Interface }

func (s restAPIStore) path(ns, name string) string {
	return "/apis/openinfra.dev/v1/namespaces/" + ns + "/graphqlapis/" + name
}

func (s restAPIStore) Get(ctx context.Context, ns, name string) (map[string]any, error) {
	raw, err := s.cs.CoreV1().RESTClient().Get().AbsPath(s.path(ns, name)).DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// List reads a page of GraphQLApi claims across the cluster with the API server's limit/continue paging.
func (s restAPIStore) List(ctx context.Context, limit int64, cont string) ([]map[string]any, string, error) {
	req := s.cs.CoreV1().RESTClient().Get().AbsPath("/apis/openinfra.dev/v1/graphqlapis").
		Param("limit", strconv.FormatInt(limit, 10))
	if cont != "" {
		req = req.Param("continue", cont)
	}
	raw, err := req.DoRaw(ctx)
	if err != nil {
		return nil, "", err
	}
	var list struct {
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, "", err
	}
	return list.Items, list.Metadata.Continue, nil
}

func (s restAPIStore) Update(ctx context.Context, ns, name string, obj map[string]any) error {
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = s.cs.CoreV1().RESTClient().Put().AbsPath(s.path(ns, name)).
		SetHeader("Content-Type", "application/json").Body(body).DoRaw(ctx)
	return err
}

func (h *appsyncHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeAppsyncError(w, http.StatusUnauthorized, "UnauthorizedException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func (h *appsyncHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	// The management (control) plane and the data plane share the SigV4 service "appsync"; they are
	// told apart by path. /v1/... is the AWS management API → the Stage-2 skin (patch the GraphQLApi
	// object). Everything else is the GraphQL data plane → forward to the engine.
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		h.serveManagement(w, r, claims, requestID)
		return
	}
	if r.Method != http.MethodPost {
		writeAppsyncError(w, http.StatusBadRequest, "BadRequestException", requestID, "GraphQL requests must be POST")
		return
	}

	// Coarse platform-membership gate via the shared impersonated SubjectAccessReview — one policy
	// world. Fine-grained (per-type/field/resolver) authorization lives INSIDE open-appsync, which
	// resolves the same principal conveyed below.
	// appsync:GraphQL on GraphQLApi::* (decide) — this endpoint does not name one API, so a grant on a
	// specific API ARN does not reach it. In legacy the coarse platform-membership gate first, then the
	// data-plane check: an assumed role's authority is its data-plane policy (CanDo passes a role), so it is
	// default-deny for a role; for a User it holds an explicit Deny of appsync:GraphQL (the gate stays its
	// grant). In enforce IAM policy alone.
	//
	// The engine behind this endpoint is the platform's one open-appsync engine, the management account's
	// (each account's GraphQLApi claims are its own on the management plane): a member account's principal
	// reaches it as AWS reaches another account's resource, so the request is decided outside the account
	// scope the router gave the "appsync" signing name (appsync_accounts.go).
	dctx := withAccountScope(r.Context(), false)
	if ok, reason := decide(dctx, r, h.authz, claims, "appsync:GraphQL", "GraphQLApi", "",
		coarseThenDataPlane(dctx, r, h.cs, h.authz, claims, "get", "openinfra.dev", "applications", h.authzNS, "",
			"appsync:GraphQL", "GraphQLApi", "")); !ok {
		h.logger.Warn("appsync denied (data plane)", "user", claims.Sub, "reason", reason)
		writeAppsyncError(w, http.StatusForbidden, "UnauthorizedException", requestID,
			"not authorized to use the GraphQL API")
		return
	}

	// Fresh upstream request — never forward client headers. The GraphQL body streams straight
	// through; the verified principal is conveyed as open-appsync's auth context.
	target := strings.TrimRight(h.endpoint, "/") + "/graphql"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, r.Body)
	if err != nil {
		writeAppsyncError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not build upstream request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Convey the principal as iam.Identity resolves it — the SINGLE definition of "who this is to the API
	// server", the same one this handler's coarse gate (iam.CanDo) authorized against. That means the
	// NAMESPACED user (openinfra:<sub>), never the raw, attacker-influenced subject: otherwise the engine's
	// field-level SAR would impersonate a raw sub, and a sub equal to a privileged cluster identity (e.g.
	// a kube-system ServiceAccount) would pass field gates the real caller must fail. Groups are already
	// namespaced + comma-free (iam.GroupsFromSpec), so the comma-joined header round-trips losslessly.
	// In enforce the identity is the account-qualified one (callerIdentity), whose RBAC IAM policy compiles.
	if user, groups, ok := callerIdentity(r.Context(), h.authz, claims); ok {
		req.Header.Set("X-OpenInfra-User", user)
		if len(groups) > 0 {
			req.Header.Set("X-OpenInfra-Groups", strings.Join(groups, ","))
		}
	}
	// Tag the auth mode so open-appsync can enforce the field's @aws_* directive: the mode gate passes
	// and the field's SAR then runs against the principal above. SigV4 requests are aws_iam (the default);
	// an OIDC/Cognito bearer-JWT request carries its mode via the request context (set by the router).
	// Same trust boundary as X-OpenInfra-User — only the shim sets these; the engine isn't exposed.
	req.Header.Set("X-OpenInfra-Auth-Mode", forwardedMode(r.Context()))

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

// writeAppsyncError writes AppSync's error dialect: a GraphQL-style JSON `errors` array carrying an
// AWS `errorType`, which both GraphQL clients and the AppSync SDK can parse.
func writeAppsyncError(w http.ResponseWriter, status int, errorType, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-ErrorType", errorType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"errors":[{"errorType":"`+errorType+`","message":"`+jsonEscape(message)+`"}]}`)
}

// jsonEscape escapes the few characters that could break the inline error JSON above.
func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
