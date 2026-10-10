// AWS ECR (Elastic Container Registry) front door for the aws-shim (polyhedron#177).
//
// Speaks the Amazon ECR API (AWS JSON 1.1, the operation named in X-Amz-Target:
// AmazonEC2ContainerRegistry_V20150921.<Op>), authenticates through the shared SigV4 path, authorizes with
// the one policy world every front door uses (coarse impersonated SubjectAccessReview + fine-grained Cedar
// dataPlane at REPOSITORY granularity), and answers against a backing OCI registry (the Distribution /v2
// API) for image facts, plus small ConfigMap records for repository metadata (see ecr_store.go).
//
// The data plane is deliberately the STANDARD OCI protocol: `aws ecr get-login-password` yields the
// registry credential, and `docker login/push/pull` then talk to the registry directly at the
// proxyEndpoint. GetAuthorizationToken hands back exactly that credential. The control plane here
// (repositories, image listing/description, deletion) is what the ECR SDK/CLI drive.
//
// Deliberate carve-outs, refused honestly rather than faked (see ecrRefusal): image scanning, lifecycle
// policies, cross-region replication, repository/registry resource policies (authorization is the shim's
// one RBAC + Cedar world, not a second ECR-native policy language), pull-through cache, the ECR internal
// layer upload API (PutImage/InitiateLayerUpload/UploadLayerPart/CompleteLayerUpload — the data plane is
// standard OCI, not this), and resource tags.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// the AWS JSON 1.1 X-Amz-Target prefix the ECR SDKs and aws CLI sign for.
const ecrTargetPrefix = "AmazonEC2ContainerRegistry_V20150921"

// ecrNamePattern is AWS's repository-name constraint (lowercase; '.', '_', '-' only as single separators
// between alphanumeric runs; '/' as a namespace separator), checked alongside the 256-char length cap.
const ecrNamePattern = `^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*$`

var ecrNameRE = regexp.MustCompile(ecrNamePattern)

type ecrHandler struct {
	cs            kubernetes.Interface
	authzNS       string
	account       string // registryId, e.g. "open-infra"
	region        string // e.g. "us-east-1"
	ns            string // bookkeeping + registry-auth namespace (open-infra-ecr)
	registryURL   string // in-cluster registry base for the shim's own /v2 calls, no trailing slash
	proxyEndpoint string // what GetAuthorizationToken returns + the repositoryUri base (e.g. http://ecr-registry...:5000)
	authSecret    string // name of the registry credential Secret in ns (ecr-registry-auth; keys: username, password)
	authz         *dataplaneauthz.Checker
	// Per-repo data-plane auth (the Docker bearer-token protocol). signer mints the caller credential
	// + the per-repo registry tokens; tokenAuth gates GetAuthorizationToken onto that path (set together
	// with the registry's token-auth config — until then GetAuthorizationToken returns the htpasswd cred).
	signer    *ecrTokenSigner
	tokenAuth bool
	issuer    string // the registry token issuer (must match the registry config's ISSUER)
	service   string // the registry token service/audience (must match the registry config's SERVICE)
	logger    *slog.Logger
}

func newECRHandler(cs kubernetes.Interface, authzNS, account, region, ns, registryURL, proxyEndpoint, authSecret string, logger *slog.Logger) *ecrHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &ecrHandler{
		cs:            cs,
		authzNS:       authzNS,
		account:       account,
		region:        region,
		ns:            ns,
		registryURL:   registryURL,
		proxyEndpoint: proxyEndpoint,
		authSecret:    authSecret,
		logger:        logger,
	}
}

// --- error dialect (AWS JSON 1.1). ECR surfaces the bare exception name in __type, like KMS. ---

func writeECRError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeECRJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *ecrHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	// AWS surfaces a SigV4 mismatch as InvalidSignatureException before the service sees it.
	writeECRError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForECROp maps an ECR operation to the coarse RBAC verb its SubjectAccessReview checks
// (read ops -> get, repository create/config -> create, deletions -> delete). Unknown -> not recognized.
func verbForECROp(op string) (string, bool) {
	switch op {
	case "GetAuthorizationToken", "DescribeRepositories", "ListImages", "DescribeImages",
		"BatchGetImage", "BatchCheckLayerAvailability", "GetDownloadUrlForLayer":
		return "get", true
	case "CreateRepository", "PutImageTagMutability":
		return "create", true
	case "DeleteRepository", "BatchDeleteImage":
		return "delete", true
	}
	return "", false
}

// ecrResource resolves the repository name an op scopes to (for the authz gate). Ops with no single
// repository (GetAuthorizationToken, an unfiltered DescribeRepositories) return "".
func ecrResource(op string, body map[string]any) string {
	switch op {
	case "CreateRepository", "DeleteRepository", "ListImages", "DescribeImages", "BatchDeleteImage",
		"PutImageTagMutability", "BatchGetImage", "BatchCheckLayerAvailability", "GetDownloadUrlForLayer":
		return firstString(body, "repositoryName")
	case "DescribeRepositories":
		if n := stringSlice(body["repositoryNames"]); len(n) > 0 {
			return n[0]
		}
	}
	return ""
}

// ecrRefusal returns the honest reason an op is deliberately NOT implemented (and true), or "" and false.
// Each message names the op and WHY — a refusal is never a faked success.
func ecrRefusal(op string) (string, bool) {
	switch op {
	case "PutImageScanningConfiguration", "StartImageScan", "DescribeImageScanFindings", "BatchGetImageScanFindings":
		return "ECR " + op + " is not implemented: image scanning is not implemented (no scanner backend).", true
	case "PutLifecyclePolicy", "GetLifecyclePolicy", "DeleteLifecyclePolicy", "StartLifecyclePolicyPreview", "GetLifecyclePolicyPreview":
		return "ECR " + op + " is not implemented: lifecycle policies are not implemented.", true
	case "PutReplicationConfiguration", "DescribeRegistry":
		return "ECR " + op + " is not implemented: cross-region replication is not applicable.", true
	case "SetRepositoryPolicy", "GetRepositoryPolicy", "DeleteRepositoryPolicy", "PutRegistryPolicy", "GetRegistryPolicy":
		return "ECR " + op + " is not implemented: repository/registry resource policies are not the shim's authz world (RBAC + Cedar govern access).", true
	case "CreatePullThroughCacheRule", "DeletePullThroughCacheRule", "DescribePullThroughCacheRules":
		return "ECR " + op + " is not implemented: pull-through cache is not implemented.", true
	case "PutImage", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload":
		return "ECR " + op + " is not implemented: image push/pull uses the standard OCI registry protocol at the proxyEndpoint (docker login/push), not the ECR layer API.", true
	case "TagResource", "UntagResource", "ListTagsForResource":
		return "ECR " + op + " is not implemented: resource tags are not implemented.", true
	}
	return "", false
}

func (h *ecrHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeECRError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"No operation named in the X-Amz-Target header (expected "+ecrTargetPrefix+".<Op>).")
		return
	}

	// Carry the resolved principal on the context so every audit record names *who* (AU-2/AU-9).
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// Deliberately-refused ops are a flat capability statement (not an access decision), so they are
	// refused up front with an honest "why" — before the verb table, which does not list them.
	if reason, refused := ecrRefusal(op); refused {
		h.audit(ctx, op, "", "refuse", reason)
		writeECRError(w, http.StatusBadRequest, "InvalidParameterException", requestID, reason)
		return
	}

	verb, known := verbForECROp(op)
	if !known {
		writeECRError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"ECR "+op+" is not implemented by the open-infra shim.")
		return
	}

	body := readJSONBody(r)
	repoName := ecrResource(op, body)

	// One policy world: the coarse impersonated SubjectAccessReview (resource-agnostic, as every front door).
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, repoName); !allowed {
		h.audit(ctx, op, repoName, "deny", reason)
		writeECRError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only tighten. Scoped to the repository when we have one.
	if repoName != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "ecr:"+op, "Repository", repoName, r); denied {
			h.audit(ctx, op, repoName, "deny", reason)
			writeECRError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
			return
		}
	}

	switch op {
	case "GetAuthorizationToken":
		h.getAuthorizationToken(ctx, w, requestID, claims)
	case "CreateRepository":
		h.createRepository(ctx, w, requestID, body)
	case "DescribeRepositories":
		h.describeRepositories(ctx, w, requestID, body)
	case "DeleteRepository":
		h.deleteRepository(ctx, w, requestID, body)
	case "ListImages":
		h.listImages(ctx, w, requestID, body)
	case "DescribeImages":
		h.describeImages(ctx, w, requestID, body)
	case "BatchDeleteImage":
		h.batchDeleteImage(ctx, w, requestID, body)
	default:
		// A recognized op (e.g. the layer-pull API or PutImageTagMutability) that the shim does not
		// front yet — honest, never faked.
		writeECRError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"ECR "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- authorization token (the data-plane credential) ---

func (h *ecrHandler) getAuthorizationToken(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims) {
	var user, pass string
	if h.tokenAuth && h.signer != nil {
		// Per-repo mode: the credential is a shim-signed caller token carrying the caller's identity.
		// docker login -u AWS -p <token>; docker then presents it to /ecr/token, which authorizes the
		// requested repos against THIS caller and mints a registry token scoped to only what's granted.
		caller, err := h.signer.mintCaller(ecrCaller{Sub: claims.Sub, Groups: claims.Groups, Role: claims.Role}, 12*time.Hour)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		user, pass = "AWS", caller
	} else {
		// htpasswd mode (pre-cutover): the shared registry credential. Coarse — any token holder can
		// push/pull any repo — which is exactly what the token-auth path above replaces.
		u, p, err := h.registryCred(ctx)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		user, pass = u, p
	}
	// The ECR authorization token is base64("<user>:<pass>") — exactly what `docker login -u AWS` consumes.
	token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	h.audit(ctx, "GetAuthorizationToken", "", "allow", "")
	writeECRJSON(w, requestID, map[string]any{
		"authorizationData": []any{map[string]any{
			"authorizationToken": token,
			"expiresAt":          float64(time.Now().Add(12 * time.Hour).Unix()),
			"proxyEndpoint":      h.proxyEndpoint,
		}},
	})
}

// --- repositories ---

func (h *ecrHandler) createRepository(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "repositoryName")
	if !validRepoName(name) {
		writeECRError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"Invalid repository name '"+name+"': it must match "+ecrNamePattern+" and be at most 256 characters.")
		return
	}
	mut := firstString(body, "imageTagMutability")
	if mut == "" {
		mut = "MUTABLE"
	}
	if mut != "MUTABLE" && mut != "IMMUTABLE" {
		writeECRError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"imageTagMutability must be MUTABLE or IMMUTABLE.")
		return
	}
	if _, found, err := h.getRepo(ctx, name); err != nil {
		h.internal(w, requestID, err)
		return
	} else if found {
		writeECRError(w, http.StatusBadRequest, "RepositoryAlreadyExistsException", requestID,
			"The repository with name '"+name+"' already exists in the registry with id '"+h.account+"'.")
		return
	}
	rec := ecrRepoRecord{RepositoryName: name, ImageTagMutability: mut, CreatedAt: time.Now().Unix()}
	if err := h.putRepo(ctx, rec); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateRepository", name, "allow", "")
	writeECRJSON(w, requestID, map[string]any{"repository": h.repoObject(rec)})
}

func (h *ecrHandler) describeRepositories(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	names := stringSlice(body["repositoryNames"])
	repos := []any{}
	if len(names) == 0 {
		recs, err := h.listRepos(ctx)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		for _, rec := range recs {
			repos = append(repos, h.repoObject(rec))
		}
	} else {
		for _, name := range names {
			rec, found, err := h.getRepo(ctx, name)
			if err != nil {
				h.internal(w, requestID, err)
				return
			}
			if !found {
				writeECRError(w, http.StatusBadRequest, "RepositoryNotFoundException", requestID, repoNotFound(name, h.account))
				return
			}
			repos = append(repos, h.repoObject(rec))
		}
	}
	writeECRJSON(w, requestID, map[string]any{"repositories": repos})
}

func (h *ecrHandler) deleteRepository(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "repositoryName")
	rec, found, err := h.getRepo(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeECRError(w, http.StatusBadRequest, "RepositoryNotFoundException", requestID, repoNotFound(name, h.account))
		return
	}
	force, _ := body["force"].(bool)
	rc, err := h.registry(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	tags, err := rc.listTags(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if len(tags) > 0 && !force {
		writeECRError(w, http.StatusBadRequest, "RepositoryNotEmptyException", requestID,
			"The repository with name '"+name+"' in registry with id '"+h.account+"' cannot be deleted because it still contains images (use force to delete them).")
		return
	}
	// force (or empty): resolve every tag to a digest and delete each DISTINCT manifest.
	seen := map[string]bool{}
	for _, tag := range tags {
		digest, _, derr := rc.resolveDigest(ctx, name, tag)
		if derr != nil {
			h.internal(w, requestID, derr)
			return
		}
		if digest == "" || seen[digest] {
			continue
		}
		seen[digest] = true
		if derr := rc.deleteManifest(ctx, name, digest); derr != nil {
			h.internal(w, requestID, derr)
			return
		}
	}
	if err := h.deleteRepo(ctx, name); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteRepository", name, "allow", "")
	writeECRJSON(w, requestID, map[string]any{"repository": h.repoObject(rec)})
}

// --- images (answered from the backing registry's /v2 API) ---

func (h *ecrHandler) listImages(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "repositoryName")
	if _, found, err := h.getRepo(ctx, name); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !found {
		writeECRError(w, http.StatusBadRequest, "RepositoryNotFoundException", requestID, repoNotFound(name, h.account))
		return
	}
	rc, err := h.registry(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	tags, err := rc.listTags(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	imageIds := []any{}
	for _, tag := range tags {
		digest, _, derr := rc.resolveDigest(ctx, name, tag)
		if derr != nil {
			h.internal(w, requestID, derr)
			return
		}
		if digest == "" { // a tag that 404s between list and resolve — skip it
			continue
		}
		imageIds = append(imageIds, map[string]any{"imageDigest": digest, "imageTag": tag})
	}
	h.audit(ctx, "ListImages", name, "allow", "")
	writeECRJSON(w, requestID, map[string]any{"imageIds": imageIds})
}

func (h *ecrHandler) describeImages(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "repositoryName")
	if _, found, err := h.getRepo(ctx, name); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !found {
		writeECRError(w, http.StatusBadRequest, "RepositoryNotFoundException", requestID, repoNotFound(name, h.account))
		return
	}
	filterTags, filterDigests := ecrImageIDFilter(body["imageIds"])
	rc, err := h.registry(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	tags, err := rc.listTags(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	// Group tags by the digest they resolve to (one imageDetail per distinct image).
	type agg struct {
		tags []string
		size int64
	}
	byDigest := map[string]*agg{}
	var order []string
	for _, tag := range tags {
		if len(filterTags) > 0 && !filterTags[tag] {
			continue
		}
		digest, size, derr := rc.resolveDigest(ctx, name, tag)
		if derr != nil {
			h.internal(w, requestID, derr)
			return
		}
		if digest == "" {
			continue
		}
		if len(filterDigests) > 0 && !filterDigests[digest] {
			continue
		}
		a, ok := byDigest[digest]
		if !ok {
			a = &agg{size: size}
			byDigest[digest] = a
			order = append(order, digest)
		}
		a.tags = append(a.tags, tag)
	}
	details := []any{}
	for _, digest := range order {
		a := byDigest[digest]
		d := map[string]any{
			"registryId":     h.account,
			"repositoryName": name,
			"imageDigest":    digest,
			"imageTags":      a.tags,
		}
		// Omit imageSizeInBytes rather than report a size we could not actually determine.
		if a.size > 0 {
			d["imageSizeInBytes"] = a.size
		}
		details = append(details, d)
	}
	h.audit(ctx, "DescribeImages", name, "allow", "")
	writeECRJSON(w, requestID, map[string]any{"imageDetails": details})
}

func (h *ecrHandler) batchDeleteImage(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "repositoryName")
	if _, found, err := h.getRepo(ctx, name); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !found {
		writeECRError(w, http.StatusBadRequest, "RepositoryNotFoundException", requestID, repoNotFound(name, h.account))
		return
	}
	rc, err := h.registry(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	list, _ := body["imageIds"].([]any)
	deleted := []any{}
	failures := []any{}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := m["imageTag"].(string)
		digest, _ := m["imageDigest"].(string)
		ref := digest
		if ref == "" {
			ref = tag
		}
		if ref == "" {
			failures = append(failures, ecrFailure(tag, digest, "InvalidImageTag", "imageId must carry an imageTag or imageDigest"))
			continue
		}
		resolved, _, derr := rc.resolveDigest(ctx, name, ref)
		if derr != nil {
			failures = append(failures, ecrFailure(tag, digest, "ImageNotFound", derr.Error()))
			continue
		}
		if resolved == "" {
			failures = append(failures, ecrFailure(tag, digest, "ImageNotFound", "the image with the specified id does not exist"))
			continue
		}
		if derr := rc.deleteManifest(ctx, name, resolved); derr != nil {
			failures = append(failures, ecrFailure(tag, digest, "ImageNotFound", derr.Error()))
			continue
		}
		out := map[string]any{"imageDigest": resolved}
		if tag != "" {
			out["imageTag"] = tag
		}
		deleted = append(deleted, out)
	}
	h.audit(ctx, "BatchDeleteImage", name, "allow", "")
	writeECRJSON(w, requestID, map[string]any{"imageIds": deleted, "failures": failures})
}

// --- registry credential + client ---

// registryCred reads the backing-registry credential FRESH per request (keys username/password), so a
// rotated Secret takes effect immediately — the credential never lives in the handler.
func (h *ecrHandler) registryCred(ctx context.Context) (user, pass string, err error) {
	sec, err := h.cs.CoreV1().Secrets(h.ns).Get(ctx, h.authSecret, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	return string(sec.Data["username"]), string(sec.Data["password"]), nil
}

// registry builds a /v2 client for this request from a freshly-read credential. It is an honest error
// (surfaced as ServerException) when no backing registry is configured on this shim.
func (h *ecrHandler) registry(ctx context.Context) (*registryClient, error) {
	if h.registryURL == "" {
		return nil, fmt.Errorf("the OCI registry backend is not configured on this shim")
	}
	user, pass, err := h.registryCred(ctx)
	if err != nil {
		return nil, err
	}
	return newRegistryClient(h.registryURL, user, pass), nil
}

// --- object shaping + helpers ---

func (h *ecrHandler) repoObject(rec ecrRepoRecord) map[string]any {
	return map[string]any{
		"repositoryArn":      h.repoArn(rec.RepositoryName),
		"registryId":         h.account,
		"repositoryName":     rec.RepositoryName,
		"repositoryUri":      h.repoURI(rec.RepositoryName),
		"createdAt":          float64(rec.CreatedAt),
		"imageTagMutability": rec.ImageTagMutability,
	}
}

func (h *ecrHandler) repoArn(name string) string {
	return "arn:aws:ecr:" + h.region + ":" + h.account + ":repository/" + name
}

// repoURI is the pull/push base for a repository: the proxyEndpoint host (scheme stripped) + "/" + name.
func (h *ecrHandler) repoURI(name string) string {
	return stripScheme(h.proxyEndpoint) + "/" + name
}

func (h *ecrHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("ecr backend error", "error", err.Error())
	writeECRError(w, http.StatusInternalServerError, "ServerException", requestID, "The server encountered an internal error.")
}

// audit emits a structured audit record for an ECR operation (AU-2/AU-9): who, which op, which repository,
// the decision, and an optional detail — never a credential or token.
func (h *ecrHandler) audit(ctx context.Context, op, repo, decision, detail string) {
	args := []any{"service", "ecr", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if repo != "" {
		args = append(args, "repository", repo)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "ecr audit", args...)
}

// --- pure helpers ---

func validRepoName(name string) bool {
	return name != "" && len(name) <= 256 && ecrNameRE.MatchString(name)
}

func repoNotFound(name, account string) string {
	return "The repository with name '" + name + "' does not exist in the registry with id '" + account + "'."
}

// stripScheme removes a leading scheme ("http://"/"https://") and any trailing slash, leaving host[:port].
func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	return strings.TrimRight(u, "/")
}

// ecrImageIDFilter splits an imageIds request array into the set of requested tags and digests (either
// may be empty, meaning "no filter on that dimension").
func ecrImageIDFilter(v any) (tags, digests map[string]bool) {
	tags = map[string]bool{}
	digests = map[string]bool{}
	list, _ := v.([]any)
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["imageTag"].(string); t != "" {
			tags[t] = true
		}
		if d, _ := m["imageDigest"].(string); d != "" {
			digests[d] = true
		}
	}
	return tags, digests
}

func ecrFailure(tag, digest, code, reason string) map[string]any {
	id := map[string]any{}
	if tag != "" {
		id["imageTag"] = tag
	}
	if digest != "" {
		id["imageDigest"] = digest
	}
	return map[string]any{"imageId": id, "failureCode": code, "failureReason": reason}
}
