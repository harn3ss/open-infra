// AWS EKS front door for the aws-shim (polyhedron#177).
//
// open-infra IS Kubernetes, so EKS is the LEAST-additive doorway: there is no cluster to create, grow, or
// destroy — the platform already is the cluster. Its whole value is API-SHAPE compatibility, so tooling
// that drives EKS works against open-infra. Above all, DescribeCluster returns the cluster's REAL
// connection details (endpoint + CA data + name) so `aws eks update-kubeconfig --name <cluster>` produces a
// WORKING kubeconfig pointed at the open-infra API server. That is the load-bearing contract; everything
// else is shaped to let the SDK/CLI reach it.
//
// Protocol: EKS speaks restJson1 — REST paths + HTTP methods, NOT the X-Amz-Target JSON-1.1 the KMS/Glue
// doorways use. `aws eks describe-cluster --name X` is GET /clusters/X; list-clusters is GET /clusters. So
// dispatch is on r.Method + r.URL.Path (see apigateway.go, the sibling restJson1 doorway), and the error
// dialect surfaces the exception name in the x-amzn-errortype header with a {"message":"..."} JSON body.
//
// Deliberate carve-outs, refused HONESTLY rather than faked (never a half-created lie or a false green):
//   - CreateCluster / DeleteCluster — the platform substrate is not born or killed through the EKS API.
//   - UpdateCluster{Version,Config} — a substrate (platform) operation, not an EKS API call.
//   - node groups — open-infra nodes exist but are not EKS-managed node groups; ListNodegroups is an honest
//     EMPTY set (documented, not an error), and Describe/Create/Delete/Update are refused.
//   - Fargate profiles, add-ons, access entries, identity-provider configs — no open-infra analog, or
//     governed by a different mechanism (RBAC + Cedar), so refused with a message that says which.
//
// Authenticated by the shared SigV4 path; authorized by the one policy world every front door uses (the
// coarse impersonated SubjectAccessReview + the additive Cedar dataPlane check). See docs/aws-shim.md.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type eksHandler struct {
	cs              kubernetes.Interface
	authzNS         string
	account         string
	region          string
	clusterName     string // the one cluster this shim fronts, e.g. "open-infra"
	clusterEndpoint string // the Kubernetes API server URL DescribeCluster returns (for kubeconfig)
	caData          string // base64 cluster CA (certificateAuthority.data) — the SA ca.crt, already base64-encoded
	version         string // kubernetes server version "major.minor" (e.g. "1.31"); may be "" if undiscoverable
	authz           *dataplaneauthz.Checker
	logger          *slog.Logger
}

func newEKSHandler(cs kubernetes.Interface, authzNS, account, region, clusterName, clusterEndpoint, caData, version string, logger *slog.Logger) *eksHandler {
	if region == "" {
		region = "us-east-1"
	}
	if clusterName == "" {
		clusterName = "open-infra"
	}
	return &eksHandler{
		cs:              cs,
		authzNS:         authzNS,
		account:         account,
		region:          region,
		clusterName:     clusterName,
		clusterEndpoint: clusterEndpoint,
		caData:          caData,
		version:         version,
		logger:          logger,
	}
}

// --- error dialect (EKS restJson1: {"message": "..."} body + x-amzn-errortype header; mirrors apigateway.go) ---

func writeEKSError(w http.ResponseWriter, status int, errType, requestID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	if errType != "" {
		w.Header().Set("x-amzn-errortype", errType)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func writeEKSJSON(w http.ResponseWriter, status int, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *eksHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	// AWS surfaces a SigV4 mismatch as InvalidSignatureException before the service sees it.
	writeEKSError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// --- op resolution (method + REST path -> op) ---

type eksCategory int

const (
	eksUnknown eksCategory = iota // unrecognized path/subresource -> honest not-implemented
	eksRead                       // ListClusters / DescribeCluster / ListNodegroups / DescribeNodegroup (authz-gated)
	eksRefused                    // deliberately NOT fronted -> InvalidRequestException with an honest "why"
)

type eksRequest struct {
	op      string      // resolved op name (for audit, dataPlane action, and refusal messages)
	cluster string      // cluster name from the path, if any
	sub     string      // subresource name from the path (e.g. a node-group name), if any
	cat     eksCategory // how serve() should treat it
}

// resolveEKS maps an EKS restJson1 (method, path) to an op, the cluster it targets, and a category. Paths:
// /clusters[/{name}[/<subresource>[/{subName}[/<action>]]]]. Anything not recognized is eksUnknown.
func resolveEKS(r *http.Request) eksRequest {
	segs := splitPath(r.URL.Path)
	m := r.Method
	if len(segs) == 0 || segs[0] != "clusters" {
		return eksRequest{cat: eksUnknown}
	}
	switch len(segs) {
	case 1: // /clusters
		switch m {
		case http.MethodGet:
			return eksRequest{op: "ListClusters", cat: eksRead}
		case http.MethodPost:
			return eksRequest{op: "CreateCluster", cat: eksRefused}
		}
	case 2: // /clusters/{name}
		cluster := segs[1]
		switch m {
		case http.MethodGet:
			return eksRequest{op: "DescribeCluster", cluster: cluster, cat: eksRead}
		case http.MethodDelete:
			return eksRequest{op: "DeleteCluster", cluster: cluster, cat: eksRefused}
		}
	case 3: // /clusters/{name}/<subresource>
		cluster := segs[1]
		switch segs[2] {
		case "updates", "update-version":
			if m == http.MethodPost || m == http.MethodPut {
				return eksRequest{op: "UpdateClusterVersion", cluster: cluster, cat: eksRefused}
			}
		case "update-config":
			if m == http.MethodPost || m == http.MethodPut {
				return eksRequest{op: "UpdateClusterConfig", cluster: cluster, cat: eksRefused}
			}
		case "node-groups":
			switch m {
			case http.MethodGet:
				return eksRequest{op: "ListNodegroups", cluster: cluster, cat: eksRead}
			case http.MethodPost:
				return eksRequest{op: "CreateNodegroup", cluster: cluster, cat: eksRefused}
			}
		case "fargate-profiles":
			op := "ListFargateProfiles"
			if m == http.MethodPost {
				op = "CreateFargateProfile"
			}
			return eksRequest{op: op, cluster: cluster, cat: eksRefused}
		case "addons":
			op := "ListAddons"
			if m == http.MethodPost {
				op = "CreateAddon"
			}
			return eksRequest{op: op, cluster: cluster, cat: eksRefused}
		case "access-entries":
			op := "ListAccessEntries"
			if m == http.MethodPost {
				op = "CreateAccessEntry"
			}
			return eksRequest{op: op, cluster: cluster, cat: eksRefused}
		case "identity-provider-configs":
			op := "ListIdentityProviderConfigs"
			if m == http.MethodPost {
				op = "CreateIdentityProviderConfig"
			}
			return eksRequest{op: op, cluster: cluster, cat: eksRefused}
		}
	case 4: // /clusters/{name}/<subresource>/{subName}
		cluster := segs[1]
		sub := segs[3]
		switch segs[2] {
		case "node-groups":
			switch m {
			case http.MethodGet:
				return eksRequest{op: "DescribeNodegroup", cluster: cluster, sub: sub, cat: eksRead}
			case http.MethodDelete:
				return eksRequest{op: "DeleteNodegroup", cluster: cluster, sub: sub, cat: eksRefused}
			}
		case "fargate-profiles":
			op := "DescribeFargateProfile"
			if m == http.MethodDelete {
				op = "DeleteFargateProfile"
			}
			return eksRequest{op: op, cluster: cluster, sub: sub, cat: eksRefused}
		case "addons":
			op := "DescribeAddon"
			if m == http.MethodDelete {
				op = "DeleteAddon"
			}
			return eksRequest{op: op, cluster: cluster, sub: sub, cat: eksRefused}
		case "access-entries":
			op := "DescribeAccessEntry"
			if m == http.MethodDelete {
				op = "DeleteAccessEntry"
			}
			return eksRequest{op: op, cluster: cluster, sub: sub, cat: eksRefused}
		case "identity-provider-configs":
			// AWS nests the verb here: .../identity-provider-configs/{associate,describe,disassociate}.
			return eksRequest{op: idpConfigOp(sub), cluster: cluster, cat: eksRefused}
		}
	case 5: // /clusters/{name}/<subresource>/{subName}/<action>
		cluster := segs[1]
		switch segs[2] {
		case "node-groups":
			if m == http.MethodPost || m == http.MethodPut {
				op := "UpdateNodegroupConfig"
				if segs[4] == "update-version" {
					op = "UpdateNodegroupVersion"
				}
				return eksRequest{op: op, cluster: cluster, sub: segs[3], cat: eksRefused}
			}
		case "addons":
			if m == http.MethodPost || m == http.MethodPut {
				return eksRequest{op: "UpdateAddon", cluster: cluster, sub: segs[3], cat: eksRefused}
			}
		}
	}
	return eksRequest{cat: eksUnknown}
}

// idpConfigOp names the identity-provider-config verb from the trailing path segment, so the refusal and
// audit name a sensible op. All of them are refused the same way.
func idpConfigOp(action string) string {
	switch action {
	case "associate":
		return "AssociateIdentityProviderConfig"
	case "disassociate":
		return "DisassociateIdentityProviderConfig"
	case "describe":
		return "DescribeIdentityProviderConfig"
	}
	return "IdentityProviderConfig"
}

// eksRefusalMessage returns the honest reason an op is deliberately NOT fronted. Each message names the op
// and WHY — a refusal is never a faked success. Grouped by the resource family so related ops share wording.
func eksRefusalMessage(op string) string {
	switch {
	case op == "CreateCluster":
		return "EKS CreateCluster is not supported: open-infra is itself the Kubernetes cluster; it is not created via the EKS API. The cluster already exists — use DescribeCluster."
	case op == "DeleteCluster":
		return "EKS DeleteCluster is not supported: the open-infra cluster is the platform substrate; it is not deletable via the EKS API."
	case strings.HasPrefix(op, "UpdateCluster"):
		return "EKS " + op + " is not supported: cluster version/config changes are a platform (substrate) operation, not an EKS API call."
	case strings.Contains(op, "Nodegroup"):
		return "EKS " + op + " is not supported: open-infra nodes are not EKS-managed node groups; node capacity is a platform operation."
	case strings.Contains(op, "FargateProfile"):
		return "EKS " + op + " is not supported: Fargate has no open-infra analog."
	case strings.Contains(op, "Addon"):
		return "EKS " + op + " is not supported: EKS add-ons are not provided; install platform components directly."
	case strings.Contains(op, "AccessEntry") || strings.Contains(op, "IdentityProviderConfig"):
		return "EKS " + op + " is not supported: cluster access is governed by the platform's RBAC + Cedar, not EKS access entries."
	}
	return "EKS " + op + " is not supported by the open-infra shim."
}

// --- serve ---

func (h *eksHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	req := resolveEKS(r)

	// Carry the resolved principal on the context so every audit record names *who* (AU-2/AU-9).
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	switch req.cat {
	case eksUnknown:
		// Honest not-implemented for an unrecognized path or subresource — never a silent 200/empty.
		writeEKSError(w, http.StatusNotFound, "NotFoundException", requestID,
			"EKS "+r.Method+" "+r.URL.Path+" is not implemented by the open-infra shim.")
		return
	case eksRefused:
		// A deliberately-refused op is a flat capability statement (not an access decision), so it is
		// refused up front — BEFORE the authz gate — with an honest "why".
		reason := eksRefusalMessage(req.op)
		h.audit(ctx, req.op, req.cluster, "refuse", reason)
		writeEKSError(w, http.StatusBadRequest, "InvalidRequestException", requestID, reason)
		return
	}

	// Implemented reads: the one policy world. Coarse impersonated SubjectAccessReview (resource-agnostic,
	// as every front door) — both DescribeCluster and ListClusters are reads, so verb "get" scoped to the
	// one cluster this shim fronts.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, "get", "openinfra.dev", "applications", h.authzNS, h.clusterName); !allowed {
		h.audit(ctx, req.op, h.clusterName, "deny", reason)
		writeEKSError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only TIGHTEN. There is one cluster, always in scope.
	if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "eks:"+req.op, "Cluster", h.clusterName, r); denied {
		h.audit(ctx, req.op, h.clusterName, "deny", reason)
		writeEKSError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}

	switch req.op {
	case "ListClusters":
		h.audit(ctx, "ListClusters", "", "allow", "")
		// Just the one cluster the platform is.
		writeEKSJSON(w, http.StatusOK, requestID, map[string]any{"clusters": []string{h.clusterName}})
	case "DescribeCluster":
		h.describeCluster(ctx, w, requestID, req.cluster)
	case "ListNodegroups":
		// Honest EMPTY set: open-infra nodes exist but are not EKS-managed node groups. Empty, documented,
		// not an error — so tooling that enumerates node groups sees "none managed here" rather than a fault.
		h.audit(ctx, "ListNodegroups", req.cluster, "allow", "")
		writeEKSJSON(w, http.StatusOK, requestID, map[string]any{"nodegroups": []string{}})
	case "DescribeNodegroup":
		msg := "No node group found"
		if req.sub != "" {
			msg += " for name: " + req.sub
		}
		msg += ": open-infra nodes are not EKS-managed node groups."
		writeEKSError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, msg)
	default:
		writeEKSError(w, http.StatusNotFound, "NotFoundException", requestID,
			"EKS "+r.Method+" "+r.URL.Path+" is not implemented by the open-infra shim.")
	}
}

// describeCluster returns the faithful cluster object `aws eks update-kubeconfig` consumes. A name other
// than the one cluster this shim fronts is an honest 404 — there is exactly one cluster, the platform.
func (h *eksHandler) describeCluster(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	if name != h.clusterName {
		writeEKSError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"No cluster found for name: "+name+".")
		return
	}
	h.audit(ctx, "DescribeCluster", name, "allow", "")
	writeEKSJSON(w, http.StatusOK, requestID, map[string]any{"cluster": h.clusterObject()})
}

// clusterObject projects the open-infra cluster into the EKS Cluster shape the SDK/CLI expects. The
// load-bearing fields for kubeconfig generation are name + endpoint + certificateAuthority.data; roleArn and
// resourcesVpcConfig are synthetic (there is no real EKS service role or VPC) but present so the SDK's model
// is satisfied. createdAt is omitted (optional for update-kubeconfig) rather than fabricated from a live
// clock a test cannot control.
func (h *eksHandler) clusterObject() map[string]any {
	obj := map[string]any{
		"name":                    h.clusterName,
		"arn":                     "arn:aws:eks:" + h.region + ":" + h.account + ":cluster/" + h.clusterName,
		"status":                  "ACTIVE",
		"endpoint":                h.clusterEndpoint,
		"certificateAuthority":    map[string]any{"data": h.caData},
		"roleArn":                 "arn:aws:iam::" + h.account + ":role/open-infra-eks-cluster-role",
		"resourcesVpcConfig":      map[string]any{"endpointPublicAccess": true, "endpointPrivateAccess": true, "securityGroupIds": []string{}, "subnetIds": []string{}},
		"kubernetesNetworkConfig": map[string]any{"ipFamily": "ipv4"},
		"platformVersion":         "eks.1",
		"tags":                    map[string]any{},
	}
	if h.version != "" {
		obj["version"] = h.version
	}
	return obj
}

// audit emits a structured audit record for an EKS operation (AU-2/AU-9): who, which op, which resource,
// the decision, and an optional detail (the reason, for deny/refuse). Mirrors glue.go's audit.
func (h *eksHandler) audit(ctx context.Context, op, resource, decision, detail string) {
	args := []any{"service", "eks", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if resource != "" {
		args = append(args, "resource", resource)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "eks audit", args...)
}
