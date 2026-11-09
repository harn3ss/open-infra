// The node pull credential (#411): how a node's container runtime gets its credential for the in-cluster
// registry.
//
// On AWS a node pulls from ECR with a credential its own identity obtains: the kubelet's ECR credential
// provider calls GetAuthorizationToken with the instance role, so nothing is provisioned by hand and a key
// change on AWS's side never strands a node. Here the node agent (platform/aws-shim/ecr-node-pull-agent.yaml)
// is that identity: it presents its own ServiceAccount token (projected, audience ecrNodePullAudience) to
// GET /ecr/node-credential and gets the node puller's pull-only credential, signed with the current token
// key. Its authority is the node-pullers group's IAM policy (AmazonEC2ContainerRegistryPullOnly), decided
// at /ecr/token per repository like any caller's.
//
// The agent asks again only when the credential it holds stops verifying at /ecr/token or nears its end,
// so a token key rotated or retired mends itself at the agent's next pass, and the node's runtime restarts
// (to read its registries.yaml) only then. Before, the credential was minted by hand into a Secret, and the
// move of the token key into OpenBao left every node holding one that no longer verified.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	// ecrNodePullAudience is the audience the node agent's projected token carries: a token minted for
	// any other audience is refused here, and this one is good for nothing else.
	ecrNodePullAudience = "openinfra-ecr-node-pull"
	// ecrNodePullTTL is the node credential's lifetime. It is long because a node's runtime reads its
	// registry credential only when it restarts; the agent renews it well before its end.
	ecrNodePullTTL = 365 * 24 * time.Hour
	// ecrNodePuller and ecrNodePullersGroup are the node credential's principal: the node puller, a member
	// of the node-pullers group, whose policy allows pulls alone.
	ecrNodePuller       = "node-puller"
	ecrNodePullersGroup = "openinfra:node-pullers"
)

// ecrNodePull authenticates the node agents.
type ecrNodePull struct {
	// review verifies a projected ServiceAccount token for ecrNodePullAudience and returns its username.
	review func(ctx context.Context, token string) (string, bool)
	// agents are the ServiceAccount usernames (system:serviceaccount:<ns>:<name>) that may have the node
	// credential: the node agent's, from ECR_NODE_PULL_AGENTS.
	agents map[string]bool
}

// parseNodePullAgents reads ECR_NODE_PULL_AGENTS: comma-separated <namespace>/<serviceaccount>.
func parseNodePullAgents(v string) map[string]bool {
	out := map[string]bool{}
	for _, a := range strings.Split(v, ",") {
		ns, sa, ok := strings.Cut(strings.TrimSpace(a), "/")
		if ok && ns != "" && sa != "" && !strings.ContainsAny(ns+sa, ":/ ") {
			out["system:serviceaccount:"+ns+":"+sa] = true
		}
	}
	return out
}

// serveNodeCredential handles GET /ecr/node-credential: a node agent's ServiceAccount token in, the node
// puller's pull-only credential out ({"username":"AWS","password":<credential>,"expiresAt":<RFC 3339>}),
// as GetAuthorizationToken answers a node's instance role. In-cluster callers only.
func (h *ecrHandler) serveNodeCredential(w http.ResponseWriter, r *http.Request) {
	if refuseIfProxied(w, r) {
		return
	}
	if h.signer == nil || h.nodePull == nil || h.nodePull.review == nil || len(h.nodePull.agents) == 0 {
		writeDockerTokenError(w, http.StatusNotImplemented, "UNSUPPORTED", "the node pull credential is not configured on this shim")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ecr-node-pull"`)
		writeDockerTokenError(w, http.StatusUnauthorized, "UNAUTHORIZED", "a ServiceAccount token is required")
		return
	}
	ctx := r.Context()
	user, ok := h.nodePull.review(ctx, strings.TrimSpace(token))
	if !ok {
		writeDockerTokenError(w, http.StatusUnauthorized, "UNAUTHORIZED", "the identity token is not valid for "+ecrNodePullAudience)
		return
	}
	ctx = withPrincipal(ctx, "ServiceAccount::"+user)
	if !h.nodePull.agents[user] {
		h.audit(ctx, "NodeCredential", "", "deny", "not a node agent")
		writeDockerTokenError(w, http.StatusForbidden, "DENIED", "AccessDenied: "+user+" is not a node agent and may not have the node pull credential")
		return
	}
	expires := time.Now().Add(ecrNodePullTTL)
	cred, err := h.signer.mintCaller(ecrCaller{Sub: ecrNodePuller, Groups: []string{ecrNodePullersGroup}}, ecrNodePullTTL)
	if err != nil {
		h.logger.Error("ecr: minting the node pull credential", "err", err)
		writeDockerTokenError(w, http.StatusInternalServerError, "UNKNOWN", "could not mint the node pull credential")
		return
	}
	h.audit(ctx, "NodeCredential", "", "allow", "pull-only, until "+expires.UTC().Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": "AWS", "password": cred, "expiresAt": expires.UTC().Format(time.RFC3339),
	})
}
