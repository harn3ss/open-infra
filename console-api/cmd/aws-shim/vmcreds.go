package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// VM workload credentials — the "aws s3 cp at first boot, no static keys" path. A VM with
// spec.instanceRole runs the open-infra metadata agent in its guest, which serves EC2 instance metadata
// (169.254.169.254) and the container-credentials endpoint to the guest's SDKs; the agent obtains the
// role's credentials from THIS endpoint.
//
// Identity travels IN A TOKEN, never the source IP: masquerade VMs reach cluster Services through
// their node's gateway address, shared by every VM on the node, so a source IP cannot identify a VM
// (and matching it would hand one VM another's credentials). The VM carries a per-VM ServiceAccount
// token (projected into the guest, readable only by root there), and the agent sends it in the
// Authorization header. Identity is in the token, immune to the network path.
//
// This endpoint verifies that token via a Kubernetes TokenReview (exactly as sts:AssumeRoleWithWebIdentity
// does), reads the VM's role off the ServiceAccount's openinfra.dev/instance-role annotation, and mints
// awssts session credentials — but ONLY if that role's trust policy includes the "vm" principal (the
// role must opt in to being instance-assumable). The token is unforgeable (k8s-signed, TokenReview-
// verified) and bound to the VM's own launcher pod (see k8sSARoleResolver), so a VM can obtain only its
// own role's credentials, and no other pod running as the same ServiceAccount can obtain them at all.
//
// The token carries the API server's default audience: KubeVirt's serviceAccount volume projects the
// launcher pod's own token and has no audience setting. The launcher-pod binding is what confines it.
type vmCredsHandler struct {
	resolver saRoleResolver   // token -> (role, namespace) via TokenReview + SA annotation
	trust    roleTrustChecker // role.spec.trust must include "vm" (reused from imds.go)
	minter   *awssts.Minter
	ttl      time.Duration
	logger   *slog.Logger
	// commands is SSM Run Command's agent channel (vmcommands.go), served beside the credentials with the
	// same identity; nil = off.
	commands *vmCommandsHandler
	// identity serves the VM's signed instance identity document (instance_identity.go), with the same
	// identity; nil = off.
	identity *vmIdentityHandler
}

// vmCredsPath is the container-credentials endpoint (AWS_CONTAINER_CREDENTIALS_FULL_URI on the VM).
const vmCredsPath = "/v1/vm-credentials"

func (h *vmCredsHandler) isVMCredsPath(r *http.Request) bool {
	return r.URL.Path == vmCredsPath
}

// containerCreds is the JSON the AWS container-credentials provider parses.
type containerCreds struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func (h *vmCredsHandler) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	// In-cluster only: never answer through the LAN Ingress (internalonly.go).
	if refuseIfProxied(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The container-credentials provider sends the token-file contents verbatim as Authorization.
	token := strings.TrimSpace(r.Header.Get("Authorization"))
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		http.Error(w, "missing credential token", http.StatusUnauthorized)
		return
	}
	id, ok := h.resolver.resolveSARole(r.Context(), token)
	if !ok || id.role == "" {
		// Token invalid, or its ServiceAccount carries no instance-role annotation.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	groups, ok := h.trust.vmTrusted(r.Context(), id.namespace, id.role)
	if !ok {
		if h.logger != nil {
			h.logger.Warn("vm credential request denied: role not vm-trusted",
				slog.String("sa", id.caller), slog.String("role", id.namespace+"/"+id.role))
		}
		http.Error(w, "role not assumable by this instance", http.StatusForbidden)
		return
	}
	// The session names the Role's namespace: a VM's role lives in the VM's namespace, so it is a
	// different principal from a same-named Role anywhere else.
	akid, sk, tok, exp, err := h.minter.MintIn(id.namespace, id.role, groups, id.vmName, id.caller, h.ttl)
	if err != nil {
		http.Error(w, "could not mint credentials", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(containerCreds{
		AccessKeyID:     akid,
		SecretAccessKey: sk,
		Token:           tok,
		Expiration:      exp.UTC().Format(time.RFC3339),
	})
}

// saIdentity is the VM identity a credential token resolves to.
type saIdentity struct {
	role      string // kind: Role named by the SA's openinfra.dev/instance-role annotation
	namespace string // the SA's namespace (where the Role lives)
	caller    string // the SA username (audit)
	vmName    string // the VM the SA belongs to (session name; from the SA's vm annotation/name)
}

// saRoleResolver verifies a credential token and returns the VM identity it carries. Faked in tests.
type saRoleResolver interface {
	resolveSARole(ctx context.Context, token string) (saIdentity, bool)
}

// k8sSARoleResolver verifies a ServiceAccount token via a TokenReview, then reads the role off the
// ServiceAccount's annotations. The SA is the per-VM identity the composition creates and projects
// into the guest; its openinfra.dev/instance-role annotation names the Role, and openinfra.dev/vm the VM.
//
// A valid token for the SA is not enough on its own: any pod that runs as that ServiceAccount holds
// one (an Application named vm-<x> in the VM's namespace runs as an SA of that very name). So the token
// must also be bound to the VM's own launcher pod: KubeVirt projects the token of the virt-launcher
// pod, the TokenReview reports that pod's UID, and the VMI named by the SA's openinfra.dev/vm
// annotation must list that pod as active (status.activePods, written only by KubeVirt) and mount
// this ServiceAccount (spec.volumes). Tenants cannot create pods or VMIs directly.
type k8sSARoleResolver struct {
	cs       kubernetes.Interface
	dyn      dynamic.Interface
	audience string // the audience the projected VM token carries; "" validates against the apiserver default
}

const (
	annInstanceRole = "openinfra.dev/instance-role"
	annVMName       = "openinfra.dev/vm"
	// TokenReview extras the API server sets for a pod-bound ServiceAccount token.
	extraPodName = "authentication.kubernetes.io/pod-name"
	extraPodUID  = "authentication.kubernetes.io/pod-uid"
)

var vmiGVR = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}

func (r *k8sSARoleResolver) resolveSARole(ctx context.Context, token string) (saIdentity, bool) {
	spec := authnv1.TokenReviewSpec{Token: token}
	if r.audience != "" {
		spec.Audiences = []string{r.audience}
	}
	out, err := r.cs.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{Spec: spec}, metav1.CreateOptions{})
	if err != nil || !out.Status.Authenticated {
		return saIdentity{}, false
	}
	u := out.Status.User.Username // system:serviceaccount:<ns>:<sa>
	const pfx = "system:serviceaccount:"
	if !strings.HasPrefix(u, pfx) {
		return saIdentity{}, false
	}
	parts := strings.SplitN(strings.TrimPrefix(u, pfx), ":", 2)
	if len(parts) != 2 {
		return saIdentity{}, false
	}
	ns, saName := parts[0], parts[1]
	podUID := firstExtra(out.Status.User.Extra, extraPodUID)
	if podUID == "" || firstExtra(out.Status.User.Extra, extraPodName) == "" {
		return saIdentity{}, false // not a pod-bound token: no launcher pod to check it against
	}
	sa, err := r.cs.CoreV1().ServiceAccounts(ns).Get(ctx, saName, metav1.GetOptions{})
	if err != nil {
		return saIdentity{}, false
	}
	vmName := sa.Annotations[annVMName]
	if vmName == "" {
		return saIdentity{}, false // not a VM identity: the VM composition always sets openinfra.dev/vm
	}
	if !r.launcherOf(ctx, ns, vmName, saName, podUID) {
		return saIdentity{}, false
	}
	return saIdentity{
		role:      sa.Annotations[annInstanceRole],
		namespace: ns,
		caller:    u,
		vmName:    vmName,
	}, true
}

// launcherOf reports whether pod podUID is an active launcher pod of VMI ns/vmName and that VMI
// projects ServiceAccount saName into its guest. Fails closed on any read error.
func (r *k8sSARoleResolver) launcherOf(ctx context.Context, ns, vmName, saName, podUID string) bool {
	if r.dyn == nil {
		return false
	}
	vmi, err := r.dyn.Resource(vmiGVR).Namespace(ns).Get(ctx, vmName, metav1.GetOptions{})
	if err != nil {
		return false
	}
	active, _, _ := unstructured.NestedMap(vmi.Object, "status", "activePods")
	if _, ok := active[podUID]; !ok {
		return false
	}
	vols, _, _ := unstructured.NestedSlice(vmi.Object, "spec", "volumes")
	for _, v := range vols {
		vm, _ := v.(map[string]any)
		if name, _, _ := unstructured.NestedString(vm, "serviceAccount", "serviceAccountName"); name == saName {
			return true
		}
	}
	return false
}

func firstExtra(extra map[string]authnv1.ExtraValue, key string) string {
	if v := extra[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// roleTrustChecker reports whether a role (in the VM's namespace) is instance-assumable — its
// spec.trust includes "vm" (or "*") — and returns the session's groups. Faked in tests.
type roleTrustChecker interface {
	vmTrusted(ctx context.Context, namespace, role string) (groups []string, ok bool)
}

// k8sRoleTrustChecker reads a role's spec.trust in the VM's namespace and authorizes instance assumption.
type k8sRoleTrustChecker struct {
	dyn dynamic.Interface
}

func (c *k8sRoleTrustChecker) vmTrusted(ctx context.Context, namespace, role string) ([]string, bool) {
	u, err := c.dyn.Resource(roleGVR).Namespace(namespace).Get(ctx, role, metav1.GetOptions{})
	if err != nil {
		return nil, false
	}
	trust, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "trust")
	for _, t := range trust {
		if t == "vm" || t == "*" {
			// Matches dynRoleResolver: a session acts as openinfra:users at the control plane; the
			// role's real authority is its attached data-plane policies (principal type Role).
			return []string{"openinfra:users"}, true
		}
	}
	return nil, false
}
