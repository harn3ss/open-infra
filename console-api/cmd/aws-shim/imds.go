package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// EC2 Instance Metadata Service (IMDS) for open-infra VMs — the "aws s3 cp at first boot, no static
// keys" path. A kind: VirtualMachine with spec.instanceRole assumes that kind: Role and the AWS SDK's
// default credential chain fetches rotating session credentials from here, exactly as on EC2.
//
// Identity is the CALLER'S SOURCE IP, not SigV4 — IMDS is what BOOTSTRAPS credentials, so there are
// none to sign with yet. A masquerade VM's traffic egresses as its virt-launcher pod's IP (kube-ovn,
// CNI-enforced so unspoofable), so the source IP maps 1:1 to one VM. The handler finds the launcher
// pod with that IP, reads its openinfra.dev/instance-role label (set by the vm composition), and mints
// credentials for that role — but ONLY if the role's trust policy includes the "vm" service principal
// (a role must opt in to being instance-assumable; a compromised metadata path can then only ever mint
// vm-trusting roles, never a user-only role). VM-A can never obtain VM-B's credentials: the only role
// it can reach is the one labelled on its own launcher pod.
//
// These endpoints are recognized at the shim's front door BEFORE SigV4 parsing, at the IMDS path
// prefix only, so they never shadow a signed AWS call. An external or non-VM caller's source IP maps
// to no launcher pod, so it gets 404 — nothing is minted.

// vmIdentity is the VM an IMDS caller resolves to (by its launcher-pod source IP).
type vmIdentity struct {
	role      string // the kind: Role named by spec.instanceRole (empty => the VM declared none)
	namespace string // the VM's namespace (where the Role lives)
	vmName    string
}

// podRoleLookup maps a caller source IP to the VM behind it. Implemented against the k8s API; faked in tests.
type podRoleLookup interface {
	lookup(ctx context.Context, sourceIP string) (vmIdentity, bool)
}

// roleTrustChecker reports whether a role (in the VM's namespace) is instance-assumable — its
// spec.trust includes "vm" (or "*") — and returns the session's groups. Faked in tests.
type roleTrustChecker interface {
	vmTrusted(ctx context.Context, namespace, role string) (groups []string, ok bool)
}

type imdsHandler struct {
	pods   podRoleLookup
	trust  roleTrustChecker
	minter *awssts.Minter
	ttl    time.Duration
	logger *slog.Logger
}

const imdsCredPrefix = "/latest/meta-data/iam/security-credentials/"

// isIMDSPath reports whether a request targets the IMDS surface this handler serves. Kept tight so it
// never captures a real AWS API call (those are not under /latest/api/token or /latest/meta-data/).
func (h *imdsHandler) isIMDSPath(r *http.Request) bool {
	p := r.URL.Path
	return p == "/latest/api/token" || strings.HasPrefix(p, "/latest/meta-data/")
}

func (h *imdsHandler) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	switch {
	case r.URL.Path == "/latest/api/token" && r.Method == http.MethodPut:
		h.issueToken(w, r)
	case r.URL.Path == imdsCredPrefix && r.Method == http.MethodGet:
		h.roleName(w, r, requestID)
	case strings.HasPrefix(r.URL.Path, imdsCredPrefix) && r.Method == http.MethodGet:
		h.credentials(w, r, strings.TrimPrefix(r.URL.Path, imdsCredPrefix), requestID)
	default:
		// A metadata key we do not serve (instance-id, placement, …). 404 like a real IMDS for an
		// unknown key, rather than guessing.
		http.NotFound(w, r)
	}
}

// issueToken implements the IMDSv2 PUT /latest/api/token handshake. The token is a session nicety for
// SDK compatibility; the real authority is the source-IP → role binding, so the token is not required
// on GET (both IMDSv1 and v2 SDKs work). The requested TTL is echoed in the response header.
func (h *imdsHandler) issueToken(w http.ResponseWriter, r *http.Request) {
	ttl := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
	if ttl == "" {
		ttl = "21600"
	}
	tok, err := randomToken()
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", ttl)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(tok))
}

// roleName serves GET .../security-credentials/ — the list of role "profiles", which on an instance is
// the single instance-profile role name. We return the VM's resolved role, or 404 if the caller is not
// a VM with an instanceRole.
func (h *imdsHandler) roleName(w http.ResponseWriter, r *http.Request, requestID string) {
	id, ok := h.resolve(r)
	if !ok || id.role == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(id.role))
}

// imdsCreds is the AWS IMDS credential document shape the SDK credential provider parses.
type imdsCreds struct {
	Code            string `json:"Code"`
	LastUpdated     string `json:"LastUpdated"`
	Type            string `json:"Type"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// credentials serves GET .../security-credentials/<role>: it mints rotating session credentials for the
// VM's role. Fail-closed at every step — the caller must resolve to a VM, the requested <role> must be
// exactly that VM's role (no fetching another role by name), and the role must be vm-trusted.
func (h *imdsHandler) credentials(w http.ResponseWriter, r *http.Request, askedRole, requestID string) {
	id, ok := h.resolve(r)
	if !ok || id.role == "" {
		http.NotFound(w, r)
		return
	}
	// The path role must match the VM's own role: a VM may only read its own credentials.
	if askedRole != id.role {
		http.NotFound(w, r)
		return
	}
	groups, ok := h.trust.vmTrusted(r.Context(), id.namespace, id.role)
	if !ok {
		// The role exists but does not trust the "vm" principal (did not opt in) — deny, don't mint.
		h.logDeny(id, "role not vm-trusted")
		http.Error(w, "role not assumable by this instance", http.StatusForbidden)
		return
	}
	caller := "vm:" + id.namespace + "/" + id.vmName
	akid, sk, token, exp, err := h.minter.Mint(id.role, groups, id.vmName, caller, h.ttl)
	if err != nil {
		http.Error(w, "could not mint credentials", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(imdsCreds{
		Code:            "Success",
		LastUpdated:     exp.Add(-h.ttl).UTC().Format(time.RFC3339),
		Type:            "AWS-HMAC",
		AccessKeyID:     akid,
		SecretAccessKey: sk,
		Token:           token,
		Expiration:      exp.UTC().Format(time.RFC3339),
	})
}

func (h *imdsHandler) resolve(r *http.Request) (vmIdentity, bool) {
	return h.pods.lookup(r.Context(), imdsPeerIP(r))
}

func (h *imdsHandler) logDeny(id vmIdentity, reason string) {
	if h.logger != nil {
		h.logger.Warn("imds credential request denied", slog.String("vm", id.namespace+"/"+id.vmName),
			slog.String("role", id.role), slog.String("reason", reason))
	}
}

// imdsPeerIP is the caller's source IP — the launcher pod's IP for a masquerade VM. It is the real TCP
// peer (RemoteAddr) ONLY: unlike the SigV4 path's clientIP, it deliberately does NOT trust
// X-Forwarded-For, because here the source IP IS the credential (trusting a header would let any caller
// claim another VM's IP and steal its role credentials). The shim is reached directly (ClusterIP), so
// RemoteAddr is the genuine peer.
func imdsPeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- k8s-backed implementations ----

// randomToken mints an opaque IMDSv2 session token (SDK-compatibility nicety; the real authority is
// the source-IP → role binding).
func randomToken() (string, error) {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// k8sPodRoleLookup finds the virt-launcher pod with a given IP and reads the VM's role off its labels.
// Launcher pods carry the VMI's template labels (kubevirt.io/domain, vm.kubevirt.io/name, and — set by
// the vm composition — openinfra.dev/instance-role), so one list by the launcher label + an IP match
// yields the VM identity.
type k8sPodRoleLookup struct {
	cs kubernetes.Interface
}

const (
	labelLauncher     = "kubevirt.io"
	labelInstanceRole = "openinfra.dev/instance-role"
	labelVMName       = "vm.kubevirt.io/name"
)

func (l *k8sPodRoleLookup) lookup(ctx context.Context, sourceIP string) (vmIdentity, bool) {
	if sourceIP == "" {
		return vmIdentity{}, false
	}
	pods, err := l.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{LabelSelector: labelLauncher + "=virt-launcher"})
	if err != nil {
		return vmIdentity{}, false
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.PodIP != sourceIP {
			continue
		}
		id := vmIdentity{
			role:      p.Labels[labelInstanceRole],
			namespace: p.Namespace,
			vmName:    p.Labels[labelVMName],
		}
		if id.vmName == "" {
			id.vmName = p.Labels["kubevirt.io/domain"]
		}
		return id, id.role != ""
	}
	return vmIdentity{}, false
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
