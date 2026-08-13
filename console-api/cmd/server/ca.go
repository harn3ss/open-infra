package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/harn3ss/open-infra/console-api/internal/proxy"
)

// The Certificate Authority view — customer-owned private CAs (kind: CertificateAuthority, Vault PKI).
//
// The composition mirrors each CA's spec to a ConfigMap (openinfra-ca-<name>), and the reconciler
// writes the live Vault PKI state to a second ConfigMap (openinfra-ca-state-<name>); both carry the
// label openinfra.dev/ca=<name>. GET /api/ca merges them so the console can show each CA, its
// hierarchy/key type/allowed domains, and whether its PKI mount is actually provisioned — without
// the console ever touching Vault (it never sees a private key).
//
// Issue/revoke are NOT done here: the console ServiceAccount is deliberately powerless against
// Vault. Those two verbs SAR-gate the signed-in user against the named CA and then REVERSE-PROXY to
// the ca-issuer Service, which runs as SA ca-issuer under a least-privilege Vault policy that may
// only pki-*/issue and pki-*/revoke — never mint a root/intermediate or touch transit. The private
// key flows straight back to the browser and is never logged or persisted on this hop.

// caIssuerDefaultEndpoint is the in-cluster ca-issuer Service (crossplane-system, port 8080),
// overridable via CA_ISSUER_ENDPOINT (used by tests to point at a stub).
const caIssuerDefaultEndpoint = "http://ca-issuer.crossplane-system.svc.cluster.local:8080"

func caIssuerURL() *url.URL {
	u, err := url.Parse(getenv("CA_ISSUER_ENDPOINT", caIssuerDefaultEndpoint))
	if err != nil {
		return nil
	}
	return u
}

type caView struct {
	Name           string   `json:"name"`
	CommonName     string   `json:"commonName"`
	Hierarchy      string   `json:"hierarchy"`
	Parent         string   `json:"parent,omitempty"`
	KeyType        string   `json:"keyType"`
	MaxTtl         string   `json:"maxTtl"`
	AllowedDomains []string `json:"allowedDomains"`
	PkiMount       string   `json:"pkiMount"`
	// Live state from the reconciler (absent until it has run against Vault):
	Ready     bool   `json:"ready"`
	CaCertPem string `json:"caCertPem,omitempty"`
	Serial    string `json:"serial,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
}

// splitCSV turns the comma-joined allowedDomains value back into a slice, dropping blanks.
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// handleCertificateAuthorities lists CAs by merging the spec-mirror and state ConfigMaps —
// EXACTLY the shape of handleEncryptionKeys, keyed on the openinfra.dev/ca label both carry.
func handleCertificateAuthorities(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "openinfra.dev", "certificateauthorities", auth.ns, "") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		cms, err := cs.CoreV1().ConfigMaps(auth.ns).List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/ca"})
		if err != nil {
			logger.Warn("ca: list configmaps", slog.String("error", err.Error()))
			writeJSON(w, http.StatusOK, []caView{})
			return
		}

		cas := map[string]*caView{}
		get := func(name string) *caView {
			if cas[name] == nil {
				cas[name] = &caView{Name: name, AllowedDomains: []string{}}
			}
			return cas[name]
		}
		for i := range cms.Items {
			cm := &cms.Items[i]
			name := cm.Labels["openinfra.dev/ca"]
			if name == "" {
				continue
			}
			c := get(name)
			d := cm.Data
			// The spec mirror carries commonName/hierarchy/parent/keyType/maxTtl/allowedDomains/pkiMount;
			// the state carries ready/pkiMount/caCertPem/serial/notAfter.
			if v, ok := d["commonName"]; ok {
				c.CommonName = v
			}
			if v, ok := d["hierarchy"]; ok {
				c.Hierarchy = v
			}
			if v, ok := d["parent"]; ok && v != "" {
				c.Parent = v
			}
			if v, ok := d["keyType"]; ok {
				c.KeyType = v
			}
			if v, ok := d["maxTtl"]; ok {
				c.MaxTtl = v
			}
			if v, ok := d["allowedDomains"]; ok {
				c.AllowedDomains = splitCSV(v)
			}
			if v, ok := d["pkiMount"]; ok && v != "" {
				c.PkiMount = v
			}
			if d["ready"] == "true" {
				c.Ready = true
			}
			if v, ok := d["caCertPem"]; ok && v != "" {
				c.CaCertPem = v
			}
			if v, ok := d["serial"]; ok && v != "" {
				c.Serial = v
			}
			if v, ok := d["notAfter"]; ok && v != "" {
				c.NotAfter = v
			}
		}

		out := make([]caView, 0, len(cas))
		for _, c := range cas {
			out = append(out, *c)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		writeJSON(w, http.StatusOK, out)
	}
}

// handleCAIssue reverse-proxies POST /api/ca/{namespace}/{name}/issue to the ca-issuer's /issue,
// after the signed-in user has been authorized against the named CA.
func handleCAIssue(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return caProxyHandler(cs, auth, logger, "issue")
}

// handleCARevoke reverse-proxies POST /api/ca/{namespace}/{name}/revoke to the ca-issuer's /revoke.
func handleCARevoke(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return caProxyHandler(cs, auth, logger, "revoke")
}

// caProxyHandler is the shared body of issue/revoke. It authorizes, forces the request's target CA
// to the one named in the (authorized) path, and hands off to the internal reverse proxy. The
// console ServiceAccount never authenticates to Vault — the ca-issuer does, under its own
// least-privilege identity.
func caProxyHandler(cs kubernetes.Interface, auth *authStore, logger *slog.Logger, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		if ns == "" || name == "" {
			writeError(w, http.StatusBadRequest, "namespace and name are required")
			return
		}
		// Issuing or revoking a leaf certificate exercises the CA — gate it on the right to
		// mutate that specific CertificateAuthority, so the SAR the audit log records names the
		// exact object the action touches.
		if !authorize(w, r, cs, auth, logger, "update", "openinfra.dev", "certificateauthorities", ns, name) {
			return
		}

		issuer := caIssuerURL()
		if issuer == nil {
			writeError(w, http.StatusInternalServerError, "ca-issuer endpoint misconfigured")
			return
		}

		// Rewrite the body so "ca" is ALWAYS the CA named in the path — never a value the caller
		// supplied. Otherwise a caller authorized for CA "public" could set ca:"root" in the body
		// and issue from a CA the SAR gate never checked. Everything else (commonName, ttl,
		// altNames, serialNumber) passes through untouched.
		var in map[string]any
		if r.Body != nil {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if len(bytes.TrimSpace(raw)) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					writeError(w, http.StatusBadRequest, "invalid request body")
					return
				}
			}
		}
		if in == nil {
			in = map[string]any{}
		}
		in["ca"] = name
		nb, err := json.Marshal(in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not build issuer request")
			return
		}

		// Point the inbound request at the ca-issuer's action path and let the shared proxy carry
		// it there. stripPrefix "" means the (rewritten) path forwards verbatim; identity nil means
		// no impersonation — the ca-issuer, not any console user, authenticates to Vault.
		r.Body = io.NopCloser(bytes.NewReader(nb))
		r.ContentLength = int64(len(nb))
		r.Header.Set("Content-Type", "application/json")
		r.URL.Path = "/" + action
		r.URL.RawPath = ""

		proxy.New(issuer, http.DefaultTransport, "", logger, nil).ServeHTTP(w, r)
	}
}
