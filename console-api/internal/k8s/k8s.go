// Package k8s centralizes how the BFF talks to the Kubernetes API server.
//
// Everything the console-api does against the cluster (reverse proxy, watch SSE,
// CRD schema fetch) flows through the *rest.Config built here. In-cluster we use
// the pod's mounted ServiceAccount; for local development we fall back to a
// kubeconfig. The ServiceAccount's RBAC — never this process — is the authority
// on what a request is allowed to do.
package k8s

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client bundles the pieces the rest of the BFF needs to reach the API server:
// the resolved REST config, an authenticated http.RoundTripper (TLS + bearer
// token injected), the API server base URL, and a typed clientset for the few
// places that want structured access (e.g. fetching CRDs).
type Client struct {
	// Config is the resolved client-go REST config (in-cluster or kubeconfig).
	Config *rest.Config
	// Transport is an http.RoundTripper that injects the API server's CA-pinned
	// TLS config and the ServiceAccount bearer token onto every request. Reuse
	// it; client-go caches connections and rotates the token transparently.
	Transport http.RoundTripper
	// Host is the API server base URL (scheme + host[:port]), with any path
	// component stripped. Proxy/watch targets are built relative to this.
	Host *url.URL
	// Clientset is a typed client for structured reads (used by the CRD handler).
	Clientset *kubernetes.Interface
}

// New resolves cluster credentials and builds an authenticated Client.
//
// Resolution order:
//  1. rest.InClusterConfig() — the normal production path, reading the pod's
//     mounted ServiceAccount token + CA.
//  2. The kubeconfig at $KUBECONFIG or ~/.kube/config — the local-dev fallback.
//
// kubeconfigPath, when non-empty, overrides the loader's default search and is
// useful for tests; pass "" in production.
func New(kubeconfigPath string) (*Client, error) {
	cfg, err := loadConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}

	// rest.TransportFor wires TLS (CA bundle / insecure flag) and bearer-token
	// auth into a single RoundTripper, so neither the proxy nor the watch code
	// has to handle credentials by hand.
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("building authenticated transport: %w", err)
	}

	host, err := apiServerURL(cfg.Host)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building clientset: %w", err)
	}
	var iface kubernetes.Interface = clientset

	return &Client{
		Config:    cfg,
		Transport: transport,
		Host:      host,
		Clientset: &iface,
	}, nil
}

// loadConfig returns an in-cluster config when running inside a pod, otherwise
// falls back to a kubeconfig file for local development.
func loadConfig(kubeconfigPath string) (*rest.Config, error) {
	// Try in-cluster first; this is the production path.
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	} else if err != rest.ErrNotInCluster {
		// A real error (e.g. malformed token file) — surface it rather than
		// silently falling through to a kubeconfig that may not exist.
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	// Local-dev fallback: honor an explicit path, then $KUBECONFIG, then the
	// recommended default (~/.kube/config). clientcmd handles the precedence
	// for us via the loading rules.
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig (set KUBECONFIG or run in-cluster): %w", err)
	}
	return cfg, nil
}

// apiServerURL parses the REST config Host into a clean base URL containing only
// scheme + host[:port]. client-go sometimes carries an "/api"-ish path on Host;
// we drop it so callers can append full Kubernetes paths unambiguously.
func apiServerURL(host string) (*url.URL, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parsing API server host %q: %w", host, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("API server host %q is missing scheme or host", host)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}
