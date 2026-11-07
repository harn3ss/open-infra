package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/proxy"
	"github.com/harn3ss/open-infra/console-api/internal/watch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Account scope: what the console lists for a user is their account's, as on AWS — "every bucket in this
// account", never "in this namespace" or "in the cluster". The UI asks for it with scope=account on an
// all-namespaces list or watch; the console answers for the caller's account (callerAccount) over the
// account's namespaces (accountNamespaces), granting nothing beyond what each request's own checks allow:
//
//   - a list is asked cluster-wide exactly as a plain all-namespaces list is (the IAM gate, then the API
//     server as the principal) and filtered to the account's namespaces; when the API server refuses it
//     cluster-wide — an account's generated RBAC is per namespace — it is asked in each of the account's
//     namespaces through the same gate and proxy, and the answers are merged;
//   - a watch is the cluster-wide watch stream, authorized as before, filtered to the account's
//     namespaces.
//
// In enforce, a cluster-wide watch without scope=account is filtered to the caller's account too, unless
// the caller is the account's root user or the platform's operator: the stream reads with the console's
// ServiceAccount, so without the filter it would carry other accounts' objects.

const (
	scopeParam   = "scope"
	scopeAccount = "account"
)

// accountNamespacesTTL bounds how stale an account's namespace set may be (a namespace moved into or out
// of an account is seen within it).
const accountNamespacesTTL = 30 * time.Second

// fanOutConcurrency bounds the per-namespace lists one account-scoped list makes at once.
const fanOutConcurrency = 8

type accountNSEntry struct {
	names []string
	set   map[string]bool
	home  string
	at    time.Time
}

// accountNamespaceCache is the consoleAuthz's account → namespaces cache.
type accountNamespaceCache struct {
	mu      sync.Mutex
	entries map[string]accountNSEntry
}

// accountNamespaces are account's namespaces, sorted, and its home — the one a new resource lands in.
// They are the namespaces labelled with the account (openinfra.dev/account-id) and, for the management
// account, every tenant namespace no account has claimed as well (as accounts.Directory.AccountOf decides);
// a platform namespace is never an account's. The home is the namespace labelled
// openinfra.dev/account-home, else for the management account the console's IAM home, else the first.
func (z *consoleAuthz) accountNamespaces(ctx context.Context, acct string) ([]string, string, error) {
	e, err := z.accountNamespaceEntry(ctx, acct)
	return e.names, e.home, err
}

func (z *consoleAuthz) accountNamespaceEntry(ctx context.Context, acct string) (accountNSEntry, error) {
	c := &z.acctNS
	c.mu.Lock()
	if e, ok := c.entries[acct]; ok && time.Since(e.at) < accountNamespacesTTL {
		c.mu.Unlock()
		return e, nil
	}
	c.mu.Unlock()
	list, err := z.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return accountNSEntry{}, err
	}
	mgmt := acct == iam.ManagementAccount
	e := accountNSEntry{set: map[string]bool{}, at: time.Now()}
	for _, ns := range list.Items {
		if accounts.IsPlatformNamespace(ns.Name) {
			continue
		}
		label := strings.TrimSpace(ns.Labels[accounts.LabelAccountID])
		if label != acct && (label != "" || !mgmt) {
			continue
		}
		e.names = append(e.names, ns.Name)
		e.set[ns.Name] = true
		if label == acct && ns.Labels[accounts.LabelAccountHome] == "true" {
			e.home = ns.Name
		}
	}
	sort.Strings(e.names)
	if e.home == "" && mgmt && e.set[accounts.DefaultManagementHome] {
		e.home = accounts.DefaultManagementHome
	}
	if e.home == "" && len(e.names) > 0 {
		e.home = e.names[0]
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]accountNSEntry{}
	}
	c.entries[acct] = e
	c.mu.Unlock()
	return e, nil
}

// inAccount is a watch filter: whether a namespace is one of acct's (re-read through the cache, so a
// long-lived stream follows namespaces moving between accounts).
func (z *consoleAuthz) inAccount(acct string) func(string) bool {
	return func(ns string) bool {
		if ns == "" {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		e, err := z.accountNamespaceEntry(ctx, acct)
		return err == nil && e.set[ns]
	}
}

// accountScoped reports whether the request asks for the caller's account (scope=account).
func accountScoped(r *http.Request) bool { return r.URL.Query().Get(scopeParam) == scopeAccount }

// unrestrictedWatcher reports whether the caller may watch the whole cluster in enforce: the management
// account's root user, or the platform's operator.
func (z *consoleAuthz) unrestrictedWatcher(r *http.Request) bool {
	c, ok := claimsFrom(r)
	if !ok {
		return false
	}
	p := z.principal(c)
	return breakGlassRoot(p) || z.isOperator(r, c, p, z.modeFor(r))
}

// bufferedResponse captures one sub-request's answer from the proxy.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse { return &bufferedResponse{header: http.Header{}} }

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

func (b *bufferedResponse) relay(w http.ResponseWriter) {
	for k, v := range b.header {
		if k == "Content-Length" {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// k8sListDoc is a Kubernetes list answer, items kept raw.
type k8sListDoc struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]any    `json:"metadata"`
	Items      []json.RawMessage `json:"items"`
}

// itemNamespace is an item's metadata.namespace ("" when it has none or is not an object).
func itemNamespace(raw json.RawMessage) string {
	var o struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return ""
	}
	return o.Metadata.Namespace
}

// serveAccountList answers an all-namespaces list with scope=account (see the top of this file). next is
// the Kubernetes reverse proxy (it acts as the principal); each request is authorized here first, as the
// gate authorizes a plain one.
func (z *consoleAuthz) serveAccountList(w http.ResponseWriter, r *http.Request, prefix string, next http.Handler) {
	q := r.URL.Query()
	q.Del(scopeParam)
	k, ok := proxy.ParseRequest(r.Method, strings.TrimPrefix(r.URL.Path, prefix), q)
	if !ok || k.Discovery || k.Verb != "list" || k.Namespace != "" || k.Subresource != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "scope=account is for an all-namespaces list of a resource", "errorCode": "ValidationException"})
		return
	}
	if proxiedRootUser(r, k) {
		writeReservedRoot(w)
		return
	}
	acct := callerAccount(r)
	e, err := z.accountNamespaceEntry(r.Context(), acct)
	if err != nil {
		z.logger.Warn("account namespaces", "account", acct, "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "The account's resources could not be listed; retry.", "errorCode": "ServiceUnavailableException"})
		return
	}
	if allowed, reason, action, arn := z.authorizeKubernetes(r, k, nil); !allowed {
		writeAccessDenied(w, action, arn, reason)
		return
	}

	// 1. Cluster-wide, as a plain list, filtered to the account.
	whole := z.subList(r, prefix, k.CollectionPath(""), q, next)
	if whole.status == http.StatusOK {
		var doc k8sListDoc
		if err := json.Unmarshal(whole.body.Bytes(), &doc); err == nil {
			kept := doc.Items[:0]
			for _, it := range doc.Items {
				if e.set[itemNamespace(it)] {
					kept = append(kept, it)
				}
			}
			doc.Items = kept
			writeListDoc(w, doc)
			return
		}
	}
	if whole.status != http.StatusForbidden {
		whole.relay(w)
		return
	}

	// 2. Refused cluster-wide: each of the account's namespaces, through the same gate and proxy.
	answers := make([]*bufferedResponse, len(e.names))
	sem := make(chan struct{}, fanOutConcurrency)
	var wg sync.WaitGroup
	for i, ns := range e.names {
		kn := k
		kn.Namespace = ns
		if allowed, _, _, _ := z.authorizeKubernetes(r, kn, nil); !allowed {
			continue // the gate refuses this namespace: it lists nothing for this caller
		}
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			answers[i] = z.subList(r, prefix, path, q, next)
		}(i, kn.CollectionPath(ns))
	}
	wg.Wait()

	var merged *k8sListDoc
	var minRV uint64
	var rvSet bool
	var refused *bufferedResponse
	for _, a := range answers {
		switch {
		case a == nil:
			continue
		case a.status == http.StatusForbidden || a.status == http.StatusNotFound:
			if refused == nil {
				refused = a
			}
			continue
		case a.status != http.StatusOK:
			a.relay(w)
			return
		}
		var doc k8sListDoc
		if err := json.Unmarshal(a.body.Bytes(), &doc); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream Kubernetes API error"})
			return
		}
		if merged == nil {
			merged = &k8sListDoc{APIVersion: doc.APIVersion, Kind: doc.Kind, Metadata: map[string]any{}}
		}
		merged.Items = append(merged.Items, doc.Items...)
		// The merged list's position is the earliest of the lists': a watch from it replays whatever a
		// later list already holds, and the client upserts by uid.
		if rv, err := strconv.ParseUint(listRV(doc), 10, 64); err == nil && (!rvSet || rv < minRV) {
			minRV, rvSet = rv, true
		}
	}
	if merged == nil {
		if refused != nil {
			refused.relay(w)
			return
		}
		merged = &k8sListDoc{APIVersion: "v1", Kind: "List", Metadata: map[string]any{}}
	}
	if rvSet {
		merged.Metadata["resourceVersion"] = strconv.FormatUint(minRV, 10)
	}
	writeListDoc(w, *merged)
}

func listRV(doc k8sListDoc) string {
	rv, _ := doc.Metadata["resourceVersion"].(string)
	return rv
}

func writeListDoc(w http.ResponseWriter, doc k8sListDoc) {
	if doc.Items == nil {
		doc.Items = []json.RawMessage{}
	}
	if doc.Metadata == nil {
		doc.Metadata = map[string]any{}
	}
	writeJSON(w, http.StatusOK, doc)
}

// subList is one list through the proxy as the caller: path (a Kubernetes API path) with query q,
// uncompressed JSON so it can be read here.
func (z *consoleAuthz) subList(r *http.Request, prefix, path string, q url.Values, next http.Handler) *bufferedResponse {
	sub := r.Clone(r.Context())
	sub.URL.Path = prefix + path
	sub.URL.RawPath = ""
	sub.URL.RawQuery = q.Encode()
	sub.RequestURI = ""
	sub.Header.Del("Accept-Encoding")
	sub.Header.Set("Accept", "application/json")
	out := newBufferedResponse()
	next.ServeHTTP(out, sub)
	if out.status == 0 {
		out.status = http.StatusOK
	}
	return out
}

// watchScope is the namespace filter a watch request gets, or nil for none: the caller's account for
// scope=account, and in enforce for a cluster-wide watch by anyone but root and the operator.
func (z *consoleAuthz) watchScope(r *http.Request, k proxy.Request) func(string) bool {
	if accountScoped(r) {
		return z.inAccount(callerAccount(r))
	}
	if k.Namespace == "" && z.enforced(r) && !z.unrestrictedWatcher(r) {
		return z.inAccount(callerAccount(r))
	}
	return nil
}

// withWatchScope puts the watch filter for k on r's context (unchanged when there is none).
func (z *consoleAuthz) withWatchScope(r *http.Request, k proxy.Request) *http.Request {
	if keep := z.watchScope(r, k); keep != nil {
		return r.WithContext(watch.WithNamespaceFilter(r.Context(), keep))
	}
	return r
}
