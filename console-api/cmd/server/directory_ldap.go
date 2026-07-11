package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-ldap/ldap/v3"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Read-only AD Explorer for kind: Directory. Powers the console's "Explorer" tab: the BFF
// binds to the Samba AD DC and runs LDAP *searches only* (never modify/add/delete). The
// connection is resolved from the directory's own generated Secret ("<name>-directory"),
// namespace-scoped — never from the client (same anti-SSRF rule as DB Peek).

type ldapSearchReq struct {
	BaseDN     string   `json:"baseDN"`     // default: the domain DN
	Filter     string   `json:"filter"`     // default: (objectClass=*)
	Scope      string   `json:"scope"`      // base | one | sub  (default: one)
	Attributes []string `json:"attributes"` // default: a useful set
	SizeLimit  int      `json:"sizeLimit"`  // capped at 500
}

type ldapEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

type ldapSearchResp struct {
	BaseDN  string      `json:"baseDN"`  // the base the search actually ran against
	Domain  string      `json:"domain"`  // the AD domain
	Entries []ldapEntry `json:"entries"`
}

// domainToBaseDN turns "ams-aws-prod.com" into "DC=ams-aws-prod,DC=com".
func domainToBaseDN(domain string) string {
	parts := strings.Split(strings.TrimSpace(domain), ".")
	dc := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			dc = append(dc, "DC="+p)
		}
	}
	return strings.Join(dc, ",")
}

func handleDirectoryLDAP(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		if ns == "" || name == "" {
			writeError(w, http.StatusBadRequest, "namespace and name are required")
			return
		}
		var req ldapSearchReq
		_ = json.NewDecoder(r.Body).Decode(&req) // all fields optional; defaults on empty/parse error

		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()

		// Resolve creds from the directory's own Secret (namespace-scoped, never client-supplied).
		sec, err := cs.CoreV1().Secrets(ns).Get(ctx, name+"-directory", metav1.GetOptions{})
		if err != nil {
			writeError(w, http.StatusNotFound, "no connection secret for this directory (is it a kind: Directory?)")
			return
		}
		domain := string(sec.Data["DOMAIN"])
		adminUser := string(sec.Data["ADMIN_USER"])
		adminPass := string(sec.Data["ADMIN_PASSWORD"])
		if domain == "" || adminUser == "" || adminPass == "" {
			writeError(w, http.StatusNotFound, "directory secret is missing DOMAIN/ADMIN_USER/ADMIN_PASSWORD")
			return
		}

		entries, base, err := searchAD(ctx, adSearchParams{
			host:     name + "." + ns + ".svc.cluster.local",
			domain:   domain,
			bindUser: adminUser,
			bindPass: adminPass,
			req:      req,
		})
		if err != nil {
			logger.Warn("directory ldap search failed", "ns", ns, "name", name, "err", err)
			writeError(w, http.StatusBadGateway, "couldn't query the directory: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ldapSearchResp{BaseDN: base, Domain: domain, Entries: entries})
	}
}

type adSearchParams struct {
	host, domain, bindUser, bindPass string
	req                              ldapSearchReq
}

// searchAD binds to the DC over LDAPS (the DC self-signs its cert, so skip verification —
// the connection is in-cluster to a resource we own) and runs a single read-only search.
func searchAD(ctx context.Context, p adSearchParams) ([]ldapEntry, string, error) {
	l, err := ldap.DialURL("ldaps://"+p.host+":636", ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		// fall back to plain LDAP in-cluster if LDAPS is unavailable
		l, err = ldap.DialURL("ldap://" + p.host + ":389")
		if err != nil {
			return nil, "", fmt.Errorf("connect: %w", err)
		}
	}
	defer l.Close()
	if d, ok := ctx.Deadline(); ok {
		l.SetTimeout(time.Until(d))
	}

	// Bind as a UPN (Administrator@domain) — Samba AD accepts it.
	bindUser := p.bindUser
	if !strings.Contains(bindUser, "@") && !strings.Contains(bindUser, "=") {
		bindUser = bindUser + "@" + p.domain
	}
	if err := l.Bind(bindUser, p.bindPass); err != nil {
		return nil, "", fmt.Errorf("bind: %w", err)
	}

	base := p.req.BaseDN
	if base == "" {
		base = domainToBaseDN(p.domain)
	}
	filter := p.req.Filter
	if strings.TrimSpace(filter) == "" {
		filter = "(objectClass=*)"
	}
	scope := ldap.ScopeSingleLevel
	switch p.req.Scope {
	case "base":
		scope = ldap.ScopeBaseObject
	case "sub":
		scope = ldap.ScopeWholeSubtree
	}
	attrs := p.req.Attributes
	if len(attrs) == 0 {
		attrs = []string{
			"objectClass", "distinguishedName", "name", "cn", "sAMAccountName",
			"displayName", "description", "mail", "userPrincipalName",
			"memberOf", "member", "whenCreated", "userAccountControl", "objectCategory",
		}
	}
	size := p.req.SizeLimit
	if size <= 0 || size > 500 {
		size = 500
	}

	res, err := l.Search(ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases, size, 10, false, filter, attrs, nil,
	))
	if err != nil {
		return nil, base, fmt.Errorf("search: %w", err)
	}
	out := make([]ldapEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		am := make(map[string][]string, len(e.Attributes))
		for _, a := range e.Attributes {
			am[a.Name] = a.Values
		}
		out = append(out, ldapEntry{DN: e.DN, Attributes: am})
	}
	return out, base, nil
}
