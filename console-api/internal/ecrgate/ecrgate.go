// Package ecrgate decides each registry request as the ECR action AWS authorizes it as.
//
// ECR authorizes every call a Docker client makes to the registry as an IAM action on the repository:
// checking whether a layer exists is ecr:BatchCheckLayerAvailability, downloading one is
// ecr:GetDownloadUrlForLayer, uploading one is ecr:InitiateLayerUpload, ecr:UploadLayerPart and
// ecr:CompleteLayerUpload, writing a manifest is ecr:PutImage, reading one is ecr:BatchGetImage. So a
// principal holding ECR's documented push policy pushes without being able to download layers.
//
// The registry behind the gate (CNCF distribution) knows only three token scopes, pull, push and delete,
// and requires pull for every write, so it cannot express that split. The gate sits in front of it, in
// the same pod, and decides each request against the ECR actions the shim's token service granted, which
// it writes into the same signed registry token beside the scopes distribution reads.
//
// The gate only refuses. Whatever it lets through is still checked by distribution, which verifies the
// token's signature and scopes as before, so a request the gate forwards can never do more than the
// token allows. A token the gate cannot read, a token with no entry for the repository (a client that has
// not yet asked for this repository's scope, which distribution answers with its 401 challenge), and an
// entry from a token service that did not decide per action are forwarded unchanged.
package ecrgate

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The ECR actions the gate decides.
const (
	BatchGetImage               = "ecr:BatchGetImage"
	GetDownloadURLForLayer      = "ecr:GetDownloadUrlForLayer"
	BatchCheckLayerAvailability = "ecr:BatchCheckLayerAvailability"
	InitiateLayerUpload         = "ecr:InitiateLayerUpload"
	UploadLayerPart             = "ecr:UploadLayerPart"
	CompleteLayerUpload         = "ecr:CompleteLayerUpload"
	PutImage                    = "ecr:PutImage"
	BatchDeleteImage            = "ecr:BatchDeleteImage"
	ListImages                  = "ecr:ListImages"
)

// Access is one entry of a registry token's access claim. Type, Name and Actions are the Docker registry
// token's; Actions carries both the scopes distribution enforces (pull, push, delete) and the ECR actions
// granted. Requested is the scopes the token service was asked for and decided on: an entry that has it
// was decided per ECR action, so an action missing from it was refused. Resource is the repository's ARN,
// for the access-denied message.
type Access struct {
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Actions   []string `json:"actions"`
	Requested []string `json:"requested,omitempty"`
	Resource  string   `json:"resource,omitempty"`
}

// Request is a registry request as ECR authorizes it.
type Request struct {
	Repo    string   // the registry path of the repository
	Scope   string   // the distribution scope the method needs: pull, push or delete
	Actions []string // the ECR actions the request needs, all of them
	// MountFrom is the repository a blob mount (POST .../blobs/uploads/?mount=<digest>&from=<repo>) takes
	// the layer from; mounting needs ecr:GetDownloadUrlForLayer there, as ECR documents.
	MountFrom string
}

// The grammar distribution routes by (github.com/distribution/reference): a repository name is
// lower-case components separated by '/', a tag is up to 128 word characters, a digest is
// <algorithm>:<hex>. The gate classifies a path only when it matches the route distribution would take,
// so the two always agree on which repository a request names.
const (
	component = `[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*`
	name      = component + `(?:/` + component + `)*`
	tag       = `[\w][\w.-]{0,127}`
	digest    = `[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}`
	uploadID  = `[a-zA-Z0-9-_.=]+`
)

type route int

const (
	routeManifest route = iota
	routeTags
	routeBlob
	routeUpload
	routeUploadChunk
	routeReferrers
)

// routes in distribution's registration order (registry/api/v2/descriptors.go); the first match wins.
var routes = []struct {
	re *regexp.Regexp
	r  route
}{
	{regexp.MustCompile(`^/v2/(` + name + `)/manifests/(?:` + tag + `|` + digest + `)$`), routeManifest},
	{regexp.MustCompile(`^/v2/(` + name + `)/tags/list$`), routeTags},
	{regexp.MustCompile(`^/v2/(` + name + `)/blobs/` + digest + `$`), routeBlob},
	{regexp.MustCompile(`^/v2/(` + name + `)/blobs/uploads/?$`), routeUpload},
	{regexp.MustCompile(`^/v2/(` + name + `)/blobs/uploads/` + uploadID + `$`), routeUploadChunk},
	{regexp.MustCompile(`^/v2/(` + name + `)/referrers/` + digest + `$`), routeReferrers},
}

// scopeOf is the distribution scope a method needs (registry/handlers/app.go appendAccessRecords).
func scopeOf(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "pull"
	case http.MethodDelete:
		return "delete"
	}
	return "push"
}

// Classify maps a registry request to the ECR actions it needs. ok is false for a path or method ECR's
// registry API does not serve (the catalog, deleting a layer), which the gate refuses without forwarding.
func Classify(method, path string, query url.Values, contentLength int64) (req Request, ok bool) {
	for _, rt := range routes {
		m := rt.re.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		req = Request{Repo: m[1], Scope: scopeOf(method)}
		switch rt.r {
		case routeManifest:
			switch method {
			case http.MethodGet, http.MethodHead:
				req.Actions = []string{BatchGetImage}
			case http.MethodPut:
				req.Actions = []string{PutImage}
			case http.MethodDelete:
				req.Actions = []string{BatchDeleteImage}
			}
		case routeTags:
			if method == http.MethodGet {
				req.Actions = []string{ListImages}
			}
		case routeReferrers:
			if method == http.MethodGet {
				req.Actions = []string{BatchGetImage}
			}
		case routeBlob:
			switch method {
			case http.MethodGet:
				req.Actions = []string{GetDownloadURLForLayer}
			case http.MethodHead:
				req.Actions = []string{BatchCheckLayerAvailability}
			}
		case routeUpload:
			if method == http.MethodPost {
				req.Actions = []string{InitiateLayerUpload}
				if query.Get("digest") != "" { // a monolithic upload: initiate, upload and complete in one
					req.Actions = append(req.Actions, UploadLayerPart, CompleteLayerUpload)
				}
				if query.Get("mount") != "" {
					req.MountFrom = query.Get("from")
				}
			}
		case routeUploadChunk:
			switch method {
			case http.MethodGet, http.MethodPatch, http.MethodDelete: // status, a chunk, cancelling
				req.Actions = []string{UploadLayerPart}
			case http.MethodPut:
				req.Actions = []string{CompleteLayerUpload}
				if contentLength > 0 { // the final chunk rides on the PUT
					req.Actions = []string{UploadLayerPart, CompleteLayerUpload}
				}
			}
		}
		return req, len(req.Actions) > 0
	}
	return Request{}, false
}

// tokenAccess reads the access claim of the request's registry bearer token. The signature is not
// checked here: distribution checks it on everything the gate forwards, and the gate only ever refuses.
func tokenAccess(r *http.Request) (sub string, access []Access, ok bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return "", nil, false
	}
	parts := strings.Split(strings.TrimSpace(h[7:]), ".")
	if len(parts) != 3 {
		return "", nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, false
	}
	var claims struct {
		Sub    string   `json:"sub"`
		Access []Access `json:"access"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "", nil, false
	}
	return claims.Sub, claims.Access, true
}

func entryFor(access []Access, repo string) (Access, bool) {
	for _, a := range access {
		if a.Type == "repository" && a.Name == repo {
			return a, true
		}
	}
	return Access{}, false
}

// Gate is the registry's front: it refuses what ECR would refuse and forwards the rest to Upstream.
type Gate struct {
	proxy *httputil.ReverseProxy
}

// New is a Gate in front of the registry at upstream (e.g. http://127.0.0.1:5001).
func New(upstream *url.URL) *Gate {
	p := &httputil.ReverseProxy{
		// Director, not Rewrite: the registry builds its upload Location URLs from the client's Host and
		// X-Forwarded-Proto, which must reach it as the client sent them.
		Director: func(r *http.Request) {
			r.URL.Scheme = upstream.Scheme
			r.URL.Host = upstream.Host
		},
		FlushInterval: -1, // stream layer bytes as they come
	}
	return &Gate{proxy: p}
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/v2" || r.URL.Path == "/v2/" {
		g.proxy.ServeHTTP(w, r) // health, and the version check `docker login` makes
		return
	}
	req, ok := Classify(r.Method, r.URL.Path, r.URL.Query(), r.ContentLength)
	if !ok {
		writeError(w, http.StatusNotFound, "UNSUPPORTED", "The operation is unsupported.")
		return
	}
	sub, access, ok := tokenAccess(r)
	if !ok {
		g.proxy.ServeHTTP(w, r) // no token: distribution answers with its challenge
		return
	}
	entry, ok := entryFor(access, req.Repo)
	if !ok || len(entry.Requested) == 0 || !slices.Contains(entry.Requested, req.Scope) {
		// Not decided for this repository and scope yet: distribution's 401 sends the client back to the
		// token service, which decides it.
		g.proxy.ServeHTTP(w, r)
		return
	}
	for _, a := range req.Actions {
		if !slices.Contains(entry.Actions, a) {
			writeError(w, http.StatusForbidden, "DENIED", denied(sub, a, entry))
			return
		}
	}
	if req.MountFrom != "" {
		from, ok := entryFor(access, req.MountFrom)
		if !ok || !slices.Contains(from.Actions, GetDownloadURLForLayer) {
			// ECR mounts a layer only for a caller that may download it from the source repository;
			// otherwise the upload starts afresh, as on a registry that does not mount.
			q := r.URL.Query()
			q.Del("mount")
			q.Del("from")
			r.URL.RawQuery = q.Encode()
		}
	}
	g.proxy.ServeHTTP(w, r)
}

// denied is ECR's access-denied message.
func denied(sub, action string, entry Access) string {
	resource := entry.Resource
	if resource == "" {
		resource = entry.Name
	}
	who := sub
	if who == "" {
		who = "the caller"
	}
	return "User: " + who + " is not authorized to perform: " + action + " on resource: " + resource
}

// writeError answers in the registry API's error format.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]any{"code": code, "message": message}}})
}
