package proxy

import (
	"net/http"
	"net/url"
	"strings"
)

// Request is a Kubernetes API request as an authorization question: the verb it amounts to and the
// object it names. Discovery is a request for the API's own description (/api, /apis/<group>/<v>,
// /version, /openapi/…), which names no object.
type Request struct {
	Verb        string // get, list, watch, create, update, patch, delete, deletecollection
	Group       string // "" for the core group
	Version     string
	Resource    string // plural, e.g. pods, virtualmachines
	Subresource string // e.g. log, status, exec ("" when none)
	Namespace   string
	Name        string
	Discovery   bool
}

// ResourcePath is Resource with its subresource ("pods/log"), the form RBAC and the action table use.
func (k Request) ResourcePath() string {
	if k.Subresource == "" {
		return k.Resource
	}
	return k.Resource + "/" + k.Subresource
}

// CollectionPath is the API path of k's collection in namespace ns:
// /api/v1/namespaces/<ns>/<resource> or /apis/<group>/<version>/namespaces/<ns>/<resource>.
func (k Request) CollectionPath(ns string) string {
	base := "/apis/" + k.Group + "/" + k.Version
	if k.Group == "" {
		base = "/api/" + k.Version
	}
	if ns == "" {
		return base + "/" + k.Resource
	}
	return base + "/namespaces/" + url.PathEscape(ns) + "/" + k.Resource
}

// ParseRequest reads the Kubernetes request a method, API path and query make, the way the API server
// does: /api/v1[/namespaces/<ns>]/<resource>[/<name>[/<sub>]] for the core group and
// /apis/<group>/<version>[/namespaces/<ns>]/<resource>[/<name>[/<sub>]] for the others. A path that
// names no resource is discovery. ok=false for a path that is neither (it is refused, never guessed).
func ParseRequest(method, path string, query url.Values) (Request, bool) {
	p := strings.Trim(path, "/")
	if p == "" || p == "version" || p == "healthz" || p == "livez" || p == "readyz" || p == "openapi" ||
		strings.HasPrefix(p, "openapi/") || p == "api" || p == "apis" {
		return Request{Verb: "get", Discovery: true}, true
	}
	segs := strings.Split(p, "/")
	var k Request
	var rest []string
	switch segs[0] {
	case "api":
		if len(segs) < 2 {
			return Request{Verb: "get", Discovery: true}, true
		}
		k.Version, rest = segs[1], segs[2:]
	case "apis":
		switch len(segs) {
		case 1, 2, 3: // /apis, /apis/<group>, /apis/<group>/<version>
			return Request{Verb: "get", Discovery: true}, true
		}
		k.Group, k.Version, rest = segs[1], segs[2], segs[3:]
	default:
		return Request{}, false
	}
	if len(rest) == 0 {
		return Request{Verb: "get", Discovery: true}, true
	}
	if rest[0] == "namespaces" && len(rest) == 3 && (rest[2] == "status" || rest[2] == "finalize") {
		// A namespace's own subresource (/api/v1/namespaces/<ns>/status), not a resource inside it.
		k.Resource, k.Name, k.Subresource, k.Namespace = "namespaces", rest[1], rest[2], rest[1]
		k.Verb = verbOf(method, true, query)
		return k, k.Verb != ""
	}
	if rest[0] == "namespaces" && len(rest) >= 3 {
		k.Namespace, rest = rest[1], rest[2:]
	}
	switch len(rest) {
	case 1:
		k.Resource = rest[0]
	case 2:
		k.Resource, k.Name = rest[0], rest[1]
		if k.Resource == "namespaces" && k.Namespace == "" {
			k.Namespace = k.Name // a namespace's own object
		}
	case 3:
		k.Resource, k.Name, k.Subresource = rest[0], rest[1], rest[2]
	default:
		return Request{}, false
	}
	if k.Resource == "" {
		return Request{}, false
	}
	k.Verb = verbOf(method, k.Name != "", query)
	if k.Verb == "" {
		return Request{}, false
	}
	return k, true
}

// verbOf is the verb an HTTP method is on a collection (named=false) or an object.
func verbOf(method string, named bool, query url.Values) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		if query.Get("watch") == "true" || query.Get("watch") == "1" {
			return "watch"
		}
		if named {
			return "get"
		}
		return "list"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		if named {
			return "delete"
		}
		return "deletecollection"
	}
	return ""
}
