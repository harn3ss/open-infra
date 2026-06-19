package main

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	webui "github.com/harn3ss/open-infra/console-api"
)

// webFS holds the built React SPA, embedded at the module root (see webui.go).
// In development it contains only the placeholder index.html committed to the
// repo; in the container image the real ui/dist is copied into web/ before the
// build, so the same binary serves the production UI.
var webFS = webui.FS

// newSPAHandler returns a handler that serves the embedded SPA with history-mode
// fallback: a request for a real embedded file is served as-is, while any other
// path (a client-side route like /apps/foo) falls back to index.html so the
// React router can take over.
//
// API and health routes are mounted ahead of this handler in the router, so they
// never reach the fallback.
func newSPAHandler() (http.Handler, error) {
	// Re-root the embedded FS at "web" so URLs map to file paths directly:
	// "/" -> "index.html", "/assets/app.js" -> "assets/app.js".
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Normalize and confine the request path before touching the FS.
		upath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		name := strings.TrimPrefix(upath, "/")

		if name == "" {
			// Root request -> index.html.
			serveIndex(w, r, sub)
			return
		}

		// If the requested file exists in the embedded FS, serve it directly
		// (this covers index.html, assets, favicon, etc.).
		if f, err := sub.Open(name); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// Unknown path with a file extension is treated as a genuine 404 (a
		// missing asset), not a client-side route — avoids masking broken asset
		// references behind index.html.
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}

		// Otherwise: SPA history-mode fallback.
		serveIndex(w, r, sub)
	}), nil
}

// serveIndex writes the embedded index.html. We read and serve it explicitly so
// the response is always 200 (not the file server's redirect behavior for "/").
func serveIndex(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	data, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		http.Error(w, "UI not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The SPA shell must not be cached aggressively, or clients pin a stale
	// asset manifest after a deploy.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}
