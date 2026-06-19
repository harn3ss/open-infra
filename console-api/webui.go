// Package webui embeds the built React SPA so the BFF can serve the UI and the
// API from a single binary / container (the Headlamp pattern).
//
// The embed directive lives at the module root because //go:embed can only
// reference files in or below its own source directory, and the web/ build
// output sits here (the Dockerfile copies ui/dist into web/ before `go build`).
//
// In development web/ holds only the committed placeholder index.html; in the
// image it holds the real production assets.
package webui

import "embed"

// FS holds the embedded SPA. `all:web` includes dotfiles and underscore-prefixed
// files (e.g. Vite asset chunks) that the default embed pattern would skip.
//
//go:embed all:web
var FS embed.FS
