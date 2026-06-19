// Package watch bridges a Kubernetes watch stream to browser-friendly
// Server-Sent Events (SSE).
//
// A browser cannot speak the Kubernetes streaming-watch protocol directly (it
// holds no credentials and EventSource only does GET), so this handler:
//
//  1. Opens a watch against the API server using the authenticated transport
//     (?watch=true&resourceVersion=<rv>&allowWatchBookmarks=true).
//  2. Reads the newline-delimited JSON watch.Event stream.
//  3. Re-emits each event as an SSE `data:` frame, tagging the SSE event id with
//     the object's resourceVersion so the browser can resume via Last-Event-ID.
//  4. Detects a "410 Gone" ERROR event and emits `event: expired`, the signal
//     for the client to drop its cache and relist.
//
// The ServiceAccount's RBAC governs what may be watched; an unauthorized watch
// simply fails upstream and we relay the error.
package watch

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// maxLineBytes caps a single watch-event line. Individual objects can be large
// (CRDs with big schemas), so we allow a generous buffer before giving up.
const maxLineBytes = 8 << 20 // 8 MiB

// Handler serves GET /api/watch. Construct it with New and mount it on the router.
type Handler struct {
	host      *url.URL
	transport http.RoundTripper
	logger    *slog.Logger
}

// New returns a watch Handler that targets the API server at host using
// transport for authentication.
func New(host *url.URL, transport http.RoundTripper, logger *slog.Logger) *Handler {
	return &Handler{host: host, transport: transport, logger: logger}
}

// watchEnvelope is the minimal shape we need to parse out of each watch event.
// Kubernetes emits {"type": "...", "object": {...}} per line; for ERROR events
// the object is a metav1.Status carrying the HTTP-equivalent code.
type watchEnvelope struct {
	Type   string `json:"type"`
	Object struct {
		Kind     string `json:"kind"`
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		// Status fields, present when Type == "ERROR" and Kind == "Status".
		Code int32 `json:"code"`
	} `json:"object"`
}

// ServeHTTP opens the upstream watch and streams it to the client as SSE.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	listPath := r.URL.Query().Get("path")
	if listPath == "" {
		http.Error(w, "missing required query parameter: path", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(listPath, "/") {
		http.Error(w, "path must be an absolute Kubernetes API path", http.StatusBadRequest)
		return
	}

	// resourceVersion comes from the query param, but a reconnecting EventSource
	// will send the last id it saw via the Last-Event-ID header — that takes
	// precedence so we resume exactly where the stream left off.
	resourceVersion := r.URL.Query().Get("resourceVersion")
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		resourceVersion = lastID
	}

	// The SSE response must be flushable; without a Flusher we can't stream.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Build the upstream watch URL: <apiserver><path>?watch=true&...
	target := *h.host
	target.Path = listPath
	q := target.Query()
	q.Set("watch", "true")
	q.Set("allowWatchBookmarks", "true")
	if resourceVersion != "" {
		q.Set("resourceVersion", resourceVersion)
	}
	target.RawQuery = q.Encode()

	ctx := r.Context()
	upReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		http.Error(w, "failed to build watch request", http.StatusInternalServerError)
		return
	}
	// Ask the API server for the streaming JSON watch protocol.
	upReq.Header.Set("Accept", "application/json")

	resp, err := h.transport.RoundTrip(upReq)
	if err != nil {
		// Client gone before/while we connected upstream is normal, not an error.
		if ctx.Err() != nil {
			return
		}
		h.logger.Error("watch upstream connect failed",
			slog.String("path", listPath), slog.String("error", err.Error()))
		http.Error(w, "failed to connect to Kubernetes watch", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// If the API server rejected the watch outright (e.g. 403 from RBAC, 404 for
	// a bad path), relay a meaningful status before we commit to SSE framing.
	if resp.StatusCode != http.StatusOK {
		h.logger.Warn("watch upstream non-200",
			slog.String("path", listPath), slog.Int("status", resp.StatusCode))
		http.Error(w, fmt.Sprintf("Kubernetes watch returned %d", resp.StatusCode), resp.StatusCode)
		return
	}

	// Commit to SSE. These headers disable buffering across the proxy chain
	// (nginx/ingress honor X-Accel-Buffering) so events reach the browser live.
	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream")
	hdr.Set("Cache-Control", "no-cache")
	hdr.Set("Connection", "keep-alive")
	hdr.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for scanner.Scan() {
		// Honor client disconnect promptly between events.
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev watchEnvelope
		if err := json.Unmarshal(line, &ev); err != nil {
			// Forward the raw line anyway so the client isn't starved; just skip
			// id/expiry handling we couldn't parse.
			h.writeData(w, "", line)
			flusher.Flush()
			continue
		}

		// A "410 Gone" arrives as an ERROR event whose object is a Status with
		// code 410. The client's cached resourceVersion is too old to resume —
		// tell it to relist via a dedicated SSE event type.
		if ev.Type == "ERROR" && ev.Object.Code == 410 {
			h.writeExpired(w, line)
			flusher.Flush()
			// The upstream watch is finished after a 410; stop reading.
			return
		}

		// Tag the SSE event id with the object's resourceVersion so a reconnect
		// (Last-Event-ID) resumes from the right point.
		h.writeData(w, ev.Object.Metadata.ResourceVersion, line)
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		// Upstream closed unexpectedly. EventSource will auto-reconnect with the
		// last id it saw; just log and let the connection end.
		h.logger.Debug("watch stream ended",
			slog.String("path", listPath), slog.String("error", err.Error()))
	}
}

// writeData emits a single SSE message carrying the raw watch-event JSON as the
// data payload, optionally setting the event id to the resourceVersion.
//
// The watch JSON is single-line (newline-delimited protocol), so it maps to one
// SSE `data:` line; we still guard against embedded newlines defensively.
func (h *Handler) writeData(w http.ResponseWriter, id string, payload []byte) {
	if id != "" {
		fmt.Fprintf(w, "id: %s\n", id)
	}
	writeDataLines(w, payload)
	// Blank line terminates the SSE event.
	fmt.Fprint(w, "\n")
}

// writeExpired emits the `expired` event the client watches for to trigger a
// relist after a 410 Gone.
func (h *Handler) writeExpired(w http.ResponseWriter, payload []byte) {
	fmt.Fprint(w, "event: expired\n")
	writeDataLines(w, payload)
	fmt.Fprint(w, "\n")
}

// writeDataLines writes payload as one or more SSE `data:` lines. Per the SSE
// spec each physical line in the payload needs its own `data:` prefix.
func writeDataLines(w http.ResponseWriter, payload []byte) {
	for _, ln := range strings.Split(string(payload), "\n") {
		fmt.Fprintf(w, "data: %s\n", ln)
	}
}
