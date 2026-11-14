package main

// A VM's "Get system log" and "Get instance screenshot", as the EC2 console's Actions → Monitor and
// troubleshoot: the guest's serial console output and a still image of its display. The route table
// decides ec2:GetConsoleOutput / ec2:GetConsoleScreenshot on the instance before either runs; the reads
// are internal/vmconsole's, shared with the AWS front door's GetConsoleOutput and GetConsoleScreenshot.

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
	"k8s.io/client-go/kubernetes"
)

type vmConsoleOutput struct {
	Output    string `json:"output"`
	Timestamp string `json:"timestamp"`
	// Note says why there is no output, when there is none.
	Note string `json:"note,omitempty"`
}

// GET /api/vms/{namespace}/{name}/console-output
func handleVMConsoleOutput(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		resp := vmConsoleOutput{Timestamp: time.Now().UTC().Format(time.RFC3339)}
		out, err := vmconsole.Output(r.Context(), cs, ns, name)
		switch {
		case err == nil:
			resp.Output = string(out)
		case errors.Is(err, vmconsole.ErrNotRunning):
			resp.Note = "The instance isn't running, so there is no system log to show."
		case errors.Is(err, vmconsole.ErrNoLog):
			resp.Note = "This instance was started before its system log was collected. The log starts at its next stop and start."
		default:
			logger.Warn("vm console output", "vm", ns+"/"+name, "err", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The system log could not be read; try again."})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// GET /api/vms/{namespace}/{name}/console-screenshot[?wake=true]: the JPEG itself.
func handleVMConsoleScreenshot(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		img, err := vmconsole.Screenshot(r.Context(), cs, ns, name, r.URL.Query().Get("wake") == "true")
		switch {
		case err == nil:
		case errors.Is(err, vmconsole.ErrNotRunning):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "The instance isn't running, so there is no screen to capture."})
			return
		default:
			logger.Warn("vm console screenshot", "vm", ns+"/"+name, "err", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The screenshot could not be taken; try again."})
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(img)
	}
}
