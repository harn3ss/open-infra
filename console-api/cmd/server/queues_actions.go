package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func natsConnect() (*nats.Conn, error) {
	return nats.Connect(
		getenv("NATS_URL", "nats://nats.nats.svc.cluster.local:4222"),
		nats.Timeout(5*time.Second),
	)
}

// handleQueuePublish publishes a message to a subject (e.g. to test a stream).
func handleQueuePublish(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Subject string `json:"subject"`
			Data    string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Subject == "" {
			writeError(w, http.StatusBadRequest, "subject required")
			return
		}
		nc, err := natsConnect()
		if err != nil {
			writeError(w, http.StatusBadGateway, "messaging unavailable")
			return
		}
		defer nc.Close()
		if err := nc.Publish(body.Subject, []byte(body.Data)); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := nc.FlushTimeout(3 * time.Second); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "published", "subject": body.Subject})
	}
}

// handleQueuePurge drops all messages from a JetStream stream.
func handleQueuePurge(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stream := chi.URLParam(r, "stream")
		nc, err := natsConnect()
		if err != nil {
			writeError(w, http.StatusBadGateway, "messaging unavailable")
			return
		}
		defer nc.Close()
		js, err := jetstream.New(nc)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		s, err := js.Stream(ctx, stream)
		if err != nil {
			writeError(w, http.StatusNotFound, "stream not found")
			return
		}
		if err := s.Purge(ctx); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "purged", "stream": stream})
	}
}
