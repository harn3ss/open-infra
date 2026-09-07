package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
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

// peekMsg is one stored JetStream message returned by a non-destructive peek.
type peekMsg struct {
	Seq       uint64 `json:"seq"`
	Subject   string `json:"subject"`
	Data      string `json:"data"`
	Time      string `json:"time"`
	Truncated bool   `json:"truncated"`
}

// handleQueuePeek returns the most recent messages STORED in a JetStream stream
// without consuming them — a non-destructive read by sequence number. This is the
// honest JetStream analog of SQS "poll for messages": it creates no consumer,
// advances no cursor, and leaves delivery to the stream's real durable consumers
// (the apps/Functions/sinks that subscribe) completely untouched. It is NOT an
// SQS receive (there is no per-message visibility timeout or ack here) — it is a
// read-only look at what the stream currently holds, newest first.
func handleQueuePeek(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stream := chi.URLParam(r, "stream")
		limit := 25
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
				limit = n
			}
		}
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
		info, err := s.Info(ctx)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		const maxLen = 4096 // cap each payload so a peek can't return unbounded data
		out := make([]peekMsg, 0, limit)
		first := info.State.FirstSeq
		// Walk backwards from the newest stored message (newest first), skipping any
		// gaps left by deleted/expired sequences, until we have `limit` messages.
		for seq := info.State.LastSeq; seq >= first && seq != 0 && len(out) < limit; seq-- {
			msg, err := s.GetMsg(ctx, seq)
			if err != nil {
				continue // deleted/expired/limits-rolled sequence — skip it
			}
			data := msg.Data
			truncated := false
			if len(data) > maxLen {
				data = data[:maxLen]
				truncated = true
			}
			out = append(out, peekMsg{
				Seq:       msg.Sequence,
				Subject:   msg.Subject,
				Data:      string(data),
				Time:      msg.Time.UTC().Format(time.RFC3339Nano),
				Truncated: truncated,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"stream": stream, "messages": out})
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
