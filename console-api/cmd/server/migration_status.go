package main

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nats-io/nats.go/jetstream"
)

// Migration/Replication observability: the apply pipeline's live signals come
// from NATS JetStream (the browser can't reach NATS), so the BFF aggregates them:
//   - lag      = the apply-sink consumer's pending count (events captured but not
//                yet applied to the target) — the headline "how far behind" number,
//   - captured = messages buffered in the stream, broken down per table (subject),
//   - deadLetter = rows that failed to apply and were dead-lettered.
// Component (Debezium / apply-sink) health + CR conditions are read by the UI via
// the k8s proxy; this endpoint adds what only the server can see.

type tableStat struct {
	Subject string `json:"subject"`
	Table   string `json:"table"`
	Count   uint64 `json:"count"`
}

type pipelineStatus struct {
	Stream      string      `json:"stream"`
	Found       bool        `json:"found"`       // stream exists yet?
	Captured    uint64      `json:"captured"`    // messages in the stream
	Bytes       uint64      `json:"bytes"`       // stream size
	Lag         uint64      `json:"lag"`         // consumer pending = unapplied backlog
	AckPending  int         `json:"ackPending"`  // in-flight (being applied)
	Redelivered int         `json:"redelivered"` // retries
	Tables      []tableStat `json:"tables"`
	DeadLetter  uint64      `json:"deadLetter"`
	DLQSubjects []tableStat `json:"dlqSubjects"`
}

// lastTwo turns a CDC subject (e.g. "mig.foo.public.orders") into "public.orders".
func lastTwo(subject string) string {
	p := strings.Split(subject, ".")
	if len(p) >= 2 {
		return strings.Join(p[len(p)-2:], ".")
	}
	return subject
}

// gatherPipeline fills a pipelineStatus for one (stream, durable, subjectPrefix).
func gatherPipeline(ctx context.Context, js jetstream.JetStream, stream, durable, subjectPrefix string) pipelineStatus {
	out := pipelineStatus{Stream: stream}
	s, err := js.Stream(ctx, stream)
	if err != nil {
		return out // not provisioned yet
	}
	out.Found = true
	if si, err := s.Info(ctx, jetstream.WithSubjectFilter(subjectPrefix+".>")); err == nil {
		out.Bytes = si.State.Bytes
		for subj, cnt := range si.State.Subjects {
			out.Captured += cnt
			out.Tables = append(out.Tables, tableStat{Subject: subj, Table: lastTwo(subj), Count: cnt})
		}
		sort.Slice(out.Tables, func(i, j int) bool { return out.Tables[i].Table < out.Tables[j].Table })
	}
	if c, err := s.Consumer(ctx, durable); err == nil {
		if ci, err := c.Info(ctx); err == nil {
			out.Lag = ci.NumPending
			out.AckPending = ci.NumAckPending
			out.Redelivered = ci.NumRedelivered
		}
	}
	if d, err := js.Stream(ctx, "DLQ"); err == nil {
		if di, err := d.Info(ctx, jetstream.WithSubjectFilter("dlq."+subjectPrefix+".>")); err == nil {
			for subj, cnt := range di.State.Subjects {
				out.DeadLetter += cnt
				out.DLQSubjects = append(out.DLQSubjects, tableStat{Subject: subj, Table: lastTwo(subj), Count: cnt})
			}
			sort.Slice(out.DLQSubjects, func(i, j int) bool { return out.DLQSubjects[i].Table < out.DLQSubjects[j].Table })
		}
	}
	return out
}

// handleMigrationStatus returns the live apply-pipeline status for a Migration.
func handleMigrationStatus(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
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
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		// Migration: one stream mig-<name>, durable mig-<name>, subject prefix mig.<name>.
		p := gatherPipeline(ctx, js, "mig-"+name, "mig-"+name, "mig."+name)
		writeJSON(w, http.StatusOK, p)
	}
}

// handleReplicationStatus returns both directions of a Replication's pipeline.
func handleReplicationStatus(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		siteA := r.URL.Query().Get("siteA")
		siteB := r.URL.Query().Get("siteB")
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
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		out := map[string]pipelineStatus{}
		if siteA != "" {
			out[siteA] = gatherPipeline(ctx, js, "repl-"+name+"-"+siteA, name+"-"+siteA+"-"+siteB, "r"+siteA)
		}
		if siteB != "" {
			out[siteB] = gatherPipeline(ctx, js, "repl-"+name+"-"+siteB, name+"-"+siteB+"-"+siteA, "r"+siteB)
		}
		writeJSON(w, http.StatusOK, out)
	}
}
