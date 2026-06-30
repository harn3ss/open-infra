package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// Garbage-collect JetStream resources orphaned when a DataFlow is deleted.
//
// Crossplane removes a DataFlow's rendered pods, but the per-node capture/transform
// streams (flow-<flow>-<node>) are created imperatively by init-containers and the
// shared DLQ accumulates per-flow subjects (dlq.f.<flow>.*) — neither is owned by the
// CR, so without GC a delete leaks JetStream storage and leaves stale status. This
// reaper periodically lists live DataFlows and removes any flow-* stream (and purges
// any dlq.f.<flow>.* subjects) that no longer corresponds to a live flow.

func startDataFlowGC(host *url.URL, transport http.RoundTripper, logger *slog.Logger) {
	if getenv("DATAFLOW_GC", "on") != "on" {
		return
	}
	interval := 10 * time.Minute
	if d, err := time.ParseDuration(getenv("DATAFLOW_GC_INTERVAL", "")); err == nil && d >= time.Minute {
		interval = d
	}
	go func() {
		time.Sleep(90 * time.Second) // let the platform settle on boot
		for {
			dataflowGCOnce(host, transport, logger)
			time.Sleep(interval)
		}
	}()
	logger.Info("dataflow gc: started", slog.Duration("interval", interval))
}

func dataflowGCOnce(host *url.URL, transport http.RoundTripper, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	live, expected, err := liveDataFlows(ctx, host, transport)
	if err != nil {
		logger.Warn("dataflow gc: list dataflows failed; skipping", slog.String("error", err.Error()))
		return // never reap on an API error — only when we have a trustworthy live set
	}

	nc, err := natsConnect()
	if err != nil {
		return
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		return
	}

	// 1. delete orphaned capture/transform streams (flow-<flow>-<node>)
	names := []string{}
	lister := js.StreamNames(ctx)
	for n := range lister.Name() {
		names = append(names, n)
	}
	if lister.Err() != nil {
		return
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "flow-") || expected[name] {
			continue
		}
		if err := js.DeleteStream(ctx, name); err == nil {
			logger.Info("dataflow gc: deleted orphan stream", slog.String("stream", name))
		}
	}

	// 2. purge DLQ subjects belonging to flows that no longer exist
	if dlq, err := js.Stream(ctx, "DLQ"); err == nil {
		if info, err := dlq.Info(ctx, jetstream.WithSubjectFilter("dlq.f.>")); err == nil {
			dead := map[string]bool{}
			for subj := range info.State.Subjects {
				// dlq.f.<flow>.<node>.<schema>.<table> — <flow> is segment 2
				if parts := strings.Split(subj, "."); len(parts) >= 3 && !live[parts[2]] {
					dead[parts[2]] = true
				}
			}
			for flow := range dead {
				if err := dlq.Purge(ctx, jetstream.WithPurgeSubject("dlq.f."+flow+".>")); err == nil {
					logger.Info("dataflow gc: purged DLQ for deleted flow", slog.String("flow", flow))
				}
			}
		}
	}
}

// liveDataFlows returns the set of live DataFlow names and the set of stream names they
// legitimately own (flow-<name>-<node> for every node — an over-approximation, so a live
// stream is never mistaken for an orphan).
func liveDataFlows(ctx context.Context, host *url.URL, transport http.RoundTripper) (live, expected map[string]bool, err error) {
	u := *host
	u.Path = "/apis/openinfra.dev/v1/dataflows"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := (&http.Client{Transport: transport, Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &gcStatusError{resp.StatusCode}
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Nodes []struct {
					Name string `json:"name"`
				} `json:"nodes"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, nil, err
	}
	live = map[string]bool{}
	expected = map[string]bool{}
	for _, it := range list.Items {
		// NATS names are namespace-qualified (<ns>-<name>); see the composition.
		fqd := it.Metadata.Namespace + "-" + it.Metadata.Name
		live[fqd] = true
		for _, n := range it.Spec.Nodes {
			expected["flow-"+fqd+"-"+n.Name] = true
		}
	}
	return live, expected, nil
}

type gcStatusError struct{ code int }

func (e *gcStatusError) Error() string { return "dataflows list returned status " + http.StatusText(e.code) }
