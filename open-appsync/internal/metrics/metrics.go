// Package metrics is the open-appsync engine's Prometheus surface: request, data-source and
// subscription instrumentation exposed at /metrics for in-cluster scraping.
//
// Design notes that keep this honest under load:
//   - LABELS ARE BOUNDED. Cardinality is the classic metrics footgun: a label whose values come
//     from client input (a query string, a field name, a raw header) grows the time-series set
//     without limit and eventually OOMs the scraper. Every label here is drawn from a small fixed
//     set — outcome ∈ {ok,error}, data-source type ∈ the 8 known types, auth mode sanitized to a
//     known-mode allowlist — so the series count is fixed no matter what a caller sends.
//   - The registry is private to a Metrics value. New() builds a fresh one (tests get isolation);
//     production uses the process-wide singleton via the package-level helpers.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "openappsync"

// knownAuthModes bounds the `mode` label so a spoofable X-OpenInfra-Auth-Mode header can't explode
// cardinality. Anything outside this set collapses to "other"; the empty mode reports as "none".
var knownAuthModes = map[string]bool{
	"aws_api_key":            true,
	"aws_iam":                true,
	"aws_oidc":               true,
	"aws_cognito_user_pools": true,
	"aws_lambda":             true,
}

// Metrics holds the engine's collectors and the registry they are registered on.
type Metrics struct {
	reg *prometheus.Registry

	gqlRequests *prometheus.CounterVec   // by outcome, mode
	gqlDuration *prometheus.HistogramVec // by outcome
	gqlInFlight prometheus.Gauge

	dsRequests *prometheus.CounterVec   // by type, outcome
	dsDuration *prometheus.HistogramVec // by type

	subConnections prometheus.Gauge
}

// New builds a Metrics on its own registry (also collecting Go runtime + process stats). Each call is
// independent, so tests can assert against a clean set without cross-test contamination.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		gqlRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "graphql", Name: "requests_total",
			Help: "GraphQL requests handled, by outcome (ok|error) and authentication mode.",
		}, []string{"outcome", "mode"}),
		gqlDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "graphql", Name: "request_duration_seconds",
			Help: "GraphQL request handling latency in seconds, by outcome.", Buckets: prometheus.DefBuckets,
		}, []string{"outcome"}),
		gqlInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "graphql", Name: "requests_in_flight",
			Help: "GraphQL requests currently being handled.",
		}),
		dsRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "datasource", Name: "requests_total",
			Help: "Data-source Execute calls, by data-source type and outcome (ok|error).",
		}, []string{"type", "outcome"}),
		dsDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "datasource", Name: "request_duration_seconds",
			Help: "Data-source Execute latency in seconds, by data-source type.", Buckets: prometheus.DefBuckets,
		}, []string{"type"}),
		subConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "subscription", Name: "connections",
			Help: "Active graphql-transport-ws subscription connections.",
		}),
	}
	reg.MustRegister(
		m.gqlRequests, m.gqlDuration, m.gqlInFlight,
		m.dsRequests, m.dsDuration, m.subConnections,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Handler serves this Metrics' registry in the Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// GraphQLStarted marks a request in flight and returns a function to call when it finishes, with
// whether the result carried errors. Deferring the returned func guarantees the in-flight gauge is
// decremented even on panic.
func (m *Metrics) GraphQLStarted(mode string) func(isError bool) {
	m.gqlInFlight.Inc()
	start := time.Now()
	return func(isError bool) {
		m.gqlInFlight.Dec()
		outcome := boolOutcome(isError)
		m.gqlRequests.WithLabelValues(outcome, sanitizeMode(mode)).Inc()
		m.gqlDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
	}
}

// IncSubscriptions / DecSubscriptions track the live subscription-connection gauge.
func (m *Metrics) IncSubscriptions() { m.subConnections.Inc() }
func (m *Metrics) DecSubscriptions() { m.subConnections.Dec() }

// MeteredStore wraps a data source so every Execute is counted and timed under a bounded `type`
// label, without the source or the engine knowing anything about metrics.
func (m *Metrics) MeteredStore(dsType string, s datasource.Store) datasource.Store {
	return &meteredStore{typ: dsType, inner: s, m: m}
}

type meteredStore struct {
	typ   string
	inner datasource.Store
	m     *Metrics
}

func (ms *meteredStore) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	start := time.Now()
	res, err := ms.inner.Execute(ctx, op)
	ms.m.dsDuration.WithLabelValues(ms.typ).Observe(time.Since(start).Seconds())
	ms.m.dsRequests.WithLabelValues(ms.typ, boolOutcome(err != nil)).Inc()
	return res, err
}

func boolOutcome(isError bool) string {
	if isError {
		return "error"
	}
	return "ok"
}

// sanitizeMode maps an auth-mode string onto the bounded label set (see knownAuthModes).
func sanitizeMode(mode string) string {
	if mode == "" {
		return "none"
	}
	if knownAuthModes[mode] {
		return mode
	}
	return "other"
}

// --- process-wide singleton + package-level helpers used by the running engine ---

var std = New()

// Handler serves the process-wide registry.
func Handler() http.Handler { return std.Handler() }

// GraphQLStarted / IncSubscriptions / DecSubscriptions / MeteredStore delegate to the singleton.
func GraphQLStarted(mode string) func(isError bool) { return std.GraphQLStarted(mode) }
func IncSubscriptions()                             { std.IncSubscriptions() }
func DecSubscriptions()                             { std.DecSubscriptions() }
func MeteredStore(dsType string, s datasource.Store) datasource.Store {
	return std.MeteredStore(dsType, s)
}
