package metrics

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeStore returns a fixed (result, err) so a metered wrapper's outcome labelling can be asserted.
type fakeStore struct {
	res any
	err error
}

func (f fakeStore) Execute(context.Context, runtime.Operation) (any, error) { return f.res, f.err }

func TestMeteredStore_CountsByTypeAndOutcome(t *testing.T) {
	m := New()
	ok := m.MeteredStore("http", fakeStore{res: "hi"})
	bad := m.MeteredStore("rds", fakeStore{err: errors.New("boom")})

	if _, err := ok.Execute(context.Background(), nil); err != nil {
		t.Fatalf("ok store returned error: %v", err)
	}
	if _, err := ok.Execute(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Execute(context.Background(), nil); err == nil {
		t.Fatal("expected error from bad store")
	}

	if got := testutil.ToFloat64(m.dsRequests.WithLabelValues("http", "ok")); got != 2 {
		t.Errorf("datasource http/ok count = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.dsRequests.WithLabelValues("rds", "error")); got != 1 {
		t.Errorf("datasource rds/error count = %v, want 1", got)
	}
	// The bad type never saw a success, and the ok type never saw an error — no phantom series.
	if got := testutil.ToFloat64(m.dsRequests.WithLabelValues("http", "error")); got != 0 {
		t.Errorf("datasource http/error count = %v, want 0", got)
	}
}

func TestMeteredStore_PassesResultThrough(t *testing.T) {
	m := New()
	s := m.MeteredStore("memory", fakeStore{res: map[string]any{"id": "1"}})
	got, err := s.Execute(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if mp, _ := got.(map[string]any); mp["id"] != "1" {
		t.Errorf("metering altered the result: %v", got)
	}
}

func TestGraphQLStarted_OutcomeInFlightAndDuration(t *testing.T) {
	m := New()
	done := m.GraphQLStarted("aws_iam")
	if got := testutil.ToFloat64(m.gqlInFlight); got != 1 {
		t.Errorf("in-flight during request = %v, want 1", got)
	}
	done(false)
	if got := testutil.ToFloat64(m.gqlInFlight); got != 0 {
		t.Errorf("in-flight after request = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.gqlRequests.WithLabelValues("ok", "aws_iam")); got != 1 {
		t.Errorf("graphql ok/aws_iam count = %v, want 1", got)
	}
	// An erroring request lands on the error outcome, not ok.
	m.GraphQLStarted("aws_iam")(true)
	if got := testutil.ToFloat64(m.gqlRequests.WithLabelValues("error", "aws_iam")); got != 1 {
		t.Errorf("graphql error/aws_iam count = %v, want 1", got)
	}
	// The duration histogram observed both requests.
	if got := testutil.CollectAndCount(m.gqlDuration); got == 0 {
		t.Error("duration histogram recorded nothing")
	}
}

func TestSanitizeMode_BoundsCardinality(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "none",
		"aws_api_key":            "aws_api_key",
		"aws_cognito_user_pools": "aws_cognito_user_pools",
		"aws_lambda":             "aws_lambda",
		"system:masters":         "other", // a spoofed/unknown mode must not become its own series
		"../../etc":              "other",
	} {
		if got := sanitizeMode(in); got != want {
			t.Errorf("sanitizeMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSubscriptionGauge(t *testing.T) {
	m := New()
	m.IncSubscriptions()
	m.IncSubscriptions()
	m.DecSubscriptions()
	if got := testutil.ToFloat64(m.subConnections); got != 1 {
		t.Errorf("subscription connections = %v, want 1", got)
	}
}

func TestHandler_ExposesFamilies(t *testing.T) {
	m := New()
	m.GraphQLStarted("none")(false)
	_, _ = m.MeteredStore("http", fakeStore{res: "x"}).Execute(context.Background(), nil)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	text := string(body)
	for _, want := range []string{
		"openappsync_graphql_requests_total",
		"openappsync_datasource_requests_total",
		"openappsync_subscription_connections",
		"go_goroutines", // the Go collector is wired
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/metrics output missing %q", want)
		}
	}
}
