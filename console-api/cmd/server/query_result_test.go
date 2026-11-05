package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// queryAPIServer serves kind: Query objects (by API path) and 404s everything else.
func queryAPIServer(t *testing.T, queries map[string]map[string]any) kubernetes.Interface {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		obj, ok := queries[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
			return
		}
		_ = json.NewEncoder(w).Encode(obj)
	}))
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// The results of a Query are read from the output location the Query declares, never from a bucket
// the caller names: the console reads object storage with credentials that reach every bucket, so a
// caller-named bucket would read any object in the estate (the platform's backups and audit trail
// included) behind nothing more than athena:GetQueryResults on a Query of the caller's own.
func TestQueryResult_ReadsOnlyTheQuerysOwnOutputLocation(t *testing.T) {
	cs := queryAPIServer(t, map[string]map[string]any{
		"/apis/openinfra.dev/v1/namespaces/team/queries/plain":    {"spec": map[string]any{}},
		"/apis/openinfra.dev/v1/namespaces/team/queries/platform": {"spec": map[string]any{"outputBucket": "openinfra-audit"}},
		"/apis/openinfra.dev/v1/namespaces/team/queries/custom":   {"spec": map[string]any{"outputBucket": "team-results"}},
	})

	type call struct{ bucket, key string }
	serve := func(buckets *bucketAuthz, path string) (*httptest.ResponseRecorder, []call) {
		var opened []call
		open := func() (objectOpener, error) {
			return func(_ context.Context, bucket, key string) (io.ReadCloser, error) {
				opened = append(opened, call{bucket, key})
				if strings.HasSuffix(key, ".metadata.json") {
					return io.NopCloser(strings.NewReader(`{"state":"SUCCEEDED","row_count":1}`)), nil
				}
				return io.NopCloser(strings.NewReader("a\n1\n")), nil
			}, nil
		}
		rt := chi.NewRouter()
		rt.Get("/queries/{namespace}/{name}/result", serveQueryResult(cs, buckets, open))
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec, opened
	}

	// A bucket in the request is not where the results are read from.
	rec, opened := serve(nil, "/queries/team/plain/result?bucket=openinfra-audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("plain query: status %d: %s", rec.Code, rec.Body)
	}
	if len(opened) == 0 {
		t.Fatal("plain query: no result object was read")
	}
	for _, c := range opened {
		if c.bucket != managedQueryResults || !strings.HasPrefix(c.key, "team/plain.") {
			t.Fatalf("plain query read %s/%s: results come only from %s/team/plain.*", c.bucket, c.key, managedQueryResults)
		}
	}

	// A Query that declares a platform bucket as its output location never reads it.
	rec, opened = serve(nil, "/queries/team/platform/result")
	if rec.Code != http.StatusForbidden || len(opened) != 0 {
		t.Fatalf("platform output location: status %d, read %v; want 403 and nothing read", rec.Code, opened)
	}

	// A customer output location needs s3:GetObject for the signed-in user, as in AWS: with
	// authentication on and no signed-in user, nothing is read.
	gated := &bucketAuthz{auth: &authStore{mode: "local"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec, opened = serve(gated, "/queries/team/custom/result")
	if rec.Code != http.StatusUnauthorized || len(opened) != 0 {
		t.Fatalf("custom output location without a user: status %d, read %v; want 401 and nothing read", rec.Code, opened)
	}
	// The managed location needs nothing beyond the route's athena:GetQueryResults.
	if rec, opened = serve(gated, "/queries/team/plain/result"); rec.Code != http.StatusOK || len(opened) == 0 {
		t.Fatalf("managed output location: status %d, read %v; want 200", rec.Code, opened)
	}

	// A Query that does not exist reads nothing.
	if rec, opened = serve(nil, "/queries/team/missing/result"); rec.Code != http.StatusNotFound || len(opened) != 0 {
		t.Fatalf("missing query: status %d, read %v; want 404 and nothing read", rec.Code, opened)
	}

	// An unreachable object store is an error, not an empty result.
	rt := chi.NewRouter()
	rt.Get("/queries/{namespace}/{name}/result", serveQueryResult(cs, nil, func() (objectOpener, error) { return nil, errors.New("down") }))
	rec = httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/queries/team/plain/result", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("object store down: status %d; want 500", rec.Code)
	}
}
