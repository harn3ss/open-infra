package opensearchsource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// A _search request is sent to the domain at path with the JSON body, and the domain's response is
// returned parsed (so a response template can read result.hits.hits[]._source).
func TestOpenSearch_Search(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"total": map[string]any{"value": 1},
				"hits": []any{map[string]any{"_source": map[string]any{"id": "1", "title": "Ada"}}}},
		})
	}))
	defer ts.Close()

	s := New(ts.URL, "", "")
	res, err := s.Execute(context.Background(), runtime.Operation{
		"operation": "POST",
		"path":      "/notes/_search",
		"params":    map[string]any{"body": map[string]any{"query": map[string]any{"match_all": map[string]any{}}}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotMethod != "POST" || gotPath != "/notes/_search" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if gotBody["query"] == nil {
		t.Errorf("body not forwarded: %v", gotBody)
	}
	hits := res.(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if hits[0].(map[string]any)["_source"].(map[string]any)["title"] != "Ada" {
		t.Errorf("search result not returned: %v", res)
	}
}

// Optional HTTP basic auth is sent when configured.
func TestOpenSearch_BasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": []any{}}})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "admin", "s3cret").Execute(context.Background(), runtime.Operation{
		"operation": "GET", "path": "/_search",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || user != "admin" || pass != "s3cret" {
		t.Errorf("basic auth not sent: user=%q ok=%v", user, ok)
	}
}

// A non-2xx from the domain surfaces as an error (the resolver fails).
func TestOpenSearch_ErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"index_not_found_exception"}`, http.StatusNotFound)
	}))
	defer ts.Close()
	if _, err := New(ts.URL, "", "").Execute(context.Background(), runtime.Operation{"path": "/missing/_search"}); err == nil {
		t.Error("a non-2xx domain response must surface as an error")
	}
}
