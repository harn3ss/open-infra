// Package opensearchsource is the "OpenSearch" data source: it runs search/index requests against an
// OpenSearch (or Elasticsearch) domain and returns the response JSON, behind the same neutral
// datasource.Store contract as the other sources. It mirrors AppSync's OpenSearch data source — the
// request mapping emits
//
//	{"version":"2018-05-29","operation":"GET","path":"/index/_search",
//	 "params":{"headers":{…},"queryString":{…},"body":{ "query": {…}, "size": 10 }}}
//
// and the result is the domain's response object (so a response template reads
// $ctx.result.hits.hits[]._source). It is HTTP-flavored but specialized to this contract and, unlike the
// generic HTTP source, returns the parsed body directly rather than a {statusCode, headers, body} wrapper.
//
// Auth: optional HTTP basic auth (username/password from a Secret) for a self-hosted or fine-grained-
// access domain. SigV4 to an AWS-managed domain is an AWS-specific concern for a later fidelity item.
package opensearchsource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

const maxResponseBytes = 8 << 20 // 8 MiB cap on a search response

// Store queries an OpenSearch domain at endpoint (the domain base URL).
type Store struct {
	endpoint string
	username string // optional HTTP basic auth
	password string
	client   *http.Client
}

var _ datasource.Store = (*Store)(nil)

// New builds an OpenSearch data source. username/password enable HTTP basic auth when non-empty.
func New(endpoint, username, password string) *Store {
	return &Store{
		endpoint: endpoint, username: username, password: password,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// NewWithClient builds one with a caller-supplied client (tests inject an httptest client).
func NewWithClient(endpoint, username, password string, client *http.Client) *Store {
	return &Store{endpoint: endpoint, username: username, password: password, client: client}
}

// Execute runs the operation the request template rendered and returns the domain's parsed JSON response.
func (s *Store) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	method := str(op["operation"], http.MethodGet)
	path := str(op["path"], "/")

	var body io.Reader
	headers := map[string]string{}
	query := url.Values{}
	if params, ok := op["params"].(map[string]any); ok {
		if b, ok := params["body"]; ok && b != nil {
			if bs, isStr := b.(string); isStr {
				body = bytes.NewReader([]byte(bs))
			} else {
				j, err := json.Marshal(b)
				if err != nil {
					return nil, fmt.Errorf("opensearchsource: encode body: %w", err)
				}
				body = bytes.NewReader(j)
			}
		}
		if h, ok := params["headers"].(map[string]any); ok {
			for k, v := range h {
				headers[k] = str(v, "")
			}
		}
		if q, ok := params["queryString"].(map[string]any); ok {
			for k, v := range q {
				query.Set(k, str(v, ""))
			}
		}
	}

	target := s.endpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("opensearchsource: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if s.username != "" || s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opensearchsource: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("opensearchsource: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("opensearchsource: domain returned status %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("opensearchsource: response is not JSON: %w", err)
	}
	return parsed, nil
}

func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
