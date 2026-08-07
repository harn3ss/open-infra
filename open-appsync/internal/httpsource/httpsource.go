// Package httpsource is a second, non-DynamoDB data source: it fronts an HTTP
// endpoint. Its whole reason to exist is the neutrality test — it implements the SAME
// datasource.Store contract as the DynamoDB store, but its Operation is a completely different
// document ({"method":"POST","resourcePath":"/x","params":{…}}), and it flows through the exact same
// resolver lifecycle and executor with NO code path branching on data-source type. Only this Store
// knows this shape.
package httpsource

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

const maxResponseBytes = 4 << 20 // 4 MiB cap on a response body

// Store calls an HTTP endpoint. base is the endpoint the resolver's resourcePath is joined to.
type Store struct {
	base   string
	client *http.Client
}

var _ datasource.Store = (*Store)(nil)

// New builds an HTTP data source targeting base, with a sane default client timeout.
func New(base string) *Store {
	return &Store{base: base, client: &http.Client{Timeout: 30 * time.Second}}
}

// NewWithClient builds one with a caller-supplied client (tests inject an httptest client).
func NewWithClient(base string, client *http.Client) *Store {
	return &Store{base: base, client: client}
}

// Execute runs the HTTP operation the request template rendered and returns {statusCode, headers,
// body} — the AppSync HTTP data-source result shape, with body parsed as JSON when possible. The op:
//
//	{"method":"GET|POST|…", "resourcePath":"/path",
//	 "params":{"query":{…}, "headers":{…}, "body":<any>}}
func (s *Store) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	method := str(op["method"], http.MethodGet)
	path := str(op["resourcePath"], "")

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
					return nil, fmt.Errorf("httpsource: encode body: %w", err)
				}
				body = bytes.NewReader(j)
			}
		}
		if h, ok := params["headers"].(map[string]any); ok {
			for k, v := range h {
				headers[k] = str(v, "")
			}
		}
		if q, ok := params["query"].(map[string]any); ok {
			for k, v := range q {
				query.Set(k, str(v, ""))
			}
		}
	}

	target := s.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("httpsource: build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpsource: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("httpsource: read response: %w", err)
	}
	var parsed any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			parsed = string(raw) // not JSON — expose the raw body as a string
		}
	}
	respHeaders := map[string]any{}
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}
	return map[string]any{
		"statusCode": float64(resp.StatusCode),
		"headers":    respHeaders,
		"body":       parsed,
	}, nil
}

func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
