// Package lambdasource is the "Lambda" data source: it invokes a function over HTTP with AppSync's
// Lambda-invoke shape. In open-infra a "Lambda" is a kind: Function (Knative) with an HTTP endpoint, so
// this Store POSTs the invoke payload to that endpoint and returns the function's JSON response as the
// resolver result — the SAME datasource.Store contract as the DynamoDB/HTTP sources, with a third,
// distinct Operation shape and no branching in the engine or lifecycle.
//
// AppSync's Lambda data source expects the request mapping template to emit:
//
//	{"version":"2018-05-29","operation":"Invoke","payload": <any>}
//
// The function is invoked with `payload`, and whatever JSON it returns becomes $ctx.result. That is what
// this Store implements. (BatchInvoke — operation "BatchInvoke" with a list payload — is a later rung.)
//
// GRADUATION — two clocks: green-light-one (this, now) is "the caller works with zero AWS" — unit-tested
// against an httptest function. Green-light-two — fidelity of the full AppSync→Lambda→DB→JSON round trip
// against a real kind: Function — is a separate, later bar (needs a live function + DB, not fast CI).
package lambdasource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

const maxResponseBytes = 4 << 20 // 4 MiB cap on a function response

// Store invokes a function at endpoint (a kind: Function's HTTP URL).
type Store struct {
	endpoint string
	client   *http.Client
}

var _ datasource.Store = (*Store)(nil)

// New builds a Lambda data source targeting a function endpoint, with a sane default client timeout.
func New(endpoint string) *Store {
	return &Store{endpoint: endpoint, client: &http.Client{Timeout: 30 * time.Second}}
}

// NewWithClient builds one with a caller-supplied client (tests inject an httptest client).
func NewWithClient(endpoint string, client *http.Client) *Store {
	return &Store{endpoint: endpoint, client: client}
}

// Execute invokes the function with the operation's payload and returns the parsed JSON response. The op
// is the AppSync Lambda-invoke document; the `payload` field is what the function receives (if absent,
// the whole operation is sent, which is lenient but keeps a mis-templated resolver working).
func (s *Store) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	if operation, ok := op["operation"].(string); ok && operation == "BatchInvoke" {
		return nil, fmt.Errorf("lambdasource: BatchInvoke is not supported yet")
	}

	var payload any = op
	if p, ok := op["payload"]; ok {
		payload = p
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("lambdasource: encode payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("lambdasource: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lambdasource: invoke failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("lambdasource: read response: %w", err)
	}
	// A non-2xx from the function is an invocation error (like a Lambda function error).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("lambdasource: function returned status %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("lambdasource: function response is not JSON: %w", err)
	}
	return parsed, nil
}
