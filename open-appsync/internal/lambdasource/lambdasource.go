// Package lambdasource is the "Lambda" data source: it invokes a function over HTTP with AppSync's
// Lambda-invoke shape. In open-infra a "Lambda" is a kind: Function (Knative) with an HTTP endpoint, so
// this Store POSTs the invoke payload to that endpoint and returns the function's JSON response as the
// resolver result — the SAME datasource.Store contract as the DynamoDB/HTTP sources, with a third,
// distinct Operation shape and no branching in the engine or lifecycle.
//
// AppSync's Lambda data source takes the request document
// {"version":"2018-05-29","operation":"Invoke"|"BatchInvoke","payload":<any>,"invocationType":"RequestResponse"}.
// For Invoke the function is invoked with `payload`, and whatever JSON it returns becomes $ctx.result.
// For BatchInvoke (datasource.BatchStore) the `payload` of each of N sibling resolutions is merged into
// ONE list, the function is invoked once with that list, and it must return a list of the same size and
// order — element i becomes item i's $ctx.result (null elements are valid). A response that is not such
// a list fails every item of the batch.
//
// The function is invoked AWS-Invoke style (X-Openinfra-Invoke: direct): its RAW return value is the
// result, and only a THROWN error (X-Amz-Function-Error) is a failure, surfaced with Lambda's
// errorType/errorMessage the way AppSync shows it. invocationType Event (an asynchronous invoke) is not
// served and fails closed, as does an operation other than Invoke/BatchInvoke.
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
	"strings"
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

var (
	_ datasource.Store      = (*Store)(nil)
	_ datasource.BatchStore = (*Store)(nil)
)

// New builds a Lambda data source targeting a function endpoint, with a sane default client timeout.
func New(endpoint string) *Store {
	return &Store{endpoint: endpoint, client: &http.Client{Timeout: 30 * time.Second}}
}

// NewWithClient builds one with a caller-supplied client (tests inject an httptest client).
func NewWithClient(endpoint string, client *http.Client) *Store {
	return &Store{endpoint: endpoint, client: client}
}

// FunctionError is a THROWN function error: the runtime signalled it with X-Amz-Function-Error and the
// body is Lambda's error payload ({"errorType": …, "errorMessage": …}). It surfaces on the field the way
// AppSync shows a Lambda error (see AppSyncError).
type FunctionError struct {
	FunctionError string // the X-Amz-Function-Error value, e.g. "Unhandled"
	ErrorType     string // the payload's errorType: the thrown error's name (e.g. "CustomException")
	ErrorMessage  string // the payload's errorMessage
}

func (e *FunctionError) Error() string {
	msg, typ, _ := e.AppSyncError()
	return typ + ": " + msg
}

// unauthorizedMessage is the message AppSync returns in place of the function's own when it throws an
// UnauthorizedException.
const unauthorizedMessage = "You are not authorized to make this call."

// AppSyncError is the GraphQL error AppSync reports for a function error: the thrown error's errorType
// and errorMessage (an error thrown with no errorType is "Lambda:<X-Amz-Function-Error>", e.g.
// "Lambda:Unhandled"), and AppSync's fixed message for an UnauthorizedException.
func (e *FunctionError) AppSyncError() (message, errorType string, data any) {
	errorType = e.ErrorType
	if errorType == "" {
		errorType = "Lambda:" + e.FunctionError
	}
	message = e.ErrorMessage
	if errorType == "UnauthorizedException" {
		message = unauthorizedMessage
	}
	return message, errorType, nil
}

// BatchResponseError is a BatchInvoke response that cannot be matched back to the batch: not a list,
// or a list of another size. AppSync maps a batch response to its items by position, so every item of
// the batch fails with it.
type BatchResponseError struct {
	Want int // the batch size
	Got  int // the returned list's length (-1 when the response was not a list)
}

// BatchResponseMismatch is the errorType of a BatchResponseError. AWS documents that the response must
// match the request in size and order but not the wording of the error it raises, so this one is the
// engine's own.
const BatchResponseMismatch = "BatchInvokeResponseMismatch"

func (e *BatchResponseError) Error() string {
	msg, _, _ := e.AppSyncError()
	return msg
}

// AppSyncError reports the mismatch on each item's field.
func (e *BatchResponseError) AppSyncError() (message, errorType string, data any) {
	if e.Got < 0 {
		return fmt.Sprintf("the Lambda function's BatchInvoke response is not a list — it must be a list of %d results, matching the batch in size and order", e.Want), BatchResponseMismatch, nil
	}
	return fmt.Sprintf("the Lambda function returned %d results for a batch of %d — a BatchInvoke response must match the batch in size and order", e.Got, e.Want), BatchResponseMismatch, nil
}

// Execute runs one Lambda request document. Invoke sends the document's `payload` (if absent, the whole
// document is sent, which is lenient but keeps a mis-templated resolver working) and returns the parsed
// response; a BatchInvoke document is a batch of one.
func (s *Store) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	if err := checkOperation(op); err != nil {
		return nil, err
	}
	if operation(op) == "BatchInvoke" {
		res, err := s.ExecuteBatch(ctx, []runtime.Operation{op})
		if err != nil {
			return nil, err
		}
		return res[0], nil
	}
	var payload any = op
	if p, ok := op["payload"]; ok {
		payload = p
	}
	return s.invoke(ctx, payload)
}

// ExecuteBatch is AppSync's BatchInvoke: the `payload` of each op (null when a template gives none) is
// merged into one list, the function is invoked ONCE with it, and the returned list is matched back to
// the ops by position. A thrown error fails the whole batch (every op shares it); so does a response
// that is not a list of len(ops).
func (s *Store) ExecuteBatch(ctx context.Context, ops []runtime.Operation) ([]any, error) {
	payloads := make([]any, len(ops))
	for i, op := range ops {
		if err := checkOperation(op); err != nil {
			return nil, err
		}
		payloads[i] = op["payload"]
	}
	res, err := s.invoke(ctx, payloads)
	if err != nil {
		return nil, err
	}
	list, ok := res.([]any)
	if !ok {
		return nil, &BatchResponseError{Want: len(ops), Got: -1}
	}
	if len(list) != len(ops) {
		return nil, &BatchResponseError{Want: len(ops), Got: len(list)}
	}
	return list, nil
}

func operation(op runtime.Operation) string {
	s, _ := op["operation"].(string)
	return s
}

// checkOperation fails closed on a request document this source does not serve: an operation other than
// Invoke/BatchInvoke (AppSync's two), or invocationType Event — an asynchronous invoke, whose field AWS
// resolves to null while the function runs on its own; open-appsync would have to wait for the function
// and return what it returned, which is not that, so it refuses rather than pretend.
func checkOperation(op runtime.Operation) error {
	switch v := op["operation"].(type) {
	case nil:
	case string:
		if v != "Invoke" && v != "BatchInvoke" {
			return fmt.Errorf("lambdasource: operation %q is not a Lambda operation (Invoke | BatchInvoke)", v)
		}
	default:
		return fmt.Errorf("lambdasource: operation must be Invoke or BatchInvoke (got %v)", v)
	}
	switch v := op["invocationType"].(type) {
	case nil:
	case string:
		switch v {
		case "RequestResponse":
		case "Event":
			return fmt.Errorf("lambdasource: invocationType Event (an asynchronous Lambda invoke) is not supported by open-appsync — use RequestResponse")
		default:
			return fmt.Errorf("lambdasource: invocationType %q is not a Lambda invocation type (RequestResponse | Event)", v)
		}
	default:
		return fmt.Errorf("lambdasource: invocationType must be RequestResponse or Event (got %v)", v)
	}
	return nil
}

// invoke POSTs one event to the function in direct-invoke mode and returns its parsed raw return value.
func (s *Store) invoke(ctx context.Context, event any) (any, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("lambdasource: encode payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("lambdasource: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Direct-invoke: the runtime returns the handler's RAW value (what becomes $ctx.result) and signals
	// a thrown error via X-Amz-Function-Error, instead of mapping the return to an API-Gateway proxy
	// response. This matches AWS, where AppSync calls Lambda Invoke directly.
	req.Header.Set("X-Openinfra-Invoke", "direct")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lambdasource: invoke failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("lambdasource: read response: %w", err)
	}
	// A THROWN handler error is signalled by X-Amz-Function-Error and is the ONLY "failure" (→ a
	// resolver error). A RETURNED value — including one shaped like { statusCode: 500, ... } — is
	// ordinary data and becomes $ctx.result, exactly as AppSync→Lambda Invoke behaves (the runtime
	// returns HTTP 200 for both and does not proxy-map the return).
	if fe := resp.Header.Get("X-Amz-Function-Error"); fe != "" {
		return nil, functionError(fe, raw)
	}
	// A non-2xx WITHOUT that header is a genuine invocation/transport failure (e.g. Knative could not
	// scale the function up), not a handler return — surface it as an error too.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("lambdasource: invocation failed, status %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
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

// functionError reads Lambda's error payload. A body that is not the {errorType, errorMessage} object
// (e.g. a bare string a handler failed with) is the message itself.
func functionError(kind string, raw []byte) *FunctionError {
	fe := &FunctionError{FunctionError: kind}
	var payload struct {
		ErrorType    any `json:"errorType"`
		ErrorMessage any `json:"errorMessage"`
	}
	trimmed := bytes.TrimSpace(raw)
	if err := json.Unmarshal(trimmed, &payload); err == nil && (payload.ErrorType != nil || payload.ErrorMessage != nil) {
		fe.ErrorType = text(payload.ErrorType)
		fe.ErrorMessage = text(payload.ErrorMessage)
		return fe
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		fe.ErrorMessage = s
		return fe
	}
	fe.ErrorMessage = strings.TrimSpace(string(trimmed))
	return fe
}

func text(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
