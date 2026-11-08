// A custom resource's ResponseURL (#404).
//
// AWS gives a Lambda-backed custom resource's event a ResponseURL, a pre-signed S3 URL the handler PUTs its
// response to (cfn-response does), and CloudFormation waits for that response. Here the front door does the
// same: each invocation gets a one-time URL on this shim, /v1/cfn-response/<token>, where <token> is 32
// random bytes, as unguessable as a pre-signed URL's signature and like it a capability for that one
// response. The URL names this replica's own address (POD_IP), since the invocation waits here.
//
// The response body is AWS's: {Status, Reason, PhysicalResourceId, StackId, RequestId, LogicalResourceId,
// NoEcho, Data}, at most 4096 bytes as on AWS; one whose StackId, RequestId or LogicalResourceId is not the
// event's is refused. A handler that returns its response instead of PUT-ing it (open-infra's earlier
// contract) is answered by what it returns. The endpoint is in-cluster only (a request that came through the
// front proxy is not served).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// cfnResponsePath is where a custom resource's handler PUTs its response.
	cfnResponsePath = "/v1/cfn-response/"
	// maxCFNResponse is AWS's limit for a custom resource's response body.
	maxCFNResponse = 4096
)

// cfnResponseGrace is how long a response is waited for once the handler's invocation has ended (a handler
// that sends its response as it finishes).
var cfnResponseGrace = 30 * time.Second

// cfnResponses holds the custom-resource invocations waiting for a response.
type cfnResponses struct {
	base string // the URL this replica is reached at: http://<pod address>:4566

	mu      sync.Mutex
	pending map[string]*cfnPending
}

type cfnPending struct {
	stackID, requestID, logicalID string
	ch                            chan map[string]any // one response
}

func newCFNResponses() *cfnResponses {
	base := os.Getenv("CFN_RESPONSE_BASE_URL")
	if base == "" {
		if ip := os.Getenv("POD_IP"); ip != "" {
			base = "http://" + net.JoinHostPort(ip, "4566")
		} else {
			base = "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566"
		}
	}
	return &cfnResponses{base: strings.TrimRight(base, "/"), pending: map[string]*cfnPending{}}
}

// open registers an invocation waiting for its response and returns its ResponseURL; done releases it.
func (c *cfnResponses) open(stackID, requestID, logicalID string) (url string, p *cfnPending, done func()) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	p = &cfnPending{stackID: stackID, requestID: requestID, logicalID: logicalID, ch: make(chan map[string]any, 1)}
	c.mu.Lock()
	c.pending[token] = p
	c.mu.Unlock()
	return c.base + cfnResponsePath + token, p, func() {
		c.mu.Lock()
		delete(c.pending, token)
		c.mu.Unlock()
	}
}

// serve takes a handler's PUT of its response.
func (c *cfnResponses) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	if refuseIfProxied(w, r) {
		return
	}
	if r.Method != http.MethodPut {
		writeS3ErrorMsg(w, "MethodNotAllowed", http.StatusMethodNotAllowed, requestID, "The specified method is not allowed against this resource.")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, cfnResponsePath)
	c.mu.Lock()
	p := c.pending[token]
	c.mu.Unlock()
	if p == nil || token == "" {
		// As S3 answers a pre-signed URL that is no longer valid.
		writeS3ErrorMsg(w, "AccessDenied", http.StatusForbidden, requestID, "Request has expired")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCFNResponse+1))
	if err != nil {
		writeS3ErrorMsg(w, "IncompleteBody", http.StatusBadRequest, requestID, "The request body could not be read.")
		return
	}
	resp, err := parseCFNResponse(body, p)
	if err != nil {
		writeS3ErrorMsg(w, "InvalidRequest", http.StatusBadRequest, requestID, err.Error())
		return
	}
	select {
	case p.ch <- resp:
	default: // a response was already taken; the first one stands, as on AWS
	}
	w.WriteHeader(http.StatusOK)
}

// parseCFNResponse reads a response body as CloudFormation does, for the invocation p.
func parseCFNResponse(body []byte, p *cfnPending) (map[string]any, error) {
	if len(body) > maxCFNResponse {
		return nil, fmt.Errorf("the custom resource's response is larger than %d bytes", maxCFNResponse)
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil || resp == nil {
		return nil, errors.New("the custom resource's response is not a JSON object")
	}
	for field, want := range map[string]string{"StackId": p.stackID, "RequestId": p.requestID, "LogicalResourceId": p.logicalID} {
		if got, _ := resp[field].(string); got != want {
			return nil, fmt.Errorf("the response's %s is not the request's", field)
		}
	}
	switch s, _ := resp["Status"].(string); s {
	case "SUCCESS", "FAILED":
	default:
		return nil, errors.New("the response's Status must be SUCCESS or FAILED")
	}
	return resp, nil
}

// invokeWithResponseURL invokes a custom resource's Function with the event given a ResponseURL, and returns
// the response PUT there; failing that, the {Status, …} the handler returned.
func (h *cfnDoorway) invokeWithResponseURL(ctx context.Context, namespace, functionName string, event []byte,
	invoke func(ctx context.Context, event []byte) (out map[string]any, fnErr string, err error)) (map[string]any, error) {
	var ev map[string]any
	if err := json.Unmarshal(event, &ev); err != nil {
		return nil, fmt.Errorf("custom-resource event: %w", err)
	}
	url, p, done := h.responses.open(str(ev["StackId"]), str(ev["RequestId"]), str(ev["LogicalResourceId"]))
	defer done()
	ev["ResponseURL"] = url
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	out, fnErr, err := invoke(ctx, b)
	if err != nil {
		return nil, err
	}
	select {
	case resp := <-p.ch:
		return resp, nil
	default:
	}
	if out != nil {
		if _, ok := out["Status"]; ok && fnErr == "" {
			return out, nil
		}
	}
	timer := time.NewTimer(cfnResponseGrace)
	defer timer.Stop()
	select {
	case resp := <-p.ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if fnErr != "" {
		return nil, fmt.Errorf("custom-resource Function %q failed without sending a response: %s", functionName, fnErr)
	}
	return nil, fmt.Errorf("custom-resource Function %q sent no response: neither a PUT to its ResponseURL (cfn-response) nor a returned {Status}", functionName)
}

// responseHandler serves custom resources' ResponseURLs ahead of SigV4: the one-time URL is the credential,
// as AWS's pre-signed one is.
func (h *cfnDoorway) responseHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.responses == nil || !strings.HasPrefix(r.URL.Path, cfnResponsePath) {
			next.ServeHTTP(w, r)
			return
		}
		h.responses.serve(w, r, requestIDFrom(r))
	})
}
