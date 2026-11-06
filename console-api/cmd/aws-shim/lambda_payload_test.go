package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// toServer sends every request to one test server, whatever host the handler addressed.
type toServer struct{ u *url.URL }

func (t toServer) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = t.u.Scheme, t.u.Host
	return http.DefaultTransport.RoundTrip(r2)
}

// A synchronous Invoke hands the function its payload whole, with its length: a streamed (chunked) body
// reached a runtime that reads Content-Length as an empty event. A payload over AWS's 6 MB synchronous
// limit is RequestEntityTooLargeException, and the function is never called.
func TestLambda_InvokeForwardsThePayloadWithItsLength(t *testing.T) {
	var gotLen int64
	var gotTE []string
	var gotBody string
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotLen, gotTE = r.ContentLength, r.TransferEncoding
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	h := newLambdaHandler(csWithSAR(true), "default", "svc.cluster.local", nil, discardLogger())
	h.client = &http.Client{Transport: toServer{u}}

	payload := `{"op":"whoami"}`
	// A server-side request body has no length the client can see, as the shim receives it.
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", io.NopCloser(strings.NewReader(payload)))
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-1")
	if w.Code != http.StatusOK {
		t.Fatalf("Invoke: %d %s", w.Code, w.Body.String())
	}
	if gotBody != payload || gotLen != int64(len(payload)) || len(gotTE) != 0 {
		t.Fatalf("the function got body %q, Content-Length %d, Transfer-Encoding %v; want the payload with its length, not chunked", gotBody, gotLen, gotTE)
	}

	big := strings.Repeat("x", maxSyncInvokePayload+1)
	req = httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", io.NopCloser(strings.NewReader(big)))
	w = httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-2")
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("x-amzn-errortype") != "RequestEntityTooLargeException" {
		t.Fatalf("a 6 MB+ payload: %d %s", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Fatalf("the function was called %d times, want once (never for the oversized payload)", calls)
	}
}
