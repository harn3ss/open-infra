package main

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// headerTransport records each request's host and headers, and answers with status and header.
type headerTransport struct {
	mu      sync.Mutex
	hosts   []string
	headers []http.Header
	status  int
	answer  http.Header
}

func (c *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.hosts = append(c.hosts, r.URL.Host)
	c.headers = append(c.headers, r.Header.Clone())
	c.mu.Unlock()
	rec := httptest.NewRecorder()
	for k, v := range c.answer {
		rec.Header()[k] = v
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	rec.WriteHeader(status)
	_, _ = rec.WriteString("{}")
	return rec.Result(), nil
}

// A synchronous invoke tells the function's runtime the ARN it was invoked by (with its qualifier), the
// version that runs, and the caller's ClientContext (#406); a ClientContext that is not base64 JSON is
// refused, as Lambda refuses it, without invoking.
func TestInvoke_PassesTheInvocationContext(t *testing.T) {
	h, _ := versionsFixture(t, nil, versionedFunction())
	ht := &headerTransport{}
	h.client = &http.Client{Transport: ht}
	cc := base64.StdEncoding.EncodeToString([]byte(`{"custom":{"k":"v"}}`))
	req := lambdaReq(http.MethodPost, "/2015-03-31/functions/orders:live/invocations", `{}`)
	req.Header.Set("X-Amz-Client-Context", cc)
	if w := serveWith(h, req, testUser); w.Code != http.StatusOK || len(ht.headers) != 1 {
		t.Fatalf("invoke: %d %s", w.Code, w.Body)
	}
	got := ht.headers[0]
	if a := got.Get("X-Openinfra-Invoked-Function-Arn"); a != "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders:live" {
		t.Errorf("invoked ARN = %q", a)
	}
	if v := got.Get("X-Openinfra-Function-Version"); v != "1" {
		t.Errorf("version = %q, want the alias's version 1", v)
	}
	if c := got.Get("X-Amz-Client-Context"); c != cc {
		t.Errorf("ClientContext = %q", c)
	}

	ht.headers = nil
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/invocations", `{}`), testUser); w.Code != http.StatusOK {
		t.Fatalf("unqualified invoke: %d %s", w.Code, w.Body)
	}
	if a, v := ht.headers[0].Get("X-Openinfra-Invoked-Function-Arn"), ht.headers[0].Get("X-Openinfra-Function-Version"); a != "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders" || v != "$LATEST" {
		t.Errorf("unqualified: ARN %q version %q", a, v)
	}

	ht.headers = nil
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("[1]")), strings.Repeat("A", 3584)} {
		req := lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/invocations", `{}`)
		req.Header.Set("X-Amz-Client-Context", bad)
		if w := serveWith(h, req, testUser); w.Code != http.StatusBadRequest || !isDenied(w, "InvalidRequestContentException") || len(ht.headers) != 0 {
			t.Errorf("ClientContext %.20q: %d %s, %d invokes", bad, w.Code, w.Body, len(ht.headers))
		}
	}
}

// An asynchronous invocation is delivered as Lambda delivers one: the payload as sent (direct-invoke), to
// the version it names, with the ARN it was invoked by; a function error is a failed attempt, retried.
func TestAsyncDelivery_IsDirectAndAFunctionErrorIsRetried(t *testing.T) {
	ht := &headerTransport{answer: http.Header{"X-Amz-Function-Error": {"Unhandled"}}}
	var logs bytes.Buffer
	a := &asyncInvoker{client: &http.Client{Transport: ht}, maxDeliver: 3,
		urlFor: func(name, ns string) string { return "http://" + name + "." + ns + ".svc.invalid/" },
		logger: slog.New(slog.NewTextHandler(&logs, nil))}
	m := asyncMsg("", "orders", "default", "application/json", []byte(`[1,2]`), "rid")
	m.Header.Set("X-Fn-Version", "2")
	m.Header.Set("X-Fn-Invoked-Arn", "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders:live")
	a.deliver(m)
	if len(ht.hosts) != 1 || ht.hosts[0] != "v2-orders.default.svc.invalid" {
		t.Fatalf("delivered to %v, want version 2's address", ht.hosts)
	}
	got := ht.headers[0]
	if got.Get("X-Openinfra-Invoke") != "direct" || got.Get("X-Openinfra-Function-Version") != "2" ||
		got.Get("X-Openinfra-Invoked-Function-Arn") != "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders:live" {
		t.Errorf("delivery headers = %v", got)
	}
	if !strings.Contains(logs.String(), "will retry") {
		t.Errorf("a function error must be retried; log: %s", logs.String())
	}
}
