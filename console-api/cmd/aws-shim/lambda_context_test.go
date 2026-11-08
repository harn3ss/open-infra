package main

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

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

// LogType Tail answers the invocation's log tail (#407): the runtime's, when it gives one, else the lines
// Lambda writes around a function's output; the runtime gets the invocation's request ID, the one the
// answer carries; no tail unless asked; a LogType Lambda does not take is refused.
func TestInvoke_LogTail(t *testing.T) {
	h, _ := versionsFixture(t, nil, versionedFunction())
	runtimeTail := base64.StdEncoding.EncodeToString([]byte("START RequestId: x Version: $LATEST\nhello\nEND RequestId: x\n"))
	ht := &headerTransport{answer: http.Header{"X-Amz-Log-Result": {runtimeTail}}}
	h.client = &http.Client{Transport: ht}
	invoke := func(logType string) *httptest.ResponseRecorder {
		req := lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/invocations", `{}`)
		if logType != "" {
			req.Header.Set("X-Amz-Log-Type", logType)
		}
		return serveWith(h, req, testUser)
	}
	w := invoke("Tail")
	if w.Code != http.StatusOK || w.Header().Get("X-Amz-Log-Result") != runtimeTail {
		t.Fatalf("the runtime's tail: %d %v", w.Code, w.Header())
	}
	id := w.Header().Get("x-amzn-RequestId")
	if !uuidRe.MatchString(id) || ht.headers[0].Get("X-Openinfra-Request-Id") != id || ht.headers[0].Get("X-Amz-Log-Type") != "Tail" {
		t.Errorf("request ID %q, sent %v", id, ht.headers[0])
	}
	if w := invoke(""); w.Header().Get("X-Amz-Log-Result") != "" || ht.headers[1].Get("X-Amz-Log-Type") != "" {
		t.Errorf("no tail unless asked: %v", w.Header())
	}
	if w := invoke("None"); w.Code != http.StatusOK || w.Header().Get("X-Amz-Log-Result") != "" {
		t.Errorf("LogType None: %d %v", w.Code, w.Header())
	}
	if w := invoke("Everything"); w.Code != http.StatusBadRequest || !isDenied(w, "ValidationException") {
		t.Errorf("a LogType Lambda does not take: %d %s", w.Code, w.Body)
	}

	// A function on its own image gives no tail (or one that is not Lambda's shape): the shim's lines.
	for _, given := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(make([]byte, 5000))} {
		ht.answer = http.Header{"X-Amz-Log-Result": {given}}
		w := invoke("Tail")
		log, err := base64.StdEncoding.DecodeString(w.Header().Get("X-Amz-Log-Result"))
		id := w.Header().Get("x-amzn-RequestId")
		if err != nil || !strings.HasPrefix(string(log), "START RequestId: "+id+" Version: $LATEST\nEND RequestId: "+id+"\nREPORT RequestId: "+id+"\tDuration: ") {
			t.Errorf("tail %.20q: the shim's lines expected, got %q", given, log)
		}
	}
}
