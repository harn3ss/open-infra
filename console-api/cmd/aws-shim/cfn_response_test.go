package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const crEvent = `{"RequestType":"Create","ResponseURL":"","StackId":"arn:aws:cloudformation:us-east-1:123456789012:stack/s/1",` +
	`"RequestId":"s/Custom","ResourceType":"Custom::Thing","LogicalResourceId":"Custom","ResourceProperties":{}}`

// fnServer is a custom resource's function: it answers with handle(event).
func crDoor(t *testing.T, handle func(t *testing.T, ev map[string]any, w http.ResponseWriter, r *http.Request)) (*cfnDoorway, *httptest.Server) {
	t.Helper()
	h := &cfnDoorway{svcSuffix: "svc.invalid", responses: &cfnResponses{pending: map[string]*cfnPending{}}}
	shim := httptest.NewServer(h.responseHandler(http.NotFoundHandler()))
	t.Cleanup(shim.Close)
	h.responses.base = shim.URL
	fn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		_ = json.NewDecoder(r.Body).Decode(&ev)
		handle(t, ev, w, r)
	}))
	t.Cleanup(fn.Close)
	u, _ := url.Parse(fn.URL)
	h.invoker = &http.Client{Transport: toServer{u}}
	return h, shim
}

// put sends a response to the event's ResponseURL, as cfn-response does.
func put(t *testing.T, ev map[string]any, resp map[string]any) int {
	t.Helper()
	b, _ := json.Marshal(resp)
	req, _ := http.NewRequest(http.MethodPut, ev["ResponseURL"].(string), bytes.NewReader(b))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func response(ev map[string]any, status string) map[string]any {
	return map[string]any{"Status": status, "Reason": "r", "PhysicalResourceId": "pid-1", "StackId": ev["StackId"],
		"RequestId": ev["RequestId"], "LogicalResourceId": ev["LogicalResourceId"], "NoEcho": false, "Data": map[string]any{"Greeting": "hello"}}
}

// A handler that PUTs its response to the ResponseURL (cfn-response) is answered by that response, though
// it returns nothing; the invocation is Lambda's Invoke (direct).
func TestCustomResource_ResponsePutToTheResponseURL(t *testing.T) {
	h, _ := crDoor(t, func(t *testing.T, ev map[string]any, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Openinfra-Invoke") != "direct" {
			t.Error("a custom resource is invoked as Lambda's Invoke")
		}
		if !strings.Contains(ev["ResponseURL"].(string), cfnResponsePath) {
			t.Errorf("the event must carry a ResponseURL: %v", ev["ResponseURL"])
		}
		if code := put(t, ev, response(ev, "SUCCESS")); code != http.StatusOK {
			t.Errorf("the PUT: %d", code)
		}
		_, _ = w.Write([]byte("null"))
	})
	out, err := h.invokeCustomResourceFn(context.Background(), "ns", "fn", []byte(crEvent))
	if err != nil || out["Status"] != "SUCCESS" || out["PhysicalResourceId"] != "pid-1" || out["Data"].(map[string]any)["Greeting"] != "hello" {
		t.Fatalf("the PUT response decides: %v %v", out, err)
	}
	if len(h.responses.pending) != 0 {
		t.Fatal("the ResponseURL is released once answered")
	}
}

// A handler that returns its response (no PUT) is answered by what it returns, without waiting.
func TestCustomResource_ReturnedResponse(t *testing.T) {
	h, _ := crDoor(t, func(t *testing.T, ev map[string]any, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Status":"SUCCESS","Data":{"A":"1"}}`))
	})
	start := time.Now()
	out, err := h.invokeCustomResourceFn(context.Background(), "ns", "fn", []byte(crEvent))
	if err != nil || out["Status"] != "SUCCESS" || time.Since(start) > 5*time.Second {
		t.Fatalf("a returned response: %v %v (%v)", out, err, time.Since(start))
	}
}

// A response is taken only for its own request, once, while the invocation waits, and within AWS's size.
func TestCustomResource_ResponseURLRefusals(t *testing.T) {
	prev := cfnResponseGrace
	cfnResponseGrace = 200 * time.Millisecond
	defer func() { cfnResponseGrace = prev }()
	var codes []int
	h, shim := crDoor(t, func(t *testing.T, ev map[string]any, w http.ResponseWriter, r *http.Request) {
		wrong := response(ev, "SUCCESS")
		wrong["RequestId"] = "other/Custom"
		codes = append(codes, put(t, ev, wrong))
		big := response(ev, "SUCCESS")
		big["Data"] = map[string]any{"X": strings.Repeat("x", maxCFNResponse)}
		codes = append(codes, put(t, ev, big))
		bad := response(ev, "MAYBE")
		codes = append(codes, put(t, ev, bad))
		w.Header().Set("X-Amz-Function-Error", "Unhandled")
		_, _ = w.Write([]byte(`{"errorType":"Error","errorMessage":"boom"}`))
	})
	_, err := h.invokeCustomResourceFn(context.Background(), "ns", "fn", []byte(crEvent))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("no valid response and a function error: %v", err)
	}
	for i, c := range codes {
		if c != http.StatusBadRequest {
			t.Errorf("refused PUT %d: %d", i, c)
		}
	}
	req, _ := http.NewRequest(http.MethodPut, shim.URL+cfnResponsePath+"0123", strings.NewReader("{}"))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "AccessDenied") {
		t.Fatalf("an unknown ResponseURL is S3's AccessDenied: %d %s", res.StatusCode, b)
	}
}

// A handler that neither PUTs nor returns a response fails the resource, saying so.
func TestCustomResource_NoResponse(t *testing.T) {
	prev := cfnResponseGrace
	cfnResponseGrace = 100 * time.Millisecond
	defer func() { cfnResponseGrace = prev }()
	h, _ := crDoor(t, func(t *testing.T, ev map[string]any, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("null"))
	})
	if _, err := h.invokeCustomResourceFn(context.Background(), "ns", "fn", []byte(crEvent)); err == nil || !strings.Contains(err.Error(), "sent no response") {
		t.Fatalf("no response: %v", err)
	}
}
