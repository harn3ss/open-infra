// Task-state invocation: POST the resolved task input to a kind: Function and turn
// its HTTP response into a result or a typed ASL error.
//
// Resource forms:
//   - "function:<name>"  -> http://<name>.<namespace>.svc.cluster.local/ (the
//     cluster-local URL that drives Knative scale-from-zero)
//   - "http(s)://..."    -> used verbatim (escape hatch)
//
// Response contract: HTTP 2xx => the JSON body is the task result. Non-2xx => a task
// failure; the error name comes from the X-Openinfra-Error header or a top-level
// "error"/"Error" field in the body, defaulting to States.TaskFailed. Exceeding the
// state's TimeoutSeconds yields States.Timeout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type taskError struct {
	Name  string
	Cause string
}

func (e *taskError) Error() string { return e.Name + ": " + e.Cause }

// TaskInvoker runs a Task's Resource. The engine depends on this interface so it can
// be unit-tested without a network.
type TaskInvoker interface {
	Invoke(ctx context.Context, resource string, input any, timeoutSeconds int) (any, *taskError)
}

type httpInvoker struct {
	namespace string
	client    *http.Client
}

func newHTTPInvoker(namespace string) *httpInvoker {
	return &httpInvoker{
		namespace: namespace,
		// No per-client timeout: each Invoke sets its own deadline via context so
		// TimeoutSeconds maps to States.Timeout rather than a generic transport error.
		client: &http.Client{},
	}
}

func (h *httpInvoker) resolveURL(resource string) (string, *taskError) {
	switch {
	case strings.HasPrefix(resource, "function:"):
		name := strings.TrimPrefix(resource, "function:")
		if name == "" {
			return "", &taskError{ErrRuntime, "empty function name in Resource"}
		}
		return fmt.Sprintf("http://%s.%s.svc.cluster.local/", name, h.namespace), nil
	case strings.HasPrefix(resource, "http://"), strings.HasPrefix(resource, "https://"):
		return resource, nil
	default:
		return "", &taskError{ErrRuntime, fmt.Sprintf("unsupported Task Resource %q (use function:<name> or an http(s):// URL)", resource)}
	}
}

func (h *httpInvoker) Invoke(ctx context.Context, resource string, input any, timeoutSeconds int) (any, *taskError) {
	url, terr := h.resolveURL(resource)
	if terr != nil {
		return nil, terr
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, &taskError{ErrRuntime, "task input is not serializable: " + err.Error()}
	}

	if timeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, &taskError{ErrTaskFailed, err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, &taskError{ErrTimeout, fmt.Sprintf("task exceeded TimeoutSeconds=%d", timeoutSeconds)}
		}
		return nil, &taskError{ErrTaskFailed, err.Error()}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap result at 1MiB

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		name := resp.Header.Get("X-Openinfra-Error")
		cause := resp.Header.Get("X-Openinfra-Cause")
		if name == "" || cause == "" {
			if n, c, ok := errorFromBody(respBody); ok {
				if name == "" {
					name = n
				}
				if cause == "" {
					cause = c
				}
			}
		}
		if name == "" {
			name = ErrTaskFailed
		}
		if cause == "" {
			cause = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 512))
		}
		return nil, &taskError{name, cause}
	}

	if len(bytes.TrimSpace(respBody)) == 0 {
		return nil, nil
	}
	var result any
	if err := json.Unmarshal(respBody, &result); err != nil {
		// Non-JSON 2xx body: pass it through as a string rather than fail the task.
		return string(respBody), nil
	}
	return result, nil
}

// errorFromBody pulls an error name/cause out of a JSON body ({"error"/"Error", "cause"/"Cause"}).
func errorFromBody(b []byte) (name, cause string, ok bool) {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return "", "", false
	}
	for _, k := range []string{"error", "Error"} {
		if s, is := m[k].(string); is && s != "" {
			name = s
			break
		}
	}
	for _, k := range []string{"cause", "Cause"} {
		if s, is := m[k].(string); is && s != "" {
			cause = s
			break
		}
	}
	return name, cause, name != "" || cause != ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
