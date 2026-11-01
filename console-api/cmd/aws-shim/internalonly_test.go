package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The VM credentials endpoint answers in-cluster callers only. A request that came through the LAN
// Ingress (any proxy forwarding header) gets 404 even with a valid VM token; the same request sent
// directly is served. The public CA bundle stays reachable through the Ingress.
func TestInternalOnly_VMCredsRefusedThroughProxy(t *testing.T) {
	h, _ := testVMCreds(t)
	ca, _ := testCert(t, "root", true)
	now := time.Now()
	rt := &serviceRouter{vmCreds: h, caBundle: testCABundle(&fakeCASource{data: ca}, &now),
		services: map[string]awsService{}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	call := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if path == vmCredsPath {
			r.Header.Set("Authorization", "good-token")
		}
		for k, v := range hdr {
			r.Header[http.CanonicalHeaderKey(k)] = []string{v}
		}
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, r)
		return w
	}

	if w := call(vmCredsPath, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "AccessKeyId") {
		t.Fatalf("direct in-cluster request must be served: %d %s", w.Code, w.Body.String())
	}
	for _, hdr := range []map[string]string{
		{"X-Forwarded-For": "192.0.2.10"},
		{"X-Forwarded-Host": "s3.example.test"},
		{"X-Real-IP": "192.0.2.10"},
		{"Forwarded": "for=192.0.2.10;proto=https"},
		{"X-Forwarded-For": ""}, // present but empty still counts
	} {
		w := call(vmCredsPath, hdr)
		if w.Code != http.StatusNotFound {
			t.Errorf("proxied request %v must get 404, got %d", hdr, w.Code)
		}
		if strings.Contains(w.Body.String(), "AccessKeyId") {
			t.Errorf("proxied request %v leaked credentials", hdr)
		}
	}
	if w := call(caBundlePath, map[string]string{"X-Forwarded-For": "192.0.2.10"}); w.Code != http.StatusOK {
		t.Errorf("the public CA bundle must stay reachable through the Ingress, got %d", w.Code)
	}
}
