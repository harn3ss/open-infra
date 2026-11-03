package main

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #350 item T: a service the shim does not front answers 501 NotImplemented in its own protocol's error
// shape, which the SDKs parse into the code (the CLI showed "Unknown" for S3's XML on a JSON service).
func TestUnsupportedService_ErrorShapePerProtocol(t *testing.T) {
	req := func(method, body string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(method, "http://shim/", strings.NewReader(body))
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	type xmlErr struct {
		Code string `xml:"Error>Code"`
	}
	type ec2Err struct {
		Code string `xml:"Errors>Error>Code"`
	}
	cases := []struct {
		name, service string
		r             *http.Request
		code          func(t *testing.T, w *httptest.ResponseRecorder) string
	}{
		{"json-rpc", "elasticache", req("POST", `{}`, map[string]string{"X-Amz-Target": "AmazonElastiCacheV9.DescribeCacheClusters", "Content-Type": "application/x-amz-json-1.0"}),
			func(t *testing.T, w *httptest.ResponseRecorder) string {
				var b map[string]string
				_ = json.Unmarshal(w.Body.Bytes(), &b)
				if w.Header().Get("Content-Type") != "application/x-amz-json-1.0" {
					t.Errorf("json-rpc content type = %q", w.Header().Get("Content-Type"))
				}
				return b["__type"]
			}},
		{"query", "autoscaling", req("POST", "Action=DescribeAutoScalingGroups&Version=2011-01-01", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}),
			func(t *testing.T, w *httptest.ResponseRecorder) string {
				var e struct {
					XMLName xml.Name `xml:"ErrorResponse"`
					Code    string   `xml:"Error>Code"`
				}
				_ = xml.Unmarshal(w.Body.Bytes(), &e)
				return e.Code
			}},
		{"rest-json", "batch", req("POST", `{}`, nil),
			func(t *testing.T, w *httptest.ResponseRecorder) string { return w.Header().Get("X-Amzn-ErrorType") }},
		{"rest-xml", "route53", req("GET", "", nil),
			func(t *testing.T, w *httptest.ResponseRecorder) string {
				var e xmlErr
				_ = xml.Unmarshal(w.Body.Bytes(), &e)
				return e.Code
			}},
		{"s3", "s3-outposts", req("GET", "", nil),
			func(t *testing.T, w *httptest.ResponseRecorder) string {
				var e struct {
					Code string `xml:"Code"`
				}
				_ = xml.Unmarshal(w.Body.Bytes(), &e)
				return e.Code
			}},
		{"ec2", "ec2", req("POST", "Action=RunInstances", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}),
			func(t *testing.T, w *httptest.ResponseRecorder) string {
				var e ec2Err
				_ = xml.Unmarshal(w.Body.Bytes(), &e)
				return e.Code
			}},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		writeUnsupportedService(w, c.r, c.service, "req-1")
		if w.Code != http.StatusNotImplemented {
			t.Errorf("%s: status %d, want 501", c.name, w.Code)
		}
		if got := c.code(t, w); got != "NotImplemented" {
			t.Errorf("%s: the %s error shape must carry NotImplemented, got %q in %s", c.name, c.service, got, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), c.service) {
			t.Errorf("%s: the message must name the service: %s", c.name, w.Body.String())
		}
	}
}

// The router answers an unfronted service in that service's shape.
func TestRouter_UnsupportedServiceDialect(t *testing.T) {
	const id, secret = "OIAKROUTER0000000000", "router-secret"
	rt := newTestRouter(map[string]awsService{"s3": &recordingService{}})
	r := signedFor(t, "elasticache", id, secret, "POST", "http://shim/")
	r.Header.Set("X-Amz-Target", "AmazonElastiCacheV9.DescribeCacheClusters")
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	var b map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	if w.Code != http.StatusNotImplemented || b["__type"] != "NotImplemented" {
		t.Fatalf("an unfronted JSON service: %d %s", w.Code, w.Body.String())
	}
}
