package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The Lambda service port passes only a function's package and its web-identity credential exchange.
func TestLambdaServiceOnly(t *testing.T) {
	var reached []string
	h := lambdaServiceOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = append(reached, r.Method+" "+r.URL.Path+" "+r.PostFormValue("Action"))
		w.WriteHeader(http.StatusOK)
	}))
	form := func(action string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://shim:4568/", strings.NewReader(url.Values{"Action": {action}, "Version": {"2011-06-15"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	signed := form("AssumeRoleWithWebIdentity")
	signed.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=00")
	sqs := httptest.NewRequest(http.MethodPost, "http://shim:4568/", strings.NewReader(`{}`))
	sqs.Header.Set("X-Amz-Target", "AmazonSQS.SendMessage")
	sqs.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00")

	cases := []struct {
		name string
		req  *http.Request
		pass bool
	}{
		{"the package", httptest.NewRequest(http.MethodGet, "http://shim:4568"+functionCodePath, nil), true},
		{"the role's credentials", form("AssumeRoleWithWebIdentity"), true},
		{"another STS call", form("GetCallerIdentity"), false},
		{"a signed web-identity call", signed, false},
		{"any other AWS API", sqs, false},
		{"another path", httptest.NewRequest(http.MethodGet, "http://shim:4568/healthz", nil), false},
	}
	for _, c := range cases {
		reached = nil
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.req)
		if got := len(reached) == 1; got != c.pass {
			t.Errorf("%s: passed=%v, want %v (status %d)", c.name, got, c.pass, w.Code)
		}
		if !c.pass && w.Code != http.StatusNotFound {
			t.Errorf("%s: answered %d, want 404", c.name, w.Code)
		}
	}
}
