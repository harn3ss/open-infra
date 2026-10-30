package awssig

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestPresigned_RoundTrip(t *testing.T) {
	const (
		host    = "examplebucket.s3.example.com"
		secret  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		amzDate = "20150830T123600Z"
	)
	q := url.Values{}
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request")
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", "900")
	q.Set("X-Amz-SignedHeaders", "host")

	// Sign over the request WITHOUT the signature parameter (as a client does).
	signReq := httptest.NewRequest("GET", "https://"+host+"/report.pdf?"+q.Encode(), nil)
	signReq.Host = host
	p := Presigned{
		Credential: Credential{
			AccessKeyID: "AKIDEXAMPLE", Date: "20150830", Region: "us-east-1", Service: "s3",
			SignedHeaders: []string{"host"},
		},
		AmzDate: amzDate, Expires: 900,
	}
	sig, err := SignPresigned(signReq, p, secret)
	if err != nil {
		t.Fatalf("SignPresigned: %v", err)
	}

	// The browser's request carries the signature in the query.
	q.Set("X-Amz-Signature", sig)
	req := httptest.NewRequest("GET", "https://"+host+"/report.pdf?"+q.Encode(), nil)
	req.Host = host

	got, err := ParsePresigned(req)
	if err != nil {
		t.Fatalf("ParsePresigned: %v", err)
	}
	if got.AccessKeyID != "AKIDEXAMPLE" || got.Service != "s3" || got.Expires != 900 {
		t.Fatalf("parsed wrong: %+v", got)
	}

	start, _ := time.Parse("20060102T150405Z", amzDate)

	// Within the window → valid.
	if err := VerifyPresigned(req, got, secret, start.Add(100*time.Second)); err != nil {
		t.Errorf("valid presigned URL rejected: %v", err)
	}
	// After the window → expired (and ONLY because the signature was otherwise valid).
	if err := VerifyPresigned(req, got, secret, start.Add(1000*time.Second)); !errors.Is(err, ErrSignatureExpired) {
		t.Errorf("expired URL: want ErrSignatureExpired, got %v", err)
	}
	// Wrong secret → mismatch, never "expired" (a forged URL learns nothing).
	if err := VerifyPresigned(req, got, "not-the-secret", start.Add(1000*time.Second)); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("wrong secret: want ErrSignatureMismatch, got %v", err)
	}
}

func TestPresigned_TamperedPathRejected(t *testing.T) {
	const (
		host    = "examplebucket.s3.example.com"
		secret  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		amzDate = "20150830T123600Z"
	)
	q := url.Values{}
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request")
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", "900")
	q.Set("X-Amz-SignedHeaders", "host")
	signReq := httptest.NewRequest("GET", "https://"+host+"/report.pdf?"+q.Encode(), nil)
	signReq.Host = host
	p := Presigned{Credential: Credential{AccessKeyID: "AKIDEXAMPLE", Date: "20150830", Region: "us-east-1", Service: "s3", SignedHeaders: []string{"host"}}, AmzDate: amzDate, Expires: 900}
	sig, err := SignPresigned(signReq, p, secret)
	if err != nil {
		t.Fatalf("SignPresigned: %v", err)
	}
	q.Set("X-Amz-Signature", sig)
	// Fetch a DIFFERENT key with the same signature → canonical path differs → mismatch.
	req := httptest.NewRequest("GET", "https://"+host+"/secret-other.pdf?"+q.Encode(), nil)
	req.Host = host
	got, err := ParsePresigned(req)
	if err != nil {
		t.Fatalf("ParsePresigned: %v", err)
	}
	start, _ := time.Parse("20060102T150405Z", amzDate)
	if err := VerifyPresigned(req, got, secret, start.Add(100*time.Second)); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("tampered path: want ErrSignatureMismatch, got %v", err)
	}
}

func TestPresigned_NotPresigned(t *testing.T) {
	req := httptest.NewRequest("GET", "https://host/key", nil)
	if _, err := ParsePresigned(req); !errors.Is(err, ErrNoAuthorization) {
		t.Errorf("non-presigned request: want ErrNoAuthorization, got %v", err)
	}
}
