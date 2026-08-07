// Package k8sauth is the production Authorizer (forward-map §6): it answers "may this caller access
// this field?" with an impersonated Kubernetes SubjectAccessReview — the SAME RBAC + permission
// boundary the console BFF and the aws-shim's coarse gate use. This is what makes field-level auth
// "one policy world" and not a parallel rule engine.
//
// It talks to the API server over plain REST (in-cluster service-account token + CA) rather than
// pulling in client-go, so the engine stays lean and the whole path is testable against an httptest
// server. The engine's own ServiceAccount needs permission to create subjectaccessreviews.
package k8sauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
)

// SARAuthorizer performs SubjectAccessReviews against a Kubernetes API server.
type SARAuthorizer struct {
	apiServer string // e.g. https://kubernetes.default.svc
	token     string // bearer token for the engine's ServiceAccount
	client    *http.Client
}

var _ authz.Authorizer = (*SARAuthorizer)(nil)

const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const caPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

// InCluster builds an authorizer from the in-cluster ServiceAccount (token + CA + the API server from
// KUBERNETES_SERVICE_HOST/PORT). It returns an error when not running in a cluster, so the caller can
// fall back (dev) and log that field auth is not enforced.
func InCluster() (*SARAuthorizer, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("k8sauth: not in a cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("k8sauth: read service-account token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("k8sauth: read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("k8sauth: cluster CA not valid PEM")
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	return &SARAuthorizer{apiServer: fmt.Sprintf("https://%s:%s", host, port), token: string(token), client: client}, nil
}

// New builds an authorizer against an explicit API server (used by tests with an httptest server).
func New(apiServer, token string, client *http.Client) *SARAuthorizer {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &SARAuthorizer{apiServer: apiServer, token: token, client: client}
}

// the SubjectAccessReview request/response shapes (only the fields we use).
type sarSpec struct {
	User               string              `json:"user,omitempty"`
	Groups             []string            `json:"groups,omitempty"`
	ResourceAttributes *resourceAttributes `json:"resourceAttributes,omitempty"`
}
type resourceAttributes struct {
	Group     string `json:"group,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Verb      string `json:"verb,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}
type sarReview struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Spec       sarSpec  `json:"spec"`
	Status     *sarStat `json:"status,omitempty"`
}
type sarStat struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// Authorize creates a SubjectAccessReview for the caller's identity and the field's requirement and
// returns nil (allowed) or authz.ErrDenied (rejected). A zero Requirement is allowed without a call.
func (a *SARAuthorizer) Authorize(ctx context.Context, id authz.Identity, need authz.Requirement) error {
	if need.IsZero() {
		return nil
	}
	review := sarReview{
		APIVersion: "authorization.k8s.io/v1",
		Kind:       "SubjectAccessReview",
		Spec: sarSpec{
			User:   id.Username,
			Groups: id.Groups,
			ResourceAttributes: &resourceAttributes{
				Group: need.Group, Resource: need.Resource, Verb: need.Verb,
				Namespace: need.Namespace, Name: need.Name,
			},
		},
	}
	payload, err := json.Marshal(review)
	if err != nil {
		return err
	}
	url := a.apiServer + "/apis/authorization.k8s.io/v1/subjectaccessreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("k8sauth: SAR request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("k8sauth: SAR returned %d: %s", resp.StatusCode, string(body))
	}
	var out sarReview
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("k8sauth: decode SAR response: %w", err)
	}
	if out.Status == nil || !out.Status.Allowed {
		reason := "denied by RBAC"
		if out.Status != nil && out.Status.Reason != "" {
			reason = out.Status.Reason
		}
		return fmt.Errorf("%w: %s", authz.ErrDenied, reason)
	}
	return nil
}
