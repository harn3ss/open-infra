// A dependency-free in-cluster Kubernetes client — just enough REST to list
// Execution objects and patch their status subresource. Staying on net/http (no
// client-go) keeps the image a distroless static binary, matching apply-sink.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type k8sClient struct {
	host  string
	token string
	http  *http.Client
}

func newInClusterClient() (*k8sClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in-cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	tok, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("cluster CA is not valid PEM")
	}
	return &k8sClient{
		host:  fmt.Sprintf("https://%s:%s", host, port),
		token: string(tok),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
	}, nil
}

// Execution mirrors the executions.openinfra.dev object (only the fields we use).
type Execution struct {
	Metadata struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
		CreationTS      string `json:"creationTimestamp"`
	} `json:"metadata"`
	Spec struct {
		StateMachineRef struct {
			Name string `json:"name"`
		} `json:"stateMachineRef"`
		Input string `json:"input"`
		// CredentialsSecret/Namespace point at a Secret holding the state-machine role's minted STS
		// session (accessKeyId/secretAccessKey/sessionToken), written by the aws-shim at StartExecution.
		// The controller reads it and injects the session into every Task so a Task runs under the role's
		// authority (polyhedron#172/#168). Empty ⇒ no role on the state machine (legacy behaviour).
		CredentialsSecret    string `json:"credentialsSecret,omitempty"`
		CredentialsNamespace string `json:"credentialsNamespace,omitempty"`
	} `json:"spec"`
	Status ExecStatus `json:"status"`
}

// ExecStatus is the checkpointed execution state. context/waitUntil/history live
// under the CRD's preserve-unknown-fields status.
type ExecStatus struct {
	Phase        string           `json:"phase,omitempty"`
	Output       string           `json:"output,omitempty"`
	Error        string           `json:"error,omitempty"`
	Cause        string           `json:"cause,omitempty"`
	CurrentState string           `json:"currentState,omitempty"`
	StartedAt    string           `json:"startedAt,omitempty"`
	StoppedAt    string           `json:"stoppedAt,omitempty"`
	Context      string           `json:"context,omitempty"`
	WaitUntil    string           `json:"waitUntil,omitempty"`
	History      []map[string]any `json:"history,omitempty"`
	// StopRequested is set by the aws-shim's StopExecution (the analogue of the AWS API). The controller
	// observes it on its next poll and cancels the running execution, which finalizes as Aborted with
	// StopCause — the shim never writes a terminal phase itself, so it can't race the running goroutine.
	StopRequested bool   `json:"stopRequested,omitempty"`
	StopCause     string `json:"stopCause,omitempty"`
}

func (c *k8sClient) do(ctx context.Context, method, path string, contentType string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.host+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

// listAllExecutions lists Execution objects across every namespace (cluster-scoped
// collection endpoint) — the singleton controller watches them all.
func (c *k8sClient) listAllExecutions(ctx context.Context) ([]Execution, error) {
	b, code, err := c.do(ctx, http.MethodGet, "/apis/openinfra.dev/v1/executions", "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list executions: HTTP %d: %s", code, truncate(string(b), 256))
	}
	var list struct {
		Items []Execution `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// getStateMachineDefinition reads a StateMachine's spec.definition (the ASL JSON).
func (c *k8sClient) getStateMachineDefinition(ctx context.Context, ns, name string) (string, error) {
	path := fmt.Sprintf("/apis/openinfra.dev/v1/namespaces/%s/statemachines/%s", ns, name)
	b, code, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", code, truncate(string(b), 256))
	}
	var sm struct {
		Spec struct {
			Definition string `json:"definition"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(b, &sm); err != nil {
		return "", err
	}
	if sm.Spec.Definition == "" {
		return "", fmt.Errorf("state machine has an empty spec.definition")
	}
	return sm.Spec.Definition, nil
}

// getCredentials reads the state-machine role's STS session from a Secret. The Secret's data holds
// accessKeyId / secretAccessKey / sessionToken (base64, per the core/v1 Secret encoding). Returns nil
// (no error) when name is empty — a state machine without a role runs Tasks with no injected identity.
func (c *k8sClient) getCredentials(ctx context.Context, ns, name string) (*taskCreds, error) {
	if name == "" {
		return nil, nil
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", ns, name)
	b, code, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("read credentials secret %s/%s: HTTP %d: %s", ns, name, code, truncate(string(b), 256))
	}
	var sec struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(b, &sec); err != nil {
		return nil, err
	}
	dec := func(k string) string {
		v, err := base64.StdEncoding.DecodeString(sec.Data[k])
		if err != nil {
			return ""
		}
		return string(v)
	}
	creds := &taskCreds{
		AccessKeyID:  dec("accessKeyId"),
		SecretKey:    dec("secretAccessKey"),
		SessionToken: dec("sessionToken"),
	}
	if creds.AccessKeyID == "" || creds.SecretKey == "" {
		return nil, fmt.Errorf("credentials secret %s/%s missing accessKeyId/secretAccessKey", ns, name)
	}
	return creds, nil
}

// patchStatus merge-patches an Execution's status subresource.
func (c *k8sClient) patchStatus(ctx context.Context, ns, name string, status map[string]any) error {
	path := fmt.Sprintf("/apis/openinfra.dev/v1/namespaces/%s/executions/%s/status", ns, name)
	body, err := json.Marshal(map[string]any{"status": status})
	if err != nil {
		return err
	}
	b, code, err := c.do(ctx, http.MethodPatch, path, "application/merge-patch+json", body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("patch status: HTTP %d: %s", code, truncate(string(b), 256))
	}
	return nil
}
