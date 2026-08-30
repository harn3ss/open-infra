// A dependency-free in-cluster Kubernetes client — just enough REST to list
// Execution objects and patch their status subresource. Staying on net/http (no
// client-go) keeps the image a distroless static binary, matching apply-sink.
package main

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
