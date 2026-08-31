// A dependency-free in-cluster Kubernetes client for the tuning controller — just
// enough REST to list TuningJobs, create trial TrainingJobs, read a trial's Job status
// and pod logs, and patch TuningJob status. No client-go, so a distroless static binary.
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
	"net/url"
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
		return nil, fmt.Errorf("not running in-cluster")
	}
	tok, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("bad CA PEM")
	}
	return &k8sClient{
		host:  fmt.Sprintf("https://%s:%s", host, port),
		token: string(tok),
		http:  &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}},
	}, nil
}

func (c *k8sClient) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, int, error) {
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

// --- Types ---

type TuningJob struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Training   map[string]any `json:"training"`
		Parameters []Param        `json:"parameters"`
		Objective  struct {
			Metric string `json:"metric"`
			Goal   string `json:"goal"`
		} `json:"objective"`
		MetricRegex string `json:"metricRegex"`
		MaxParallel int    `json:"maxParallel"`
		MaxTrials   int    `json:"maxTrials"`
	} `json:"spec"`
	Status TuningStatus `json:"status"`
}

type TuningStatus struct {
	Phase          string  `json:"phase,omitempty"`
	Trials         []Trial `json:"trials,omitempty"`
	BestTrial      string  `json:"bestTrial,omitempty"`
	BestValue      string  `json:"bestValue,omitempty"`
	BestParameters string  `json:"bestParameters,omitempty"`
	TrialsTotal    int     `json:"trialsTotal,omitempty"`
	TrialsComplete int     `json:"trialsComplete,omitempty"`
}

type Trial struct {
	Name       string            `json:"name"`
	Parameters map[string]string `json:"parameters"`
	Status     string            `json:"status"` // Pending | Running | Succeeded | Failed
	Metric     string            `json:"metric,omitempty"`
}

func (c *k8sClient) listTuningJobs(ctx context.Context) ([]TuningJob, error) {
	b, code, err := c.do(ctx, http.MethodGet, "/apis/openinfra.dev/v1/tuningjobs", "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list tuningjobs: HTTP %d: %s", code, trunc(b))
	}
	var list struct {
		Items []TuningJob `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *k8sClient) patchTuningStatus(ctx context.Context, ns, name string, status map[string]any) error {
	path := fmt.Sprintf("/apis/openinfra.dev/v1/namespaces/%s/tuningjobs/%s/status", ns, name)
	body, _ := json.Marshal(map[string]any{"status": status})
	b, code, err := c.do(ctx, http.MethodPatch, path, "application/merge-patch+json", body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("patch status: HTTP %d: %s", code, trunc(b))
	}
	return nil
}

// createTrainingJob POSTs a TrainingJob claim; a 409 (already exists) is not an error.
func (c *k8sClient) createTrainingJob(ctx context.Context, ns string, obj map[string]any) error {
	path := fmt.Sprintf("/apis/openinfra.dev/v1/namespaces/%s/trainingjobs", ns)
	body, _ := json.Marshal(obj)
	b, code, err := c.do(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return err
	}
	if code == http.StatusConflict || code == http.StatusCreated || code == http.StatusOK {
		return nil
	}
	return fmt.Errorf("create trainingjob: HTTP %d: %s", code, trunc(b))
}

type jobStatus struct {
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	Active     int `json:"active"`
	Conditions []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	} `json:"conditions"`
}

// getJobStatus returns the trial's batch Job status, or found=false if it doesn't exist yet.
func (c *k8sClient) getJobStatus(ctx context.Context, ns, name string) (jobStatus, bool, error) {
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", ns, name)
	b, code, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return jobStatus{}, false, err
	}
	if code == http.StatusNotFound {
		return jobStatus{}, false, nil
	}
	if code != http.StatusOK {
		return jobStatus{}, false, fmt.Errorf("get job: HTTP %d: %s", code, trunc(b))
	}
	var j struct {
		Status jobStatus `json:"status"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return jobStatus{}, false, err
	}
	return j.Status, true, nil
}

func (js jobStatus) succeeded() bool { return js.Succeeded > 0 }
func (js jobStatus) failed() bool {
	if js.Failed == 0 {
		return false
	}
	for _, c := range js.Conditions {
		if c.Type == "Failed" && c.Status == "True" {
			return true
		}
	}
	return false
}

// trialLogs returns the logs of the trial's pod (by the TrainingJob label).
func (c *k8sClient) trialLogs(ctx context.Context, ns, trial string) (string, error) {
	sel := url.QueryEscape("openinfra.dev/trainingjob=" + trial)
	b, code, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=%s", ns, sel), "", nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("list pods: HTTP %d", code)
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &pods); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", nil
	}
	pod := pods.Items[len(pods.Items)-1].Metadata.Name
	lb, code, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?tailLines=200", ns, pod), "", nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", nil
	}
	return string(lb), nil
}

func trunc(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
