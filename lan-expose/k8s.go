// A dependency-free in-cluster Kubernetes client — just enough REST to list
// Services/Pods and CRUD the kube-ovn OvnEip/OvnFip CRs plus patch the default VPC's
// policyRoutes. net/http only (no client-go) so the image stays a distroless static
// binary, matching statemachine/apply-sink.
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

	ovnAPI  = "/apis/kubeovn.io/v1"
	coreAPI = "/api/v1"
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- core objects (only the fields we use) ----

type Service struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Selector map[string]string `json:"selector"`
		Type     string            `json:"type"`
	} `json:"spec"`
}

type Pod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Status struct {
		PodIP string `json:"podIP"`
		Phase string `json:"phase"`
	} `json:"status"`
}

func (c *k8sClient) listServices(ctx context.Context) ([]Service, error) {
	b, code, err := c.do(ctx, http.MethodGet, coreAPI+"/services", "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list services: HTTP %d: %s", code, truncate(string(b), 256))
	}
	var list struct {
		Items []Service `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// listPods lists pods in a namespace filtered by an equality label selector
// (map -> "k=v,k2=v2"). An empty selector matches nothing (a Service with no
// selector has no pods we can target).
func (c *k8sClient) listPods(ctx context.Context, ns string, selector map[string]string) ([]Pod, error) {
	if len(selector) == 0 {
		return nil, nil
	}
	sel := ""
	for k, v := range selector {
		if sel != "" {
			sel += ","
		}
		sel += k + "=" + v
	}
	path := fmt.Sprintf("%s/namespaces/%s/pods?labelSelector=%s", coreAPI, ns, url.QueryEscape(sel))
	b, code, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list pods in %s: HTTP %d: %s", ns, code, truncate(string(b), 256))
	}
	var list struct {
		Items []Pod `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// patchServiceAnnotations merge-patches metadata.annotations on a Service (used to
// publish the assigned EIP back onto the Service for visibility).
func (c *k8sClient) patchServiceAnnotations(ctx context.Context, ns, name string, annos map[string]string) error {
	body, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": annos}})
	path := fmt.Sprintf("%s/namespaces/%s/services/%s", coreAPI, ns, name)
	b, code, err := c.do(ctx, http.MethodPatch, path, "application/merge-patch+json", body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("patch service %s/%s: HTTP %d: %s", ns, name, code, truncate(string(b), 256))
	}
	return nil
}

// ---- kube-ovn OvnEip (cluster-scoped) ----

type OvnEip struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		ExternalSubnet string `json:"externalSubnet"`
		Type           string `json:"type"`
		V4Ip           string `json:"v4Ip"`
	} `json:"spec"`
	Status struct {
		V4Ip  string `json:"v4Ip"`
		Ready bool   `json:"ready"`
	} `json:"status"`
}

func (c *k8sClient) listOvnEips(ctx context.Context) ([]OvnEip, error) {
	b, code, err := c.do(ctx, http.MethodGet, ovnAPI+"/ovn-eips", "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list ovn-eips: HTTP %d: %s", code, truncate(string(b), 256))
	}
	var list struct {
		Items []OvnEip `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *k8sClient) getOvnEip(ctx context.Context, name string) (*OvnEip, int, error) {
	b, code, err := c.do(ctx, http.MethodGet, ovnAPI+"/ovn-eips/"+name, "", nil)
	if err != nil {
		return nil, 0, err
	}
	if code == http.StatusNotFound {
		return nil, code, nil
	}
	if code != http.StatusOK {
		return nil, code, fmt.Errorf("get ovn-eip %s: HTTP %d: %s", name, code, truncate(string(b), 256))
	}
	var e OvnEip
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, code, err
	}
	return &e, code, nil
}

func (c *k8sClient) createOvnEip(ctx context.Context, name, subnet, v4ip string) error {
	obj := map[string]any{
		"apiVersion": "kubeovn.io/v1",
		"kind":       "OvnEip",
		"metadata":   map[string]any{"name": name, "labels": ownerLabels()},
		"spec":       map[string]any{"externalSubnet": subnet, "type": "nat", "v4Ip": v4ip},
	}
	return c.create(ctx, ovnAPI+"/ovn-eips", name, obj)
}

func (c *k8sClient) deleteOvnEip(ctx context.Context, name string) error {
	return c.delete(ctx, ovnAPI+"/ovn-eips/"+name)
}

// ---- kube-ovn OvnFip (cluster-scoped) ----

type OvnFip struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		OvnEip string `json:"ovnEip"`
		IPName string `json:"ipName"`
		Type   string `json:"type"`
	} `json:"spec"`
	Status struct {
		Ready bool `json:"ready"`
	} `json:"status"`
}

func (c *k8sClient) getOvnFip(ctx context.Context, name string) (*OvnFip, int, error) {
	b, code, err := c.do(ctx, http.MethodGet, ovnAPI+"/ovn-fips/"+name, "", nil)
	if err != nil {
		return nil, 0, err
	}
	if code == http.StatusNotFound {
		return nil, code, nil
	}
	if code != http.StatusOK {
		return nil, code, fmt.Errorf("get ovn-fip %s: HTTP %d: %s", name, code, truncate(string(b), 256))
	}
	var f OvnFip
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, code, err
	}
	return &f, code, nil
}

func (c *k8sClient) createOvnFip(ctx context.Context, name, eip, ipName string) error {
	obj := map[string]any{
		"apiVersion": "kubeovn.io/v1",
		"kind":       "OvnFip",
		"metadata":   map[string]any{"name": name, "labels": ownerLabels()},
		"spec":       map[string]any{"ovnEip": eip, "ipName": ipName, "type": "centralized"},
	}
	return c.create(ctx, ovnAPI+"/ovn-fips", name, obj)
}

func (c *k8sClient) deleteOvnFip(ctx context.Context, name string) error {
	return c.delete(ctx, ovnAPI+"/ovn-fips/"+name)
}

// ---- kube-ovn Vpc (cluster-scoped) ----

type Vpc struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		PolicyRoutes []PolicyRoute `json:"policyRoutes"`
	} `json:"spec"`
}

func (c *k8sClient) getVpc(ctx context.Context, name string) (*Vpc, error) {
	b, code, err := c.do(ctx, http.MethodGet, ovnAPI+"/vpcs/"+name, "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("get vpc %s: HTTP %d: %s", name, code, truncate(string(b), 256))
	}
	var v Vpc
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// patchVpcPolicyRoutes merge-patches the full policyRoutes list onto the VPC. A JSON
// merge patch replaces the array wholesale, which is what we want — mergePolicyRoutes
// has already folded in the foreign entries we must preserve.
func (c *k8sClient) patchVpcPolicyRoutes(ctx context.Context, name string, routes []PolicyRoute) error {
	if routes == nil {
		routes = []PolicyRoute{}
	}
	body, _ := json.Marshal(map[string]any{"spec": map[string]any{"policyRoutes": routes}})
	b, code, err := c.do(ctx, http.MethodPatch, ovnAPI+"/vpcs/"+name, "application/merge-patch+json", body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("patch vpc %s policyRoutes: HTTP %d: %s", name, code, truncate(string(b), 256))
	}
	return nil
}

// ---- generic create/delete ----

func (c *k8sClient) create(ctx context.Context, collectionPath, name string, obj map[string]any) error {
	body, _ := json.Marshal(obj)
	b, code, err := c.do(ctx, http.MethodPost, collectionPath, "application/json", body)
	if err != nil {
		return err
	}
	if code == http.StatusConflict {
		return nil // already exists — idempotent
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return fmt.Errorf("create %s/%s: HTTP %d: %s", collectionPath, name, code, truncate(string(b), 256))
	}
	return nil
}

func (c *k8sClient) delete(ctx context.Context, resourcePath string) error {
	b, code, err := c.do(ctx, http.MethodDelete, resourcePath, "", nil)
	if err != nil {
		return err
	}
	if code == http.StatusOK || code == http.StatusAccepted || code == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("delete %s: HTTP %d: %s", resourcePath, code, truncate(string(b), 256))
}

// ownerLabels tags every CR this controller creates so listing/GC can find them.
func ownerLabels() map[string]any {
	return map[string]any{"app.kubernetes.io/managed-by": "lan-expose"}
}
