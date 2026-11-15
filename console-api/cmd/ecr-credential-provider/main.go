// ecr-credential-provider is the kubelet's image credential provider for the platform's ECR registry: it
// pulls an application's image with the application's task execution role, as ECS pulls a task's image with
// its ExecutionRoleArn.
//
// The kubelet runs it for each image the node pulls from the registry (the provider's matchImages), passing a
// CredentialProviderRequest on stdin with a service-account token bound to the pod the image is for (the
// kubelet's service-account token for image pulls; audience openinfra-ecr-pull). It posts the token to the
// aws-shim's /ecr/pod-credential and answers with a CredentialProviderResponse on stdout:
//   - the execution role's ECR credential when the pod is an application's that names one;
//   - no credential when it is not (the node then pulls with its own, as before);
//   - a credential the registry refuses when the execution role may not pull, so the pull fails as ECS's
//     does instead of falling back to the node's.
//
// Usage (CredentialProviderConfig args): ecr-credential-provider --shim http://<aws-shim address>:4566
// The node installer runs it once as ecr-credential-provider --install <dir> to copy itself there (its
// image has no shell).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const apiVersion = "credentialprovider.kubelet.k8s.io/v1"

type request struct {
	APIVersion          string `json:"apiVersion"`
	Image               string `json:"image"`
	ServiceAccountToken string `json:"serviceAccountToken"`
}

type authConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type response struct {
	Kind          string                `json:"kind"`
	APIVersion    string                `json:"apiVersion"`
	CacheKeyType  string                `json:"cacheKeyType"`
	CacheDuration string                `json:"cacheDuration,omitempty"`
	Auth          map[string]authConfig `json:"auth"`
}

func main() {
	shim := flag.String("shim", os.Getenv("OPENINFRA_SHIM"), "the aws-shim's in-cluster URL")
	timeout := flag.Duration("timeout", 10*time.Second, "how long to wait for the aws-shim")
	install := flag.String("install", "", "copy this binary into the directory and exit")
	flag.Parse()
	if *install != "" {
		if err := installTo(*install); err != nil {
			fmt.Fprintln(os.Stderr, "ecr-credential-provider:", err)
			os.Exit(1)
		}
		return
	}
	out, err := run(os.Stdin, strings.TrimRight(*shim, "/"), &http.Client{Timeout: *timeout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ecr-credential-provider:", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

// registryOf is the registry part of an image reference: everything before the first '/'.
func registryOf(image string) string {
	host, _, _ := strings.Cut(image, "/")
	return host
}

func run(in io.Reader, shim string, hc *http.Client) (response, error) {
	var req request
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		return response{}, fmt.Errorf("reading the request: %w", err)
	}
	if req.APIVersion != "" && req.APIVersion != apiVersion {
		return response{}, fmt.Errorf("unsupported apiVersion %q", req.APIVersion)
	}
	if shim == "" {
		return response{}, errors.New("no aws-shim address (--shim)")
	}
	resp := response{Kind: "CredentialProviderResponse", APIVersion: apiVersion, CacheKeyType: "Registry",
		Auth: map[string]authConfig{}}
	registry := registryOf(req.Image)
	if req.ServiceAccountToken == "" || registry == "" {
		resp.CacheDuration = "5m" // no pod identity: the node's own credential
		return resp, nil
	}
	body, _ := json.Marshal(map[string]string{"image": req.Image})
	hreq, err := http.NewRequest(http.MethodPost, shim+"/ecr/pod-credential", bytes.NewReader(body))
	if err != nil {
		return response{}, err
	}
	hreq.Header.Set("Authorization", "Bearer "+req.ServiceAccountToken)
	hreq.Header.Set("Content-Type", "application/json")
	hres, err := hc.Do(hreq)
	if err != nil {
		return response{}, fmt.Errorf("asking the aws-shim: %w", err)
	}
	defer hres.Body.Close()
	switch hres.StatusCode {
	case http.StatusNoContent:
		resp.CacheDuration = "5m" // not an application's execution role: the node's own credential
		return resp, nil
	case http.StatusForbidden:
		// The execution role may not pull: a credential the registry refuses, so the pull fails rather
		// than use the node's.
		resp.CacheDuration = "1m"
		resp.Auth[registry] = authConfig{Username: "AWS", Password: "refused"}
		return resp, nil
	case http.StatusOK:
	default:
		msg, _ := io.ReadAll(io.LimitReader(hres.Body, 512))
		return response{}, fmt.Errorf("the aws-shim answered %d: %s", hres.StatusCode, bytes.TrimSpace(msg))
	}
	var cred struct {
		Username, Password, ExpiresAt string
	}
	if err := json.NewDecoder(hres.Body).Decode(&cred); err != nil || cred.Password == "" {
		return response{}, fmt.Errorf("the aws-shim's credential is unreadable")
	}
	// Cached for half its life, so the kubelet never pulls with one about to expire.
	ttl := 30 * time.Minute
	if exp, err := time.Parse(time.RFC3339, cred.ExpiresAt); err == nil {
		if half := time.Until(exp) / 2; half < ttl {
			ttl = half
		}
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	resp.CacheDuration = ttl.Round(time.Second).String()
	resp.Auth[registry] = authConfig{Username: cred.Username, Password: cred.Password}
	return resp, nil
}

// installTo copies this binary into dir as ecr-credential-provider, replacing any copy atomically.
func installTo(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ecr-credential-provider-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, "ecr-credential-provider"))
}
