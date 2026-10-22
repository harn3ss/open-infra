// A tiny client for the backing OCI registry's Distribution /v2 API.
//
// The ECR doorway's control plane (CreateRepository/DescribeImages/…) answers metadata questions the
// registry itself already knows — which tags a repository holds, what a tag resolves to, how big an
// image is — so rather than re-implement a registry we ask the real one over its standard /v2 HTTP API.
// The data plane (docker push/pull) never comes through here: clients talk to the registry directly at
// the proxyEndpoint. This client is deliberately dependency-free (net/http + encoding/json).
//
// Auth follows whichever mode the backing registry is in. A token-auth registry (the per-repo
// bearer-token cutover) rejects Basic, so the client mints a shim-signed registry Bearer scoped to
// exactly the repo + actions each call needs (the shim is the token issuer, so no realm round-trip is
// required). A legacy htpasswd registry still takes the shared Basic credential. Either way the shim
// presents exactly the authority a `docker` client would for the same operation.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// registryClient speaks the Distribution /v2 API against a single registry base URL. One is built per
// request from a freshly-read credential (so a rotated Secret takes effect immediately).
type registryClient struct {
	base string // registry base URL, no trailing slash (the shim's in-cluster reach, e.g. http://ecr-registry:5000)
	user string // htpasswd fallback (pre-token-auth registries)
	pass string
	// mintToken, when non-nil, authenticates each /v2 call with a shim-signed per-repo registry Bearer
	// token (the registry's token-auth mode) instead of Basic auth, scoped to exactly the repo + actions
	// the call needs. When nil the client falls back to the Basic credential above.
	mintToken func(repo string, actions ...string) (string, error)
	hc        *http.Client
}

func newRegistryClient(base, user, pass string) *registryClient {
	return &registryClient{
		base: strings.TrimRight(base, "/"),
		user: user,
		pass: pass,
		hc:   &http.Client{Timeout: 10 * time.Second},
	}
}

// newTokenRegistryClient builds a client for a token-auth registry: each call mints a shim-signed
// registry Bearer scoped to the repo + actions it needs, via mint.
func newTokenRegistryClient(base string, mint func(repo string, actions ...string) (string, error)) *registryClient {
	return &registryClient{
		base:      strings.TrimRight(base, "/"),
		mintToken: mint,
		hc:        &http.Client{Timeout: 10 * time.Second},
	}
}

// the manifest media types a GET must Accept so the registry returns (and digests) the real manifest
// rather than converting/omitting it — the common OCI + Docker single-image and index/list types.
var manifestAcceptTypes = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

// do issues a /v2 request bounded by the caller's context and the client's own timeout. It authenticates
// with a shim-minted per-repo Bearer token (token-auth registries) scoped to repo + actions, or with the
// shared Basic credential (legacy htpasswd registries) when no minter is configured.
func (c *registryClient) do(ctx context.Context, method, path, accept, repo string, actions ...string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case c.mintToken != nil:
		tok, err := c.mintToken(repo, actions...)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case c.user != "" || c.pass != "":
		req.SetBasicAuth(c.user, c.pass)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return c.hc.Do(req)
}

// listTags returns the tags a repository holds. A 404 means the registry has never seen the repository
// (an ECR repo declared but not yet pushed to), which is an EMPTY tag set, not an error.
func (c *registryClient) listTags(ctx context.Context, repo string) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v2/"+repo+"/tags/list", "", repo, "pull")
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &registryStatusError{op: "tags/list", repo: repo, status: resp.StatusCode}
	}
	var out struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Tags, nil
}

// resolveDigest resolves a reference (a tag or a digest) to its manifest digest and a best-effort image
// size. A 404 is NOT an error — it is the sentinel (digest=="", err==nil) for "no such image", so a
// caller iterating tags can skip one that vanished between the list and the resolve. The size is the sum
// of the config + layer sizes parsed from the manifest when present (the real pushed image size), and the
// manifest Content-Length only as a fallback — never a fabricated number.
func (c *registryClient) resolveDigest(ctx context.Context, repo, ref string) (digest string, size int64, err error) {
	resp, err := c.do(ctx, http.MethodGet, "/v2/"+repo+"/manifests/"+ref, manifestAcceptTypes, repo, "pull")
	if err != nil {
		return "", 0, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, &registryStatusError{op: "manifests GET", repo: repo, status: resp.StatusCode}
	}
	digest = resp.Header.Get("Docker-Content-Digest")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	size = manifestSize(body)
	if size == 0 && resp.ContentLength > 0 {
		size = resp.ContentLength
	}
	return digest, size, nil
}

// deleteManifest removes a manifest by digest. A 404 means it is already gone, which is success for a
// delete (idempotent) — the same stance the KMS crypto-erase reaper takes toward an already-destroyed key.
func (c *registryClient) deleteManifest(ctx context.Context, repo, digest string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v2/"+repo+"/manifests/"+digest, "", repo, "delete")
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	return &registryStatusError{op: "manifests DELETE", repo: repo, status: resp.StatusCode}
}

// manifestSize sums the config + layer sizes declared in an image manifest. A manifest list / index has
// no top-level layers, so it returns 0 (the caller then falls back to Content-Length or omits the size).
func manifestSize(body []byte) int64 {
	var m struct {
		Config struct {
			Size int64 `json:"size"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
	}
	if json.Unmarshal(body, &m) != nil {
		return 0
	}
	total := m.Config.Size
	for _, l := range m.Layers {
		total += l.Size
	}
	return total
}

func drainClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<20))
	_ = rc.Close()
}

// registryStatusError is an unexpected (non-404) /v2 status — surfaced to the doorway as an internal
// ServerException rather than mistaken for a clean/empty result.
type registryStatusError struct {
	op     string
	repo   string
	status int
}

func (e *registryStatusError) Error() string {
	return "registry " + e.op + " for " + e.repo + ": unexpected status " + itoa(e.status)
}
