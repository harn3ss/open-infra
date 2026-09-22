package main

import (
	"context"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// roleCutoffTTL is how long a role's revokeSessionsBefore cutoff is cached before re-reading. It
// bounds how quickly a "Revoke sessions" action takes effect on already-issued sessions (~one TTL);
// short enough to be prompt, long enough that the every-request verify path is not a Role GET each
// time.
const roleCutoffTTL = 15 * time.Second

// sessionRevoker reports a role's "revoke sessions before" cutoff. Any assumed-role session minted
// before that instant is revoked — it falls closed at verify even though its sealed token is
// otherwise valid and unexpired. This is the faithful analog of AWS's "Revoke sessions" action,
// which attaches an AWSRevokeOlderSessions inline policy denying tokens issued before a timestamp
// (polyhedron#147). ok=false means the role sets no cutoff, so no session is revoked on its account.
type sessionRevoker interface {
	RevokedBefore(ctx context.Context, roleName string) (cutoff time.Time, ok bool)
}

// roleCutoffCache reads spec.revokeSessionsBefore off a kind: Role claim and caches it per role on a
// short TTL, so the every-request assumed-role verify path does not GET the Role each time. It reuses
// the shim's existing role read path and RBAC — the same dynamic client and roles.iam.openinfra.dev
// resource the trust resolver uses — so the cutoff lives on the Role itself (one source of truth, no
// mirror object to keep in sync).
//
// Failure posture is deliberate and matches internal/awssts's rule that "a control-plane hiccup must
// not deny all data-plane traffic": a read error SERVES THE LAST-KNOWN cutoff for that role rather
// than denying, so a transient API blip cannot suddenly revoke every live session. A role never yet
// loaded, read during an outage, reads as "no cutoff" (allow) — the one bounded gap, capped by the
// session's ≤12h hard expiry. The cutoff is a fast, best-effort, targeted lever layered on top of the
// always-enforced crypto signature + hard expiry; the blunt, guaranteed lever remains a signing-key
// rotation (revoke-all).
type roleCutoffCache struct {
	dyn dynamic.Interface
	ns  string
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]cutoffEntry
}

type cutoffEntry struct {
	cutoff   time.Time
	set      bool // the role carries a (parseable, non-empty) cutoff
	loadedAt time.Time
}

func newRoleCutoffCache(dyn dynamic.Interface, ns string, ttl time.Duration) *roleCutoffCache {
	return &roleCutoffCache{dyn: dyn, ns: ns, ttl: ttl, entries: map[string]cutoffEntry{}}
}

// RevokedBefore returns the role's cutoff, reading through the cache. A fresh cached entry answers
// without a k8s call; a stale or missing one triggers a read, and a read error serves the last-known
// entry (never widening on a blip).
func (c *roleCutoffCache) RevokedBefore(ctx context.Context, roleName string) (time.Time, bool) {
	c.mu.Lock()
	e, have := c.entries[roleName]
	if have && time.Since(e.loadedAt) < c.ttl {
		c.mu.Unlock()
		return e.cutoff, e.set
	}
	c.mu.Unlock()

	cutoff, set, ok := c.read(ctx, roleName)
	if !ok {
		// Read failed: serve the last-known cutoff (or, if never loaded, no cutoff). A control-plane
		// blip must not revoke every session; the crypto + expiry checks still gate the request.
		return e.cutoff, e.set
	}
	c.mu.Lock()
	c.entries[roleName] = cutoffEntry{cutoff: cutoff, set: set, loadedAt: time.Now()}
	c.mu.Unlock()
	return cutoff, set
}

// read GETs the role claim and parses spec.revokeSessionsBefore (RFC3339). ok=false only on a read
// error. set=false when the field is absent, empty, or unparseable — a malformed cutoff is treated as
// "no cutoff" rather than silently revoking everything; the XRD enforces format: date-time so a
// malformed value cannot be written through the API in the first place.
func (c *roleCutoffCache) read(ctx context.Context, roleName string) (cutoff time.Time, set, ok bool) {
	u, err := c.dyn.Resource(roleGVR).Namespace(c.ns).Get(ctx, roleName, metav1.GetOptions{})
	if err != nil {
		return time.Time{}, false, false
	}
	s, found, _ := unstructured.NestedString(u.Object, "spec", "revokeSessionsBefore")
	if !found || s == "" {
		return time.Time{}, false, true
	}
	t, perr := time.Parse(time.RFC3339, s)
	if perr != nil {
		return time.Time{}, false, true
	}
	return t.UTC(), true, true
}
