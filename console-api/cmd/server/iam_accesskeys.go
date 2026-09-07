package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"k8s.io/client-go/kubernetes"
)

// Managing a kind: User's AWS-shim access keys from the console — the "Security credentials"
// surface (create/list/deactivate/delete an access key). This is the one genuinely-secret-bearing
// IAM surface, so it is built to two rules:
//
//  1. The SECRET IS SHOWN EXACTLY ONCE. GenerateKeyPair mints it, Put stores it (in the shim's
//     KEYS namespace, as a real Secret — SigV4 needs the material back to verify a signature),
//     and it is returned only in the CREATE response. No list/get path can read it again: those
//     project onto awskeys.Meta, which has no secret field. There is deliberately no "reveal
//     secret" endpoint. Lose it → mint a new key. (AWS behaviour.)
//
//  2. AUTHORIZATION IS THE ONE POLICY WORLD. A signed-in user manages their OWN keys (self-
//     service, the AWS "My security credentials" page); managing SOMEONE ELSE's keys requires the
//     same SubjectAccessReview against iam.openinfra.dev/users that gates every other IAM handler
//     (admins only). The console's ServiceAccount does the Secret I/O, but the human's own RBAC
//     decides whether it happens — see authz.go.
//
// The keys live in the shim's KEYS_NAMESPACE (default open-infra-aws-shim), NOT the console
// namespace: the same least-privilege split the shim uses (keys away from the bcrypt password
// hashes + session key). The console SA reaches that namespace via a narrow Role (see
// platform/aws-shim/aws-shim.yaml). When the aws-shim overlay isn't deployed, that namespace
// doesn't exist and these endpoints fail honestly (list → empty, create → a clear error).

// maxKeysPerUser caps a user at two active-or-inactive keys, matching AWS's per-user limit. The
// cap makes key ROTATION the intended workflow (mint the second, cut over, delete the first)
// rather than an unbounded pile of long-lived credentials.
const maxKeysPerUser = 2

// accessKeyView is a key as the console sees it — its ID, owner, status and creation time, and
// NEVER the secret. LastUsed is honestly null: per-key last-used is not tracked yet (it would come
// from shim/Loki request logs, a data-plumbing task), so the UI shows "—" rather than a fake value.
type accessKeyView struct {
	AccessKeyID string  `json:"accessKeyId"`
	Owner       string  `json:"owner"`
	Status      string  `json:"status"` // "Active" | "Inactive"
	Created     string  `json:"created"`
	LastUsed    *string `json:"lastUsed"`
}

// accessKeyCreateView is the create response — the ONLY place the secret is ever returned. The
// field name mirrors AWS's CreateAccessKey (SecretAccessKey) so a migrant recognises it.
type accessKeyCreateView struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	Owner           string `json:"owner"`
	Status          string `json:"status"`
	Created         string `json:"created"`
}

func accessKeyStatusLabel(disabled bool) string {
	if disabled {
		return "Inactive"
	}
	return "Active"
}

func viewFromMeta(m awskeys.Meta) accessKeyView {
	created := ""
	if !m.Created.IsZero() {
		created = m.Created.UTC().Format(time.RFC3339)
	}
	return accessKeyView{
		AccessKeyID: m.AccessKeyID,
		Owner:       m.Owner,
		Status:      accessKeyStatusLabel(m.Disabled),
		Created:     created,
		LastUsed:    nil, // not tracked yet — honest null
	}
}

// authorizeAccessKey is the access-key authorization gate: self-service OR the admin SAR.
//
//   - AUTH_MODE=none → allowed (consistent with authorize()).
//   - the signed-in user acting on their OWN keys (claims.Sub == user) → allowed. This is what
//     makes the page self-service for ordinary users, exactly like AWS "My security credentials";
//     it grants nothing new, since a key only ever resolves to its owner's current groups.
//   - anyone else → the same SubjectAccessReview on iam.openinfra.dev/users that every other IAM
//     handler uses (verb "get" to view, "update" to mutate). Admins pass; nobody else does.
//
// It writes the 401/403 response itself and returns false when the caller may not proceed.
func authorizeAccessKey(w http.ResponseWriter, r *http.Request, cs kubernetes.Interface,
	auth *authStore, logger *slog.Logger, verb, user string) bool {
	if auth.mode == "none" {
		return true
	}
	c, ok := claimsFrom(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return false
	}
	if c.Sub == user {
		return true // self-service: a user manages their own access keys
	}
	return authorize(w, r, cs, auth, logger, verb, "iam.openinfra.dev", "users", auth.ns, user)
}

// keyStore binds an awskeys.Store to the shim's KEYS namespace with the console's clientset. Built
// per request; NewStore is trivial (no I/O), and this keeps the wiring next to where it is used.
func keyStore(cs kubernetes.Interface, keysNS string) *awskeys.Store {
	return awskeys.NewStore(cs, keysNS)
}

func handleIAMAccessKeysList(cs kubernetes.Interface, auth *authStore, keysNS string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "root" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account and has no access keys"})
			return
		}
		if !authorizeAccessKey(w, r, cs, auth, logger, "get", name) {
			return
		}
		metas, err := keyStore(cs, keysNS).List(r.Context(), name)
		if err != nil {
			// The KEYS namespace may not exist (aws-shim not deployed) or the console SA may lack
			// list there — either way there is nothing to show, not a server fault. Return an empty
			// list so the page renders its honest empty state.
			logger.Warn("iam: list access keys", "user", name, "error", err.Error())
			writeJSON(w, http.StatusOK, []accessKeyView{})
			return
		}
		out := make([]accessKeyView, 0, len(metas))
		for _, m := range metas {
			out = append(out, viewFromMeta(m))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func handleIAMAccessKeyCreate(cs kubernetes.Interface, auth *authStore, keysNS string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "root" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account and cannot hold access keys"})
			return
		}
		if !authorizeAccessKey(w, r, cs, auth, logger, "update", name) {
			return
		}
		// The owner must be a real kind: User — an access key resolves to its owner's groups on
		// every request, so a key with no resolvable owner would just fail at the shim. Refuse up
		// front (this also excludes root, which is not a User).
		if _, ok := auth.rawUser(r.Context(), name); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		store := keyStore(cs, keysNS)
		// Enforce the per-user cap. A List error here means the store is unreachable — surface it
		// rather than mint into a namespace we can't read (which would strand the key).
		existing, err := store.List(r.Context(), name)
		if err != nil {
			logger.Error("iam: access-key create — store unreachable", "user", name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the access-key store is not reachable (is the aws-shim deployed?)"})
			return
		}
		if len(existing) >= maxKeysPerUser {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "this user already has the maximum of 2 access keys — delete one before creating another",
			})
			return
		}
		id, secret, err := awskeys.GenerateKeyPair()
		if err != nil {
			logger.Error("iam: access-key generate", "user", name, "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate an access key"})
			return
		}
		if err := store.Put(r.Context(), awskeys.Key{AccessKeyID: id, SecretKey: secret, Owner: name}); err != nil {
			logger.Error("iam: access-key store", "user", name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not store the access key"})
			return
		}
		logger.Info("iam: access key created", "user", name, "accessKeyId", id, "by", subjectOf(r))
		// The secret is returned HERE and never again. Everything after this point can only ever
		// see the metadata.
		writeJSON(w, http.StatusCreated, accessKeyCreateView{
			AccessKeyID:     id,
			SecretAccessKey: secret,
			Owner:           name,
			Status:          "Active",
			Created:         time.Now().UTC().Format(time.RFC3339),
		})
	}
}

type accessKeyUpdateReq struct {
	// Status is "Active" or "Inactive" — the AWS UpdateAccessKey verb (Make active / Deactivate).
	Status string `json:"status"`
}

func handleIAMAccessKeyUpdate(cs kubernetes.Interface, auth *authStore, keysNS string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		id := chi.URLParam(r, "id")
		if name == "root" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account and has no access keys"})
			return
		}
		var in accessKeyUpdateReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		var disable bool
		switch in.Status {
		case "Active":
			disable = false
		case "Inactive":
			disable = true
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": `status must be "Active" or "Inactive"`})
			return
		}
		if !authorizeAccessKey(w, r, cs, auth, logger, "update", name) {
			return
		}
		store := keyStore(cs, keysNS)
		// Ownership binding: the key in the path must actually belong to the user in the path.
		// Without this, a mismatched {name}/{id} pair (or a self-service user naming a key that
		// isn't theirs) could toggle another principal's key. Describe returns the key even when
		// it is already Inactive, so re-activation works.
		m, ok := store.Describe(r.Context(), id)
		if !ok || m.Owner != name {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such access key for this user"})
			return
		}
		var err error
		if disable {
			err = store.Revoke(r.Context(), id)
		} else {
			err = store.Activate(r.Context(), id)
		}
		if err != nil {
			logger.Error("iam: access-key update", "user", name, "accessKeyId", id, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not update the access key"})
			return
		}
		logger.Info("iam: access key updated", "user", name, "accessKeyId", id, "status", in.Status, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"accessKeyId": id, "status": in.Status})
	}
}

func handleIAMAccessKeyDelete(cs kubernetes.Interface, auth *authStore, keysNS string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		id := chi.URLParam(r, "id")
		if name == "root" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account and has no access keys"})
			return
		}
		if !authorizeAccessKey(w, r, cs, auth, logger, "update", name) {
			return
		}
		store := keyStore(cs, keysNS)
		m, ok := store.Describe(r.Context(), id)
		if !ok || m.Owner != name {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such access key for this user"})
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			logger.Error("iam: access-key delete", "user", name, "accessKeyId", id, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not delete the access key"})
			return
		}
		logger.Info("iam: access key deleted", "user", name, "accessKeyId", id, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"accessKeyId": id})
	}
}
