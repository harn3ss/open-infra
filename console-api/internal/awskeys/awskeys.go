// Package awskeys is the credential store for SigV4 access keys: the one genuinely-new piece of
// state the AWS-shim introduces. It maps an access key ID → (secret access
// key, owning principal), backed by a Kubernetes Secret per key.
//
// Why a Secret holding the ACTUAL secret (not a hash, the way passwords are stored): SigV4
// verification is symmetric — to recompute a request's signature you must HMAC with the very same
// secret the client used, so the store has to be able to hand that secret back. It is therefore
// protected the way any sensitive Secret is (etcd encryption at rest + tightly-scoped RBAC), not
// by one-way hashing. This is the deliberate difference from iam-pw-<user> (a bcrypt hash).
//
// An access key is a sub-resource of a kind: User — the Secret is labelled with its owner, so the
// console can list/revoke a user's keys, and deleting the User can cascade to them. The key's
// PERMISSIONS are never stored here: after Verify succeeds, the owner is resolved to its current
// groups and the normal impersonated SubjectAccessReview decides — so revoking a group takes
// effect immediately, without touching the key.
//
// Secret naming: an AWS access key ID is uppercase (not a valid DNS-1123 Secret name), so the
// Secret name is a lowercase hash of the ID (deterministic, collision-guarded on read). The raw
// ID lives in the Secret's data, and Lookup verifies it — so a hash collision can never return
// the wrong key's secret.
package awskeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	secretNamePrefix = "iam-ak-"
	// LabelManagedBy / LabelOwner mark and attribute a key Secret; LabelOwner lets the console
	// list a User's keys with a selector and lets User deletion cascade to them.
	labelManagedBy = "app.kubernetes.io/managed-by"
	managedByValue = "open-infra-console"
	LabelOwner     = "openinfra.dev/iam-user"

	dataAccessKeyID = "accessKeyId"
	dataSecretKey   = "secretKey"
	dataOwner       = "owner"
	dataDisabled    = "disabled" // "true" revokes a key without deleting the Secret
)

// Key is a resolved access key: its ID, secret material, and owning principal (a kind: User name).
type Key struct {
	AccessKeyID string
	SecretKey   string
	Owner       string
}

// Store reads and writes access-key Secrets in a single namespace (the IAM/console namespace).
type Store struct {
	cs kubernetes.Interface
	ns string
}

// NewStore binds a Store to a clientset and the namespace access-key Secrets live in.
func NewStore(cs kubernetes.Interface, ns string) *Store { return &Store{cs: cs, ns: ns} }

// SecretName is the deterministic, DNS-1123-safe Secret name for an access key ID: a lowercase
// hex prefix of its SHA-256. Deterministic so Lookup is a single Get (no list/scan), and the raw
// ID is re-checked from the Secret data on read to defeat the (astronomically unlikely) collision.
func SecretName(accessKeyID string) string {
	sum := sha256.Sum256([]byte(accessKeyID))
	return secretNamePrefix + hex.EncodeToString(sum[:])[:40]
}

// Lookup resolves an access key ID to its secret + owner. ok=false when no such key exists, the
// stored ID doesn't match (hash collision guard), or the key has been revoked (disabled). A
// missing key is indistinguishable from a bad one to the caller — the shim maps both to a signature
// mismatch, so an attacker can't enumerate valid key IDs by probing.
func (s *Store) Lookup(ctx context.Context, accessKeyID string) (Key, bool) {
	if accessKeyID == "" {
		return Key{}, false
	}
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, SecretName(accessKeyID), metav1.GetOptions{})
	if err != nil {
		return Key{}, false
	}
	if strings.EqualFold(string(sec.Data[dataDisabled]), "true") {
		return Key{}, false
	}
	// Collision guard: the Secret name is a hash, so confirm the stored ID is the one asked for.
	if string(sec.Data[dataAccessKeyID]) != accessKeyID {
		return Key{}, false
	}
	secret := string(sec.Data[dataSecretKey])
	if secret == "" {
		return Key{}, false
	}
	return Key{AccessKeyID: accessKeyID, SecretKey: secret, Owner: string(sec.Data[dataOwner])}, true
}

// Put creates or updates the Secret for a key (used by the console when minting/importing a key).
// It is idempotent on the access key ID (same ID → same Secret name → update).
func (s *Store) Put(ctx context.Context, k Key) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecretName(k.AccessKeyID),
			Namespace: s.ns,
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				LabelOwner:     k.Owner,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			dataAccessKeyID: []byte(k.AccessKeyID),
			dataSecretKey:   []byte(k.SecretKey),
			dataOwner:       []byte(k.Owner),
		},
	}
	_, err := s.cs.CoreV1().Secrets(s.ns).Create(ctx, sec, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	// Already exists → update in place (idempotent mint / re-import).
	existing, gerr := s.cs.CoreV1().Secrets(s.ns).Get(ctx, sec.Name, metav1.GetOptions{})
	if gerr != nil {
		return err
	}
	existing.Labels = sec.Labels
	existing.Data = sec.Data
	_, uerr := s.cs.CoreV1().Secrets(s.ns).Update(ctx, existing, metav1.UpdateOptions{})
	return uerr
}

// Revoke disables a key without deleting its Secret (so its ID can never be silently reissued to a
// different principal). A revoked key stops verifying immediately.
func (s *Store) Revoke(ctx context.Context, accessKeyID string) error {
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, SecretName(accessKeyID), metav1.GetOptions{})
	if err != nil {
		return err
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data[dataDisabled] = []byte("true")
	_, err = s.cs.CoreV1().Secrets(s.ns).Update(ctx, sec, metav1.UpdateOptions{})
	return err
}

// GenerateKeyPair mints a fresh, AWS-shaped access key ID + secret using crypto/rand. The ID is
// opaque to SigV4 (any string works); the "OIAK" prefix marks it as an open-infra access key and
// keeps it visually distinct from a real AWS AKIA… key while staying 20 chars.
func GenerateKeyPair() (accessKeyID, secretKey string, err error) {
	idBytes := make([]byte, 10) // 10 bytes → 16 base32 chars
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", err
	}
	secBytes := make([]byte, 30) // 30 bytes → 40 base64 chars, matching AWS secret length
	if _, err = rand.Read(secBytes); err != nil {
		return "", "", err
	}
	id := "OIAK" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(idBytes)
	return id, base64.StdEncoding.EncodeToString(secBytes), nil
}
