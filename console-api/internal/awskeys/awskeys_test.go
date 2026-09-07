package awskeys

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretName_DNSSafe(t *testing.T) {
	// A real AWS access key ID is uppercase; the Secret name must still be DNS-1123 valid.
	name := SecretName("AKIAIOSFODNN7EXAMPLE")
	if !strings.HasPrefix(name, secretNamePrefix) {
		t.Fatalf("missing prefix: %q", name)
	}
	for _, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			t.Fatalf("Secret name %q contains non-DNS-1123 char %q", name, c)
		}
	}
	// Deterministic.
	if SecretName("AKIAIOSFODNN7EXAMPLE") != name {
		t.Fatal("SecretName is not deterministic")
	}
	// Distinct IDs → distinct names.
	if SecretName("AKIAOTHER") == name {
		t.Fatal("distinct IDs collided")
	}
}

func TestPutLookupRoundTrip(t *testing.T) {
	s := NewStore(fake.NewSimpleClientset(), "open-infra-console")
	ctx := context.Background()

	want := Key{AccessKeyID: "OIAKABCDEF1234567890", SecretKey: "s3cr3t/secretkey", Owner: "alice"}
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Lookup(ctx, want.AccessKeyID)
	if !ok {
		t.Fatal("Lookup after Put returned not-found")
	}
	if got != want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}

	// Put is idempotent-update on the same ID (e.g. re-import / rotation of the secret material).
	want.SecretKey = "rotated-secret"
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put (update): %v", err)
	}
	got, _ = s.Lookup(ctx, want.AccessKeyID)
	if got.SecretKey != "rotated-secret" {
		t.Fatalf("update did not take: %q", got.SecretKey)
	}
}

func TestLookup_Missing(t *testing.T) {
	s := NewStore(fake.NewSimpleClientset(), "open-infra-console")
	if _, ok := s.Lookup(context.Background(), "OIAKDOESNOTEXIST0000"); ok {
		t.Fatal("Lookup of a missing key must be not-found")
	}
	if _, ok := s.Lookup(context.Background(), ""); ok {
		t.Fatal("Lookup of empty ID must be not-found")
	}
}

func TestLookup_Revoked(t *testing.T) {
	s := NewStore(fake.NewSimpleClientset(), "open-infra-console")
	ctx := context.Background()
	k := Key{AccessKeyID: "OIAKREVOKEME00000000", SecretKey: "x", Owner: "bob"}
	if err := s.Put(ctx, k); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Revoke(ctx, k.AccessKeyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := s.Lookup(ctx, k.AccessKeyID); ok {
		t.Fatal("a revoked key must not verify")
	}
}

// TestLookup_CollisionGuard: if a Secret sits at the hashed name but stores a DIFFERENT access key
// ID (a hash collision, or a crafted Secret), Lookup must NOT hand back its secret for the queried
// ID. This is the guard that makes the hash-named store safe.
func TestLookup_CollisionGuard(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewStore(cs, "open-infra-console")
	ctx := context.Background()

	// Hand-craft a Secret at the name for "QUERIED-ID" but storing a different accessKeyId.
	_, err := cs.CoreV1().Secrets("open-infra-console").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretName("QUERIED-ID"), Namespace: "open-infra-console"},
		Data: map[string][]byte{
			dataAccessKeyID: []byte("SOME-OTHER-ID"),
			dataSecretKey:   []byte("not-yours"),
			dataOwner:       []byte("mallory"),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if _, ok := s.Lookup(ctx, "QUERIED-ID"); ok {
		t.Fatal("collision guard failed: returned a key whose stored ID did not match the query")
	}
}

// Describe returns a key's public metadata WITHOUT its secret, and — unlike Lookup — returns a
// revoked key too (so the console can show an Inactive key and re-activate it).
func TestDescribe(t *testing.T) {
	s := NewStore(fake.NewSimpleClientset(), "open-infra-console")
	ctx := context.Background()
	k := Key{AccessKeyID: "OIAKDESCRIBE00000000", SecretKey: "super-secret", Owner: "dana"}
	if err := s.Put(ctx, k); err != nil {
		t.Fatalf("Put: %v", err)
	}
	m, ok := s.Describe(ctx, k.AccessKeyID)
	if !ok {
		t.Fatal("Describe returned not-found for an existing key")
	}
	if m.AccessKeyID != k.AccessKeyID || m.Owner != "dana" || m.Disabled {
		t.Fatalf("Describe meta mismatch: %+v", m)
	}
	// A revoked key is still describable, now Inactive.
	if err := s.Revoke(ctx, k.AccessKeyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	m, ok = s.Describe(ctx, k.AccessKeyID)
	if !ok || !m.Disabled {
		t.Fatalf("revoked key must describe as Disabled: ok=%v meta=%+v", ok, m)
	}
	if _, ok := s.Describe(ctx, "OIAKNOPE000000000000"); ok {
		t.Fatal("Describe of a missing key must be not-found")
	}
}

// Activate reverses Revoke: a deactivated key verifies again after Activate.
func TestActivate(t *testing.T) {
	s := NewStore(fake.NewSimpleClientset(), "open-infra-console")
	ctx := context.Background()
	k := Key{AccessKeyID: "OIAKACTIVATE00000000", SecretKey: "x", Owner: "erin"}
	if err := s.Put(ctx, k); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Revoke(ctx, k.AccessKeyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := s.Lookup(ctx, k.AccessKeyID); ok {
		t.Fatal("precondition: a revoked key must not verify")
	}
	if err := s.Activate(ctx, k.AccessKeyID); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if _, ok := s.Lookup(ctx, k.AccessKeyID); !ok {
		t.Fatal("an activated key must verify again")
	}
}

// Delete removes a key permanently — Lookup fails and the Secret is gone (not merely tombstoned
// the way Revoke leaves it).
func TestDelete(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewStore(cs, "open-infra-console")
	ctx := context.Background()
	k := Key{AccessKeyID: "OIAKDELETE0000000000", SecretKey: "x", Owner: "frank"}
	if err := s.Put(ctx, k); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, k.AccessKeyID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.Lookup(ctx, k.AccessKeyID); ok {
		t.Fatal("a deleted key must not verify")
	}
	if _, err := cs.CoreV1().Secrets("open-infra-console").Get(ctx, SecretName(k.AccessKeyID), metav1.GetOptions{}); err == nil {
		t.Fatal("Delete must remove the underlying Secret, not tombstone it")
	}
}

// List returns only the queried owner's keys, includes revoked (Inactive) ones, and never leaks
// secret material through the Meta it returns.
func TestList(t *testing.T) {
	s := NewStore(fake.NewSimpleClientset(), "open-infra-console")
	ctx := context.Background()
	must := func(err error) {
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	must(s.Put(ctx, Key{AccessKeyID: "OIAKGRACE00000000001", SecretKey: "s1", Owner: "grace"}))
	must(s.Put(ctx, Key{AccessKeyID: "OIAKGRACE00000000002", SecretKey: "s2", Owner: "grace"}))
	must(s.Put(ctx, Key{AccessKeyID: "OIAKHEIDI00000000001", SecretKey: "s3", Owner: "heidi"}))
	// Revoke one of grace's — it must still appear in the list, marked Disabled.
	if err := s.Revoke(ctx, "OIAKGRACE00000000002"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.List(ctx, "grace")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List(grace) returned %d keys, want 2 (including the revoked one)", len(got))
	}
	seen := map[string]bool{}
	for _, m := range got {
		if m.Owner != "grace" {
			t.Fatalf("List(grace) leaked another owner's key: %+v", m)
		}
		seen[m.AccessKeyID] = true
	}
	if !seen["OIAKGRACE00000000001"] || !seen["OIAKGRACE00000000002"] {
		t.Fatalf("List(grace) missing an expected key: %v", seen)
	}

	// Heidi sees only her own; a stranger sees none.
	if h, _ := s.List(ctx, "heidi"); len(h) != 1 {
		t.Fatalf("List(heidi) = %d, want 1", len(h))
	}
	if n, _ := s.List(ctx, "nobody"); len(n) != 0 {
		t.Fatalf("List(nobody) = %d, want 0", len(n))
	}
}

func TestGenerateKeyPair(t *testing.T) {
	id1, sec1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if !strings.HasPrefix(id1, "OIAK") || len(id1) != 20 {
		t.Fatalf("access key ID not AWS-shaped: %q (len %d)", id1, len(id1))
	}
	if len(sec1) != 40 {
		t.Fatalf("secret key length = %d, want 40", len(sec1))
	}
	// Two mints must differ (crypto/rand, not a fixed seed).
	id2, sec2, _ := GenerateKeyPair()
	if id1 == id2 || sec1 == sec2 {
		t.Fatal("GenerateKeyPair produced duplicate material")
	}
	// A freshly minted key must round-trip through the store and be resolvable by SigV4 later.
	s := NewStore(fake.NewSimpleClientset(), "ns")
	if err := s.Put(context.Background(), Key{AccessKeyID: id1, SecretKey: sec1, Owner: "carol"}); err != nil {
		t.Fatalf("Put minted key: %v", err)
	}
	if got, ok := s.Lookup(context.Background(), id1); !ok || got.SecretKey != sec1 {
		t.Fatal("minted key did not round-trip through the store")
	}
}
