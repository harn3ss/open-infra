package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image/png"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	storeNS = "open-infra-aws-shim"
	acct    = "000000000000"
	usersNS = "open-infra-console"
)

// RFC 6238 Appendix B's SHA-1 vectors, as six digits (the low six of the eight the RFC lists).
func TestCode_RFC6238Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		if got := Code(seed, StepAt(time.Unix(v.unix, 0))); got != v.want {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestSeedAndURI(t *testing.T) {
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != SeedBytes || len(Base32(seed)) != 64 {
		t.Fatalf("seed %d bytes, base32 %d chars: want AWS's 64-character seed", len(seed), len(Base32(seed)))
	}
	uri := OTPAuthURI("alice-phone", "123456789012", seed)
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/alice-phone@123456789012" {
		t.Fatalf("uri %q: want otpauth://totp/<device>@<account>", uri)
	}
	if u.Query().Get("secret") != Base32(seed) || u.Query().Get("issuer") != Issuer {
		t.Fatalf("uri %q lacks the secret or issuer", uri)
	}
	img, err := QRCodePNG(uri)
	if err != nil {
		t.Fatal(err)
	}
	p, err := png.Decode(bytes.NewReader(img))
	if err != nil || p.Bounds().Dx() < 100 {
		t.Fatalf("QR code is not a usable PNG: %v %v", err, p)
	}
}

func TestParseSerial(t *testing.T) {
	for _, c := range []struct {
		serial, acct, path, name string
		ok                       bool
	}{
		{"arn:aws:iam::123456789012:mfa/alice", "123456789012", "/", "alice", true},
		{"arn:aws:iam::123456789012:mfa/division/abc/alice@x.y", "123456789012", "/division/abc/", "alice@x.y", true},
		{"arn:aws:iam::123456789012:user/alice", "", "", "", false},
		{"GAHT12345678", "", "", "", false},
		{"arn:aws:iam::123456789012:mfa/", "", "", "", false},
		{"arn:aws:iam:us-east-1:123456789012:mfa/a", "", "", "", false},
	} {
		a, p, n, ok := ParseSerial(c.serial)
		if ok != c.ok || a != c.acct || p != c.path || n != c.name {
			t.Errorf("%s: %q %q %q %v", c.serial, a, p, n, ok)
		}
		if ok && SerialNumber(a, p, n) != c.serial {
			t.Errorf("%s does not round-trip: %s", c.serial, SerialNumber(a, p, n))
		}
	}
	if !ValidName("Alice_Phone+1=,.@-") || ValidName("") || ValidName("a b") || ValidPath("x/") || !ValidPath("/a/b/") {
		t.Error("name/path validation is not AWS's")
	}
}

func TestSecretName(t *testing.T) {
	a, b := SecretName(acct, "Alice"), SecretName("111111111111", "alice")
	if a == b || !strings.HasPrefix(a, SecretPrefix+"alice-") || a != SecretName(acct, "ALICE") {
		t.Fatalf("names must be per account and case-insensitive: %q %q", a, b)
	}
	if n := SecretName(acct, strings.Repeat("Z@", 120)); len(n) > 63 {
		t.Fatalf("too long for a Secret: %d", len(n))
	}
}

// clock is a settable test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore() (Store, *clock, *fake.Clientset) {
	cs := fake.NewSimpleClientset()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	return Store{CS: cs, NS: storeNS, Now: c.now}, c, cs
}

func codesAt(seed []byte, t time.Time) (string, string) {
	s := StepAt(t)
	return Code(seed, s), Code(seed, s+1)
}

func TestDeviceLifecycle(t *testing.T) {
	ctx := context.Background()
	s, clk, cs := newStore()

	d, seed, err := s.Create(ctx, acct, "alice-phone", "/", []Tag{{Key: "team", Value: "a"}})
	if err != nil || len(seed) != SeedBytes || d.Assigned() {
		t.Fatalf("create: %v %+v", err, d)
	}
	if _, _, err := s.Create(ctx, acct, "ALICE-PHONE", "/", nil); !errors.Is(err, ErrExists) {
		t.Fatalf("a name differing only in case must conflict: %v", err)
	}
	if _, _, err := s.Create(ctx, "111111111111", "alice-phone", "/", nil); err != nil {
		t.Fatalf("another account may use the same name: %v", err)
	}
	sec, _ := cs.CoreV1().Secrets(storeNS).Get(ctx, SecretName(acct, "alice-phone"), metav1.GetOptions{})
	if !bytes.Equal(sec.Data[seedKey], seed) || sec.Labels[LabelDevice] != "true" || sec.Labels[LabelAccount] != acct {
		t.Fatalf("the device Secret is not shaped as admission expects: %+v", sec.ObjectMeta)
	}

	// Enable: two consecutive codes; a wrong pair, or one that is not consecutive, is refused.
	c1, c2 := codesAt(seed, clk.t.Add(-30*time.Second))
	if err := s.Enable(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", c1, c1); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("two equal codes must not enable: %v", err)
	}
	if err := s.Enable(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", "000000", "000001"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong codes must not enable: %v", err)
	}
	if err := s.Enable(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", c1, c2); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := s.Enable(ctx, acct, "alice-phone", usersNS, "bob", "uid-2", c1, c2); !errors.Is(err, ErrAssigned) {
		t.Fatalf("an assigned device cannot be enabled again: %v", err)
	}
	mine, _ := s.ForUser(ctx, acct, usersNS, "alice", "uid-1")
	if len(mine) != 1 || mine[0].EnableDate.IsZero() || mine[0].Tags[0].Key != "team" {
		t.Fatalf("alice's devices: %+v", mine)
	}
	if other, _ := s.ForUser(ctx, acct, usersNS, "alice", "uid-recreated"); len(other) != 0 {
		t.Fatal("a recreated user (another UID) must not inherit the device")
	}

	// The codes Enable consumed cannot be replayed; the next one is accepted once.
	if err := s.Verify(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", c2); !errors.Is(err, ErrReplayed) {
		t.Fatalf("the enable code must not be accepted again: %v", err)
	}
	clk.t = clk.t.Add(30 * time.Second)
	next := Code(seed, StepAt(clk.t))
	if err := s.Verify(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", next); err != nil {
		t.Fatalf("a fresh code must verify: %v", err)
	}
	if err := s.Verify(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", next); !errors.Is(err, ErrReplayed) {
		t.Fatalf("a replayed code must be refused: %v", err)
	}
	if err := s.Verify(ctx, acct, "alice-phone", usersNS, "bob", "uid-2", next); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another user's device is not found for bob: %v", err)
	}
	// One step of skew either way.
	clk.t = clk.t.Add(60 * time.Second)
	if err := s.Verify(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", Code(seed, StepAt(clk.t)+1)); err != nil {
		t.Fatalf("a code one step ahead must verify: %v", err)
	}
	clk.t = clk.t.Add(5 * time.Minute)
	if err := s.Verify(ctx, acct, "alice-phone", usersNS, "alice", "uid-1", Code(seed, StepAt(clk.t)-3)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("a code three steps old must be refused: %v", err)
	}

	// Delete refuses an assigned device; Deactivate unassigns it (only for its user), then Delete removes it.
	if err := s.Delete(ctx, acct, "alice-phone"); !errors.Is(err, ErrAssigned) {
		t.Fatalf("delete of an assigned device: %v", err)
	}
	if err := s.Deactivate(ctx, acct, "alice-phone", usersNS, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob cannot deactivate alice's device: %v", err)
	}
	if err := s.Deactivate(ctx, acct, "alice-phone", usersNS, "alice"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Get(ctx, acct, "alice-phone"); d.Assigned() {
		t.Fatal("deactivated, the device must be unassigned")
	}
	if err := s.Delete(ctx, acct, "alice-phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, acct, "alice-phone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	all, _ := s.List(ctx, "111111111111")
	if len(all) != 1 {
		t.Fatalf("the other account's device is its own: %+v", all)
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	ctx := context.Background()
	s, clk, _ := newStore()
	_, seed, _ := s.Create(ctx, acct, "dev", "/", nil)
	c1, c2 := codesAt(seed, clk.t.Add(-30*time.Second))
	if err := s.Enable(ctx, acct, "dev", usersNS, "alice", "u", c1, c2); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Minute)
	for i := 0; i < MaxFailures; i++ {
		if err := s.Verify(ctx, acct, "dev", usersNS, "alice", "u", "999999"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	good := Code(seed, StepAt(clk.t))
	if err := s.Verify(ctx, acct, "dev", usersNS, "alice", "u", good); !errors.Is(err, ErrLocked) {
		t.Fatalf("after %d wrong codes the device must be locked, even for a right one: %v", MaxFailures, err)
	}
	clk.t = clk.t.Add(Lockout + time.Second)
	if err := s.Verify(ctx, acct, "dev", usersNS, "alice", "u", Code(seed, StepAt(clk.t))); err != nil {
		t.Fatalf("the lockout ends: %v", err)
	}
}

func TestResyncRecordsDrift(t *testing.T) {
	ctx := context.Background()
	s, clk, cs := newStore()
	_, seed, _ := s.Create(ctx, acct, "dev", "/", nil)
	c1, c2 := codesAt(seed, clk.t.Add(-30*time.Second))
	if err := s.Enable(ctx, acct, "dev", usersNS, "alice", "u", c1, c2); err != nil {
		t.Fatal(err)
	}
	// The device's clock runs five minutes ahead: its codes are refused until it is resynced.
	clk.t = clk.t.Add(10 * time.Minute)
	ahead := clk.t.Add(5 * time.Minute)
	if err := s.Verify(ctx, acct, "dev", usersNS, "alice", "u", Code(seed, StepAt(ahead))); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("a drifted code must be refused: %v", err)
	}
	r1, r2 := codesAt(seed, ahead)
	if err := s.Resync(ctx, acct, "dev", usersNS, "alice", "u", r1, r2); err != nil {
		t.Fatalf("resync: %v", err)
	}
	sec, _ := cs.CoreV1().Secrets(storeNS).Get(ctx, SecretName(acct, "dev"), metav1.GetOptions{})
	var st state
	_ = json.Unmarshal(sec.Data[stateKey], &st)
	if st.Drift != 11 { // five minutes and one step: the device now shows its second code's step
		t.Fatalf("drift %d steps, want 11", st.Drift)
	}
	clk.t = clk.t.Add(time.Minute)
	if err := s.Verify(ctx, acct, "dev", usersNS, "alice", "u", Code(seed, StepAt(clk.t.Add(5*time.Minute)))); err != nil {
		t.Fatalf("after the resync the drifted device's code verifies: %v", err)
	}
}

func TestVerifyAnyAndLimits(t *testing.T) {
	ctx := context.Background()
	s, clk, _ := newStore()
	seeds := map[string][]byte{}
	for _, n := range []string{"a", "b"} {
		_, seed, _ := s.Create(ctx, acct, n, "/", nil)
		seeds[n] = seed
		c1, c2 := codesAt(seed, clk.t.Add(-30*time.Second))
		if err := s.Enable(ctx, acct, n, usersNS, "alice", "u", c1, c2); err != nil {
			t.Fatal(err)
		}
	}
	clk.t = clk.t.Add(time.Minute)
	if err := s.VerifyAny(ctx, acct, usersNS, "alice", "u", Code(seeds["b"], StepAt(clk.t))); err != nil {
		t.Fatalf("any of the user's devices signs in: %v", err)
	}
	if err := s.VerifyAny(ctx, acct, usersNS, "bob", "u2", "123456"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a user with no device: %v", err)
	}
	// A user holds at most eight.
	for i := 0; i < MaxDevicesPerUser; i++ {
		n := "x" + string(rune('a'+i))
		_, seed, _ := s.Create(ctx, acct, n, "/", nil)
		c1, c2 := codesAt(seed, clk.t.Add(-30*time.Second))
		err := s.Enable(ctx, acct, n, usersNS, "carol", "c", c1, c2)
		if i < MaxDevicesPerUser && err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	_, seed, _ := s.Create(ctx, acct, "ninth", "/", nil)
	c1, c2 := codesAt(seed, clk.t.Add(-30*time.Second))
	if err := s.Enable(ctx, acct, "ninth", usersNS, "carol", "c", c1, c2); !errors.Is(err, ErrLimit) {
		t.Fatalf("a ninth device: %v", err)
	}
}

// A Secret of a device's name that is not that device (no label, another account) is never read as one.
func TestForgedSecretIsNoDevice(t *testing.T) {
	ctx := context.Background()
	s, _, cs := newStore()
	_, _ = cs.CoreV1().Secrets(storeNS).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: SecretName(acct, "dev"), Namespace: storeNS,
		Labels:      map[string]string{LabelDevice: "true", LabelAccount: "111111111111", LabelUser: "alice", LabelUserNamespace: usersNS},
		Annotations: map[string]string{AnnName: "dev"},
	}, Data: map[string][]byte{seedKey: []byte("x")}}, metav1.CreateOptions{})
	if _, err := s.Get(ctx, acct, "dev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a Secret labelled for another account is not this account's device: %v", err)
	}
	if devs, _ := s.ForUser(ctx, acct, usersNS, "alice", ""); len(devs) != 0 {
		t.Fatalf("it is no one's device here: %+v", devs)
	}
}
