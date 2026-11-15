package remotedesktop

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/harn3ss/open-infra/console-api/internal/guac"
)

const (
	testNS   = "open-infra-console"
	acctA    = "111122223333"
	acctB    = "444455556666"
	instance = "i-0123456789abcdef0"
)

func conn(acct string) Connection {
	return Connection{Account: acct, InstanceID: instance, Instance: "web", Namespace: "apps", Principal: "arn:aws:iam::" + acct + ":user/alice", Username: "Administrator"}
}

// A connection is active while open and in its account's history once closed; other accounts see neither.
func TestOpenActiveHistory(t *testing.T) {
	s := &Store{CS: fake.NewClientset(), NS: testNS}
	ctx := context.Background()
	h, err := s.Open(ctx, conn(acctA), "console-0")
	if err != nil {
		t.Fatal(err)
	}
	c := h.Connection()
	if !ValidID(c.ConnectionID) || c.Status != StatusActive || c.ExpiresAt.Sub(c.StartedAt) != MaxDuration {
		t.Fatalf("opened: %+v", c)
	}
	if a, _ := s.Active(ctx, acctA); len(a) != 1 || a[0].ConnectionID != c.ConnectionID {
		t.Fatalf("active: %+v", a)
	}
	if a, _ := s.Active(ctx, acctB); len(a) != 0 {
		t.Fatalf("another account's active: %+v", a)
	}
	h.Close(StatusDisconnected, "the user disconnected")
	if a, _ := s.Active(ctx, acctA); len(a) != 0 {
		t.Fatalf("active after close: %+v", a)
	}
	hist, err := s.History(ctx, acctA)
	if err != nil || len(hist) != 1 || hist[0].Status != StatusDisconnected || hist[0].EndedAt == nil || hist[0].Username != "Administrator" {
		t.Fatalf("history: %+v %v", hist, err)
	}
	if b, _ := s.History(ctx, acctB); len(b) != 0 {
		t.Fatalf("another account's history: %+v", b)
	}
}

// An account has at most MaxConnections active; a lapsed one (its replica died) does not count.
func TestQuota(t *testing.T) {
	now := time.Now()
	s := &Store{CS: fake.NewClientset(), NS: testNS, Now: func() time.Time { return now }}
	ctx := context.Background()
	for i := 0; i < MaxConnections; i++ {
		if _, err := s.Open(ctx, conn(acctA), "console-0"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Open(ctx, conn(acctA), "console-0"); !errors.Is(err, ErrQuota) {
		t.Fatalf("over the quota: %v", err)
	}
	if _, err := s.Open(ctx, conn(acctB), "console-0"); err != nil {
		t.Fatalf("another account: %v", err)
	}
	now = now.Add(time.Minute) // nobody renewed: the leases lapsed
	if _, err := s.Open(ctx, conn(acctA), "console-1"); err != nil {
		t.Fatalf("after the others lapsed: %v", err)
	}
}

// CancelConnection reaches the replica running the connection through its record; another account's
// connection is not found.
func TestCancel(t *testing.T) {
	s := &Store{CS: fake.NewClientset(), NS: testNS}
	ctx := context.Background()
	h, err := s.Open(ctx, conn(acctA), "console-0")
	if err != nil {
		t.Fatal(err)
	}
	id := h.Connection().ConnectionID
	if err := s.Cancel(ctx, acctB, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account's cancel: %v", err)
	}
	if err := s.Cancel(ctx, acctA, "not-an-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a bad id: %v", err)
	}
	if err := s.Cancel(ctx, acctA, id); err != nil {
		t.Fatal(err)
	}
	l, _ := s.CS.CoordinationV1().Leases(testNS).Get(ctx, leaseName(id), metav1.GetOptions{})
	if l.Annotations[annCancel] != "true" {
		t.Fatalf("cancel not recorded: %v", l.Annotations)
	}
	h.stop()
	go h.renew(ctx)
	select {
	case st := <-h.Ended():
		if st != StatusTerminated {
			t.Fatalf("ended with %q", st)
		}
	case <-time.After(renewEvery + 5*time.Second):
		t.Fatal("the holder did not see the cancel")
	}
}

// ── the relay ───────────────────────────────────────────────────────────────

type fakeBrowser struct {
	in     chan string
	mu     sync.Mutex
	out    []string
	closed chan struct{}
	once   sync.Once
}

func newBrowser() *fakeBrowser {
	return &fakeBrowser{in: make(chan string, 16), closed: make(chan struct{})}
}

func (b *fakeBrowser) Send(m string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.out = append(b.out, m)
	return nil
}

func (b *fakeBrowser) Receive() (string, error) {
	select {
	case m := <-b.in:
		return m, nil
	case <-b.closed:
		return "", io.EOF
	}
}

func (b *fakeBrowser) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func (b *fakeBrowser) sent() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.out, "")
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func relayFixture(t *testing.T) (*Session, net.Conn, *Handle) {
	t.Helper()
	s := &Store{CS: fake.NewClientset(), NS: testNS}
	h, err := s.Open(context.Background(), conn(acctA), "console-0")
	if err != nil {
		t.Fatal(err)
	}
	ours, guacd := net.Pipe()
	return &Session{guacd: ours, rd: guac.NewReader(ours), tunnel: nopCloser{}}, guacd, h
}

// The browser gets the connection id and its end first, guacd's instructions as they come, its pings
// echoed; input and display pass to guacd, anything else (file transfer) does not; Renew session moves the
// end.
func TestRelay(t *testing.T) {
	sess, guacd, h := relayFixture(t)
	b := newBrowser()
	result := make(chan [2]string, 1)
	go func() {
		st, why := sess.Relay(context.Background(), b, h, RelayOptions{Tick: 10 * time.Millisecond})
		result <- [2]string{st, why}
	}()
	gr := guac.NewReader(guacd)
	b.in <- guac.New("", "ping", "1").String() + guac.New("file", "1", "x", "y").String() + guac.New("mouse", "1", "2", "0").String()
	got, _, err := gr.Read()
	if err != nil || got.Opcode != "mouse" {
		t.Fatalf("guacd got %+v %v (the file instruction must not pass)", got, err)
	}
	io.WriteString(guacd, guac.New("sync", "5").String())
	before := h.Connection().ExpiresAt
	b.in <- guac.New("", "renew").String()
	time.Sleep(50 * time.Millisecond)
	out := b.sent()
	if !strings.HasPrefix(out, guac.New("", h.Connection().ConnectionID).String()) {
		t.Fatalf("the connection id first: %q", out)
	}
	for _, want := range []string{"0.,4.ping,1.1;", "4.sync,1.5;", "0.,7.expires,"} {
		if !strings.Contains(out, want) {
			t.Errorf("browser missing %q in %q", want, out)
		}
	}
	if strings.Count(out, "0.,7.expires,") != 2 {
		t.Errorf("renew did not answer a new end: %q", out)
	}
	_ = before
	b.in <- guac.New("disconnect").String()
	if d, _, _ := gr.Read(); d.Opcode != "disconnect" {
		t.Errorf("guacd got %+v, want disconnect", d)
	}
	go io.Copy(io.Discard, guacd)
	r := <-result
	if r[0] != StatusDisconnected {
		t.Fatalf("ended %v", r)
	}
}

// No input for the idle timeout ends the connection, telling the browser why.
func TestRelayIdle(t *testing.T) {
	sess, guacd, h := relayFixture(t)
	go io.Copy(io.Discard, guacd)
	b := newBrowser()
	st, _ := sess.Relay(context.Background(), b, h, RelayOptions{Tick: 5 * time.Millisecond, IdleTimeout: 20 * time.Millisecond})
	if st != StatusIdleTimeout || !strings.Contains(b.sent(), "idle for more than 10 minutes") {
		t.Fatalf("%s %q", st, b.sent())
	}
}

// Past its end the connection is over (Time Limit Exceeded).
func TestRelayTimeLimit(t *testing.T) {
	sess, guacd, h := relayFixture(t)
	go io.Copy(io.Discard, guacd)
	b := newBrowser()
	later := time.Now().Add(MaxDuration + time.Minute)
	st, _ := sess.Relay(context.Background(), b, h, RelayOptions{Tick: 5 * time.Millisecond, Now: func() time.Time { return later }})
	if st != StatusTimeLimitExceeded || !strings.Contains(b.sent(), "maximum duration of 60 minutes") {
		t.Fatalf("%s %q", st, b.sent())
	}
}

// guacd's error (a refused sign-in) reaches the browser and is the connection's reason.
func TestRelayGuacdError(t *testing.T) {
	sess, guacd, h := relayFixture(t)
	b := newBrowser()
	go func() {
		io.WriteString(guacd, guac.Error("Authentication failure", guac.StatusClientUnauthorized).String())
		guacd.Close()
	}()
	st, why := sess.Relay(context.Background(), b, h, RelayOptions{Tick: time.Second})
	if st != StatusFailed || why != "Authentication failure" || !strings.Contains(b.sent(), "Authentication failure") {
		t.Fatalf("%s %q %q", st, why, b.sent())
	}
}

// ── the gateway ─────────────────────────────────────────────────────────────

// Connect hands guacd this replica's tunnel address; guacd's connection back (and only guacd's) is
// piped to the instance.
func TestConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	vmSide, platformSide := net.Pipe()
	params := make(chan []string, 1)
	go func() { // a guacd: handshake, then connect to the host:port it was given and say hello
		c, err := ln.Accept()
		if err != nil {
			return
		}
		rd := guac.NewReader(c)
		rd.Read() // select
		io.WriteString(c, guac.New("args", "VERSION_1_5_0", "hostname", "port", "username", "password", "security").String())
		for {
			i, _, err := rd.Read()
			if err != nil {
				return
			}
			if i.Opcode == "connect" {
				params <- i.Args
				rdp, err := net.Dial("tcp", net.JoinHostPort(i.Args[1], i.Args[2]))
				if err == nil {
					io.WriteString(rdp, "hello")
				}
				io.WriteString(c, guac.New("ready", "$x").String())
				return
			}
		}
	}()
	g := &Gateway{
		Guacd:    func(context.Context) ([]string, error) { return []string{ln.Addr().String()}, nil },
		DialVM:   func(context.Context, string, string, int) (io.ReadWriteCloser, error) { return platformSide, nil },
		ListenIP: "127.0.0.1",
	}
	sess, err := g.Connect(context.Background(), "apps", "web", Credentials{Username: "Administrator", Password: "pw"}, guac.Size{Width: 800, Height: 600}, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	defer sess.close()
	p := <-params
	if p[3] != "Administrator" || p[4] != "pw" || p[5] != "any" {
		t.Fatalf("connect values %v", p)
	}
	buf := make([]byte, 5)
	vmSide.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(vmSide, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("the instance got %q %v", buf, err)
	}
}

// A connection to the tunnel from anywhere but its guacd is refused.
func TestTunnelRefusesOthers(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	vm, other := net.Pipe()
	defer other.Close()
	tun := &tunnel{ln: ln, vm: vm}
	go tun.serve("192.0.2.1", 2*time.Second, nil)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the tunnel accepted a stranger")
	}
	tun.Close()
}
