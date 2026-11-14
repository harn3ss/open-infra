package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
)

// fakeSerial is a VM's serial port: it prints a login prompt and echoes what it is sent.
type fakeSerial struct {
	r      *io.PipeReader
	w      *io.PipeWriter
	closed chan struct{}
	once   sync.Once
}

func newFakeSerial() *fakeSerial {
	r, w := io.Pipe()
	f := &fakeSerial{r: r, w: w, closed: make(chan struct{})}
	go func() { _, _ = w.Write([]byte("\r\nubuntu login: ")) }()
	return f
}
func (f *fakeSerial) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeSerial) Write(p []byte) (int, error) {
	go func() { _, _ = f.w.Write(append([]byte{}, p...)) }()
	return len(p), nil
}
func (f *fakeSerial) Close() error {
	f.once.Do(func() { close(f.closed); _ = f.w.Close() })
	return nil
}

type gwFixture struct {
	gw      *serialGateway
	addr    string
	access  bool
	busy    bool
	dialled []string
	mu      sync.Mutex
}

func newGWFixture(t *testing.T) *gwFixture {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	f := &gwFixture{access: true}
	f.gw = &serialGateway{keys: newSerialKeys(), hostKey: hk,
		enabled: func(context.Context, string) (bool, error) { return f.access, nil },
		acquire: func(context.Context, string) (func(), error) {
			if f.busy {
				return nil, serialconsole.ErrSessionLimit
			}
			return func() {}, nil
		},
		dial: func(ns, vm string) (io.ReadWriteCloser, error) {
			f.mu.Lock()
			f.dialled = append(f.dialled, ns+"/"+vm)
			f.mu.Unlock()
			return newFakeSerial(), nil
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = f.gw.serve(l) }()
	f.addr = l.Addr().String()
	return f
}

func (f *gwFixture) connect(user string, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", f.addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.hostKey.PublicKey()), Timeout: 5 * time.Second})
}

// shell opens the session's shell and returns what arrives on stdout and stderr within d, after sending in.
func shell(t *testing.T, c *ssh.Client, in string, d time.Duration) (string, string) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out, errOut safeBuf
	s.Stdout, s.Stderr = &out, &errOut
	stdin, _ := s.StdinPipe()
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	if in != "" {
		_, _ = stdin.Write([]byte(in))
	}
	done := make(chan struct{})
	go func() { _ = s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
	return out.String(), errOut.String()
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// A key pushed for the instance lets "<instance id>.port0" in to that instance's serial console, both ways.
func TestSerialGateway_Session(t *testing.T) {
	f := newGWFixture(t)
	pub, signer := edKey(t)
	f.gw.keys.push(webID, serialKey{key: pub, account: "111122223333", ns: "acct-ns", vm: "s-web"})
	c, err := f.connect(webID+".port0", signer)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	out, _ := shell(t, c, "root\r", 2*time.Second)
	if !strings.Contains(out, "ubuntu login: ") || !strings.Contains(out, "root") {
		t.Errorf("the serial console: %q", out)
	}
	if len(f.dialled) != 1 || f.dialled[0] != "acct-ns/s-web" {
		t.Errorf("dialled %v, want the instance's VM", f.dialled)
	}
}

// Nothing gets in without a key pushed for that instance in the last minute: another user form, another
// instance, another key, or an expired push.
func TestSerialGateway_Authentication(t *testing.T) {
	f := newGWFixture(t)
	pub, signer := edKey(t)
	_, other := edKey(t)
	f.gw.keys.push(webID, serialKey{key: pub, account: "111122223333", ns: "acct-ns", vm: "s-web"})
	for _, c := range []struct {
		user   string
		signer ssh.Signer
	}{
		{"root", signer},
		{webID, signer},
		{webID + ".port1", signer},
		{"i-0fedcba9876543210.port0", signer},
		{webID + ".port0", other},
	} {
		if cl, err := f.connect(c.user, c.signer); err == nil {
			cl.Close()
			t.Errorf("%s got in", c.user)
		}
	}
	f.gw.keys.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if cl, err := f.connect(webID+".port0", signer); err == nil {
		cl.Close()
		t.Error("an expired push got in")
	}
	if len(f.dialled) != 0 {
		t.Errorf("a refused connection reached a console: %v", f.dialled)
	}
}

// Access turned off after the push, or the instance's one session already open, ends the session with
// EC2's message, and no console is reached.
func TestSerialGateway_Refusals(t *testing.T) {
	for _, c := range []struct {
		access, busy bool
		want         string
	}{
		{false, false, "not authorized to use the EC2 Serial Console"},
		{true, true, "1 active serial console session"},
	} {
		f := newGWFixture(t)
		f.access, f.busy = c.access, c.busy
		pub, signer := edKey(t)
		f.gw.keys.push(webID, serialKey{key: pub, account: "111122223333", ns: "acct-ns", vm: "s-web"})
		cl, err := f.connect(webID+".port0", signer)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		_, errOut := shell(t, cl, "", 2*time.Second)
		cl.Close()
		if !strings.Contains(errOut, c.want) || len(f.dialled) != 0 {
			t.Errorf("access=%v busy=%v: stderr %q, dialled %v", c.access, c.busy, errOut, f.dialled)
		}
	}
}
