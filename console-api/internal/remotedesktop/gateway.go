package remotedesktop

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/guac"
)

// RDPPort is the port Fleet Manager connects to: Windows' Remote Desktop service on its default port.
const RDPPort = 3389

// Credentials are the Windows account a connection signs in as (Fleet Manager's User credentials).
type Credentials struct {
	Username string
	Password string
	Domain   string
}

// Gateway reaches guacd and the instances.
type Gateway struct {
	// Guacd answers the addresses (ip:port) of guacd's replicas.
	Guacd func(ctx context.Context) ([]string, error)
	// TLS is the client configuration for guacd's TLS port; nil connects in clear text (tests).
	TLS func() (*tls.Config, error)
	// DialVM opens a stream to a port of VM ns/name, through the platform rather than the instance's
	// network (KubeVirt's port-forward), so the instance's security groups need not allow it.
	DialVM func(ctx context.Context, ns, name string, port int) (io.ReadWriteCloser, error)
	// ListenIP is this replica's address, where guacd connects back for the instance's RDP stream;
	// PortMin..PortMax the ports it may listen on.
	ListenIP         string
	PortMin, PortMax int
	Logger           *slog.Logger
}

// Errors before a connection starts.
var (
	ErrUnreachable = errors.New("the instance's Remote Desktop service could not be reached")
	ErrGateway     = errors.New("the remote desktop gateway could not be reached")
)

// Session is a started RDP connection through guacd.
type Session struct {
	guacd  net.Conn
	rd     *guac.Reader
	tunnel io.Closer
	once   sync.Once
}

func (s *Session) close() {
	s.once.Do(func() {
		_, _ = io.WriteString(s.guacd, guac.New("disconnect").String())
		_ = s.guacd.Close()
		_ = s.tunnel.Close()
	})
}

// Connect starts an RDP connection to VM ns/name as cr, with the browser's display size and time zone.
func (g *Gateway) Connect(ctx context.Context, ns, name string, cr Credentials, size guac.Size, timezone string) (*Session, error) {
	vm, err := g.DialVM(ctx, ns, name, RDPPort)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	ln, port, err := g.listen()
	if err != nil {
		_ = vm.Close()
		return nil, fmt.Errorf("%w: %v", ErrGateway, err)
	}
	gc, err := g.dialGuacd(ctx)
	if err != nil {
		_ = ln.Close()
		_ = vm.Close()
		return nil, fmt.Errorf("%w: %v", ErrGateway, err)
	}
	peer, _, _ := net.SplitHostPort(gc.RemoteAddr().String())
	tun := &tunnel{ln: ln, vm: vm}
	go tun.serve(peer, 30*time.Second, g.Logger)

	params := map[string]string{
		"hostname": g.ListenIP, "port": strconv.Itoa(port),
		"username": cr.Username, "password": cr.Password, "domain": cr.Domain,
		// Negotiate what the server offers (Network Level Authentication on Windows Server); the
		// instance's certificate is its own self-signed one, and the stream reaches it inside the platform.
		"security": "any", "ignore-cert": "true",
		// Adapt Automatically: the session follows the browser's size.
		"resize-method": "display-update",
		// Remote Desktop takes English (US) input, as Fleet Manager's does.
		"server-layout": "en-us-qwerty",
		"disable-audio": "true",
	}
	_ = gc.SetDeadline(time.Now().Add(30 * time.Second))
	rd := guac.NewReader(gc)
	if _, err := guac.Handshake(gc, rd, "rdp", params, size, timezone); err != nil {
		_ = gc.Close()
		_ = tun.Close()
		return nil, fmt.Errorf("%w: %v", ErrGateway, err)
	}
	_ = gc.SetDeadline(time.Time{})
	return &Session{guacd: gc, rd: rd, tunnel: tun}, nil
}

func (g *Gateway) listen() (net.Listener, int, error) {
	lo, hi := g.PortMin, g.PortMax
	if lo <= 0 || hi < lo {
		ln, err := net.Listen("tcp", net.JoinHostPort(g.ListenIP, "0"))
		if err != nil {
			return nil, 0, err
		}
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	}
	var last error
	for i := 0; i < 32; i++ {
		p := lo + rand.IntN(hi-lo+1)
		ln, err := net.Listen("tcp", net.JoinHostPort(g.ListenIP, strconv.Itoa(p)))
		if err == nil {
			return ln, p, nil
		}
		last = err
	}
	return nil, 0, last
}

func (g *Gateway) dialGuacd(ctx context.Context) (net.Conn, error) {
	addrs, err := g.Guacd(ctx)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no remote desktop gateway is ready")
	}
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	d := net.Dialer{Timeout: 5 * time.Second}
	var last error
	for _, a := range addrs {
		var c net.Conn
		if g.TLS != nil {
			cfg, err := g.TLS()
			if err != nil {
				return nil, err
			}
			c, err = (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(ctx, "tcp", a)
			if err != nil {
				last = err
				continue
			}
		} else if c, err = d.DialContext(ctx, "tcp", a); err != nil {
			last = err
			continue
		}
		return c, nil
	}
	return nil, last
}

// tunnel carries one RDP stream: it accepts guacd's connection back (from the guacd replica this
// connection uses, once, within the deadline) and pipes it to the instance.
type tunnel struct {
	ln   net.Listener
	vm   io.ReadWriteCloser
	once sync.Once
	mu   sync.Mutex
	conn net.Conn
}

func (t *tunnel) serve(peer string, within time.Duration, logger *slog.Logger) {
	if tl, ok := t.ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(within))
	}
	for {
		c, err := t.ln.Accept()
		if err != nil {
			_ = t.Close()
			return
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if host != peer {
			if logger != nil {
				logger.Warn("remote desktop tunnel: refused a connection from an address other than its gateway", "from", host)
			}
			_ = c.Close()
			continue
		}
		_ = t.ln.Close()
		t.mu.Lock()
		t.conn = c
		t.mu.Unlock()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(t.vm, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, t.vm); done <- struct{}{} }()
		<-done
		_ = t.Close()
		return
	}
}

func (t *tunnel) Close() error {
	t.once.Do(func() {
		_ = t.ln.Close()
		_ = t.vm.Close()
		t.mu.Lock()
		if t.conn != nil {
			_ = t.conn.Close()
		}
		t.mu.Unlock()
	})
	return nil
}

// Browser is the browser's end of a connection: whole Guacamole instructions, as text messages.
type Browser interface {
	Send(msg string) error
	Receive() (string, error)
	Close() error
}

// clientOpcodes are the instructions a browser may send guacd: display, input, clipboard and the
// stream acknowledgements they need. File transfer and the rest are not passed.
var clientOpcodes = map[string]bool{
	"ack": true, "blob": true, "clipboard": true, "disconnect": true, "end": true, "key": true,
	"mouse": true, "nop": true, "size": true, "sync": true, "touch": true,
}

// inputOpcodes are the user's input, which keeps a connection from idling out.
var inputOpcodes = map[string]bool{"key": true, "mouse": true, "touch": true}

// RelayOptions are a relay's clock and limits (zero: AWS's, checked every 5 seconds).
type RelayOptions struct {
	Now         func() time.Time
	Tick        time.Duration
	IdleTimeout time.Duration
}

// The tunnel's own instructions to the browser and from it (the Guacamole tunnel's internal opcode):
// the connection id (the tunnel's UUID), when the connection ends ("expires", Unix milliseconds), and
// the browser's "ping" (echoed) and "renew" (Renew session).
const (
	internalExpires = "expires"
	internalPing    = "ping"
	internalRenew   = "renew"
)

// Relay carries the connection between the browser and guacd until it ends, enforcing its maximum
// duration (renewable) and idle timeout and ending it when h's record says so. It answers the status and
// reason the connection ended with.
func (s *Session) Relay(ctx context.Context, b Browser, h *Handle, o RelayOptions) (status, reason string) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	tick, idle := o.Tick, o.IdleTimeout
	if tick <= 0 {
		tick = 5 * time.Second
	}
	if idle <= 0 {
		idle = IdleTimeout
	}
	defer s.close()
	defer b.Close()

	var sendMu sync.Mutex
	send := func(m string) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return b.Send(m)
	}
	var mu sync.Mutex
	lastInput := now()
	expires := h.Connection().ExpiresAt
	expiresMsg := func(t time.Time) string {
		return guac.New(guac.Internal, internalExpires, strconv.FormatInt(t.UnixMilli(), 10)).String()
	}
	if send(guac.New(guac.Internal, h.Connection().ConnectionID).String()) != nil || send(expiresMsg(expires)) != nil {
		return StatusDisconnected, "the browser closed the connection"
	}

	type end struct{ status, reason string }
	done := make(chan end, 2)

	// guacd → browser, whole instructions, batched while more are already read.
	go func() {
		var buf strings.Builder
		var lastErr string
		for {
			in, raw, err := s.rd.Read()
			if err != nil {
				if buf.Len() > 0 {
					_ = send(buf.String())
				}
				if lastErr != "" {
					done <- end{StatusFailed, lastErr}
				} else {
					done <- end{StatusDisconnected, "the remote session ended"}
				}
				return
			}
			if in.Opcode == "error" && len(in.Args) > 0 {
				lastErr = in.Args[0]
			}
			buf.WriteString(raw)
			if s.rd.Buffered() == 0 || buf.Len() >= 32<<10 {
				if send(buf.String()) != nil {
					done <- end{StatusDisconnected, "the browser closed the connection"}
					return
				}
				buf.Reset()
			}
		}
	}()

	// browser → guacd: the tunnel's own instructions answered here, the rest passed if allowed.
	go func() {
		for {
			msg, err := b.Receive()
			if err != nil {
				done <- end{StatusDisconnected, "the browser closed the connection"}
				return
			}
			ins, err := guac.ParseAll(msg)
			if err != nil {
				done <- end{StatusDisconnected, "the browser sent a malformed instruction"}
				return
			}
			var out strings.Builder
			for _, in := range ins {
				if in.Opcode == guac.Internal {
					switch {
					case len(in.Args) > 0 && in.Args[0] == internalPing:
						_ = send(in.String())
					case len(in.Args) > 0 && in.Args[0] == internalRenew:
						exp := h.Renew()
						mu.Lock()
						expires = exp
						mu.Unlock()
						_ = send(expiresMsg(exp))
					}
					continue
				}
				if !clientOpcodes[in.Opcode] {
					continue
				}
				if inputOpcodes[in.Opcode] {
					mu.Lock()
					lastInput = now()
					mu.Unlock()
				}
				out.WriteString(in.String())
				if in.Opcode == "disconnect" {
					_, _ = io.WriteString(s.guacd, out.String())
					done <- end{StatusDisconnected, "the user disconnected"}
					return
				}
			}
			if out.Len() > 0 {
				if _, err := io.WriteString(s.guacd, out.String()); err != nil {
					done <- end{StatusDisconnected, "the remote session ended"}
					return
				}
			}
		}
	}()

	t := time.NewTicker(tick)
	defer t.Stop()
	fail := func(msg string, code int) { _ = send(guac.Error(msg, code).String()) }
	for {
		select {
		case e := <-done:
			return e.status, e.reason
		case st := <-h.Ended():
			fail("This Remote Desktop connection was ended.", guac.StatusSessionClosed)
			return st, "the connection was cancelled"
		case <-ctx.Done():
			return StatusDisconnected, "the console stopped"
		case <-t.C:
			mu.Lock()
			exp, last := expires, lastInput
			mu.Unlock()
			n := now()
			switch {
			case !exp.IsZero() && n.After(exp):
				fail("The Remote Desktop connection reached its maximum duration of 60 minutes.", guac.StatusSessionTimeout)
				return StatusTimeLimitExceeded, "the connection reached its maximum duration"
			case n.Sub(last) > idle:
				fail("The Remote Desktop connection was idle for more than 10 minutes.", guac.StatusClientTimeout)
				return StatusIdleTimeout, "the connection was idle"
			}
		}
	}
}
