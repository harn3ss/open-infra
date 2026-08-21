package pool

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend returns a *Backend wrapping one end of a pipe (never actually read/written here).
func fakeBackend() *Backend {
	c, _ := net.Pipe()
	return &Backend{Conn: c, Fresh: true}
}

// closeSpyConn records whether Close was called, so a test can assert Discard actually closes the
// backend socket (a pinned-discard that frees the token but leaks the FD is still a leak).
type closeSpyConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeSpyConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func spyBackend() (*Backend, *closeSpyConn) {
	a, _ := net.Pipe()
	cc := &closeSpyConn{Conn: a}
	return &Backend{Conn: cc, Fresh: true}, cc
}

func TestCapBoundsOpenConnections(t *testing.T) {
	p := New(2)
	const key = "k"
	// Two cold acquires exhaust the cap.
	_, warm1, ok1 := p.Acquire(key, 50*time.Millisecond)
	_, warm2, ok2 := p.Acquire(key, 50*time.Millisecond)
	if !ok1 || !ok2 || warm1 || warm2 {
		t.Fatalf("first two acquires should be cold+ok, got ok=%v,%v warm=%v,%v", ok1, ok2, warm1, warm2)
	}
	// Third must block and time out — the cap is enforced.
	start := time.Now()
	_, _, ok3 := p.Acquire(key, 80*time.Millisecond)
	if ok3 {
		t.Fatal("third acquire should have timed out at the cap")
	}
	if time.Since(start) < 70*time.Millisecond {
		t.Fatal("third acquire returned too fast — it did not block on the cap")
	}
}

func TestDiscardFreesSlot(t *testing.T) {
	p := New(1)
	const key = "k"
	_, _, ok := p.Acquire(key, 50*time.Millisecond)
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	if _, _, ok := p.Acquire(key, 40*time.Millisecond); ok {
		t.Fatal("second acquire should block at cap 1")
	}
	p.Discard(key, nil) // free the reserved slot
	if _, _, ok := p.Acquire(key, 50*time.Millisecond); !ok {
		t.Fatal("after discard a slot should be free")
	}
}

func TestReturnEnablesWarmReuse(t *testing.T) {
	p := New(2)
	const key = "k"
	p.Acquire(key, time.Second) // cold, reserves a slot
	be := fakeBackend()
	p.Return(key, be) // return it clean
	got, warm, ok := p.Acquire(key, time.Second)
	if !ok || !warm {
		t.Fatalf("acquire after Return should be warm, got warm=%v ok=%v", warm, ok)
	}
	if got != be {
		t.Fatal("warm acquire should hand back the returned backend")
	}
	if got.Fresh {
		t.Fatal("a returned+reused backend must not be marked Fresh")
	}
}

// ── Fault axis (#4): prove the semaphore ceiling holds under failure rather than leaking tokens. ──
// These are the cross-session-leak guarantees a pooler must never violate: a pinned session that
// discards, a client that vanishes, a stampede, and repeated failure cycles must each leave the cap
// exactly intact — never permanently consuming a slot (leak) and never inflating it above the cap
// (over-issue, which would exhaust the database's real connection slots).

// Pinned-discard: when a pinned (or client-abandoned) session ends, the proxy Discards its backend.
// That must free the token AND close the socket — else the pinned slot is gone forever.
func TestPinnedDiscardFreesTokenAndClosesConn(t *testing.T) {
	p := New(1)
	const key = "k"
	if _, warm, ok := p.Acquire(key, 50*time.Millisecond); !ok || warm {
		t.Fatalf("first acquire should be cold+ok, got warm=%v ok=%v", warm, ok)
	}
	if _, _, ok := p.Acquire(key, 40*time.Millisecond); ok {
		t.Fatal("second acquire should block at cap 1 (the one token is held)")
	}
	be, cc := spyBackend()
	p.Discard(key, be) // pinned-discard of a real backend
	if !cc.closed.Load() {
		t.Fatal("Discard must close the backend connection (FD leak otherwise)")
	}
	if _, _, ok := p.Acquire(key, 50*time.Millisecond); !ok {
		t.Fatal("after pinned-discard the freed token must be acquirable (token leak otherwise)")
	}
}

// Stampede: with cap N, 3N concurrent cold acquirers — at most N ever hold a token at once (no
// over-issue), the rest hit acquire-timeout backpressure, and after the storm exactly N slots are free
// (no leak).
func TestStampedeBackpressureNoLeak(t *testing.T) {
	const max = 4
	p := New(max)
	const key = "k"
	var live, peak, granted, timedout atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 3*max; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			be, _, ok := p.Acquire(key, 80*time.Millisecond)
			if !ok {
				timedout.Add(1)
				return
			}
			granted.Add(1)
			n := live.Add(1)
			for { // record the peak concurrent token holders
				pk := peak.Load()
				if n <= pk || peak.CompareAndSwap(pk, n) {
					break
				}
			}
			time.Sleep(25 * time.Millisecond) // hold the slot
			live.Add(-1)
			p.Discard(key, be) // free the token (be is nil on the cold path)
		}()
	}
	wg.Wait()
	if peak.Load() > max {
		t.Fatalf("peak concurrent tokens %d exceeded cap %d (over-issue)", peak.Load(), max)
	}
	if granted.Load() < max {
		t.Fatalf("only %d acquires granted; the cap should allow at least %d", granted.Load(), max)
	}
	// No leak: exactly `max` slots free afterwards.
	free := 0
	for i := 0; i < max; i++ {
		if _, _, ok := p.Acquire(key, 100*time.Millisecond); ok {
			free++
		}
	}
	if free != max {
		t.Fatalf("post-storm free slots = %d, want %d (token leak)", free, max)
	}
	if _, _, ok := p.Acquire(key, 40*time.Millisecond); ok {
		t.Fatal("acquiring beyond the cap after the storm should time out, not succeed (over-issue)")
	}
}

// Repeated fault cycles (acquire → discard, as on every pinned close or client disconnect) far beyond
// the cap must leave the cap exactly intact.
func TestNoTokenLeakAcrossFaultCycles(t *testing.T) {
	const max = 3
	p := New(max)
	const key = "k"
	for i := 0; i < 100; i++ {
		if _, _, ok := p.Acquire(key, 50*time.Millisecond); !ok {
			t.Fatalf("cycle %d: acquire failed — a token leaked", i)
		}
		p.Discard(key, nil) // reclaim the slot (pinned-discard / client-gone)
	}
	free := 0
	for i := 0; i < max; i++ {
		if _, _, ok := p.Acquire(key, 50*time.Millisecond); ok {
			free++
		}
	}
	if free != max {
		t.Fatalf("after 100 fault cycles, free slots = %d, want %d (leak)", free, max)
	}
}

// Over-discard safety: Discarding more times than the cap must NOT inflate the token pool above max —
// otherwise more than `max` backends could open, exhausting the database's real connection slots.
func TestOverDiscardDoesNotOverIssue(t *testing.T) {
	const max = 2
	p := New(max)
	const key = "k"
	for i := 0; i < 5; i++ {
		p.Discard(key, nil) // more discards than the cap
	}
	granted := 0
	for i := 0; i < max+3; i++ {
		if _, _, ok := p.Acquire(key, 40*time.Millisecond); ok {
			granted++
		}
	}
	if granted != max {
		t.Fatalf("after over-discard, %d acquires succeeded, want exactly the cap %d (over-issue)", granted, max)
	}
}

func TestLoginCaptureOnce(t *testing.T) {
	p := New(1)
	const key = "k"
	p.CaptureLogin(key, []byte("first"))
	p.CaptureLogin(key, []byte("second")) // must not overwrite
	if got := string(p.LoginResp(key)); got != "first" {
		t.Fatalf("LoginResp = %q, want first (capture is once)", got)
	}
}

func TestPreloginCapturedGlobally(t *testing.T) {
	p := New(1)
	if p.Prelogin() != nil {
		t.Fatal("prelogin should start nil")
	}
	p.CapturePrelogin([]byte("pre"))
	p.CapturePrelogin([]byte("other"))
	if got := string(p.Prelogin()); got != "pre" {
		t.Fatalf("Prelogin = %q, want pre", got)
	}
}
