package pool

import (
	"net"
	"testing"
	"time"
)

// fakeBackend returns a *Backend wrapping one end of a pipe (never actually read/written here).
func fakeBackend() *Backend {
	c, _ := net.Pipe()
	return &Backend{Conn: c, Fresh: true}
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
