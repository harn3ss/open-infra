// Package pool bounds and reuses backend TDS connections behind the proxy. Connections that share a
// credential key (backend + user + database + password) are interchangeable once reset-clean, so a
// finished clean session hands its backend to the next borrower instead of opening a new one. A
// per-key semaphore caps how many backend connections can ever be open for that key — the RDS-Proxy
// guarantee that a client stampede can't exhaust the database's connection slots.
package pool

import (
	"net"
	"sync"
	"time"
)

// Backend is one live, logged-in connection to the database.
type Backend struct {
	Conn  net.Conn
	Fresh bool // just opened (cold) — never yet returned; no reset needed on first use
}

// sub is the pool for one credential key.
type sub struct {
	idle      chan *Backend // returned-clean backends ready to reuse (each still holds a token)
	tokens    chan struct{} // capacity = max; a token is held for every open backend
	loginResp []byte        // the backend's LOGIN7 response, captured cold, replayed to warm clients
	once      sync.Once     // guards loginResp capture
}

// Pool is the set of per-key subpools plus the one globally-cached PRELOGIN response.
type Pool struct {
	mu           sync.Mutex
	subs         map[string]*sub
	max          int
	prelogin     []byte
	preloginOnce sync.Once
}

// New returns a pool that allows at most maxPerKey backend connections per credential key.
func New(maxPerKey int) *Pool {
	if maxPerKey < 1 {
		maxPerKey = 1
	}
	return &Pool{subs: map[string]*sub{}, max: maxPerKey}
}

func (p *Pool) subFor(key string) *sub {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.subs[key]
	if s == nil {
		s = &sub{idle: make(chan *Backend, p.max), tokens: make(chan struct{}, p.max)}
		for i := 0; i < p.max; i++ {
			s.tokens <- struct{}{} // start with all slots free
		}
		p.subs[key] = s
	}
	return s
}

// Acquire returns either a warm idle backend to reuse (warm=true) or, having reserved a slot, signals
// the caller to open+login a fresh backend (warm=false, be=nil). It blocks up to timeout when the key is
// at its connection cap and nothing is free — that backpressure IS the connection ceiling. On timeout it
// returns warm=false, be=nil, ok=false.
func (p *Pool) Acquire(key string, timeout time.Duration) (be *Backend, warm bool, ok bool) {
	s := p.subFor(key)
	// Prefer a warm idle backend over opening a new one. A plain 3-way select would pick between a ready
	// idle backend and a free token at RANDOM (Go select is nondeterministic when several cases are ready),
	// so a warm backend would be passed over for a needless cold open ~half the time — wasting reuse and,
	// under -tx-multiplex where every next statement re-borrows, wasting it constantly. Check idle first.
	select {
	case b := <-s.idle:
		return b, true, true
	default:
	}
	select {
	case b := <-s.idle:
		return b, true, true
	case <-s.tokens:
		return nil, false, true
	case <-time.After(timeout):
		return nil, false, false
	}
}

// Return puts a reset-clean backend back for reuse (it keeps its token — still an open connection).
func (p *Pool) Return(key string, be *Backend) {
	be.Fresh = false
	s := p.subFor(key)
	select {
	case s.idle <- be:
	default:
		// idle full (shouldn't happen: idle+in-use ≤ max) — discard rather than leak.
		p.Discard(key, be)
	}
}

// Discard closes a backend and frees its slot so another can open.
func (p *Pool) Discard(key string, be *Backend) {
	if be != nil && be.Conn != nil {
		be.Conn.Close()
	}
	s := p.subFor(key)
	select {
	case s.tokens <- struct{}{}:
	default:
	}
}

// CaptureLogin records the backend's LOGIN7 response for a key the first time (cold path), for replay to
// later warm clients that reuse a pooled backend instead of logging in again.
func (p *Pool) CaptureLogin(key string, resp []byte) {
	s := p.subFor(key)
	s.once.Do(func() {
		s.loginResp = append([]byte(nil), resp...)
	})
}

// LoginResp returns the cached LOGIN7 response for a key (nil if none captured yet).
func (p *Pool) LoginResp(key string) []byte {
	s := p.subFor(key)
	return s.loginResp
}

// CapturePrelogin records the server's PRELOGIN response once, globally (it's server-static).
func (p *Pool) CapturePrelogin(resp []byte) {
	p.preloginOnce.Do(func() { p.prelogin = append([]byte(nil), resp...) })
}

// Prelogin returns the cached PRELOGIN response (nil until the first cold handshake captures one).
func (p *Pool) Prelogin() []byte { return p.prelogin }
