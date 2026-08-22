// openinfra-tds-proxy — a TDS-aware connection pool for the managed SQL-Server / Babelfish engine, the
// open-infra analog of AWS RDS Proxy. It terminates each client's TDS handshake itself (answering
// PRELOGIN, reading LOGIN7), then borrows a backend connection from a bounded per-credential pool for the
// life of the session. A session that never leaves unsharable state (see package classify) returns its
// backend to the pool reset-clean for the next client to reuse — skipping a fresh TCP connect + login —
// while a session that pins (temp tables, explicit txn, prepared handles, cursors, …) keeps its backend
// 1:1 and discards it on close. The per-key semaphore caps how many backend connections can ever open,
// so a client stampede queues instead of exhausting the database's connection slots.
//
// Reuse across clients is what makes it a pool: the backend's LOGIN7 response is captured on the first
// (cold) login and replayed to later (warm) clients, and the borrowed backend is wiped with the TDS
// RESETCONNECTION bit on the new client's first batch. v1's classifier and multiplex-opportunity metric
// are retained; this adds the pooling that acts on the verdict.
//
// Client attention/cancel IS forwarded promptly mid-response (a two-direction relay), so cancelling a
// slow query takes effect immediately. Not yet handled (honestly scoped): per-transaction multiplexing
// within one session (a session holds its backend for its lifetime, not per-statement), MARS, and
// TLS-terminated (encrypt=strict) sessions — the engine is TDS-no-TLS.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"openinfra-tds-proxy/classify"
	"openinfra-tds-proxy/pool"
	"openinfra-tds-proxy/tds"
)

var (
	sessionsTotal   atomic.Int64
	sessionsActive  atomic.Int64
	pinnedSessions  atomic.Int64
	cleanSessions   atomic.Int64
	coldOpens       atomic.Int64
	warmReuses      atomic.Int64
	returns         atomic.Int64
	discards        atomic.Int64
	acquireTimeouts atomic.Int64
	marsRequested   atomic.Int64 // clients that asked for MARS in PRELOGIN (the pool does not grant it)
	integratedAuth  atomic.Int64 // integrated/Windows (SSPI) logins refused — not poolable by credential
	deadEvicted     atomic.Int64 // pooled backends found dead/dirty at borrow time and evicted (fault axis)
	tlsStrict       atomic.Int64 // clients terminated via TDS 8.0 strict (TLS-first)
	tlsOn           atomic.Int64 // clients terminated via legacy encrypt=on (TLS tunneled in PRELOGIN)
	tlsHandshakeErr atomic.Int64 // TLS handshakes that failed
	tlsUnsupported  atomic.Int64 // clients that required encryption while the proxy has no cert (rejected)
	pinReasonsMu    sync.Mutex
	pinReasonCounts = map[string]int64{}

	backendPool    *pool.Pool
	preloginResp   = tds.BuildPreloginResponse()
	clientPrelogin = tds.BuildClientPrelogin() // plaintext PRELOGIN sent to the backend when client TLS is terminated
	tlsConfig      *tls.Config                 // set when -tls-cert/-tls-key are given; enables TLS termination (#6)
	debugClassify  = os.Getenv("TDSPROXY_DEBUG") != ""
)

func main() {
	listen := flag.String("listen", ":1433", "listen address for TDS clients")
	backend := flag.String("backend", "", "backend TDS address host:port (the SQL Server / Babelfish)")
	metrics := flag.String("metrics", ":9114", "address for the /metrics + /status endpoints")
	poolMax := flag.Int("pool-max", 20, "max backend connections per credential key (the connection ceiling)")
	acquireMs := flag.Int("acquire-timeout-ms", 10000, "how long a client waits for a backend when the pool is at its cap")
	tlsCert := flag.String("tls-cert", "", "PEM cert to TERMINATE client TLS (encrypt=on/strict); backend stays plaintext (#6)")
	tlsKey := flag.String("tls-key", "", "PEM key for -tls-cert")
	flag.Parse()
	if *backend == "" {
		log.Fatal("tds-proxy: -backend host:port is required")
	}
	// TLS termination is opt-in: only when a cert is supplied. Without it the proxy stays plaintext-only
	// and a client that REQUIRES encryption is refused cleanly (never silently downgraded).
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("tds-proxy: -tls-cert and -tls-key must be given together")
		}
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tds-proxy: load TLS cert: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"tds/8.0"}, // ALPN for TDS 8.0 strict; harmless for legacy clients
		}
		log.Printf("tds-proxy: TLS termination ENABLED (encrypt=on + strict); backend connection stays plaintext")
	}
	backendPool = pool.New(*poolMax)
	acquireTimeout := time.Duration(*acquireMs) * time.Millisecond

	go serveMetrics(*metrics)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("tds-proxy: listen %s: %v", *listen, err)
	}
	log.Printf("tds-proxy: pooling on %s → backend %s (pool-max %d/key, metrics %s)", *listen, *backend, *poolMax, *metrics)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tds-proxy: accept: %v", err)
			continue
		}
		go handle(c, *backend, acquireTimeout)
	}
}

// handle terminates one client's handshake, borrows a backend, relays the session, and returns or
// discards the backend based on the classifier verdict.
func handle(client net.Conn, backendAddr string, acquireTimeout time.Duration) {
	id := sessionsTotal.Add(1)
	sessionsActive.Add(1)
	defer sessionsActive.Add(-1)
	defer client.Close()

	// 0. TLS termination (#6), opt-in via -tls-cert. TDS negotiates TLS INSIDE the protocol, so the proxy
	//    must be the TLS peer; the backend connection stays plaintext (the managed engine is TDS-no-TLS).
	//    A TDS 8.0 "strict" client opens with a raw TLS ClientHello (record type 0x16) before any TDS —
	//    detect it by peeking one byte and wrap the conn immediately.
	tlsTerminated := false
	if tlsConfig != nil {
		pc := tds.NewPrefaceConn(client)
		client = pc
		first, e := pc.Peek(1)
		if e != nil {
			return
		}
		if first[0] == 0x16 { // TLS ClientHello → TDS 8.0 strict (TLS-first)
			tconn := tls.Server(pc, tlsConfig)
			if e := tconn.Handshake(); e != nil {
				tlsHandshakeErr.Add(1)
				return
			}
			client = tconn
			tlsTerminated = true
			tlsStrict.Add(1)
		}
	}

	// 1. PRELOGIN. Read the client's, then either tunnel a TLS handshake (legacy encrypt=on/mandatory) or
	//    answer plaintext — so we can pick a backend by the LOGIN7 identity that follows.
	pType, preBody, preRaw, err := tds.ReadMessage(client)
	if err != nil || pType != tds.TypePreLogin {
		return
	}
	if tds.PreloginRequestsMARS(preBody) {
		marsRequested.Add(1) // visibility only — the synthesized response omits MARS, so it is not granted
	}
	clientEnc := tds.PreloginEncryption(preBody)
	switch {
	case tlsTerminated:
		// strict: encryption already established by the outer TLS; answer the inner PRELOGIN as on.
		if _, err := client.Write(tds.BuildPreloginResponseEnc(tds.EncryptOn)); err != nil {
			return
		}
	case tlsConfig != nil && (clientEnc == tds.EncryptOn || clientEnc == tds.EncryptReq):
		// legacy encrypt=on/mandatory: require TLS, then carry the handshake inside PRELOGIN packets.
		if _, err := client.Write(tds.BuildPreloginResponseEnc(tds.EncryptReq)); err != nil {
			return
		}
		hc := tds.NewTDSHandshakeConn(client)
		tconn := tls.Server(hc, tlsConfig)
		if e := tconn.Handshake(); e != nil {
			tlsHandshakeErr.Add(1)
			return
		}
		hc.SetDone() // handshake done → TLS now rides the bare stream
		client = tconn
		tlsTerminated = true
		tlsOn.Add(1)
	case clientEnc == tds.EncryptReq:
		// client REQUIRES encryption but no cert is configured — refuse cleanly, never silently downgrade.
		tlsUnsupported.Add(1)
		log.Printf("tds-proxy: session %d: client requires TLS but no -tls-cert configured — refusing", id)
		return
	default:
		// plaintext path (encrypt=disable/off): unchanged original behaviour.
		if _, err := client.Write(preloginResp); err != nil {
			return
		}
	}
	// When TLS was terminated, the client's PRELOGIN advertised encryption; the plaintext backend must get
	// a plaintext one instead. (LOGIN7 replays verbatim — it's the same login, just now decrypted.)
	backendPre := preRaw
	if tlsTerminated {
		backendPre = clientPrelogin
	}

	// 2. Read the client LOGIN7 and key the pool on (backend, user, db, password).
	lType, lBody, lRaw, err := tds.ReadMessage(client)
	if err != nil || lType != tds.TypeLogin7 {
		return
	}
	info, ok := tds.ParseLogin7(lBody)
	if !ok {
		return
	}
	// Integrated/Windows (SSPI) auth carries no credential to key on — pooling it would risk collapsing
	// distinct Windows identities onto one shared backend, and the multi-round SSPI token exchange isn't
	// relayed by the pool's terminated handshake. Refuse cleanly; SQL auth is the supported mode. (A
	// transparent pass-through mode for integrated auth is a documented follow-up.)
	if info.Integrated {
		integratedAuth.Add(1)
		log.Printf("tds-proxy: session %d: integrated/Windows (SSPI) auth is not poolable — use SQL auth", id)
		return
	}
	key := poolKey(backendAddr, info)

	// 3. Acquire a USABLE backend: a warm idle one still clean-and-alive to reuse, or a reserved slot to
	//    open a cold one. A pooled backend can die or accumulate residual bytes while idle (backend
	//    restart, network blip) — those are probed and evicted so the client always gets a live backend.
	be, warm, ok := acquireUsable(key, acquireTimeout)
	if !ok {
		acquireTimeouts.Add(1)
		log.Printf("tds-proxy: session %d: pool at cap for %s@%s — timed out", id, info.User, info.Database)
		return
	}

	needReset := false
	if warm {
		// Reuse: replay the captured LOGIN7 response to the client; wipe the backend on its first batch.
		loginResp := backendPool.LoginResp(key)
		if loginResp == nil {
			backendPool.Discard(key, be)
			return
		}
		if _, err := client.Write(loginResp); err != nil {
			backendPool.Discard(key, be) // backend is fine, but client is gone — reclaim the slot
			return
		}
		needReset = true
		warmReuses.Add(1)
	} else {
		// Cold: open a backend and do the real login, forwarding the client's PRELOGIN + LOGIN7 verbatim.
		bc, err := net.Dial("tcp", backendAddr)
		if err != nil {
			backendPool.Discard(key, nil) // release the reserved slot
			log.Printf("tds-proxy: session %d: dial backend: %v", id, err)
			return
		}
		if _, err := bc.Write(backendPre); err != nil { // client PRELOGIN → backend (plaintext if client TLS was terminated)
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		if _, _, _, err := tds.ReadMessage(bc); err != nil { // backend PRELOGIN response (discarded)
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		if _, err := bc.Write(lRaw); err != nil { // client LOGIN7 → backend
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		_, _, loginRaw, err := tds.ReadMessage(bc) // backend LOGIN7 response
		if err != nil {
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		if _, err := client.Write(loginRaw); err != nil {
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		backendPool.CaptureLogin(key, loginRaw)
		be = &pool.Backend{Conn: bc, Fresh: true}
		coldOpens.Add(1)
	}

	// 4. Relay the session synchronously (TDS is request/response), classifying each client message.
	pinned, reasons, returnable := relaySession(client, be.Conn, needReset)

	// 5. Return the backend for reuse only if the session stayed clean AND the backend is quiescent.
	if pinned {
		pinnedSessions.Add(1)
		recordReasons(reasons)
		log.Printf("tds-proxy: session %d PINNED (%s@%s): %v — backend discarded", id, info.User, info.Database, reasons)
	} else {
		cleanSessions.Add(1)
	}
	if returnable {
		returns.Add(1)
		backendPool.Return(key, be)
	} else {
		discards.Add(1)
		backendPool.Discard(key, be)
	}
}

// acquireUsable borrows a backend that is actually usable: a cold slot (caller opens fresh), or a warm
// idle backend still clean-and-alive. A pooled backend that died or left residual bytes while idle
// (backend restart, network blip, an unexpected server push) is evicted and the acquire retried, so
// backend faults stay transparent to the client instead of surfacing as a first-query failure after a
// "successful" login. Bounded retries keep a run of dead backends from spinning.
func acquireUsable(key string, timeout time.Duration) (be *pool.Backend, warm, ok bool) {
	for tries := 0; tries < 4; tries++ {
		be, warm, ok = backendPool.Acquire(key, timeout)
		if !ok {
			return nil, false, false
		}
		if !warm || probeIdle(be.Conn) {
			return be, warm, true
		}
		deadEvicted.Add(1)
		backendPool.Discard(key, be)
	}
	return nil, false, false
}

// probeIdle reports whether an idle pooled backend is still clean and alive: a very short non-blocking
// read must time out with no data. EOF/error means the connection died; any bytes waiting mean residual
// state that would desync the next session — either way the backend is not reusable.
func probeIdle(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	var b [1]byte
	_, err := c.Read(b[:])
	if err == nil {
		return false // unexpected pending bytes — not clean
	}
	ne, isNet := err.(net.Error)
	return isNet && ne.Timeout() // timeout = alive + idle; EOF/reset/other = dead
}

// relaySession relays a session with two concurrent directions, so a client ATTENTION (cancel) is
// forwarded to the backend PROMPTLY — mid-response — instead of waiting for the in-flight response to
// finish, which is what makes cancel actually take effect. client→backend forwards every packet
// (requests AND attentions) and reassembles messages to classify; backend→client streams responses and
// counts completions. On a clean client close between requests with every request answered, the backend
// is quiescent and returnable; otherwise it is discarded. The classify/pin state is written only by the
// client goroutine and read after it has exited (channel-close happens-before), so it needs no lock.
func relaySession(client net.Conn, backend net.Conn, needReset bool) (pinned bool, reasons []string, returnable bool) {
	seen := map[string]bool{}
	sawRealBatch := false
	cleanClose := false
	var reqCount, respCount int64

	beDone := make(chan struct{})
	go func() { // backend → client: stream responses, count completed ones
		defer close(beDone)
		for {
			p, err := tds.ReadPacket(backend)
			if err != nil {
				return
			}
			if _, err := client.Write(p.Raw); err != nil {
				return
			}
			if p.EOM() && p.Type == tds.TypeTabular {
				atomic.AddInt64(&respCount, 1)
			}
		}
	}()

	clDone := make(chan struct{})
	go func() { // client → backend: forward requests AND attentions promptly; classify each message
		defer close(clDone)
		first, atBoundary := true, true
		var mType byte
		var buf []byte
		for {
			p, err := tds.ReadPacket(client)
			if err != nil {
				if atBoundary {
					cleanClose = true // client left between messages, not mid-request
				}
				return
			}
			atBoundary = false
			raw := p.Raw
			if first {
				if needReset {
					raw = tds.WithResetConnection(raw)
				}
				first = false
			}
			if _, err := backend.Write(raw); err != nil { // forwards ATTENTION promptly too
				return
			}
			if len(buf) == 0 {
				mType = p.Type
			}
			buf = append(buf, p.Body...)
			if p.EOM() {
				if isClientWork(mType) {
					atomic.AddInt64(&reqCount, 1)
					v := classify.Classify(mType, buf)
					if debugClassify {
						txt := ""
						switch mType {
						case tds.TypeSQLBatch:
							txt = tds.BatchText(buf)
						case tds.TypeRPC:
							txt = "RPC:" + tds.RPCProc(buf)
						}
						if len(txt) > 90 {
							txt = txt[:90]
						}
						log.Printf("tds-proxy: DEBUG type=%s pin=%v prelude=%v sawReal=%v reason=%q text=%q",
							tds.TypeName(mType), v.Pin, v.Prelude, sawRealBatch, v.Reason, txt)
					}
					if v.Pin && !(v.Prelude && !sawRealBatch) {
						pinned = true
						if !seen[v.Reason] {
							seen[v.Reason] = true
							reasons = append(reasons, v.Reason)
						}
					}
					if mType == tds.TypeSQLBatch && !v.Pin {
						sawRealBatch = true
					}
				}
				buf = buf[:0]
				atBoundary = true
			}
		}
	}()

	select {
	case <-clDone:
		// Client closed. If it left cleanly between requests and every request has its response, the
		// backend is quiescent — stop the backend reader via a read deadline (not a close) so we can
		// return the connection to the pool.
		if cleanClose && atomic.LoadInt64(&reqCount) == atomic.LoadInt64(&respCount) {
			_ = backend.SetReadDeadline(time.Now())
			<-beDone
			_ = backend.SetReadDeadline(time.Time{})
			return pinned, reasons, !pinned
		}
		<-beDone // unclean close or an in-flight response — the reader errors on the closed client
		return pinned, reasons, false
	case <-beDone:
		// Backend died mid-session — discard. Unblock the client reader so it exits.
		_ = client.SetReadDeadline(time.Now())
		<-clDone
		_ = client.SetReadDeadline(time.Time{})
		return pinned, reasons, false
	}
}

func isClientWork(t byte) bool {
	return t == tds.TypeSQLBatch || t == tds.TypeRPC || t == tds.TypeBulkLoad || t == tds.TypeTxMgr
}

func poolKey(backendAddr string, info tds.Login7Info) string {
	h := fnv.New64a()
	h.Write(info.PassField)
	return fmt.Sprintf("%s|%s|%s|%x", backendAddr, info.User, info.Database, h.Sum64())
}

func recordReasons(reasons []string) {
	pinReasonsMu.Lock()
	for _, r := range reasons {
		pinReasonCounts[r]++
	}
	pinReasonsMu.Unlock()
}

func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		clean := cleanSessions.Load()
		done := clean + pinnedSessions.Load()
		ratio := 0.0
		if done > 0 {
			ratio = float64(clean) / float64(done)
		}
		reuse := 0.0
		if tot := coldOpens.Load() + warmReuses.Load(); tot > 0 {
			reuse = float64(warmReuses.Load()) / float64(tot)
		}
		fmt.Fprintf(w, "sessions_total %d\nsessions_active %d\nsessions_clean %d\nsessions_pinned %d\n",
			sessionsTotal.Load(), sessionsActive.Load(), clean, pinnedSessions.Load())
		fmt.Fprintf(w, "multiplex_opportunity %.3f\n", ratio)
		fmt.Fprintf(w, "pool_cold_opens %d\npool_warm_reuses %d\npool_returns %d\npool_discards %d\npool_acquire_timeouts %d\n",
			coldOpens.Load(), warmReuses.Load(), returns.Load(), discards.Load(), acquireTimeouts.Load())
		fmt.Fprintf(w, "pool_reuse_ratio %.3f\n", reuse)
		// MARS visibility: how many clients asked for MARS (not granted). A high count flags a fleet a
		// future per-transaction multiplexer would have to pin or specially handle — measured, not guessed.
		fmt.Fprintf(w, "mars_requested %d\n", marsRequested.Load())
		fmt.Fprintf(w, "integrated_auth_refused %d\n", integratedAuth.Load())
		fmt.Fprintf(w, "pool_dead_evicted %d\n", deadEvicted.Load())
		fmt.Fprintf(w, "tls_terminated_strict %d\ntls_terminated_on %d\ntls_handshake_errors %d\ntls_required_no_cert %d\n",
			tlsStrict.Load(), tlsOn.Load(), tlsHandshakeErr.Load(), tlsUnsupported.Load())
		pinReasonsMu.Lock()
		for reason, n := range pinReasonCounts {
			fmt.Fprintf(w, "pin_reason{reason=%q} %d\n", reason, n)
		}
		pinReasonsMu.Unlock()
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("tds-proxy: metrics server: %v", err)
	}
}
