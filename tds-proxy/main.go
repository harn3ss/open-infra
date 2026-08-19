// openinfra-tds-proxy — a TDS-aware proxy for the managed SQL-Server / Babelfish engine, the open-infra
// analog of AWS RDS Proxy. v1 relays each client session to a backend faithfully (byte-for-byte) while
// parsing the client→backend stream to classify every message multiplexable-vs-pin (see package
// classify), reporting a per-session verdict and an aggregate "multiplex opportunity" — i.e. what
// fraction of sessions never touched session state and could therefore have shared a pooled backend.
//
// This is the working foundation + the live classifier. The pooling that acts on the verdict — login
// termination so a clean backend can be handed to the next client, and transaction-boundary return —
// is the next increment (docs/design/rds-proxy-tds-multiplexing.md); the hard part there is synthesizing
// the login handshake, which is deliberately not attempted in v1.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"openinfra-tds-proxy/classify"
	"openinfra-tds-proxy/tds"
)

var (
	totalSessions   atomic.Int64
	pinnedSessions  atomic.Int64
	cleanSessions   atomic.Int64
	activeSessions  atomic.Int64
	pinReasonsMu    sync.Mutex
	pinReasonCounts = map[string]int64{}
)

func main() {
	listen := flag.String("listen", ":1433", "listen address for TDS clients")
	backend := flag.String("backend", "", "backend TDS address host:port (the SQL Server / Babelfish)")
	metrics := flag.String("metrics", ":9114", "address for the /metrics + /status endpoints")
	flag.Parse()
	if *backend == "" {
		log.Fatal("tds-proxy: -backend host:port is required")
	}

	go serveMetrics(*metrics)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("tds-proxy: listen %s: %v", *listen, err)
	}
	log.Printf("tds-proxy: listening on %s → backend %s (metrics %s)", *listen, *backend, *metrics)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tds-proxy: accept: %v", err)
			continue
		}
		go handle(c, *backend)
	}
}

// session tracks one client's classification state.
type session struct {
	id           int64
	pinned       bool
	reasons      []string
	msgs         int
	sawRealBatch bool // used for the driver login-prelude exception
}

func (s *session) observe(msgType byte, v classify.Verdict) {
	s.msgs++
	if !v.Pin {
		if msgType == tds.TypeSQLBatch {
			s.sawRealBatch = true
		}
		return
	}
	// Login prelude: a SET-only batch before any real work is the driver's connect-time prelude,
	// re-applied on fresh backends — not a pin.
	if v.Prelude && !s.sawRealBatch {
		return
	}
	if !s.pinned {
		s.pinned = true
	}
	s.reasons = append(s.reasons, v.Reason)
	pinReasonsMu.Lock()
	pinReasonCounts[v.Reason]++
	pinReasonsMu.Unlock()
}

func handle(client net.Conn, backendAddr string) {
	id := totalSessions.Add(1)
	activeSessions.Add(1)
	defer activeSessions.Add(-1)
	defer client.Close()

	be, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("tds-proxy: session %d: dial backend: %v", id, err)
		return
	}
	defer be.Close()

	s := &session{id: id}
	done := make(chan struct{}, 2)
	// backend → client: verbatim relay (results). We don't classify server tokens in v1.
	go func() { io.Copy(client, be); done <- struct{}{} }()
	// client → backend: verbatim relay + classify each reassembled message.
	go func() { relayAndClassify(client, be, s); done <- struct{}{} }()
	<-done

	// Session finished — record the verdict.
	if s.pinned {
		pinnedSessions.Add(1)
		log.Printf("tds-proxy: session %d PINNED after %d msgs: %v", id, s.msgs, dedupe(s.reasons))
	} else {
		cleanSessions.Add(1)
		log.Printf("tds-proxy: session %d clean (%d msgs) — multiplexable", id, s.msgs)
	}
}

// relayAndClassify copies src→dst faithfully, reassembling TDS messages (EOM) to classify each.
func relayAndClassify(src, dst net.Conn, s *session) {
	var msgType byte
	var buf []byte
	for {
		p, err := tds.ReadPacket(src)
		if err != nil {
			return
		}
		if _, err := dst.Write(p.Raw); err != nil { // relay verbatim BEFORE classifying — never delay the client
			return
		}
		if len(buf) == 0 {
			msgType = p.Type
		}
		buf = append(buf, p.Body...)
		if p.EOM() {
			// Only classify client work types; prelogin/login/attention are control.
			if msgType == tds.TypeSQLBatch || msgType == tds.TypeRPC || msgType == tds.TypeBulkLoad ||
				msgType == tds.TypeTxMgr {
				s.observe(msgType, classify.Classify(msgType, buf))
			}
			buf = buf[:0]
		}
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		tot := totalSessions.Load()
		clean := cleanSessions.Load()
		ratio := 0.0
		if done := clean + pinnedSessions.Load(); done > 0 {
			ratio = float64(clean) / float64(done)
		}
		fmt.Fprintf(w, "sessions_total %d\nsessions_active %d\nsessions_clean %d\nsessions_pinned %d\nmultiplex_opportunity %.3f\n",
			tot, activeSessions.Load(), clean, pinnedSessions.Load(), ratio)
		pinReasonsMu.Lock()
		for reason, n := range pinReasonCounts {
			fmt.Fprintf(w, "pin_reason{reason=%q} %d\n", reason, n)
		}
		pinReasonsMu.Unlock()
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("tds-proxy: metrics server: %v", err)
	}
}
