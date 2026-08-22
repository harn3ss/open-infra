// Command fault drives fault-injection scenarios through the tds-proxy against a THROWAWAY backend and
// prints the observed pool verdicts (from /status). It is harness-only (its own module, go-mssqldb dep);
// the proxy itself stays stdlib-only. Scenarios (issue #4 fault axis):
//   - stampede:      N concurrent pinned sessions vs a small pool cap — prove the ceiling + acquire
//     backpressure (excess clients error, no more than cap backends open, no leak).
//   - pinned-drop:   a session pins (temp table) then the client disconnects — prove pinned-discard
//     fires and frees the token (a fresh client can still connect afterwards).
//   - handshake-drop: raw TCP connect to the proxy, send partial PRELOGIN bytes, drop — prove the proxy
//     cleans up without reserving/leaking a pool slot.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
)

func dsn(addr string) string {
	pw := os.Getenv("PW")
	if pw == "" {
		pw = "Grid#Test2026!"
	}
	// Build via net/url so a password with URL-special chars (# ! …) is encoded correctly.
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword("sa", pw),
		Host:   addr,
		RawQuery: url.Values{
			"encrypt":            {"disable"},
			"database":           {"master"},
			"dial timeout":       {"5"},
			"connection timeout": {"8"},
		}.Encode(),
	}
	return u.String()
}

// status parses the proxy's plaintext /status (whitespace-separated "key value" lines).
func status(url string) map[string]int64 {
	m := map[string]int64{}
	resp, err := http.Get(url)
	if err != nil {
		return m
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			m[f[0]] = v
		}
	}
	return m
}

func num(m map[string]int64, k string) int64 { return m[k] }

// capturingDialer records the raw client-side net.Conn so a test can hard-close it mid-stream (a
// vanished client), which database/sql's graceful Close cannot simulate.
type capturingDialer struct{ conn net.Conn }

func (d *capturingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err == nil {
		d.conn = c
	}
	return c, err
}

func main() {
	proxy := os.Getenv("PROXY")      // host:port of the proxy
	statusURL := os.Getenv("STATUS") // http://host:port/status
	scenario := os.Getenv("SCENARIO")
	before := status(statusURL)

	switch scenario {
	case "stampede":
		const n = 6
		var granted, failed atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				db, err := sql.Open("sqlserver", dsn(proxy))
				if err != nil {
					failed.Add(1)
					return
				}
				defer db.Close()
				db.SetMaxOpenConns(1)
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				// Pin the backend (explicit txn + temp table) and hold it ~3s.
				conn, err := db.Conn(ctx)
				if err != nil {
					failed.Add(1)
					return
				}
				defer conn.Close()
				if _, err := conn.ExecContext(ctx, "BEGIN TRAN; CREATE TABLE #hold(x int); WAITFOR DELAY '00:00:03'; ROLLBACK"); err != nil {
					failed.Add(1)
					return
				}
				granted.Add(1)
			}(i)
			time.Sleep(120 * time.Millisecond) // stagger so the first ones grab the cap
		}
		wg.Wait()
		after := status(statusURL)
		fmt.Printf("STAMPEDE n=%d granted=%d failed=%d | cold_opens_delta=%d acquire_timeouts_delta=%d\n",
			n, granted.Load(), failed.Load(),
			num(after, "pool_cold_opens")-num(before, "pool_cold_opens"),
			num(after, "pool_acquire_timeouts")-num(before, "pool_acquire_timeouts"))

	case "pinned-drop":
		db, err := sql.Open("sqlserver", dsn(proxy))
		if err != nil {
			fmt.Println("open err:", err)
			os.Exit(1)
		}
		db.SetMaxOpenConns(1)
		ctx := context.Background()
		conn, err := db.Conn(ctx)
		if err != nil {
			fmt.Println("conn err:", err)
			os.Exit(1)
		}
		// Pin: create a session-scoped temp table (go-mssqldb sends a raw batch → session-scoped).
		if _, err := conn.ExecContext(ctx, "CREATE TABLE #pinme(x int)"); err != nil {
			fmt.Println("pin exec err:", err)
			os.Exit(1)
		}
		// Abruptly drop the client (close the pool without a graceful logout).
		conn.Close()
		db.Close()
		time.Sleep(1500 * time.Millisecond) // let the proxy observe the disconnect + discard
		after := status(statusURL)
		fmt.Printf("PINNED-DROP | pinned_delta=%d discards_delta=%d\n",
			num(after, "sessions_pinned")-num(before, "sessions_pinned"),
			num(after, "pool_discards")-num(before, "pool_discards"))
		// Prove the token freed: a fresh client can still connect+query.
		db2, e2 := sql.Open("sqlserver", dsn(proxy))
		if e2 != nil || db2 == nil {
			fmt.Println("post-check open err:", e2)
			return
		}
		defer db2.Close()
		ctx2, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		var one int
		err = db2.QueryRowContext(ctx2, "SELECT 1").Scan(&one)
		fmt.Printf("POST-DROP fresh connect+query ok=%v (token freed)\n", err == nil && one == 1)

	case "handshake-drop":
		// Raw TCP: connect to the proxy, send a truncated PRELOGIN, then drop — no login completes.
		var reserved int64
		for i := 0; i < 5; i++ {
			c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
			if err != nil {
				continue
			}
			c.Write([]byte{0x12, 0x01, 0x00, 0x10}) // partial TDS PRELOGIN header, then drop
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
		time.Sleep(1 * time.Second)
		after := status(statusURL)
		// A mid-handshake client drop must NOT reserve/leak a pool slot (login never completed).
		reserved = num(after, "pool_cold_opens") - num(before, "pool_cold_opens")
		fmt.Printf("HANDSHAKE-DROP attempts=5 | cold_opens_delta=%d (want 0 — no slot reserved/leaked)\n", reserved)
		// Prove usable afterward.
		db2, e2 := sql.Open("sqlserver", dsn(proxy))
		if e2 != nil || db2 == nil {
			fmt.Println("post-check open err:", e2)
			return
		}
		defer db2.Close()
		ctx2, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		var one int
		err := db2.QueryRowContext(ctx2, "SELECT 1").Scan(&one)
		fmt.Printf("POST-HANDSHAKE-DROP fresh connect+query ok=%v\n", err == nil && one == 1)

	case "midresult-drop":
		// Client vanishes mid-result-set: the proxy must DISCARD the backend (it is mid-stream and can't
		// be safely returned to the pool for the next borrower) and reclaim the slot. To force a HARD TCP
		// drop mid-stream (database/sql would otherwise try to drain on Close), a capturing dialer hands us
		// the raw client-side socket, which we close directly while rows are still streaming.
		connector, err := mssql.NewConnector(dsn(proxy))
		if err != nil {
			fmt.Println("connector err:", err)
			os.Exit(1)
		}
		cd := &capturingDialer{}
		connector.Dialer = cd
		db := sql.OpenDB(connector)
		db.SetMaxOpenConns(1)
		ctx := context.Background()
		// A large result set so the backend is still streaming when we drop.
		rows, err := db.QueryContext(ctx, "SELECT TOP 500000 a.object_id FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c")
		if err != nil {
			fmt.Println("query err:", err)
			os.Exit(1)
		}
		rows.Next() // read one row → backend is mid-stream
		// Hard-close the underlying client socket mid-stream (a vanished client, not a graceful close).
		if cd.conn != nil {
			cd.conn.Close()
		}
		time.Sleep(1500 * time.Millisecond)
		after := status(statusURL)
		fmt.Printf("MIDRESULT-DROP | discards_delta=%d\n", num(after, "pool_discards")-num(before, "pool_discards"))
		db2, e2 := sql.Open("sqlserver", dsn(proxy))
		if e2 != nil || db2 == nil {
			fmt.Println("post-check open err:", e2)
			return
		}
		defer db2.Close()
		ctx2, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		var one int
		err = db2.QueryRowContext(ctx2, "SELECT 1").Scan(&one)
		fmt.Printf("POST-MIDRESULT-DROP fresh connect+query ok=%v (slot reclaimed, no half-read backend reused)\n", err == nil && one == 1)

	case "backend-failover":
		// A client holds an open explicit transaction (pinned backend) when the backend dies. The client's
		// next statement must fail CLEANLY (not hang/corrupt); the pool must recover so a fresh client
		// connects once the backend is back.
		container := os.Getenv("CONTAINER")
		backendAddr := os.Getenv("BACKEND")
		db, err := sql.Open("sqlserver", dsn(proxy))
		if err != nil {
			fmt.Println("open err:", err)
			os.Exit(1)
		}
		db.SetMaxOpenConns(1)
		ctx := context.Background()
		conn, err := db.Conn(ctx)
		if err != nil {
			fmt.Println("conn err:", err)
			os.Exit(1)
		}
		if _, err := conn.ExecContext(ctx, "BEGIN TRAN; CREATE TABLE #t(x int)"); err != nil {
			fmt.Println("begin-tran err:", err)
			os.Exit(1)
		}
		// Kill+restart the backend under the open transaction.
		restart := exec.Command("docker", "restart", container)
		restart.Stdout, restart.Stderr = os.Stderr, os.Stderr
		_ = restart.Run()
		// The in-flight client's next statement should error cleanly (connection reset), not hang.
		cctx, ccancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, txErr := conn.ExecContext(cctx, "SELECT 1")
		ccancel()
		conn.Close()
		db.Close()
		fmt.Printf("BACKEND-FAILOVER | in-txn stmt errored cleanly=%v (%v)\n", txErr != nil, txErr)
		// Wait for the backend to accept again, then prove a fresh client recovers through the proxy.
		recovered := false
		for i := 0; i < 30; i++ {
			if c, e := net.DialTimeout("tcp", backendAddr, 2*time.Second); e == nil {
				c.Close()
				db2, e2 := sql.Open("sqlserver", dsn(proxy))
				if e2 == nil && db2 != nil {
					rctx, rcancel := context.WithTimeout(context.Background(), 6*time.Second)
					var one int
					if db2.QueryRowContext(rctx, "SELECT 1").Scan(&one) == nil && one == 1 {
						recovered = true
					}
					rcancel()
					db2.Close()
				}
				if recovered {
					break
				}
			}
			time.Sleep(3 * time.Second)
		}
		after := status(statusURL)
		fmt.Printf("POST-FAILOVER fresh connect+query ok=%v | dead_evicted_delta=%d discards_delta=%d\n",
			recovered, num(after, "pool_dead_evicted")-num(before, "pool_dead_evicted"),
			num(after, "pool_discards")-num(before, "pool_discards"))

	case "tls-modes":
		// #6: connect through the proxy in each TLS mode and run SELECT 1. encrypt=disable is the
		// plaintext path; encrypt=true is legacy encrypt=on (TLS tunneled in PRELOGIN); encrypt=strict is
		// TDS 8.0 (TLS-first). TrustServerCertificate=true accepts the proxy's self-signed cert.
		modes := []struct{ name, enc string }{{"disable", "disable"}, {"on", "true"}, {"strict", "strict"}}
		allok := true
		for _, m := range modes {
			q := url.Values{
				"encrypt": {m.enc}, "TrustServerCertificate": {"true"}, "database": {"master"},
				"dial timeout": {"5"}, "connection timeout": {"8"},
			}
			// strict (TDS 8.0) ignores TrustServerCertificate by design, so hand it the proxy cert to
			// trust explicitly (in production cert-manager issues a chain the client already trusts).
			if c := os.Getenv("CERT"); c != "" {
				q.Set("certificate", c)
				q.Set("hostNameInCertificate", "localhost")
			}
			u := &url.URL{
				Scheme: "sqlserver", User: url.UserPassword("sa", os.Getenv("PW")), Host: proxy,
				RawQuery: q.Encode(),
			}
			db, err := sql.Open("sqlserver", u.String())
			if err != nil {
				fmt.Printf("encrypt=%-7s -> OPEN ERR %v\n", m.enc, err)
				allok = false
				continue
			}
			db.SetMaxOpenConns(1)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			var one int
			qerr := db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
			cancel()
			db.Close()
			ok := qerr == nil && one == 1
			allok = allok && ok
			fmt.Printf("encrypt=%-7s (%s) -> ok=%v%s\n", m.enc, m.name, ok,
				func() string {
					if qerr != nil {
						return " :: " + qerr.Error()
					}
					return ""
				}())
		}
		after := status(statusURL)
		fmt.Printf("STATUS deltas: strict=%d on=%d handshake_errors=%d\n",
			num(after, "tls_terminated_strict")-num(before, "tls_terminated_strict"),
			num(after, "tls_terminated_on")-num(before, "tls_terminated_on"),
			num(after, "tls_handshake_errors")-num(before, "tls_handshake_errors"))
		if !allok {
			os.Exit(1)
		}

	default:
		fmt.Println("set SCENARIO=stampede|pinned-drop|handshake-drop|midresult-drop|backend-failover|tls-modes")
		os.Exit(2)
	}
}
