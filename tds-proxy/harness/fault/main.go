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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/microsoft/go-mssqldb"
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

	default:
		fmt.Println("set SCENARIO=stampede|pinned-drop|handshake-drop")
		os.Exit(2)
	}
}
