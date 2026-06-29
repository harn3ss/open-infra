package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/microsoft/go-mssqldb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Live database-engine internals for a Data Flow's database node (and, later, the
// RDS/Database detail page). The browser can't reach the DB; the BFF reads the
// node's credential Secret server-side, connects READ-ONLY (single conn, short
// timeout), and runs a small per-engine stats bundle. Issue #56: top queries,
// connections, replication-slot lag. Every sub-query degrades gracefully.

type dbStatsReq struct {
	Engine   string `json:"engine"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	SSL      bool   `json:"ssl"`
	Secret   struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Key       string `json:"key"`
	} `json:"secret"`
}

type connStats struct {
	Active   int `json:"active"`
	Idle     int `json:"idle"`
	IdleInTx int `json:"idleInTx"`
	Total    int `json:"total"`
	Max      int `json:"max"`
}
type queryStat struct {
	Query  string  `json:"query"`
	Calls  int64   `json:"calls"`
	MeanMs float64 `json:"meanMs"`
	TotalMs float64 `json:"totalMs"`
}
type replStat struct {
	Slot     string `json:"slot"`
	Active   bool   `json:"active"`
	LagBytes int64  `json:"lagBytes"`
}
type dbStats struct {
	Engine      string      `json:"engine"`
	Connections connStats   `json:"connections"`
	TopQueries  []queryStat `json:"topQueries"`
	Replication []replStat  `json:"replication"`
	Note        string      `json:"note,omitempty"`
}

func handleDBStats(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dbStatsReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Host == "" || in.Database == "" {
			writeError(w, http.StatusBadRequest, "database connection details required")
			return
		}
		if in.Secret.Name == "" || in.Secret.Namespace == "" {
			writeError(w, http.StatusBadRequest, "credential secret reference required")
			return
		}
		key := in.Secret.Key
		if key == "" {
			key = "password"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		sec, err := cs.CoreV1().Secrets(in.Secret.Namespace).Get(ctx, in.Secret.Name, metav1.GetOptions{})
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not read credential secret")
			return
		}
		pw := string(sec.Data[key])
		// A DataFlow node's host is often a bare Service name (e.g. "postgres"),
		// which only resolves inside that Service's namespace. The BFF runs elsewhere,
		// so qualify a dotless hostname with the flow's namespace. IPs and FQDNs
		// (which contain dots) are left untouched.
		if !strings.Contains(in.Host, ".") && in.Secret.Namespace != "" {
			in.Host = in.Host + "." + in.Secret.Namespace + ".svc.cluster.local"
		}
		if in.Port == 0 {
			switch in.Engine {
			case "mysql", "mariadb":
				in.Port = 3306
			case "sqlserver":
				in.Port = 1433
			default:
				in.Port = 5432
			}
		}

		driver, dsn := statsDSN(in, pw)
		if driver == "" {
			writeError(w, http.StatusBadRequest, "unsupported engine")
			return
		}
		db, err := sql.Open(driver, dsn)
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not open connection")
			return
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		if err := db.PingContext(ctx); err != nil {
			writeError(w, http.StatusBadGateway, "could not reach the database: "+err.Error())
			return
		}

		out := dbStats{Engine: in.Engine, TopQueries: []queryStat{}, Replication: []replStat{}}
		switch in.Engine {
		case "postgres":
			gatherPostgresStats(ctx, db, &out)
		case "mysql", "mariadb":
			gatherMysqlStats(ctx, db, &out)
		case "sqlserver":
			gatherSqlserverStats(ctx, db, &out)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func statsDSN(in dbStatsReq, pw string) (string, string) {
	switch in.Engine {
	case "postgres":
		ssl := "disable"
		if in.SSL {
			ssl = "require"
		}
		return "postgres", fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s connect_timeout=8",
			in.Host, in.Port, in.Database, in.Username, pw, ssl)
	case "mysql", "mariadb":
		tls := ""
		if in.SSL {
			tls = "&tls=skip-verify"
		}
		return "mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=8s%s", in.Username, pw, in.Host, in.Port, in.Database, tls)
	case "sqlserver":
		enc := "disable"
		q := url.Values{}
		q.Set("database", in.Database)
		if in.SSL {
			enc = "true"
			q.Set("trustservercertificate", "true")
		}
		q.Set("encrypt", enc)
		q.Set("dial timeout", "8")
		u := &url.URL{Scheme: "sqlserver", User: url.UserPassword(in.Username, pw), Host: fmt.Sprintf("%s:%d", in.Host, in.Port), RawQuery: q.Encode()}
		return "sqlserver", u.String()
	}
	return "", ""
}

func gatherPostgresStats(ctx context.Context, db *sql.DB, out *dbStats) {
	// connections by state + max_connections
	_ = db.QueryRowContext(ctx, `
		SELECT
		  count(*) FILTER (WHERE state='active'),
		  count(*) FILTER (WHERE state='idle'),
		  count(*) FILTER (WHERE state='idle in transaction'),
		  count(*),
		  (SELECT setting::int FROM pg_settings WHERE name='max_connections')
		FROM pg_stat_activity`).Scan(&out.Connections.Active, &out.Connections.Idle, &out.Connections.IdleInTx, &out.Connections.Total, &out.Connections.Max)

	// top queries — prefer pg_stat_statements; fall back to longest active queries
	rows, err := db.QueryContext(ctx, `
		SELECT query, calls, mean_exec_time, total_exec_time
		FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var q queryStat
			if rows.Scan(&q.Query, &q.Calls, &q.MeanMs, &q.TotalMs) == nil {
				out.TopQueries = append(out.TopQueries, q)
			}
		}
	} else {
		out.Note = "install pg_stat_statements for query history; showing longest active queries"
		r2, err2 := db.QueryContext(ctx, `
			SELECT query, round(extract(epoch FROM (now()-query_start))*1000)::float8
			FROM pg_stat_activity
			WHERE state='active' AND query NOT ILIKE '%pg_stat_activity%'
			ORDER BY now()-query_start DESC LIMIT 5`)
		if err2 == nil {
			defer r2.Close()
			for r2.Next() {
				var q queryStat
				if r2.Scan(&q.Query, &q.MeanMs) == nil {
					out.TopQueries = append(out.TopQueries, q)
				}
			}
		}
	}

	// replication-slot lag (the CDC-relevant one)
	r3, err := db.QueryContext(ctx, `
		SELECT slot_name, active, COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn),0)::bigint
		FROM pg_replication_slots ORDER BY 3 DESC`)
	if err == nil {
		defer r3.Close()
		for r3.Next() {
			var s replStat
			if r3.Scan(&s.Slot, &s.Active, &s.LagBytes) == nil {
				out.Replication = append(out.Replication, s)
			}
		}
	}
}

func gatherMysqlStats(ctx context.Context, db *sql.DB, out *dbStats) {
	var conn, maxc int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.processlist`).Scan(&conn)
	_ = db.QueryRowContext(ctx, `SELECT @@max_connections`).Scan(&maxc)
	out.Connections.Total, out.Connections.Active, out.Connections.Max = conn, conn, maxc
	rows, err := db.QueryContext(ctx, `
		SELECT LEFT(DIGEST_TEXT,200), COUNT_STAR, AVG_TIMER_WAIT/1e9, SUM_TIMER_WAIT/1e9
		FROM performance_schema.events_statements_summary_by_digest
		WHERE DIGEST_TEXT IS NOT NULL ORDER BY SUM_TIMER_WAIT DESC LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var q queryStat
			if rows.Scan(&q.Query, &q.Calls, &q.MeanMs, &q.TotalMs) == nil {
				out.TopQueries = append(out.TopQueries, q)
			}
		}
	} else {
		out.Note = "enable performance_schema for query stats"
	}
}

func gatherSqlserverStats(ctx context.Context, db *sql.DB, out *dbStats) {
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process=1`).Scan(&out.Connections.Total)
	out.Connections.Active = out.Connections.Total
	rows, err := db.QueryContext(ctx, `
		SELECT TOP 5 LEFT(t.text,200), s.execution_count,
		       s.total_elapsed_time/1000.0/NULLIF(s.execution_count,0), s.total_elapsed_time/1000.0
		FROM sys.dm_exec_query_stats s CROSS APPLY sys.dm_exec_sql_text(s.sql_handle) t
		ORDER BY s.total_elapsed_time DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var q queryStat
			if rows.Scan(&q.Query, &q.Calls, &q.MeanMs, &q.TotalMs) == nil {
				out.TopQueries = append(out.TopQueries, q)
			}
		}
	}
}
