package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
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

// dbStatsTarget references a database NODE in a deployed DataFlow. The server
// resolves the node's host + credential Secret FROM the resource itself, scoped to
// the DataFlow's namespace. The client may NOT pass a free-form host or secret —
// doing so was an SSRF + cross-namespace secret-exfiltration hole (read any secret,
// ship it to any host).
type dbStatsTarget struct {
	Namespace string `json:"namespace"` // the DataFlow's namespace (== the secret's namespace)
	Name      string `json:"name"`      // DataFlow name
	Node      string `json:"node"`      // database node within it
}

// dbStatsReq is the resolved connection (built server-side from the CR, never from
// the client).
type dbStatsReq struct {
	Engine   string
	Host     string
	Port     int
	Database string
	Username string
	SSL      bool
}

// dfResource is the minimal DataFlow CR shape needed to resolve a node.
type dfResource struct {
	Spec struct {
		Nodes []struct {
			Name              string `json:"name"`
			Role              string `json:"role"`
			Engine            string `json:"engine"`
			Host              string `json:"host"`
			Port              int    `json:"port"`
			Database          string `json:"database"`
			Username          string `json:"username"`
			Schema            string `json:"schema"`
			SSL               bool   `json:"ssl"`
			PasswordSecretRef struct {
				Name string `json:"name"`
				Key  string `json:"key"`
			} `json:"passwordSecretRef"`
		} `json:"nodes"`
	} `json:"spec"`
}

type connStats struct {
	Active   int `json:"active"`
	Idle     int `json:"idle"`
	IdleInTx int `json:"idleInTx"`
	Total    int `json:"total"`
	Max      int `json:"max"`
}
type queryStat struct {
	Query   string  `json:"query"`
	Calls   int64   `json:"calls"`
	MeanMs  float64 `json:"meanMs"`
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

func handleDBStats(cs kubernetes.Interface, host *url.URL, transport http.RoundTripper, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var t dbStatsTarget
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil || t.Namespace == "" || t.Name == "" || t.Node == "" {
			writeError(w, http.StatusBadRequest, "namespace, name (data flow) and node are required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()

		// Resolve the connection FROM the DataFlow CR (read with the SA's own RBAC),
		// not from the request — so host + secret are whatever the resource declares,
		// scoped to its namespace. No client-controlled host or secret.
		u := *host
		u.Path = fmt.Sprintf("/apis/openinfra.dev/v1/namespaces/%s/dataflows/%s", t.Namespace, t.Name)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not read the data flow")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			writeError(w, http.StatusNotFound, "data flow not found")
			return
		}
		var df dfResource
		if err := json.NewDecoder(resp.Body).Decode(&df); err != nil {
			writeError(w, http.StatusBadGateway, "could not parse the data flow")
			return
		}

		var in dbStatsReq
		var secretName, key string
		found := false
		for _, n := range df.Spec.Nodes {
			role := n.Role
			if role == "" {
				role = "database"
			}
			if n.Name == t.Node && role == "database" {
				in = dbStatsReq{Engine: n.Engine, Host: n.Host, Port: n.Port, Database: n.Database, Username: n.Username, SSL: n.SSL}
				secretName = n.PasswordSecretRef.Name
				key = n.PasswordSecretRef.Key
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusBadRequest, "no such database node in this data flow")
			return
		}
		if key == "" {
			key = "password"
		}
		if secretName == "" {
			writeError(w, http.StatusBadRequest, "node has no credential secret")
			return
		}

		// The secret is read ONLY from the DataFlow's own namespace.
		sec, err := cs.CoreV1().Secrets(t.Namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not read credential secret")
			return
		}
		pw := string(sec.Data[key])
		// Bare Service host (e.g. "postgres") resolves only inside its namespace; the
		// BFF runs elsewhere, so qualify a dotless host with the DataFlow's namespace.
		if !strings.Contains(in.Host, ".") {
			in.Host = in.Host + "." + t.Namespace + ".svc.cluster.local"
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

		out, err := collectDBStats(ctx, in, pw)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// collectDBStats opens a short-lived read-only connection and gathers the engine's live
// stats. Shared by DataFlow-node Peek and managed-database Peek.
func collectDBStats(ctx context.Context, in dbStatsReq, pw string) (dbStats, error) {
	driver, dsn := statsDSN(in, pw)
	if driver == "" {
		return dbStats{}, fmt.Errorf("unsupported engine")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return dbStats{}, fmt.Errorf("could not open connection")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return dbStats{}, fmt.Errorf("could not reach the database: %s", err.Error())
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
	return out, nil
}

// handleManagedDBStats powers Peek on the /databases pages. The connection is resolved
// from the managed DB's own generated Secret (CNPG's "<name>-app", or a "<name>-<engine>-app"
// for the non-CNPG engines), namespace-scoped — never from the client (same rule as
// handleDBStats: no client-supplied host or secret).
func handleManagedDBStats(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		if ns == "" || name == "" {
			writeError(w, http.StatusBadRequest, "namespace and name are required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()

		in, pw, ok := resolveManagedConn(ctx, cs, ns, name)
		if !ok {
			writeError(w, http.StatusNotFound, "live stats aren't available for this database (no resolvable PostgreSQL/MySQL credentials)")
			return
		}
		if !strings.Contains(in.Host, ".") {
			in.Host = in.Host + "." + ns + ".svc.cluster.local"
		}
		out, err := collectDBStats(ctx, in, pw)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// resolveManagedConn finds connection details from a managed DB's generated Secret.
// CNPG Postgres: "<name>-app" with discrete host/port/username/password/dbname keys.
// Managed MySQL: "<base>-mysql-app" with a DATABASE_URL. Returns ok=false if neither.
func resolveManagedConn(ctx context.Context, cs kubernetes.Interface, ns, name string) (dbStatsReq, string, bool) {
	// CNPG Postgres — the cluster is "<app>-db"; its app secret is "<name>-app".
	if sec, err := cs.CoreV1().Secrets(ns).Get(ctx, name+"-app", metav1.GetOptions{}); err == nil {
		d := sec.Data
		if len(d["password"]) > 0 && (len(d["username"]) > 0 || len(d["user"]) > 0) {
			user := string(d["username"])
			if user == "" {
				user = string(d["user"])
			}
			port := 5432
			if p, e := strconv.Atoi(string(d["port"])); e == nil && p > 0 {
				port = p
			}
			h := string(d["host"])
			if h == "" {
				h = name + "-rw"
			}
			return dbStatsReq{Engine: "postgres", Host: h, Port: port, Database: string(d["dbname"]), Username: user, SSL: true}, string(d["password"]), true
		}
	}
	// Managed MySQL — "<base>-mysql-app" carries a DATABASE_URL.
	base := strings.TrimSuffix(name, "-mysql")
	if sec, err := cs.CoreV1().Secrets(ns).Get(ctx, base+"-mysql-app", metav1.GetOptions{}); err == nil {
		if raw := string(sec.Data["DATABASE_URL"]); raw != "" {
			if u, e := url.Parse(raw); e == nil && u.User != nil {
				pw, _ := u.User.Password()
				port := 3306
				if p, e := strconv.Atoi(u.Port()); e == nil && p > 0 {
					port = p
				}
				return dbStatsReq{Engine: "mysql", Host: u.Hostname(), Port: port, Database: strings.TrimPrefix(u.Path, "/"), Username: u.User.Username(), SSL: false}, pw, true
			}
		}
	}
	return dbStatsReq{}, "", false
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
