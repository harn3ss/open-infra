package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

// --- Source table discovery (the DMS wizard's table picker) ------------------
//
// Before a Migration exists, the wizard needs the source's table list so the
// user can pick which to replicate. The BFF connects to the source database
// directly (Postgres/MySQL) using the endpoint + credentials the user entered,
// and lists base tables from information_schema. Short timeouts; single conn.

type discoverReq struct {
	Engine   string   `json:"engine"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Database string   `json:"database"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Schemas  []string `json:"schemas"`
	SSL      bool     `json:"ssl"`
}

func handleMigrationDiscover(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in discoverReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Host == "" || in.Database == "" {
			writeError(w, http.StatusBadRequest, "source connection details required")
			return
		}
		if in.Port == 0 {
			if in.Engine == "mysql" {
				in.Port = 3306
			} else {
				in.Port = 5432
			}
		}

		var driver, dsn, query string
		var args []any
		switch in.Engine {
		case "postgres":
			ssl := "disable"
			if in.SSL {
				ssl = "require"
			}
			driver = "postgres"
			dsn = fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s connect_timeout=8",
				in.Host, in.Port, in.Database, in.Username, in.Password, ssl)
			schemas := in.Schemas
			if len(schemas) == 0 {
				schemas = []string{"public"}
			}
			query = "SELECT table_name FROM information_schema.tables WHERE table_schema = ANY($1) AND table_type = 'BASE TABLE' ORDER BY table_name"
			args = []any{pq.Array(schemas)}
		case "mysql":
			tls := ""
			if in.SSL {
				tls = "&tls=skip-verify"
			}
			driver = "mysql"
			dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=8s%s",
				in.Username, in.Password, in.Host, in.Port, in.Database, tls)
			query = "SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = 'BASE TABLE' ORDER BY table_name"
			args = []any{in.Database}
		default:
			writeError(w, http.StatusBadRequest, "unsupported source engine")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		db, err := sql.Open(driver, dsn)
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not open source connection")
			return
		}
		defer db.Close()
		db.SetMaxOpenConns(1)

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			logger.Error("discover", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "could not read the source: "+err.Error())
			return
		}
		defer rows.Close()

		tables := make([]string, 0, 64)
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err != nil {
				break
			}
			tables = append(tables, t)
			if len(tables) >= 1000 {
				break
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tables": tables})
	}
}
