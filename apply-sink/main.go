// applysink — open-infra's generic CDC apply-sink + schema-sync.
//
// MODE=stream (default): consume Debezium change events (unwrapped JSON) from
//   NATS JetStream and apply them to a target SQL database (Postgres / MySQL /
//   SQL Server) as idempotent upserts/deletes. Generic: target table from the
//   subject, columns + PK discovered by introspecting the TARGET. Failed
//   messages retry up to MAX_DELIVER, then dead-letter to dlq.<subject>.
//
// MODE=schema-sync: introspect the source tables and CREATE the equivalent
//   tables on the target (auto-create). Same-engine = verbatim DDL; cross-engine
//   uses the type-mapping matrix.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/nats-io/nats.go"
)

type meta struct {
	cols    []string
	colType map[string]string
	pk      []string
	pkset   map[string]bool
}

var cache = map[string]meta{}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func atoiEnv(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func driverName(engine string) string {
	switch strings.ToLower(engine) {
	case "postgres", "postgresql", "pgx":
		return "pgx"
	case "mysql", "mariadb":
		return "mysql"
	case "sqlserver", "mssql":
		return "sqlserver"
	default:
		return engine
	}
}

func openDB(engine, dsn string) (*sql.DB, error) {
	var db *sql.DB
	// A replication apply-sink sets a per-session flag so the per-site stamping
	// trigger skips replication-applied rows (preserving the remote version,origin):
	//   - Postgres: options=-c app.replication=on in the DSN (set by the composition)
	//   - SQL Server: sp_set_session_context via the connector's SessionInitSQL
	//   - MySQL: a @app_replication user var via the DSN sessionVariables
	if driverName(engine) == "sqlserver" && os.Getenv("REPL_APPLY") == "on" {
		c, err := mssql.NewConnector(dsn)
		if err != nil {
			return nil, err
		}
		c.SessionInitSQL = "EXEC sp_set_session_context N'app_replication', N'on'"
		db = sql.OpenDB(c)
	} else {
		if driverName(engine) == "mysql" && os.Getenv("REPL_APPLY") == "on" {
			if strings.Contains(dsn, "?") {
				dsn += "&"
			} else {
				dsn += "?"
			}
			dsn += "sessionVariables=%40app_replication%3D1" // SET @app_replication=1
		}
		var err error
		db, err = sql.Open(driverName(engine), dsn)
		if err != nil {
			return nil, err
		}
	}
	var perr error
	for i := 0; i < 40; i++ {
		if perr = db.Ping(); perr == nil {
			return db, nil
		}
		log.Printf("waiting for %s db... (%v)", engine, perr)
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("ping %s: %w", engine, perr)
}

// targetSchema maps the source schema (from the subject) to the target's
// schema/namespace. MySQL has no schema layer (uses the DSN database) so we go
// unqualified; SQL Server defaults to dbo; Postgres keeps the source schema.
func targetSchema(engine, subjectSchema string) string {
	if v := os.Getenv("TARGET_SCHEMA"); v != "" {
		return v
	}
	switch driverName(engine) {
	case "mysql":
		return ""
	case "sqlserver":
		return "dbo"
	default:
		return subjectSchema
	}
}

func main() {
	switch env("MODE", "stream") {
	case "schema-sync":
		runSchemaSync()
	case "mm-prep":
		runMMPrep()
	default:
		runStream()
	}
}

// ===================== MULTI-MASTER PREP MODE =====================

// runMMPrep installs the multi-master machinery on a site: a version column +
// origin column on each table, and (Postgres) a Hybrid Logical Clock + a
// per-site BEFORE trigger that stamps (version, origin) on native writes and
// advances the local clock on replication-applied writes (those carry the
// app.replication session flag). Idempotent.
func runMMPrep() {
	engine := env("PREP_ENGINE", "postgres")
	dsn := os.ExpandEnv(env("PREP_DSN", ""))
	site := env("SITE", "")
	vcol := env("VERSION_COLUMN", "_mm_version")
	ocol := env("ORIGIN_COLUMN", "_mm_origin")
	tables := env("TABLES", "")
	if dsn == "" || site == "" {
		log.Fatal("PREP_DSN and SITE are required for mm-prep")
	}
	db, err := openDB(engine, dsn)
	if err != nil {
		log.Fatal(err)
	}
	exec := func(q string) {
		if _, err := db.Exec(q); err != nil {
			log.Fatalf("mm-prep exec failed: %v\n  sql: %s", err, q)
		}
	}
	switch driverName(engine) {
	case "pgx":
		for _, q := range pgHLCSetup(site, vcol) {
			exec(q)
		}
		for _, t := range splitTables(tables) {
			qt := qualified(engine, t[0], t[1])
			exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s bigint`, qt, quoteIdent(engine, vcol)))
			exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s text`, qt, quoteIdent(engine, ocol)))
			exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS mm_stamp_trg ON %s`, qt))
			exec(fmt.Sprintf(`CREATE TRIGGER mm_stamp_trg BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION mm_stamp()`, qt))
			log.Printf("mm-prep: prepared %s.%s (site=%s)", t[0], t[1], site)
		}
	case "sqlserver":
		// SQL Server has no BEFORE-row triggers, so stamping uses an AFTER trigger
		// with a TRIGGER_NESTLEVEL recursion guard. Native writes get an HLC
		// (version, origin); replication-applied writes (session flag) are skipped
		// but advance the local HLC (observe). A DEFAULT keeps the pre-trigger
		// version non-null. MERGE (the apply path) works with AFTER triggers.
		exec(`IF OBJECT_ID('mm_hlc_state','U') IS NULL CREATE TABLE mm_hlc_state(id int primary key, pt bigint NOT NULL DEFAULT 0, lc int NOT NULL DEFAULT 0)`)
		exec(`IF NOT EXISTS(SELECT 1 FROM mm_hlc_state) INSERT INTO mm_hlc_state(id) VALUES(1)`)
		for _, t := range splitTables(tables) {
			schema, table := t[0], t[1]
			qt := qualified(engine, schema, table)
			qv := quoteIdent(engine, vcol)
			qo := quoteIdent(engine, ocol)
			exec(fmt.Sprintf(`IF COL_LENGTH('%s.%s','%s') IS NULL ALTER TABLE %s ADD %s bigint DEFAULT (DATEDIFF_BIG(MILLISECOND,'19700101',SYSUTCDATETIME())*65536)`, schema, table, vcol, qt, qv))
			exec(fmt.Sprintf(`IF COL_LENGTH('%s.%s','%s') IS NULL ALTER TABLE %s ADD %s nvarchar(16) DEFAULT N'%s'`, schema, table, ocol, qt, qo, site))
			m, ierr := introspectSqlserver(db, schema, table)
			if ierr != nil {
				log.Fatalf("mm-prep introspect %s.%s: %v", schema, table, ierr)
			}
			var pkjoin []string
			for _, p := range m.pk {
				qp := quoteIdent(engine, p)
				pkjoin = append(pkjoin, fmt.Sprintf("t.%s=i.%s", qp, qp))
			}
			if len(pkjoin) == 0 {
				log.Fatalf("%s.%s has no primary key", schema, table)
			}
			trg := "mm_stamp_" + strings.ReplaceAll(table, ".", "_")
			hlc := `DECLARE @pt bigint,@lc int,@now bigint,@v bigint; SELECT @pt=pt,@lc=lc FROM mm_hlc_state WITH (UPDLOCK,HOLDLOCK) WHERE id=1; SET @now=DATEDIFF_BIG(MILLISECOND,'19700101',SYSUTCDATETIME()); IF @now>@pt BEGIN SET @pt=@now; SET @lc=0; END ELSE SET @lc=@lc+1; UPDATE mm_hlc_state SET pt=@pt,lc=@lc WHERE id=1; SET @v=@pt*65536+@lc;`
			obs := fmt.Sprintf(`DECLARE @rmax bigint=(SELECT MAX(%s) FROM inserted); UPDATE mm_hlc_state SET pt=CASE WHEN @rmax/65536>pt THEN @rmax/65536 ELSE pt END WHERE id=1;`, qv)
			body := fmt.Sprintf(`CREATE OR ALTER TRIGGER %s ON %s AFTER INSERT, UPDATE AS BEGIN SET NOCOUNT ON; IF TRIGGER_NESTLEVEL(OBJECT_ID(N'%s')) > 1 RETURN; IF SESSION_CONTEXT(N'app_replication')=N'on' BEGIN %s RETURN; END %s UPDATE t SET %s=@v, %s=N'%s' FROM %s t JOIN inserted i ON %s; END`,
				trg, qt, trg, obs, hlc, qv, qo, site, qt, strings.Join(pkjoin, " AND "))
			exec(body)
			log.Printf("mm-prep: prepared %s.%s + AFTER stamp trigger (site=%s)", schema, table, site)
		}
	case "mysql":
		// MySQL has BEFORE-row triggers. Stamp (version, origin) on native writes;
		// skip replication-applied writes (the @app_replication session var the sink
		// sets). version is millisecond-clock based (<<16), comparable to the PG/SQL
		// Server HLC versions for cross-engine LWW.
		for _, t := range splitTables(tables) {
			table := t[1]
			qtbl := quoteIdent(engine, table)
			qv := quoteIdent(engine, vcol)
			qo := quoteIdent(engine, ocol)
			ensureCol := func(col, typ string) {
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`, table, col).Scan(&n); err != nil {
					log.Fatalf("mm-prep check col %s: %v", col, err)
				}
				if n == 0 {
					exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", qtbl, quoteIdent(engine, col), typ))
				}
			}
			ensureCol(vcol, "bigint")
			ensureCol(ocol, "varchar(16)")
			stamp := fmt.Sprintf("SET NEW.%s = CAST(UNIX_TIMESTAMP(NOW(3))*1000 AS UNSIGNED)*65536, NEW.%s = '%s'", qv, qo, site)
			for _, ev := range []string{"INSERT", "UPDATE"} {
				trg := quoteIdent(engine, fmt.Sprintf("mm_stamp_%s_%s", table, strings.ToLower(ev[:1])))
				exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s", trg))
				exec(fmt.Sprintf("CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW BEGIN IF @app_replication IS NULL THEN %s; END IF; END",
					trg, ev, qtbl, stamp))
			}
			log.Printf("mm-prep: prepared %s + BEFORE stamp triggers (site=%s)", table, site)
		}
	default:
		log.Fatalf("mm-prep not implemented for engine %s", engine)
	}
	log.Printf("mm-prep done (site=%s)", site)
}

func splitTables(tables string) [][2]string {
	var out [][2]string
	for _, t := range strings.Split(tables, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		p := strings.SplitN(t, ".", 2)
		if len(p) == 2 {
			out = append(out, [2]string{p[0], p[1]})
		} else {
			out = append(out, [2]string{"public", p[0]})
		}
	}
	return out
}

// pgHLCSetup returns the (idempotent) Hybrid Logical Clock + stamping function
// for a Postgres site. The stamp function bakes in this site's id + version col.
func pgHLCSetup(site, vcol string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS mm_hlc_state(id int primary key, pt bigint NOT NULL DEFAULT 0, lc int NOT NULL DEFAULT 0)`,
		`INSERT INTO mm_hlc_state(id) VALUES (1) ON CONFLICT DO NOTHING`,
		`CREATE OR REPLACE FUNCTION mm_phys_ms() RETURNS bigint AS $f$ SELECT (floor(extract(epoch from clock_timestamp())*1000) + coalesce(current_setting('app.clock_skew_ms', true),'0')::bigint)::bigint; $f$ LANGUAGE sql`,
		`CREATE OR REPLACE FUNCTION mm_hlc_tick() RETURNS bigint AS $f$ DECLARE p bigint; l int; n bigint; BEGIN SELECT pt,lc INTO p,l FROM mm_hlc_state WHERE id=1 FOR UPDATE; n:=mm_phys_ms(); IF n>p THEN p:=n; l:=0; ELSE l:=l+1; END IF; UPDATE mm_hlc_state SET pt=p,lc=l WHERE id=1; RETURN p*65536+l; END; $f$ LANGUAGE plpgsql`,
		`CREATE OR REPLACE FUNCTION mm_hlc_observe(rv bigint) RETURNS void AS $f$ DECLARE p bigint; l int; n bigint; rp bigint; rl int; np bigint; nl int; BEGIN IF rv IS NULL THEN RETURN; END IF; SELECT pt,lc INTO p,l FROM mm_hlc_state WHERE id=1 FOR UPDATE; n:=mm_phys_ms(); rp:=rv/65536; rl:=(rv%65536)::int; np:=greatest(p,rp,n); IF np=p AND np=rp THEN nl:=greatest(l,rl)+1; ELSIF np=p THEN nl:=l+1; ELSIF np=rp THEN nl:=rl+1; ELSE nl:=0; END IF; UPDATE mm_hlc_state SET pt=np,lc=nl WHERE id=1; END; $f$ LANGUAGE plpgsql`,
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION mm_stamp() RETURNS trigger AS $f$ BEGIN IF current_setting('app.replication', true)='on' THEN PERFORM mm_hlc_observe(NEW.%s); RETURN NEW; END IF; NEW.%s:=mm_hlc_tick(); NEW.%s:='%s'; RETURN NEW; END; $f$ LANGUAGE plpgsql`,
			vcol, vcol, env("ORIGIN_COLUMN", "_mm_origin"), site),
	}
}

// ===================== STREAM MODE =====================

func runStream() {
	engine := env("TARGET_ENGINE", "postgres")
	dsn := os.ExpandEnv(env("TARGET_DSN", "")) // ${TARGET_PASSWORD} injected from a Secret
	natsURL := env("NATS_URL", "nats://nats:4222")
	stream := env("STREAM", "CDC")
	subject := env("SUBJECT", "cdc.>")
	durable := env("DURABLE", "gosink")
	maxDeliver := atoiEnv("MAX_DELIVER", 5)

	if dsn == "" {
		log.Fatal("TARGET_DSN is required")
	}
	db, err := openDB(engine, dsn)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("connected target engine=%s", engine)

	nc, err := nats.Connect(natsURL, nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		log.Fatalf("nats connect: %v", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("jetstream: %v", err)
	}
	_, _ = js.AddStream(&nats.StreamConfig{
		Name: "DLQ", Subjects: []string{"dlq.>"},
		Storage: nats.FileStorage, MaxBytes: 64 * 1024 * 1024, Discard: nats.DiscardOld,
	})
	sub, err := js.PullSubscribe(subject, durable,
		nats.BindStream(stream), nats.AckExplicit(), nats.DeliverAll(), nats.ManualAck())
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Printf("apply-sink running: stream=%s subject=%s durable=%s maxDeliver=%d", stream, subject, durable, maxDeliver)

	for {
		msgs, err := sub.Fetch(100, nats.MaxWait(5*time.Second))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			log.Printf("fetch: %v", err)
			time.Sleep(time.Second)
			continue
		}
		for _, m := range msgs {
			retry, err := apply(db, engine, m)
			if err == nil {
				_ = m.Ack()
				continue
			}
			if retry {
				// transient (e.g. target table not created by schema-sync yet) —
				// retry indefinitely, never dead-letter, so we don't drop good rows.
				log.Printf("retry subj=%s: %v", m.Subject, err)
				_ = m.Nak()
				continue
			}
			nd := 1
			if md, e := m.Metadata(); e == nil {
				nd = int(md.NumDelivered)
			}
			if nd >= maxDeliver {
				log.Printf("DEAD-LETTER subj=%s after %d attempts: %v", m.Subject, nd, err)
				_, _ = js.Publish("dlq."+m.Subject, m.Data)
				_ = m.Term()
			} else {
				log.Printf("apply error (attempt %d) subj=%s: %v", nd, m.Subject, err)
				_ = m.Nak()
			}
		}
	}
}

// apply returns (retryable, err). retryable=true means a transient condition
// (e.g. the target table isn't created yet) — the caller should Nak and retry
// without ever dead-lettering. retryable=false errors are data problems that
// dead-letter after MAX_DELIVER.
func apply(db *sql.DB, engine string, m *nats.Msg) (bool, error) {
	parts := strings.Split(m.Subject, ".")
	if len(parts) < 2 {
		return false, fmt.Errorf("subject too short: %s", m.Subject)
	}
	schema := targetSchema(engine, parts[len(parts)-2])
	table := parts[len(parts)-1]

	dec := json.NewDecoder(strings.NewReader(string(m.Data)))
	dec.UseNumber()
	var row map[string]any
	if err := dec.Decode(&row); err != nil {
		return false, fmt.Errorf("decode: %w", err)
	}
	if row == nil {
		return false, nil
	}
	deleted := fmt.Sprint(row["__deleted"]) == "true"
	delete(row, "__deleted")

	// Bidirectional loop prevention via an origin-marker column. Each direction's
	// sink drops events that originated at the peer site (so a write doesn't echo
	// back and loop), and stamps its own SITE on everything it forwards. Upsert
	// echoes are the loop risk (Postgres emits a WAL event even for no-op updates);
	// deletes self-terminate (deleting an absent row produces no event).
	if oc := os.Getenv("ORIGIN_COLUMN"); oc != "" {
		if skip := os.Getenv("SKIP_ORIGIN"); skip != "" && fmt.Sprint(row[oc]) == skip {
			return false, nil // originated at the peer — don't echo it back (ack + drop)
		}
		// NOTE: the writer stamps the origin (a per-site trigger), not the sink, so
		// the marker reflects the true last-writer for last-write-wins tiebreaking.
	}

	mt, err := getMeta(db, engine, schema, table)
	if err != nil {
		return true, err // target table may not be created by schema-sync yet
	}
	if deleted {
		return false, execDelete(db, engine, schema, table, mt, row)
	}
	return false, execUpsert(db, engine, schema, table, mt, row)
}

func getMeta(db *sql.DB, engine, schema, table string) (meta, error) {
	key := engine + "|" + schema + "|" + table
	if m, ok := cache[key]; ok {
		return m, nil
	}
	var m meta
	var err error
	switch driverName(engine) {
	case "pgx":
		m, err = introspectPostgres(db, schema, table)
	case "mysql":
		m, err = introspectMysql(db, schema, table)
	case "sqlserver":
		m, err = introspectSqlserver(db, schema, table)
	default:
		return meta{}, fmt.Errorf("introspection not implemented for engine %s", engine)
	}
	if err != nil {
		return meta{}, err
	}
	if len(m.pk) == 0 {
		return meta{}, fmt.Errorf("%s.%s has no primary key (required for upsert)", schema, table)
	}
	m.pkset = map[string]bool{}
	for _, p := range m.pk {
		m.pkset[p] = true
	}
	cache[key] = m
	log.Printf("introspected %s.%s cols=%v pk=%v", schema, table, m.cols, m.pk)
	return m, nil
}

func scanCols(rows *sql.Rows, m *meta) error {
	for rows.Next() {
		var c, t string
		if err := rows.Scan(&c, &t); err != nil {
			return err
		}
		m.cols = append(m.cols, c)
		m.colType[c] = strings.ToLower(t)
	}
	return nil
}

func introspectPostgres(db *sql.DB, schema, table string) (meta, error) {
	m := meta{colType: map[string]string{}}
	rows, err := db.Query(`SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema=$1 AND table_name=$2 ORDER BY ordinal_position`, schema, table)
	if err != nil {
		return m, err
	}
	if err := scanCols(rows, &m); err != nil {
		rows.Close()
		return m, err
	}
	rows.Close()
	pkRows, err := db.Query(`SELECT kcu.column_name FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema
		WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=$1 AND tc.table_name=$2
		ORDER BY kcu.ordinal_position`, schema, table)
	if err != nil {
		return m, err
	}
	defer pkRows.Close()
	for pkRows.Next() {
		var c string
		if err := pkRows.Scan(&c); err != nil {
			return m, err
		}
		m.pk = append(m.pk, c)
	}
	return m, nil
}

func introspectMysql(db *sql.DB, schema, table string) (meta, error) {
	m := meta{colType: map[string]string{}}
	var rows *sql.Rows
	var err error
	if schema == "" {
		rows, err = db.Query(`SELECT column_name, data_type FROM information_schema.columns
			WHERE table_schema=DATABASE() AND table_name=? ORDER BY ordinal_position`, table)
	} else {
		rows, err = db.Query(`SELECT column_name, data_type FROM information_schema.columns
			WHERE table_schema=? AND table_name=? ORDER BY ordinal_position`, schema, table)
	}
	if err != nil {
		return m, err
	}
	if err := scanCols(rows, &m); err != nil {
		rows.Close()
		return m, err
	}
	rows.Close()
	var pkRows *sql.Rows
	if schema == "" {
		pkRows, err = db.Query(`SELECT column_name FROM information_schema.key_column_usage
			WHERE table_schema=DATABASE() AND table_name=? AND constraint_name='PRIMARY' ORDER BY ordinal_position`, table)
	} else {
		pkRows, err = db.Query(`SELECT column_name FROM information_schema.key_column_usage
			WHERE table_schema=? AND table_name=? AND constraint_name='PRIMARY' ORDER BY ordinal_position`, schema, table)
	}
	if err != nil {
		return m, err
	}
	defer pkRows.Close()
	for pkRows.Next() {
		var c string
		if err := pkRows.Scan(&c); err != nil {
			return m, err
		}
		m.pk = append(m.pk, c)
	}
	return m, nil
}

func introspectSqlserver(db *sql.DB, schema, table string) (meta, error) {
	m := meta{colType: map[string]string{}}
	rows, err := db.Query(`SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema=@p1 AND table_name=@p2 ORDER BY ordinal_position`, schema, table)
	if err != nil {
		return m, err
	}
	if err := scanCols(rows, &m); err != nil {
		rows.Close()
		return m, err
	}
	rows.Close()
	pkRows, err := db.Query(`SELECT kcu.column_name FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name
		WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=@p1 AND tc.table_name=@p2
		ORDER BY kcu.ordinal_position`, schema, table)
	if err != nil {
		return m, err
	}
	defer pkRows.Close()
	for pkRows.Next() {
		var c string
		if err := pkRows.Scan(&c); err != nil {
			return m, err
		}
		m.pk = append(m.pk, c)
	}
	return m, nil
}

// ---- identifier / placeholder dialect ----

func quoteIdent(engine, s string) string {
	switch driverName(engine) {
	case "mysql":
		return "`" + s + "`"
	case "sqlserver":
		return "[" + s + "]"
	default:
		return `"` + s + `"`
	}
}

func placeholder(engine string, i int) string {
	switch driverName(engine) {
	case "pgx":
		return fmt.Sprintf("$%d", i+1)
	case "sqlserver":
		return fmt.Sprintf("@p%d", i+1)
	default:
		return "?"
	}
}

func qualified(engine, schema, table string) string {
	if schema == "" {
		return quoteIdent(engine, table)
	}
	return quoteIdent(engine, schema) + "." + quoteIdent(engine, table)
}

func presentCols(mt meta, row map[string]any) []string {
	var cols []string
	for _, c := range mt.cols {
		if _, ok := row[c]; ok {
			cols = append(cols, c)
		}
	}
	return cols
}

func execUpsert(db *sql.DB, engine, schema, table string, mt meta, row map[string]any) error {
	cols := presentCols(mt, row)
	if len(cols) == 0 {
		return fmt.Errorf("no matching columns for %s.%s", schema, table)
	}
	vals := make([]any, len(cols))
	for i, c := range cols {
		vals[i] = coerce(row[c], mt.colType[c])
	}
	q := buildUpsert(engine, schema, table, cols, mt)
	if _, err := db.Exec(q, vals...); err != nil {
		return err
	}
	return nil
}

// buildUpsert produces an engine-specific idempotent upsert. Column values are
// bound positionally (cols order).
func buildUpsert(engine, schema, table string, cols []string, mt meta) string {
	qt := qualified(engine, schema, table)
	qcols := make([]string, len(cols))
	ph := make([]string, len(cols))
	for i, c := range cols {
		qcols[i] = quoteIdent(engine, c)
		ph[i] = placeholder(engine, i)
	}
	var qpk []string
	for _, p := range mt.pk {
		qpk = append(qpk, quoteIdent(engine, p))
	}
	switch driverName(engine) {
	case "mysql":
		// Last-write-wins: only take the incoming value when it's newer (per-column
		// IF guarded on the version, origin tiebreak). VALUES(col) is the incoming row.
		var cond string
		if cc := os.Getenv("CONFLICT_COLUMN"); cc != "" {
			qcc := quoteIdent(engine, cc)
			cond = fmt.Sprintf("VALUES(%s) > %s", qcc, qcc)
			if oc := os.Getenv("ORIGIN_COLUMN"); oc != "" {
				qoc := quoteIdent(engine, oc)
				cond += fmt.Sprintf(" OR (VALUES(%s) = %s AND VALUES(%s) > %s)", qcc, qcc, qoc, qoc)
			}
		}
		var set []string
		for _, c := range cols {
			if mt.pkset[c] {
				continue
			}
			qc := quoteIdent(engine, c)
			if cond != "" {
				set = append(set, fmt.Sprintf("%s=IF(%s, VALUES(%s), %s)", qc, cond, qc, qc))
			} else {
				set = append(set, fmt.Sprintf("%s=VALUES(%s)", qc, qc))
			}
		}
		if len(set) == 0 { // all-PK table: no-op assignment so the clause is valid
			set = append(set, fmt.Sprintf("%s=%s", qpk[0], qpk[0]))
		}
		return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s",
			qt, strings.Join(qcols, ","), strings.Join(ph, ","), strings.Join(set, ","))

	case "sqlserver":
		using := make([]string, len(cols))
		for i, c := range cols {
			using[i] = fmt.Sprintf("%s AS %s", ph[i], quoteIdent(engine, c))
		}
		var on []string
		for _, p := range mt.pk {
			qp := quoteIdent(engine, p)
			on = append(on, fmt.Sprintf("t.%s=s.%s", qp, qp))
		}
		var set []string
		for _, c := range cols {
			if mt.pkset[c] {
				continue
			}
			qc := quoteIdent(engine, c)
			set = append(set, fmt.Sprintf("t.%s=s.%s", qc, qc))
		}
		var sCols []string
		for _, c := range cols {
			sCols = append(sCols, "s."+quoteIdent(engine, c))
		}
		matched := ""
		if len(set) > 0 {
			cond := ""
			if cc := os.Getenv("CONFLICT_COLUMN"); cc != "" {
				qcc := quoteIdent(engine, cc)
				cond = fmt.Sprintf(" AND (s.%s > t.%s", qcc, qcc)
				if oc := os.Getenv("ORIGIN_COLUMN"); oc != "" {
					qoc := quoteIdent(engine, oc)
					cond += fmt.Sprintf(" OR (s.%s = t.%s AND s.%s > t.%s)", qcc, qcc, qoc, qoc)
				}
				cond += ")"
			}
			matched = " WHEN MATCHED" + cond + " THEN UPDATE SET " + strings.Join(set, ",")
		}
		return fmt.Sprintf("MERGE INTO %s AS t USING (SELECT %s) AS s ON (%s)%s WHEN NOT MATCHED THEN INSERT (%s) VALUES (%s);",
			qt, strings.Join(using, ","), strings.Join(on, " AND "), matched,
			strings.Join(qcols, ","), strings.Join(sCols, ","))

	default: // postgres
		var set []string
		for _, c := range cols {
			if mt.pkset[c] {
				continue
			}
			qc := quoteIdent(engine, c)
			set = append(set, fmt.Sprintf("%s=EXCLUDED.%s", qc, qc))
		}
		q := fmt.Sprintf("INSERT INTO %s AS t (%s) VALUES (%s)", qt, strings.Join(qcols, ","), strings.Join(ph, ","))
		if len(set) > 0 {
			q += fmt.Sprintf(" ON CONFLICT (%s) DO UPDATE SET %s", strings.Join(qpk, ","), strings.Join(set, ","))
			// Last-write-wins conflict resolution: only overwrite when the incoming
			// version is newer; ties broken deterministically by the origin marker.
			if cc := os.Getenv("CONFLICT_COLUMN"); cc != "" {
				qcc := quoteIdent(engine, cc)
				w := fmt.Sprintf("t.%s < EXCLUDED.%s", qcc, qcc)
				if oc := os.Getenv("ORIGIN_COLUMN"); oc != "" {
					qoc := quoteIdent(engine, oc)
					w += fmt.Sprintf(" OR (t.%s = EXCLUDED.%s AND t.%s < EXCLUDED.%s)", qcc, qcc, qoc, qoc)
				}
				q += " WHERE " + w
			}
		} else {
			q += fmt.Sprintf(" ON CONFLICT (%s) DO NOTHING", strings.Join(qpk, ","))
		}
		return q
	}
}

func execDelete(db *sql.DB, engine, schema, table string, mt meta, row map[string]any) error {
	var where []string
	var vals []any
	for i, p := range mt.pk {
		if _, ok := row[p]; !ok {
			return fmt.Errorf("delete missing pk %s", p)
		}
		where = append(where, fmt.Sprintf("%s=%s", quoteIdent(engine, p), placeholder(engine, i)))
		vals = append(vals, coerce(row[p], mt.colType[p]))
	}
	q := fmt.Sprintf("DELETE FROM %s WHERE %s", qualified(engine, schema, table), strings.Join(where, " AND "))
	_, err := db.Exec(q, vals...)
	return err
}

func coerce(v any, colType string) any {
	if v == nil {
		return nil
	}
	if isTemporal(colType) {
		if s, ok := v.(string); ok {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
				if t, err := time.Parse(layout, s); err == nil {
					return t
				}
			}
		}
		// Debezium emits non-timezone temporals as epoch integers: date = days,
		// timestamp/datetime = millis or micros (by precision). Disambiguate by magnitude.
		if n, ok := v.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				if colType == "date" {
					return time.Unix(i*86400, 0).UTC()
				}
				switch {
				case i >= 1e17:
					return time.Unix(0, i).UTC() // nanos
				case i >= 1e15:
					return time.UnixMicro(i).UTC()
				case i >= 1e12:
					return time.UnixMilli(i).UTC()
				default:
					return time.Unix(i, 0).UTC()
				}
			}
		}
	}
	if n, ok := v.(json.Number); ok {
		if strings.ContainsAny(n.String(), ".eE") {
			if f, err := n.Float64(); err == nil {
				return f
			}
		}
		if i, err := n.Int64(); err == nil {
			return i
		}
		return n.String()
	}
	return v
}

func isTemporal(t string) bool {
	return strings.Contains(t, "timestamp") || strings.Contains(t, "date") || strings.Contains(t, "datetime")
}

// ===================== SCHEMA-SYNC MODE =====================

type ddlCol struct {
	name    string
	typ     string
	notnull bool
}

func runSchemaSync() {
	srcEngine := env("SOURCE_ENGINE", "postgres")
	srcDSN := os.ExpandEnv(env("SOURCE_DSN", "")) // ${SOURCE_PASSWORD} from a Secret
	tgtEngine := env("TARGET_ENGINE", "postgres")
	tgtDSN := os.ExpandEnv(env("TARGET_DSN", "")) // ${TARGET_PASSWORD} from a Secret
	tables := env("TABLES", "")
	if srcDSN == "" || tgtDSN == "" {
		log.Fatal("SOURCE_DSN and TARGET_DSN required for schema-sync")
	}
	src, err := openDB(srcEngine, srcDSN)
	if err != nil {
		log.Fatal(err)
	}
	tgt, err := openDB(tgtEngine, tgtDSN)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("schema-sync %s -> %s", srcEngine, tgtEngine)

	var list [][2]string
	if strings.TrimSpace(tables) == "" {
		list, err = discoverTables(src, srcEngine)
		if err != nil {
			log.Fatalf("discover: %v", err)
		}
	} else {
		for _, t := range strings.Split(tables, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			p := strings.SplitN(t, ".", 2)
			if len(p) == 2 {
				list = append(list, [2]string{p[0], p[1]})
			} else {
				list = append(list, [2]string{"public", p[0]})
			}
		}
	}

	for _, st := range list {
		schema, table := st[0], st[1]
		cols, pk, err := introspectSourceDDL(src, srcEngine, tgtEngine, schema, table)
		if err != nil {
			log.Fatalf("introspect %s.%s: %v", schema, table, err)
		}
		ts := targetSchema(tgtEngine, schema)
		if err := createTargetTable(tgt, tgtEngine, ts, table, cols, pk); err != nil {
			log.Fatalf("create %s.%s on target: %v", schema, table, err)
		}
		log.Printf("created %s on target (%d cols, pk=%v)", table, len(cols), pk)
	}
	log.Printf("schema-sync done: %d tables", len(list))
}

func discoverTables(db *sql.DB, engine string) ([][2]string, error) {
	var out [][2]string
	switch driverName(engine) {
	case "pgx":
		rows, err := db.Query(`SELECT table_schema, table_name FROM information_schema.tables
			WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema')`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var s, t string
			if err := rows.Scan(&s, &t); err != nil {
				return nil, err
			}
			out = append(out, [2]string{s, t})
		}
	case "mysql":
		rows, err := db.Query(`SELECT table_schema, table_name FROM information_schema.tables
			WHERE table_type='BASE TABLE' AND table_schema=DATABASE()`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var s, t string
			if err := rows.Scan(&s, &t); err != nil {
				return nil, err
			}
			out = append(out, [2]string{s, t})
		}
	case "sqlserver":
		rows, err := db.Query(`SELECT table_schema, table_name FROM information_schema.tables
			WHERE table_type='BASE TABLE'`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var s, t string
			if err := rows.Scan(&s, &t); err != nil {
				return nil, err
			}
			out = append(out, [2]string{s, t})
		}
	default:
		return nil, fmt.Errorf("discover not implemented for %s", engine)
	}
	return out, nil
}

func introspectSourceDDL(db *sql.DB, srcEngine, tgtEngine, schema, table string) ([]ddlCol, []string, error) {
	switch driverName(srcEngine) {
	case "pgx":
		return introspectSourceDDLPostgres(db, srcEngine, tgtEngine, schema, table)
	case "mysql":
		return introspectSourceDDLMysql(db, srcEngine, tgtEngine, schema, table)
	case "sqlserver":
		return introspectSourceDDLSqlserver(db, srcEngine, tgtEngine, schema, table)
	default:
		return nil, nil, fmt.Errorf("source introspection not implemented for %s yet", srcEngine)
	}
}

func introspectSourceDDLSqlserver(db *sql.DB, srcEngine, tgtEngine, schema, table string) ([]ddlCol, []string, error) {
	rows, err := db.Query(`SELECT column_name, data_type, character_maximum_length, numeric_precision, numeric_scale, is_nullable
		FROM information_schema.columns WHERE table_schema=@p1 AND table_name=@p2 ORDER BY ordinal_position`, schema, table)
	if err != nil {
		return nil, nil, err
	}
	var cols []ddlCol
	for rows.Next() {
		var name, dtype, nullable string
		var charLen, numPrec, numScale sql.NullInt64
		if err := rows.Scan(&name, &dtype, &charLen, &numPrec, &numScale, &nullable); err != nil {
			rows.Close()
			return nil, nil, err
		}
		srcType := dtype
		switch strings.ToLower(dtype) {
		case "varchar", "nvarchar", "char", "nchar", "binary", "varbinary":
			if charLen.Valid {
				if charLen.Int64 == -1 {
					srcType = dtype + "(max)"
				} else {
					srcType = fmt.Sprintf("%s(%d)", dtype, charLen.Int64)
				}
			}
		case "decimal", "numeric":
			if numPrec.Valid {
				srcType = fmt.Sprintf("%s(%d,%d)", dtype, numPrec.Int64, numScale.Int64)
			}
		}
		cols = append(cols, ddlCol{name: name, typ: mapType(srcEngine, tgtEngine, srcType), notnull: nullable == "NO"})
	}
	rows.Close()
	pkRows, err := db.Query(`SELECT kcu.column_name FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name
		WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=@p1 AND tc.table_name=@p2
		ORDER BY kcu.ordinal_position`, schema, table)
	if err != nil {
		return nil, nil, err
	}
	defer pkRows.Close()
	var pk []string
	for pkRows.Next() {
		var c string
		if err := pkRows.Scan(&c); err != nil {
			return nil, nil, err
		}
		pk = append(pk, c)
	}
	return cols, pk, nil
}

func introspectSourceDDLMysql(db *sql.DB, srcEngine, tgtEngine, schema, table string) ([]ddlCol, []string, error) {
	rows, err := db.Query(`SELECT column_name, column_type, is_nullable
		FROM information_schema.columns WHERE table_schema=? AND table_name=? ORDER BY ordinal_position`, schema, table)
	if err != nil {
		return nil, nil, err
	}
	var cols []ddlCol
	for rows.Next() {
		var name, ctype, nullable string
		if err := rows.Scan(&name, &ctype, &nullable); err != nil {
			rows.Close()
			return nil, nil, err
		}
		cols = append(cols, ddlCol{name: name, typ: mapType(srcEngine, tgtEngine, ctype), notnull: nullable == "NO"})
	}
	rows.Close()
	pkRows, err := db.Query(`SELECT column_name FROM information_schema.key_column_usage
		WHERE table_schema=? AND table_name=? AND constraint_name='PRIMARY' ORDER BY ordinal_position`, schema, table)
	if err != nil {
		return nil, nil, err
	}
	defer pkRows.Close()
	var pk []string
	for pkRows.Next() {
		var c string
		if err := pkRows.Scan(&c); err != nil {
			return nil, nil, err
		}
		pk = append(pk, c)
	}
	return cols, pk, nil
}

func introspectSourceDDLPostgres(db *sql.DB, srcEngine, tgtEngine, schema, table string) ([]ddlCol, []string, error) {
	rows, err := db.Query(`SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
		FROM pg_attribute a
		WHERE a.attrelid = ($1||'.'||$2)::regclass AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, quoteIdent("pgx", schema), quoteIdent("pgx", table))
	if err != nil {
		return nil, nil, err
	}
	var cols []ddlCol
	for rows.Next() {
		var name, pgtype string
		var notnull bool
		if err := rows.Scan(&name, &pgtype, &notnull); err != nil {
			rows.Close()
			return nil, nil, err
		}
		cols = append(cols, ddlCol{name: name, typ: mapType(srcEngine, tgtEngine, pgtype), notnull: notnull})
	}
	rows.Close()
	pkRows, err := db.Query(`SELECT kcu.column_name FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema
		WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=$1 AND tc.table_name=$2
		ORDER BY kcu.ordinal_position`, schema, table)
	if err != nil {
		return nil, nil, err
	}
	defer pkRows.Close()
	var pk []string
	for pkRows.Next() {
		var c string
		if err := pkRows.Scan(&c); err != nil {
			return nil, nil, err
		}
		pk = append(pk, c)
	}
	return cols, pk, nil
}

// ---- cross-engine type mapping ----

// splitType breaks "numeric(10,2)" into ("numeric", "(10,2)").
func splitType(t string) (string, string) {
	t = strings.TrimSpace(strings.ToLower(t))
	if i := strings.IndexByte(t, '('); i >= 0 {
		return strings.TrimSpace(t[:i]), t[i:]
	}
	return t, ""
}

func mapType(srcEngine, tgtEngine, srcType string) string {
	if driverName(srcEngine) == driverName(tgtEngine) {
		return srcType
	}
	base, params := splitType(srcType)
	if driverName(srcEngine) == "pgx" {
		switch driverName(tgtEngine) {
		case "mysql":
			return pgToMysql(base, params)
		case "sqlserver":
			return pgToMssql(base, params)
		}
	}
	if driverName(srcEngine) == "mysql" {
		base = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(base, " unsigned", ""), " zerofill", ""))
		switch driverName(tgtEngine) {
		case "pgx":
			return mysqlToPg(base, params)
		case "sqlserver":
			return mysqlToMssql(base, params)
		}
	}
	if driverName(srcEngine) == "sqlserver" {
		switch driverName(tgtEngine) {
		case "pgx":
			return mssqlSrcToPg(base, params)
		case "mysql":
			return mssqlSrcToMysql(base, params)
		}
	}
	return srcType // other source engines handled later
}

func mssqlSrcToPg(base, params string) string {
	switch base {
	case "int", "integer":
		return "integer"
	case "bigint":
		return "bigint"
	case "smallint", "tinyint":
		return "smallint"
	case "bit":
		return "boolean"
	case "decimal", "numeric", "money", "smallmoney":
		if params == "" {
			return "numeric"
		}
		return "numeric" + params
	case "float":
		return "double precision"
	case "real":
		return "real"
	case "nvarchar", "varchar", "nchar", "char", "text", "ntext":
		if params == "" || params == "(max)" {
			return "text"
		}
		return "varchar" + params
	case "date":
		return "date"
	case "datetime", "datetime2", "smalldatetime":
		return "timestamp"
	case "datetimeoffset":
		return "timestamp with time zone"
	case "time":
		return "time"
	case "uniqueidentifier":
		return "uuid"
	case "binary", "varbinary", "image":
		return "bytea"
	default:
		return "text"
	}
}

func mssqlSrcToMysql(base, params string) string {
	switch base {
	case "int", "integer":
		return "INT"
	case "bigint":
		return "BIGINT"
	case "smallint", "tinyint":
		return "SMALLINT"
	case "bit":
		return "TINYINT(1)"
	case "decimal", "numeric", "money", "smallmoney":
		if params == "" {
			return "DECIMAL(38,10)"
		}
		return "DECIMAL" + params
	case "float":
		return "DOUBLE"
	case "real":
		return "FLOAT"
	case "nvarchar", "varchar", "nchar", "char", "text", "ntext":
		if params == "" || params == "(max)" {
			return "LONGTEXT"
		}
		return "VARCHAR" + params
	case "date":
		return "DATE"
	case "datetime", "datetime2", "smalldatetime", "datetimeoffset":
		return "DATETIME(6)"
	case "time":
		return "TIME(6)"
	case "uniqueidentifier":
		return "CHAR(36)"
	case "binary", "varbinary", "image":
		return "LONGBLOB"
	default:
		return "LONGTEXT"
	}
}

func mysqlToPg(base, params string) string {
	switch base {
	case "tinyint":
		if params == "(1)" {
			return "boolean"
		}
		return "smallint"
	case "smallint", "mediumint":
		return "integer"
	case "int", "integer":
		return "integer"
	case "bigint":
		return "bigint"
	case "decimal", "numeric":
		if params == "" {
			return "numeric"
		}
		return "numeric" + params
	case "float":
		return "real"
	case "double":
		return "double precision"
	case "varchar":
		if params == "" {
			return "text"
		}
		return "varchar" + params
	case "char":
		if params == "" {
			return "char(1)"
		}
		return "char" + params
	case "text", "tinytext", "mediumtext", "longtext":
		return "text"
	case "datetime", "timestamp":
		return "timestamp"
	case "date":
		return "date"
	case "time":
		return "time"
	case "json":
		return "jsonb"
	case "blob", "tinyblob", "mediumblob", "longblob", "binary", "varbinary":
		return "bytea"
	default:
		return "text"
	}
}

func mysqlToMssql(base, params string) string {
	switch base {
	case "tinyint":
		if params == "(1)" {
			return "BIT"
		}
		return "SMALLINT"
	case "smallint", "mediumint", "int", "integer":
		return "INT"
	case "bigint":
		return "BIGINT"
	case "decimal", "numeric":
		if params == "" {
			return "DECIMAL(38,10)"
		}
		return "DECIMAL" + params
	case "float":
		return "REAL"
	case "double":
		return "FLOAT"
	case "varchar":
		if params == "" {
			return "NVARCHAR(MAX)"
		}
		return "NVARCHAR" + params
	case "char":
		if params == "" {
			return "NCHAR(1)"
		}
		return "NCHAR" + params
	case "text", "tinytext", "mediumtext", "longtext":
		return "NVARCHAR(MAX)"
	case "datetime", "timestamp":
		return "DATETIME2"
	case "date":
		return "DATE"
	case "time":
		return "TIME"
	case "json":
		return "NVARCHAR(MAX)"
	case "blob", "tinyblob", "mediumblob", "longblob", "binary", "varbinary":
		return "VARBINARY(MAX)"
	default:
		return "NVARCHAR(MAX)"
	}
}

func pgToMysql(base, params string) string {
	switch base {
	case "integer", "int", "int4", "serial":
		return "INT"
	case "bigint", "int8", "bigserial":
		return "BIGINT"
	case "smallint", "int2":
		return "SMALLINT"
	case "boolean", "bool":
		return "TINYINT(1)"
	case "text":
		return "LONGTEXT"
	case "character varying", "varchar":
		if params == "" {
			return "TEXT"
		}
		return "VARCHAR" + params
	case "character", "char", "bpchar":
		if params == "" {
			return "CHAR(1)"
		}
		return "CHAR" + params
	case "numeric", "decimal":
		if params == "" {
			return "DECIMAL(38,10)"
		}
		return "DECIMAL" + params
	case "double precision", "float8":
		return "DOUBLE"
	case "real", "float4":
		return "FLOAT"
	case "timestamp with time zone", "timestamptz", "timestamp without time zone", "timestamp":
		return "DATETIME(6)"
	case "date":
		return "DATE"
	case "time without time zone", "time with time zone", "time":
		return "TIME(6)"
	case "uuid":
		return "CHAR(36)"
	case "json", "jsonb":
		return "JSON"
	case "bytea":
		return "LONGBLOB"
	default:
		return "LONGTEXT"
	}
}

func pgToMssql(base, params string) string {
	switch base {
	case "integer", "int", "int4", "serial":
		return "INT"
	case "bigint", "int8", "bigserial":
		return "BIGINT"
	case "smallint", "int2":
		return "SMALLINT"
	case "boolean", "bool":
		return "BIT"
	case "text":
		return "NVARCHAR(MAX)"
	case "character varying", "varchar":
		if params == "" {
			return "NVARCHAR(MAX)"
		}
		return "NVARCHAR" + params
	case "character", "char", "bpchar":
		if params == "" {
			return "NCHAR(1)"
		}
		return "NCHAR" + params
	case "numeric", "decimal":
		if params == "" {
			return "DECIMAL(38,10)"
		}
		return "DECIMAL" + params
	case "double precision", "float8":
		return "FLOAT"
	case "real", "float4":
		return "REAL"
	case "timestamp with time zone", "timestamptz":
		return "DATETIMEOFFSET"
	case "timestamp without time zone", "timestamp":
		return "DATETIME2"
	case "date":
		return "DATE"
	case "time without time zone", "time with time zone", "time":
		return "TIME"
	case "uuid":
		return "UNIQUEIDENTIFIER"
	case "json", "jsonb":
		return "NVARCHAR(MAX)"
	case "bytea":
		return "VARBINARY(MAX)"
	default:
		return "NVARCHAR(MAX)"
	}
}

func createTargetTable(db *sql.DB, engine, schema, table string, cols []ddlCol, pk []string) error {
	var defs []string
	for _, c := range cols {
		d := fmt.Sprintf("%s %s", quoteIdent(engine, c.name), c.typ)
		if c.notnull {
			d += " NOT NULL"
		}
		defs = append(defs, d)
	}
	if len(pk) > 0 {
		var qpk []string
		for _, p := range pk {
			qpk = append(qpk, quoteIdent(engine, p))
		}
		defs = append(defs, fmt.Sprintf("PRIMARY KEY (%s)", strings.Join(qpk, ",")))
	}
	body := strings.Join(defs, ", ")
	qt := qualified(engine, schema, table)

	switch driverName(engine) {
	case "pgx":
		if schema != "" {
			if _, err := db.Exec(fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, quoteIdent(engine, schema))); err != nil {
				return err
			}
		}
		_, err := db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", qt, body))
		return err
	case "mysql":
		_, err := db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", qt, body))
		return err
	case "sqlserver":
		_, err := db.Exec(fmt.Sprintf("IF OBJECT_ID('%s.%s','U') IS NULL CREATE TABLE %s (%s)", schema, table, qt, body))
		return err
	default:
		return fmt.Errorf("createTargetTable unsupported engine %s", engine)
	}
}
