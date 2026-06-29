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
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
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

// ackWaitDur is the consumer's redelivery deadline. It must comfortably exceed the
// worst-case batch apply (100-row transaction + deadlock retries with backoff); the
// JetStream default of 30s can expire mid-transaction under mesh write contention,
// causing redelivery + double-apply. Tunable via ACK_WAIT.
func ackWaitDur() time.Duration {
	if d, err := time.ParseDuration(env("ACK_WAIT", "")); err == nil && d > 0 {
		return d
	}
	return 2 * time.Minute
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
			// go-sql-driver runs any unrecognized DSN param as a session SET, so the
			// param name itself is the variable -> SET @app_replication=1. The name
			// is used verbatim (not URL-decoded), so pass a literal @.
			dsn += "@app_replication=1"
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
	case "pump":
		runPump()
	case "reconcile":
		runReconcile()
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
	// "*" (or empty) = all tables: discover them, excluding our HLC helper table.
	var tlist [][2]string
	if s := strings.TrimSpace(tables); s == "" || s == "*" {
		tlist, err = discoverTables(db, engine)
		if err != nil {
			log.Fatalf("mm-prep discover tables: %v", err)
		}
		tlist = dropHelperTables(tlist)
	} else {
		tlist = splitTables(tables)
	}
	if err := mmPrepSetup(db, engine, site, vcol); err != nil {
		log.Fatalf("mm-prep setup: %v", err)
	}
	for _, t := range tlist {
		if err := mmPrepTable(db, engine, site, vcol, ocol, t[0], t[1]); err != nil {
			log.Fatalf("mm-prep %s.%s: %v", t[0], t[1], err)
		}
		log.Printf("mm-prep: prepared %s.%s (site=%s)", t[0], t[1], site)
	}
	log.Printf("mm-prep done (site=%s)", site)
}

// mmPrepSetup installs the per-database HLC scaffolding (run once per member, not per
// table). Shared by the mm-prep Job and the live table-sync reconciler.
func mmPrepSetup(db *sql.DB, engine, site, vcol string) error {
	switch driverName(engine) {
	case "pgx":
		for _, q := range pgHLCSetup(site, vcol) {
			if _, err := db.Exec(q); err != nil {
				return err
			}
		}
	case "sqlserver":
		for _, q := range []string{
			// Enable CDC on the database so tables can be captured as a source. Requires a
			// sysadmin login and a running SQL Agent. Idempotent (guarded on is_cdc_enabled).
			`IF (SELECT is_cdc_enabled FROM sys.databases WHERE name=DB_NAME())=0 EXEC sys.sp_cdc_enable_db`,
			`IF OBJECT_ID('mm_hlc_state','U') IS NULL CREATE TABLE mm_hlc_state(id int primary key, pt bigint NOT NULL DEFAULT 0, lc int NOT NULL DEFAULT 0)`,
			`IF NOT EXISTS(SELECT 1 FROM mm_hlc_state) INSERT INTO mm_hlc_state(id) VALUES(1)`,
		} {
			if _, err := db.Exec(q); err != nil {
				return err
			}
		}
	case "mysql":
		// no shared scaffolding (clock-based stamping, no HLC state table)
	default:
		return fmt.Errorf("mm-prep not implemented for engine %s", engine)
	}
	return nil
}

// mmPrepTable makes ONE table multi-master-ready: version/origin columns, a per-site
// stamping trigger, and a backfill of pre-existing rows so they aren't NULL-versioned
// (a NULL local version is never < an incoming version, so the row would freeze under
// LWW and diverge). Idempotent. Shared by the mm-prep Job and the reconciler.
func mmPrepTable(db *sql.DB, engine, site, vcol, ocol, schema, table string) error {
	exec := func(q string) error {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("%w\n  sql: %s", err, q)
		}
		return nil
	}
	switch driverName(engine) {
	case "pgx":
		qt := qualified(engine, schema, table)
		for _, q := range []string{
			fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s bigint`, qt, quoteIdent(engine, vcol)),
			fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s text`, qt, quoteIdent(engine, ocol)),
			fmt.Sprintf(`UPDATE %s SET %s = mm_hlc_tick(), %s = '%s' WHERE %s IS NULL`,
				qt, quoteIdent(engine, vcol), quoteIdent(engine, ocol), site, quoteIdent(engine, vcol)),
			fmt.Sprintf(`DROP TRIGGER IF EXISTS mm_stamp_trg ON %s`, qt),
			fmt.Sprintf(`CREATE TRIGGER mm_stamp_trg BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION mm_stamp()`, qt),
		} {
			if err := exec(q); err != nil {
				return err
			}
		}
	case "sqlserver":
		// AFTER trigger (no BEFORE-row in SQL Server) with a recursion guard; column
		// DEFAULTs keep pre-trigger rows non-null.
		qt := qualified(engine, schema, table)
		qv := quoteIdent(engine, vcol)
		qo := quoteIdent(engine, ocol)
		if err := exec(fmt.Sprintf(`IF COL_LENGTH('%s.%s','%s') IS NULL ALTER TABLE %s ADD %s bigint DEFAULT (DATEDIFF_BIG(MILLISECOND,'19700101',SYSUTCDATETIME())*65536)`, schema, table, vcol, qt, qv)); err != nil {
			return err
		}
		if err := exec(fmt.Sprintf(`IF COL_LENGTH('%s.%s','%s') IS NULL ALTER TABLE %s ADD %s nvarchar(16) DEFAULT N'%s'`, schema, table, ocol, qt, qo, site)); err != nil {
			return err
		}
		m, ierr := introspectSqlserver(db, schema, table)
		if ierr != nil {
			return ierr
		}
		var pkjoin []string
		for _, p := range m.pk {
			qp := quoteIdent(engine, p)
			pkjoin = append(pkjoin, fmt.Sprintf("t.%s=i.%s", qp, qp))
		}
		if len(pkjoin) == 0 {
			return nil // no primary key: can't stamp deterministically; skip
		}
		trg := "mm_stamp_" + strings.ReplaceAll(table, ".", "_")
		hlc := `DECLARE @pt bigint,@lc int,@now bigint,@v bigint; SELECT @pt=pt,@lc=lc FROM mm_hlc_state WITH (UPDLOCK,HOLDLOCK) WHERE id=1; SET @now=DATEDIFF_BIG(MILLISECOND,'19700101',SYSUTCDATETIME()); IF @now>@pt BEGIN SET @pt=@now; SET @lc=0; END ELSE SET @lc=@lc+1; UPDATE mm_hlc_state SET pt=@pt,lc=@lc WHERE id=1; SET @v=@pt*65536+@lc;`
		obs := fmt.Sprintf(`DECLARE @rmax bigint=(SELECT MAX(%s) FROM inserted); UPDATE mm_hlc_state SET pt=CASE WHEN @rmax/65536>pt THEN @rmax/65536 ELSE pt END WHERE id=1;`, qv)
		body := fmt.Sprintf(`CREATE OR ALTER TRIGGER %s ON %s AFTER INSERT, UPDATE AS BEGIN SET NOCOUNT ON; IF TRIGGER_NESTLEVEL(OBJECT_ID(N'%s')) > 1 RETURN; IF SESSION_CONTEXT(N'app_replication')=N'on' BEGIN %s RETURN; END %s UPDATE t SET %s=@v, %s=N'%s' FROM %s t JOIN inserted i ON %s; END`,
			trg, qt, trg, obs, hlc, qv, qo, site, qt, strings.Join(pkjoin, " AND "))
		if err := exec(body); err != nil {
			return err
		}
		// Enable CDC on the table so SQL Server captures it as a source. Done AFTER the
		// columns exist so the capture instance includes _mm_version/_mm_origin. Idempotent
		// (guarded). Requires a running SQL Agent; removes the previously-manual sp_cdc step.
		return exec(fmt.Sprintf(`IF NOT EXISTS (SELECT 1 FROM cdc.change_tables ct JOIN sys.tables tt ON ct.source_object_id=tt.object_id JOIN sys.schemas ss ON tt.schema_id=ss.schema_id WHERE ss.name='%s' AND tt.name='%s') EXEC sys.sp_cdc_enable_table @source_schema=N'%s', @source_name=N'%s', @role_name=NULL, @supports_net_changes=0`,
			schema, table, schema, table))
	case "mysql":
		qtbl := quoteIdent(engine, table)
		qv := quoteIdent(engine, vcol)
		qo := quoteIdent(engine, ocol)
		ensureCol := func(col, typ string) error {
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`, table, col).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", qtbl, quoteIdent(engine, col), typ))
			}
			return nil
		}
		if err := ensureCol(vcol, "bigint"); err != nil {
			return err
		}
		if err := ensureCol(ocol, "varchar(16)"); err != nil {
			return err
		}
		if err := exec(fmt.Sprintf("UPDATE %s SET %s = CAST(UNIX_TIMESTAMP(NOW(3))*1000 AS UNSIGNED)*65536, %s = '%s' WHERE %s IS NULL",
			qtbl, qv, qo, site, qv)); err != nil {
			return err
		}
		stamp := fmt.Sprintf("SET NEW.%s = CAST(UNIX_TIMESTAMP(NOW(3))*1000 AS UNSIGNED)*65536, NEW.%s = '%s'", qv, qo, site)
		for _, ev := range []string{"INSERT", "UPDATE"} {
			trg := quoteIdent(engine, fmt.Sprintf("mm_stamp_%s_%s", table, strings.ToLower(ev[:1])))
			if err := exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s", trg)); err != nil {
				return err
			}
			if err := exec(fmt.Sprintf("CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW BEGIN IF @app_replication IS NULL THEN %s; END IF; END",
				trg, ev, qtbl, stamp)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("mm-prep not implemented for engine %s", engine)
	}
	return nil
}

// member is one database participating in a multi-master flow, used by the reconciler.
type reconcileMember struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	DSN    string `json:"dsn"`
	Site   string `json:"site"`
	db     *sql.DB
}

// runReconcile keeps the table SET in sync across all members of a multi-master flow:
// a table created on ANY member is auto-created on every other member (cross-engine) and
// made multi-master-ready (mm-prep), with no user action. Combined with capture-all CDC,
// the per-edge sinks then replicate it like any other table. (Pre-existing ROWS in a
// late-added table aren't back-loaded without a Debezium incremental snapshot — a
// follow-up; create-then-insert syncs fully.)
func runReconcile() {
	raw := env("MEMBERS", "")
	vcol := env("VERSION_COLUMN", "_mm_version")
	ocol := env("ORIGIN_COLUMN", "_mm_origin")
	interval := time.Duration(atoiEnv("RECONCILE_INTERVAL", 20)) * time.Second
	if raw == "" {
		log.Fatal("MEMBERS required for reconcile mode")
	}
	var members []*reconcileMember
	if err := json.Unmarshal([]byte(raw), &members); err != nil {
		log.Fatalf("parse MEMBERS: %v", err)
	}
	for _, m := range members {
		db, err := openDB(m.Engine, os.ExpandEnv(m.DSN))
		if err != nil {
			log.Fatalf("reconcile open %s: %v", m.Name, err)
		}
		m.db = db
		if err := mmPrepSetup(db, m.Engine, m.Site, vcol); err != nil {
			log.Printf("reconcile: mm setup %s: %v", m.Name, err)
		}
	}
	log.Printf("reconcile: %d members, interval=%s", len(members), interval)
	prepped := map[string]bool{} // member|table already mm-prepped (avoid per-cycle churn)
	noPK := map[string]bool{}    // tables skipped: multi-master needs a primary key
	for {
		reconcileOnce(members, vcol, ocol, prepped, noPK)
		time.Sleep(interval)
	}
}

func reconcileOnce(members []*reconcileMember, vcol, ocol string, prepped, noPK map[string]bool) {
	// 1. discover the table set on each member (keyed by table name; schema is per-engine)
	have := map[string]map[string]string{} // member -> table -> schema
	union := map[string]bool{}
	for _, m := range members {
		tl, err := discoverTables(m.db, m.Engine)
		if err != nil {
			log.Printf("reconcile: discover %s: %v", m.Name, err)
			continue
		}
		hm := map[string]string{}
		for _, t := range dropHelperTables(tl) {
			hm[t[1]] = t[0]
			union[t[1]] = true
		}
		have[m.Name] = hm
	}
	// 2. create any missing table on each member, introspected from a member that has it
	for tbl := range union {
		if noPK[tbl] {
			continue // already known to lack a primary key — can't be multi-master
		}
		var src *reconcileMember
		var srcSchema string
		for _, m := range members {
			if s, ok := have[m.Name][tbl]; ok {
				src, srcSchema = m, s
				break
			}
		}
		if src == nil {
			continue
		}
		for _, m := range members {
			if _, ok := have[m.Name][tbl]; ok {
				continue
			}
			cols, pk, err := introspectSourceDDL(src.db, src.Engine, m.Engine, srcSchema, tbl)
			if err != nil {
				log.Printf("reconcile: introspect %s from %s: %v", tbl, src.Name, err)
				continue
			}
			if len(pk) == 0 {
				// Multi-master conflict resolution and the apply upsert both require a PK.
				noPK[tbl] = true
				log.Printf("reconcile: skipping table %q — no primary key (multi-master requires one)", tbl)
				break
			}
			ts := targetSchema(m.Engine, srcSchema)
			if err := createTargetTable(m.db, m.Engine, ts, tbl, cols, pk); err != nil {
				log.Printf("reconcile: create %s on %s: %v", tbl, m.Name, err)
				continue
			}
			log.Printf("reconcile: auto-created table %q on %s (from %s, %d cols)", tbl, m.Name, src.Name, len(cols))
			have[m.Name][tbl] = ts
			delete(prepped, m.Name+"|"+tbl) // force mm-prep of the new table
		}
	}
	// 3. ensure every member's tables are mm-prepped (skip ones already done this run)
	for _, m := range members {
		for tbl, sch := range have[m.Name] {
			if noPK[tbl] {
				continue
			}
			key := m.Name + "|" + tbl
			if prepped[key] {
				continue
			}
			if err := mmPrepTable(m.db, m.Engine, m.Site, vcol, ocol, sch, tbl); err != nil {
				log.Printf("reconcile: mm-prep %s.%s on %s: %v", sch, tbl, m.Name, err)
				continue
			}
			prepped[key] = true
		}
	}
}

// dropHelperTables removes open-infra's own bookkeeping tables (the HLC state)
// from a discovered "*" list so they're never stamped or replicated.
func dropHelperTables(in [][2]string) [][2]string {
	var out [][2]string
	for _, t := range in {
		if t[1] == "mm_hlc_state" {
			continue
		}
		out = append(out, t)
	}
	return out
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
	// "transient" errors (e.g. target table not created yet) are retried with a
	// pause rather than dead-lettered immediately — but NOT forever: a condition
	// that never resolves (a table that will never exist) would otherwise churn the
	// consumer and never clear. Give real transients time (paced retries), then park.
	transientMax := atoiEnv("TRANSIENT_MAX_DELIVER", 60)

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
		nats.BindStream(stream), nats.AckExplicit(), nats.DeliverAll(), nats.ManualAck(), nats.AckWait(ackWaitDur()))
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
		// Fast path: apply the whole batch in one transaction (one commit/fsync
		// for ~100 rows). On any error, fall through to per-message handling so the
		// single bad message is retried / dead-lettered without blocking the rest.
		if len(msgs) > 1 {
			if err := applyBatch(db, engine, msgs); err == nil {
				for _, m := range msgs {
					_ = m.Ack()
				}
				continue
			}
		}
		for _, m := range msgs {
			retry, err := apply(db, engine, m)
			if err == nil {
				_ = m.Ack()
				continue
			}
			nd := 1
			if md, e := m.Metadata(); e == nil {
				nd = int(md.NumDelivered)
			}
			if retry {
				// transient (e.g. target table not created by schema-sync yet): retry
				// with a pause so a real transient resolves — but cap it so a condition
				// that never resolves is parked instead of churning the consumer forever.
				if nd >= transientMax {
					log.Printf("DEAD-LETTER subj=%s: transient unresolved after %d attempts: %v", m.Subject, nd, err)
					_, _ = js.Publish("dlq."+m.Subject, m.Data)
					_ = m.Term()
				} else {
					log.Printf("retry (attempt %d) subj=%s: %v", nd, m.Subject, err)
					_ = m.NakWithDelay(3 * time.Second)
				}
				continue
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

// ===================== PUMP MODE (function transform) =====================
//
// runPump is the Transform stage of an ETL chain: consume change events from an
// upstream subject, POST each to a function over HTTP, and publish the function's
// returned event to a downstream subject (preserving the <schema>.<table> tail so
// the next stage routes it). A 204 / empty response drops the event (a filter).
func runPump() {
	natsURL := env("NATS_URL", "nats://nats:4222")
	stream := env("STREAM", "")
	subject := env("SUBJECT", "")
	durable := env("DURABLE", "pump")
	fnURL := env("FUNCTION_URL", "")
	outPrefix := env("OUTPUT_SUBJECT", "") // e.g. f.<flow>.<fn>
	maxDeliver := atoiEnv("MAX_DELIVER", 5)
	if fnURL == "" || outPrefix == "" {
		log.Fatal("FUNCTION_URL and OUTPUT_SUBJECT are required for pump mode")
	}
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
		nats.BindStream(stream), nats.AckExplicit(), nats.DeliverAll(), nats.ManualAck(), nats.AckWait(ackWaitDur()))
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	log.Printf("pump running: stream=%s subject=%s -> fn=%s -> out=%s.*", stream, subject, fnURL, outPrefix)

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
			out, drop, perr := transform(client, fnURL, m.Data)
			if perr != nil {
				nd := 1
				if md, e := m.Metadata(); e == nil {
					nd = int(md.NumDelivered)
				}
				if nd >= maxDeliver {
					log.Printf("DEAD-LETTER (pump) subj=%s after %d: %v", m.Subject, nd, perr)
					_, _ = js.Publish("dlq."+m.Subject, m.Data)
					_ = m.Term()
				} else {
					log.Printf("pump error (attempt %d) subj=%s: %v", nd, m.Subject, perr)
					_ = m.Nak()
				}
				continue
			}
			if drop {
				_ = m.Ack() // the function filtered this event out
				continue
			}
			outSubj := outPrefix + "." + lastTwoSeg(m.Subject)
			if _, err := js.Publish(outSubj, out); err != nil {
				log.Printf("publish %s: %v", outSubj, err)
				_ = m.Nak()
				continue
			}
			_ = m.Ack()
		}
	}
}

// transform POSTs the event to the function and returns its body. drop=true when
// the function returns 204 or an empty body (the event is intentionally filtered).
func transform(client *http.Client, url string, body []byte) (out []byte, drop bool, err error) {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(b)) == 0 {
		return nil, true, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("function %s status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, false, nil
}

// lastTwoSeg returns the last two dot-segments of a subject (the <schema>.<table>).
func lastTwoSeg(subject string) string {
	p := strings.Split(subject, ".")
	if len(p) >= 2 {
		return strings.Join(p[len(p)-2:], ".")
	}
	return subject
}

// apply returns (retryable, err). retryable=true means a transient condition
// (e.g. the target table isn't created yet) — the caller should Nak and retry
// without ever dead-lettering. retryable=false errors are data problems that
// dead-letter after MAX_DELIVER.
func apply(db *sql.DB, engine string, m *nats.Msg) (bool, error) {
	return applyOne(db, db, engine, m)
}

// applyBatch applies a whole Fetch in ONE transaction (one fsync for the batch,
// not one per row — the dominant cost). Returns nil on success (ack all); on any
// error it rolls back and the caller falls back to per-message apply so the one
// bad message can be retried/dead-lettered in isolation.
func applyBatch(db *sql.DB, engine string, msgs []*nats.Msg) error {
	var err error
	// Retry the whole batch on a deadlock/serialization failure (expected when
	// several mesh sinks write overlapping rows at once); the loser just re-runs.
	for attempt := 0; attempt < 4; attempt++ {
		err = tryBatch(db, engine, msgs)
		if err == nil || !isRetryable(err) {
			return err
		}
		time.Sleep(time.Duration(20*(attempt+1)) * time.Millisecond)
	}
	return err
}

func tryBatch(db *sql.DB, engine string, msgs []*nats.Msg) error {
	// Parse first, then apply in a deterministic global order (table + primary key)
	// so every concurrent sink acquires row locks in the SAME order. Sinks read
	// different source streams, so without this they touch the same target rows in
	// different orders and deadlock; ordering converts deadlocks into benign waits.
	entries := make([]*applyEntry, 0, len(msgs))
	for _, m := range msgs {
		e, skip, _, err := parseMsg(db, engine, m)
		if err != nil {
			return err // fall back to per-message so the bad one is isolated
		}
		if skip {
			continue
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sortkey < entries[j].sortkey })
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := e.exec(tx, engine); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// applyEntry is a parsed, ready-to-apply change with a deterministic sort key.
type applyEntry struct {
	schema, table string
	deleted       bool
	row           map[string]any
	mt            meta
	sortkey       string
}

func (e *applyEntry) exec(x sqlExec, engine string) error {
	if e.deleted {
		return execDelete(x, engine, e.schema, e.table, e.mt, e.row)
	}
	return execUpsert(x, engine, e.schema, e.table, e.mt, e.row)
}

// applyOne writes one change via exec (a *sql.DB or *sql.Tx); db is used only for
// (cached) target-table introspection.
func applyOne(exec sqlExec, db *sql.DB, engine string, m *nats.Msg) (bool, error) {
	e, skip, retryable, err := parseMsg(db, engine, m)
	if err != nil {
		return retryable, err
	}
	if skip {
		return false, nil
	}
	ex := e.exec(exec, engine)
	return isRetryable(ex), ex
}

// parseMsg decodes a change event into an applyEntry. Returns (entry, skip,
// retryable, err): skip=true for tombstones / origin-echoes (loop prevention,
// ack+drop); retryable=true when the target table isn't created yet.
func parseMsg(db *sql.DB, engine string, m *nats.Msg) (*applyEntry, bool, bool, error) {
	parts := strings.Split(m.Subject, ".")
	if len(parts) < 2 {
		return nil, false, false, fmt.Errorf("subject too short: %s", m.Subject)
	}
	schema := targetSchema(engine, parts[len(parts)-2])
	table := parts[len(parts)-1]
	dec := json.NewDecoder(strings.NewReader(string(m.Data)))
	dec.UseNumber()
	var row map[string]any
	if err := dec.Decode(&row); err != nil {
		return nil, false, false, fmt.Errorf("decode: %w", err)
	}
	if row == nil {
		return nil, true, false, nil
	}
	deleted := fmt.Sprint(row["__deleted"]) == "true"
	delete(row, "__deleted")
	// Loop prevention: drop events that originated at the peer site.
	if oc := os.Getenv("ORIGIN_COLUMN"); oc != "" {
		if skip := os.Getenv("SKIP_ORIGIN"); skip != "" && fmt.Sprint(row[oc]) == skip {
			return nil, true, false, nil
		}
	}
	mt, err := getMeta(db, engine, schema, table)
	if err != nil {
		return nil, false, true, err // target table may not be created yet
	}
	// Length-prefix every component so the sort key is INJECTIVE — a PK value that
	// contains the delimiter (e.g. a natural key literally "a|b") must not collide with
	// a different key, or concurrent sinks would order those rows differently and
	// reintroduce mesh deadlocks. "<len>:<value>" per part is unambiguous regardless of
	// content.
	var sk strings.Builder
	sk.WriteString(schema)
	sk.WriteString("\x1f")
	sk.WriteString(table)
	for _, pk := range mt.pk {
		v := fmt.Sprint(row[pk])
		sk.WriteString("\x1f")
		sk.WriteString(strconv.Itoa(len(v)))
		sk.WriteString(":")
		sk.WriteString(v)
	}
	return &applyEntry{schema: schema, table: table, deleted: deleted, row: row, mt: mt, sortkey: sk.String()}, false, false, nil
}

// isRetryable reports whether an apply error is transient and worth retrying
// rather than dead-lettering: deadlocks / serialization failures / lock-wait
// timeouts across Postgres (40P01/40001), MySQL (1213/1205) and SQL Server (1205).
// Concurrent mesh sinks writing overlapping rows deadlock normally; the loser retries.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "deadlock") ||
		strings.Contains(s, "40p01") || strings.Contains(s, "40001") ||
		strings.Contains(s, "serializ") || strings.Contains(s, "lock wait timeout") ||
		strings.Contains(s, "1205") || strings.Contains(s, "1213")
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
	ph := env("UNAVAILABLE_PLACEHOLDER", "__debezium_unavailable_value")
	var cols []string
	for _, c := range mt.cols {
		v, ok := row[c]
		if !ok {
			continue
		}
		// Skip Debezium's unavailable-value sentinel. An unchanged externally-stored
		// (TOASTed) Postgres column under REPLICA IDENTITY DEFAULT is not in the WAL and
		// arrives as this placeholder; writing it would CLOBBER the target's real value
		// with the literal string. Omitting the column leaves the existing value intact —
		// which is exactly its meaning: unchanged. (Tunable/disable via UNAVAILABLE_PLACEHOLDER.)
		if ph != "" {
			if s, isStr := v.(string); isStr && s == ph {
				continue
			}
			if b, isB := v.([]byte); isB && string(b) == ph {
				continue
			}
		}
		cols = append(cols, c)
	}
	return cols
}

// sqlExec is satisfied by both *sql.DB (autocommit) and *sql.Tx (batched in one
// transaction), so the apply path can commit one row or a whole Fetch at once.
type sqlExec interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func execUpsert(db sqlExec, engine, schema, table string, mt meta, row map[string]any) error {
	cols := presentCols(mt, row)
	if len(cols) == 0 {
		return fmt.Errorf("no matching columns for %s.%s", schema, table)
	}
	// MySQL/MariaDB: ON DUPLICATE KEY UPDATE evaluates SET assignments left-to-right
	// and later columns see earlier columns' ALREADY-updated values, so a per-column
	// LWW IF-guard updates version and origin INCONSISTENTLY (version newer, origin
	// stale) — which makes mesh peers disagree on origin at equal version and flip-flop
	// forever (an amplification storm). Postgres (WHERE) and SQL Server (MERGE WHEN
	// MATCHED AND) evaluate the guard on the pre-update row atomically; MySQL has no
	// such construct, so apply atomically as insert-or-noop + a guarded UPDATE.
	if driverName(engine) == "mysql" {
		return execUpsertMysql(db, engine, schema, table, cols, mt, row)
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

// execUpsertMysql applies a row to MySQL/MariaDB in two atomic steps that avoid
// ON DUPLICATE KEY UPDATE's order-dependent column evaluation:
//  1. INSERT … ON DUPLICATE KEY UPDATE pk=pk  — inserts a new row, no-ops an existing
//     one (a no-op ODKU writes no binlog, so it never echoes);
//  2. UPDATE … SET <all non-PK cols> WHERE <pk> AND <version newer> — the WHERE sees
//     the pre-update row, so every column moves together only when strictly newer
//     (0 rows otherwise → no binlog → no echo).
func execUpsertMysql(db sqlExec, engine, schema, table string, cols []string, mt meta, row map[string]any) error {
	qt := qualified(engine, schema, table)
	qcols := make([]string, len(cols))
	ph := make([]string, len(cols))
	vals := make([]any, len(cols))
	for i, c := range cols {
		qcols[i] = quoteIdent(engine, c)
		ph[i] = "?"
		vals[i] = coerce(row[c], mt.colType[c])
	}
	// 1. insert-or-noop (no-op on existing PK; emits no binlog)
	ins := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s=%s",
		qt, strings.Join(qcols, ","), strings.Join(ph, ","),
		quoteIdent(engine, mt.pk[0]), quoteIdent(engine, mt.pk[0]))
	if _, err := db.Exec(ins, vals...); err != nil {
		return err
	}
	// 2. guarded UPDATE of existing rows
	var setCols []string
	var setVals []any
	for _, c := range cols {
		if mt.pkset[c] {
			continue
		}
		setCols = append(setCols, quoteIdent(engine, c)+"=?")
		setVals = append(setVals, coerce(row[c], mt.colType[c]))
	}
	if len(setCols) == 0 {
		return nil // all-PK table: the insert-or-noop already covered it
	}
	var where []string
	args := append([]any{}, setVals...)
	for _, p := range mt.pk {
		where = append(where, quoteIdent(engine, p)+"=?")
		args = append(args, coerce(row[p], mt.colType[p]))
	}
	guard := ""
	if cc := os.Getenv("CONFLICT_COLUMN"); cc != "" {
		if _, ok := row[cc]; ok {
			qcc := quoteIdent(engine, cc)
			if oc := os.Getenv("ORIGIN_COLUMN"); oc != "" {
				if _, ok := row[oc]; ok {
					guard = fmt.Sprintf(" AND (%s < ? OR (%s = ? AND %s < ?))", qcc, qcc, quoteIdent(engine, oc))
					args = append(args, coerce(row[cc], mt.colType[cc]), coerce(row[cc], mt.colType[cc]), coerce(row[oc], mt.colType[oc]))
				}
			}
			if guard == "" {
				guard = fmt.Sprintf(" AND %s < ?", qcc)
				args = append(args, coerce(row[cc], mt.colType[cc]))
			}
		}
	}
	upd := fmt.Sprintf("UPDATE %s SET %s WHERE %s%s", qt, strings.Join(setCols, ","), strings.Join(where, " AND "), guard)
	if _, err := db.Exec(upd, args...); err != nil {
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

func execDelete(db sqlExec, engine, schema, table string, mt meta, row map[string]any) error {
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
	if s := strings.TrimSpace(tables); s == "" || s == "*" {
		list, err = discoverTables(src, srcEngine)
		if err != nil {
			log.Fatalf("discover: %v", err)
		}
		list = dropHelperTables(list)
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
