// Package classify decides, for one client TDS message, whether it leaves session state on the backend
// that makes the connection unsafe to hand to another client — i.e. whether the multiplexer must PIN.
// It is pure and stateless (given a message it returns a verdict), so it is exhaustively unit-testable;
// the prelude nuance (drivers send a SET batch right after login) is surfaced via Verdict.Prelude for
// the session layer to handle. Mirrors the v1 pin-trigger list in
// docs/design/rds-proxy-tds-multiplexing.md.
package classify

import (
	"regexp"
	"strings"

	"openinfra-tds-proxy/tds"
)

// Verdict is the outcome for one message.
type Verdict struct {
	Pin     bool   // must pin the backend to this client
	Reason  string // why it pins (empty if multiplexable)
	Prelude bool   // a SET-only batch: the session may treat the connection's FIRST such batch as the
	// driver login prelude (re-applied on every fresh backend) and NOT pin on it.
	Txn bool // the pin is because a transaction is OPENING (BEGIN TRAN / TM request) rather than because
	// the session left surviving state. Per-transaction multiplexing (#7 v2.1) tracks such a transaction's
	// begin/commit boundaries and releases the backend at COMMIT/ROLLBACK instead of pinning it for the
	// whole session — so a Txn pin is NOT session-sticky.
	ImplicitTxn bool // SET IMPLICIT_TRANSACTIONS ON: statements auto-open transactions with no explicit
	// begin to pair to a commit, so per-transaction multiplexing can't safely bound them — the tx-multiplex
	// relay holds the backend for the whole session (v1 behavior). v1's across-session pooling is unaffected.
}

var multiplexable = Verdict{}

// The pin-triggering patterns in a SQLBatch, case-insensitive, anchored to statement starts where it
// matters so "UPDATE t SET c=1" (a SET clause, not a SET option) does not false-positive.
var (
	reSetOption  = regexp.MustCompile(`(?im)^\s*set\s+([a-z_]+)`)
	reIsolation  = regexp.MustCompile(`(?is)set\s+transaction\s+isolation\s+level`)
	reContextI   = regexp.MustCompile(`(?is)set\s+context_info`)
	reTempTable  = regexp.MustCompile(`(?is)create\s+table\s+#`)
	reCursor     = regexp.MustCompile(`(?is)declare\s+.*\s+cursor\b`)
	reUseDB      = regexp.MustCompile(`(?im)^\s*use\s+\w`)
	reBeginTran  = regexp.MustCompile(`(?is)begin\s+tran(saction)?\b`)
	reAppLock    = regexp.MustCompile(`(?is)sp_getapplock`)
	reWaitFor    = regexp.MustCompile(`(?im)^\s*waitfor\s`)
	reSetContext = regexp.MustCompile(`(?is)sp_set_session_context`)
	reImplicitTx = regexp.MustCompile(`(?is)set\s+implicit_transactions\s+on\b`)
)

const maxStatementBytes = 16 * 1024 // AWS RDS Proxy's ~16KB pin ceiling

// Classify returns the verdict for one reassembled client message.
func Classify(msgType byte, body []byte) Verdict {
	switch msgType {
	case tds.TypeSQLBatch:
		return classifyBatch(tds.BatchText(body))
	case tds.TypeRPC:
		return classifyRPC(tds.RPCProc(body))
	case tds.TypeBulkLoad:
		return Verdict{Pin: true, Reason: "bulk load stream"}
	case tds.TypeTxMgr:
		return Verdict{Pin: true, Reason: "transaction manager request (explicit txn/savepoint)", Txn: true}
	case tds.TypeLogin7, tds.TypePreLogin, tds.TypeSSPI, tds.TypeFedAuth, tds.TypeAttention:
		return multiplexable // control/setup — not client work
	default:
		// Fail safe: a client message we can't classify might leave state we can't see.
		return Verdict{Pin: true, Reason: "unrecognized message type " + tds.TypeName(msgType)}
	}
}

func classifyBatch(text string) Verdict {
	if len(text) > maxStatementBytes {
		return Verdict{Pin: true, Reason: "statement text > 16KB"}
	}
	switch {
	case reIsolation.MatchString(text):
		// Poolable as a login prelude when it is a SET-only opening batch: drivers (tedious, .NET's
		// SqlClient) issue SET TRANSACTION ISOLATION LEVEL at connect time and re-issue it on every fresh
		// connection, so the proxy can re-apply it rather than pinning. Mid-session (after real work) it
		// still pins — the session layer only honours Prelude on the connection's first batch.
		return Verdict{Pin: true, Reason: "SET TRANSACTION ISOLATION LEVEL", Prelude: isSetOnly(text)}
	case reContextI.MatchString(text) || reSetContext.MatchString(text):
		return Verdict{Pin: true, Reason: "session context (CONTEXT_INFO)"}
	case reTempTable.MatchString(text):
		return Verdict{Pin: true, Reason: "temp table (#…)"}
	case reCursor.MatchString(text):
		return Verdict{Pin: true, Reason: "cursor"}
	case reUseDB.MatchString(text):
		return Verdict{Pin: true, Reason: "USE database (context change)"}
	case reBeginTran.MatchString(text):
		return Verdict{Pin: true, Reason: "explicit transaction", Txn: true}
	case reAppLock.MatchString(text):
		return Verdict{Pin: true, Reason: "session-scoped applock"}
	case reWaitFor.MatchString(text):
		return Verdict{Pin: true, Reason: "WAITFOR"}
	}
	// A SET option (not one of the above specific forms).
	if m := reSetOption.FindStringSubmatch(text); m != nil {
		// Prelude: if the batch is ONLY SET statements, the session may treat the connection's first
		// such batch as the driver login prelude and re-apply it on fresh backends instead of pinning.
		// ImplicitTxn is surfaced separately: it's a poolable prelude for v1 (across-session), but the
		// tx-multiplex relay must NOT per-transaction-multiplex a session in implicit-transaction mode.
		return Verdict{Pin: true, Reason: "SET session option (" + m[1] + ")", Prelude: isSetOnly(text), ImplicitTxn: reImplicitTx.MatchString(text)}
	}
	return multiplexable // plain SELECT/INSERT/UPDATE/DELETE autocommit — the multiplexable common path
}

// readOnlyCatalogRPC is the set of MS-documented ODBC catalog stored procedures — the ones a driver calls
// to implement SQLTables/SQLColumns/SQLGetTypeInfo/etc. They return metadata result sets and leave NO
// session state (no temp table, prepared handle, cursor, or session option), so they are multiplexable.
// The ODBC Driver 18 issues sp_datatype_info_100 on EVERY connect, so without this a benign metadata call
// fail-safe-pinned every ODBC connection and killed pooling for all ODBC/pyodbc clients (#3). Versioned
// (_100) variants are the same read-only family; both forms are listed explicitly rather than pattern-
// stripped, to keep the whitelist auditable.
var readOnlyCatalogRPC = map[string]bool{
	"sp_column_privileges": true, "sp_column_privileges_ex": true,
	"sp_columns": true, "sp_columns_ex": true, "sp_columns_100": true,
	"sp_databases":     true,
	"sp_datatype_info": true, "sp_datatype_info_100": true,
	"sp_fkeys": true, "sp_pkeys": true,
	"sp_server_info":     true,
	"sp_special_columns": true, "sp_special_columns_100": true,
	"sp_sproc_columns": true, "sp_sproc_columns_100": true,
	"sp_statistics": true, "sp_statistics_100": true,
	"sp_stored_procedures": true,
	"sp_table_privileges":  true, "sp_table_privileges_ex": true,
	"sp_tables": true, "sp_tables_ex": true,
}

// normalizeProc strips a schema qualifier ([sys].), brackets, and case so a name-invoked RPC like
// "[sys].sp_datatype_info_100" matches the bare, lowercase names below (ProcID-invoked RPCs already
// arrive bare and lowercase via procIDName, so normalization is a no-op for them).
func normalizeProc(proc string) string {
	p := strings.ToLower(strings.TrimSpace(proc))
	if i := strings.LastIndexByte(p, '.'); i >= 0 { // drop "[sys]." / "master.dbo." etc.
		p = p[i+1:]
	}
	return strings.NewReplacer("[", "", "]", "").Replace(p)
}

func classifyRPC(proc string) Verdict {
	if proc == "" {
		return Verdict{Pin: true, Reason: "unparseable RPC (fail-safe)"}
	}
	name := normalizeProc(proc)
	switch {
	case name == "sp_executesql", name == "sp_execute", name == "sp_unprepare", name == "sp_cursorclose", name == "sp_cursorunprepare":
		return multiplexable // no NEW session-scoped handle created
	case readOnlyCatalogRPC[name]:
		return multiplexable // read-only catalog metadata — no session state
	case name == "sp_prepare", name == "sp_prepexec", name == "sp_prepexecrpc":
		return Verdict{Pin: true, Reason: "server-side prepared handle (" + name + ")"}
	case name == "sp_cursor", name == "sp_cursoropen", name == "sp_cursorprepare", name == "sp_cursorprepexec", name == "sp_cursorexecute", name == "sp_cursorfetch", name == "sp_cursoroption":
		return Verdict{Pin: true, Reason: "cursor (" + name + ")"}
	default:
		// A user stored proc or an unknown system proc — we can't prove it leaves no state.
		return Verdict{Pin: true, Reason: "unrecognized RPC (" + proc + ", fail-safe)"}
	}
}

// isSetOnly reports whether every statement in the batch is a poolable session-option SET — either a
// SET TRANSACTION ISOLATION LEVEL, or a SET of a known driver-prelude option. A single non-SET statement
// (or a SET of an unlisted option) disqualifies it, so the login-prelude exception only ever applies to a
// pure prelude batch and never to one that also carries real work.
func isSetOnly(text string) bool {
	found := false
	for _, raw := range strings.FieldsFunc(text, func(r rune) bool { return r == ';' || r == '\n' }) {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		// Session context (CONTEXT_INFO / sp_set_session_context) is per-session application state, not a
		// re-applied driver default — it must pin even in an opening batch.
		if reContextI.MatchString(stmt) || reSetContext.MatchString(stmt) {
			return false
		}
		// A driver re-issues its full login prelude on every fresh connection, so a SET-only opening batch
		// — SET TRANSACTION ISOLATION LEVEL, or any SET <option> — is re-applied on a reused backend, not
		// leaked between clients. Any non-SET statement is real work and disqualifies the prelude exception.
		if reIsolation.MatchString(stmt) || reSetOption.MatchString(stmt) {
			found = true
			continue
		}
		return false
	}
	return found
}
