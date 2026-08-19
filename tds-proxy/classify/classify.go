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
		return Verdict{Pin: true, Reason: "transaction manager request (explicit txn/savepoint)"}
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
		return Verdict{Pin: true, Reason: "explicit transaction"}
	case reAppLock.MatchString(text):
		return Verdict{Pin: true, Reason: "session-scoped applock"}
	case reWaitFor.MatchString(text):
		return Verdict{Pin: true, Reason: "WAITFOR"}
	}
	// A SET option (not one of the above specific forms).
	if m := reSetOption.FindStringSubmatch(text); m != nil {
		// Prelude: if the batch is ONLY SET statements, the session may treat the connection's first
		// such batch as the driver login prelude and re-apply it on fresh backends instead of pinning.
		return Verdict{Pin: true, Reason: "SET session option (" + m[1] + ")", Prelude: isSetOnly(text)}
	}
	return multiplexable // plain SELECT/INSERT/UPDATE/DELETE autocommit — the multiplexable common path
}

func classifyRPC(proc string) Verdict {
	switch proc {
	case "sp_executesql", "sp_execute", "sp_unprepare", "sp_cursorclose", "sp_cursorunprepare":
		return multiplexable // no NEW session-scoped handle created
	case "sp_prepare", "sp_prepexec", "sp_prepexecrpc":
		return Verdict{Pin: true, Reason: "server-side prepared handle (" + proc + ")"}
	case "sp_cursor", "sp_cursoropen", "sp_cursorprepare", "sp_cursorprepexec", "sp_cursorexecute", "sp_cursorfetch", "sp_cursoroption":
		return Verdict{Pin: true, Reason: "cursor (" + proc + ")"}
	case "":
		return Verdict{Pin: true, Reason: "unparseable RPC (fail-safe)"}
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

