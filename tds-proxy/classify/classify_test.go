package classify

import (
	"encoding/binary"
	"strings"
	"testing"

	"openinfra-tds-proxy/tds"
)

func TestClassifyBatch(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		pin     bool
		reason  string // substring
		prelude bool
	}{
		{"plain select", "SELECT * FROM orders WHERE id=1", false, "", false},
		{"parameterized-looking dml", "UPDATE orders SET status='x' WHERE id=1", false, "", false}, // SET clause, not SET option
		{"insert", "INSERT INTO t(a) VALUES(1)", false, "", false},
		{"set option", "SET NOCOUNT ON", true, "SET session option", false},
		{"set isolation", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", true, "ISOLATION", false},
		{"temp table", "CREATE TABLE #scratch (id int)", true, "temp table", false},
		{"cursor", "DECLARE c CURSOR FOR SELECT 1", true, "cursor", false},
		{"use db", "USE tempdb", true, "USE database", false},
		{"begin tran", "BEGIN TRANSACTION", true, "explicit transaction", false},
		{"context_info", "SET CONTEXT_INFO 0x1234", true, "CONTEXT_INFO", false},
		{"applock", "EXEC sp_getapplock @Resource='r'", true, "applock", false},
		{"prelude set-only", "SET QUOTED_IDENTIFIER ON\nSET ANSI_NULLS ON\nSET ARITHABORT ON", true, "SET session option", true},
		{"big statement", "SELECT '" + strings.Repeat("x", 17000) + "'", true, "16KB", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := classifyBatch(c.sql)
			if v.Pin != c.pin {
				t.Fatalf("pin=%v want %v (%+v)", v.Pin, c.pin, v)
			}
			if c.reason != "" && !strings.Contains(v.Reason, c.reason) {
				t.Fatalf("reason %q missing %q", v.Reason, c.reason)
			}
			if v.Prelude != c.prelude {
				t.Fatalf("prelude=%v want %v", v.Prelude, c.prelude)
			}
		})
	}
}

func TestClassifyRPC(t *testing.T) {
	cases := []struct {
		proc string
		pin  bool
	}{
		{"sp_executesql", false},
		{"sp_execute", false},
		{"sp_prepare", true},
		{"sp_prepexec", true},
		{"sp_cursoropen", true},
		{"sp_cursorprepare", true},
		{"", true},            // unparseable → fail-safe pin
		{"dbo.my_proc", true}, // unknown user proc → fail-safe pin
	}
	for _, c := range cases {
		if v := classifyRPC(c.proc); v.Pin != c.pin {
			t.Errorf("classifyRPC(%q).Pin = %v, want %v", c.proc, v.Pin, c.pin)
		}
	}
}

// TestClassify_ThroughParse proves the parse+classify path on a real SQLBatch body (ALL_HEADERS + UCS-2).
func TestClassify_ThroughParse(t *testing.T) {
	body := buildSQLBatch("SET NOCOUNT ON")
	v := Classify(tds.TypeSQLBatch, body)
	if !v.Pin || !strings.Contains(v.Reason, "SET session option") {
		t.Fatalf("expected SET pin through parse, got %+v", v)
	}
	sel := buildSQLBatch("SELECT 1")
	if Classify(tds.TypeSQLBatch, sel).Pin {
		t.Fatalf("plain SELECT should multiplex")
	}
}

func TestClassify_UnknownTypePins(t *testing.T) {
	if !Classify(0x99, nil).Pin {
		t.Fatal("unknown message type must fail-safe pin")
	}
}

// buildSQLBatch encodes text as a SQLBatch body: a 4-byte ALL_HEADERS block (empty) + UTF-16LE text.
func buildSQLBatch(text string) []byte {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, 4) // ALL_HEADERS total length = just the length field
	u := make([]byte, 0, len(text)*2)
	for _, r := range text {
		var c [2]byte
		binary.LittleEndian.PutUint16(c[:], uint16(r))
		u = append(u, c[:]...)
	}
	return append(hdr, u...)
}
