// Package tds implements just enough of the TDS (Tabular Data Stream) wire protocol for a connection
// multiplexer to see what a client is doing: frame the 8-byte packet header, reassemble a full message
// (a "PDU" that may span several packets), and pull out the SQL text / RPC identity so the classifier
// can decide multiplex-vs-pin. It does NOT re-encode anything — the proxy relays raw packets verbatim
// and parses a copy, so the byte stream to the backend is untouched.
package tds

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// Packet types (TDS message type byte). See MS-TDS §2.2.3.1.1.
const (
	TypeSQLBatch     byte = 0x01 // client: a T-SQL batch as UCS-2 text
	TypePreTDS7Login byte = 0x02
	TypeRPC          byte = 0x03 // client: a remote-procedure call (sp_executesql, sp_prepare, …)
	TypeTabular      byte = 0x04 // server: results (token stream)
	TypeAttention    byte = 0x06 // client: cancel
	TypeBulkLoad     byte = 0x07 // client: bulk insert data stream
	TypeFedAuth      byte = 0x08
	TypeTxMgr        byte = 0x0E // client: transaction manager request (BEGIN/COMMIT/ROLLBACK, savepoints)
	TypeLogin7       byte = 0x10 // client: login
	TypeSSPI         byte = 0x11
	TypePreLogin     byte = 0x12 // client: prelogin (version/encryption negotiation)
)

// statusEOM is bit 0 of the status byte: this packet is the last of its message.
const statusEOM byte = 0x01

const headerLen = 8

// Packet is one framed TDS packet: its type/status plus the raw bytes (header included) for verbatim relay.
type Packet struct {
	Type   byte
	Status byte
	Raw    []byte // the entire packet, header + payload — relayed to the peer unchanged
	Body   []byte // payload only (Raw[8:])
}

// EOM reports whether this packet ends its message.
func (p Packet) EOM() bool { return p.Status&statusEOM != 0 }

// ReadPacket reads exactly one TDS packet (header + declared length). It returns the raw bytes so the
// caller can relay them without re-encoding.
func ReadPacket(r io.Reader) (Packet, error) {
	h := make([]byte, headerLen)
	if _, err := io.ReadFull(r, h); err != nil {
		return Packet{}, err
	}
	length := int(binary.BigEndian.Uint16(h[2:4]))
	if length < headerLen || length > 1<<20 {
		return Packet{}, fmt.Errorf("tds: implausible packet length %d", length)
	}
	raw := make([]byte, length)
	copy(raw, h)
	if _, err := io.ReadFull(r, raw[headerLen:]); err != nil {
		return Packet{}, err
	}
	return Packet{Type: h[0], Status: h[1], Raw: raw, Body: raw[headerLen:]}, nil
}

// TypeName gives a human label for a message type.
func TypeName(t byte) string {
	switch t {
	case TypeSQLBatch:
		return "SQLBatch"
	case TypeRPC:
		return "RPC"
	case TypeTabular:
		return "Response"
	case TypeAttention:
		return "Attention"
	case TypeBulkLoad:
		return "BulkLoad"
	case TypeTxMgr:
		return "TxMgr"
	case TypeLogin7:
		return "Login7"
	case TypePreLogin:
		return "PreLogin"
	case TypeSSPI:
		return "SSPI"
	default:
		return fmt.Sprintf("0x%02x", t)
	}
}

// allHeadersLen returns the length of the optional ALL_HEADERS block that prefixes a SQLBatch / RPC
// payload (MS-TDS §2.2.5.2), or 0 if none is present. The block starts with a uint32 total length.
func allHeadersLen(body []byte) int {
	if len(body) < 4 {
		return 0
	}
	total := binary.LittleEndian.Uint32(body[:4])
	// Sanity: the block must fit and be non-trivial (>= the 4-byte length + one header).
	if total >= 4 && int(total) <= len(body) && total < 1<<16 {
		return int(total)
	}
	return 0
}

// BatchText extracts the T-SQL text from a reassembled SQLBatch message body (UCS-2 / UTF-16LE),
// skipping the optional ALL_HEADERS prefix.
func BatchText(body []byte) string {
	off := allHeadersLen(body)
	if off > len(body) {
		off = 0
	}
	return decodeUTF16LE(body[off:])
}

// RPCProc extracts the procedure identity from a reassembled RPC message body: either a well-known
// ProcID (returned as its name) or an explicit procedure name. Returns "" if it can't be parsed.
func RPCProc(body []byte) string {
	off := allHeadersLen(body)
	if off+2 > len(body) {
		return ""
	}
	p := body[off:]
	nameLen := int(binary.LittleEndian.Uint16(p[:2])) // USHORT: name length in UCS-2 chars, or 0xFFFF for a ProcID
	if nameLen == 0xFFFF {
		if len(p) < 4 {
			return ""
		}
		return procIDName(binary.LittleEndian.Uint16(p[2:4]))
	}
	if 2+nameLen*2 > len(p) {
		return ""
	}
	return decodeUTF16LE(p[2 : 2+nameLen*2])
}

// procIDName maps the well-known stored-procedure IDs (MS-TDS §2.2.6.6) to names.
func procIDName(id uint16) string {
	switch id {
	case 1:
		return "sp_cursor"
	case 2:
		return "sp_cursoropen"
	case 3:
		return "sp_cursorprepare"
	case 4:
		return "sp_cursorexecute"
	case 5:
		return "sp_cursorprepexec"
	case 6:
		return "sp_cursorunprepare"
	case 7:
		return "sp_cursorfetch"
	case 8:
		return "sp_cursoroption"
	case 9:
		return "sp_cursorclose"
	case 10:
		return "sp_executesql"
	case 11:
		return "sp_prepare"
	case 12:
		return "sp_execute"
	case 13:
		return "sp_prepexec"
	case 14:
		return "sp_prepexecrpc"
	case 15:
		return "sp_unprepare"
	default:
		return fmt.Sprintf("procid:%d", id)
	}
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// TransactionManager (message type 0x0E) request subtypes (MS-TDS §2.2.6.8). Drivers open and close
// explicit transactions with these — database/sql + go-mssqldb, Microsoft.Data.SqlClient, mssql-jdbc's
// setAutoCommit, etc. — so tracking them on the request side is how the multiplexer knows a transaction's
// exact begin/commit boundaries (the server's DONE_INXACT is not set on the begin-ack DONE, so it can't).
const (
	TMBeginXact    uint16 = 5
	TMPromoteXact  uint16 = 6
	TMCommitXact   uint16 = 7
	TMRollbackXact uint16 = 8
	TMSaveXact     uint16 = 9
)

// TxMgrRequestType returns the RequestType USHORT of a TransactionManager (0x0E) message body — an
// ALL_HEADERS block (self-describing length prefix) followed by the 2-byte request type. Returns
// (0, false) if the body is too short or the ALL_HEADERS length is malformed.
func TxMgrRequestType(body []byte) (uint16, bool) {
	off := allHeadersLen(body)
	if off == 0 || off+2 > len(body) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(body[off : off+2]), true
}
