package tds

import (
	"encoding/binary"
	"io"
)

// ReadMessage reads a full TDS message — every packet up to and including the one with the EOM bit —
// and returns the message type, the reassembled payload (bodies concatenated), and the raw bytes
// (headers included) exactly as received so the caller can relay or replay them verbatim.
func ReadMessage(r io.Reader) (msgType byte, body, raw []byte, err error) {
	for {
		p, e := ReadPacket(r)
		if e != nil {
			return msgType, body, raw, e
		}
		if len(raw) == 0 {
			msgType = p.Type
		}
		body = append(body, p.Body...)
		raw = append(raw, p.Raw...)
		if p.EOM() {
			return msgType, body, raw, nil
		}
	}
}

// statusResetConnection is bit 3 of the packet status byte: reset the connection's session state before
// executing this batch (MS-TDS §2.2.3.1.2). A pooled backend handed to the next borrower gets this set
// on its first client packet so residual clean-but-nondefault state is wiped server-side.
const statusResetConnection byte = 0x08

// WithResetConnection returns a copy of a raw message with the RESETCONNECTION status bit set on its
// FIRST packet only (the reset applies to the whole batch, requested once). Later packets are unchanged.
func WithResetConnection(raw []byte) []byte {
	if len(raw) < headerLen {
		return raw
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	out[1] |= statusResetConnection // status byte of the first packet
	return out
}

// BuildPreloginResponse synthesizes a server PRELOGIN response advertising no encryption support
// (ENCRYPT_NOT_SUP), so the client proceeds in plaintext — matching Babelfish's TDS-no-TLS reality and
// SQL Server with ForceEncryption off. The proxy answers the client's PRELOGIN with this itself, before
// it has seen the credentials, so it can pick a pooled backend by identity from the LOGIN7 that follows.
// One packet, type 0x04 (server reply), EOM set.
func BuildPreloginResponse() []byte {
	// Option table: VERSION(0x00) + ENCRYPTION(0x01) + TERMINATOR(0xFF); each non-terminator entry is
	// token(1) offset(2, big-endian) length(2, big-endian). Data follows the table.
	const verOff = 11 // 5 (version entry) + 5 (encryption entry) + 1 (terminator)
	const encOff = verOff + 6
	payload := []byte{
		0x00, 0x00, verOff, 0x00, 0x06, // VERSION  @11 len 6
		0x01, 0x00, encOff, 0x00, 0x01, // ENCRYPTION @17 len 1
		0xFF,                           // TERMINATOR
		0x10, 0x00, 0x03, 0xE8, 0x00, 0x00, // version 16.0.1000.0
		0x02,                           // ENCRYPT_NOT_SUP
	}
	total := headerLen + len(payload)
	pkt := make([]byte, total)
	pkt[0] = TypeTabular // 0x04 server reply
	pkt[1] = statusEOM
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[6] = 1 // packet id
	copy(pkt[headerLen:], payload)
	return pkt
}

// Login7Info is what the pool needs from a client LOGIN7: the identity to key a backend pool on, plus
// the raw obfuscated password field (used only to prove a reusing client presents the same credentials —
// TDS password obfuscation is deterministic and unsalted, so equal plaintext ⇒ equal bytes).
type Login7Info struct {
	User      string
	Database  string
	PassField []byte
}

// ParseLogin7 extracts the identity fields from a LOGIN7 payload (MS-TDS §2.2.6.4). The offset/length
// block starts at a fixed position; every ib* offset is relative to the start of the payload and every
// cch* length counts UCS-2 characters (2 bytes each). Returns ok=false if the payload is too short or
// the offsets don't fit.
func ParseLogin7(body []byte) (Login7Info, bool) {
	// The offset/length block begins at byte 36 (after the fixed 36-byte header). We need through the
	// database offset pair at 68..71.
	if len(body) < 72 {
		return Login7Info{}, false
	}
	str := func(ibOff, cchOff int) (string, []byte, bool) {
		ib := int(binary.LittleEndian.Uint16(body[ibOff:]))
		cch := int(binary.LittleEndian.Uint16(body[cchOff:]))
		n := cch * 2
		if ib < 0 || n < 0 || ib+n > len(body) {
			return "", nil, false
		}
		return decodeUTF16LE(body[ib : ib+n]), body[ib : ib+n], true
	}
	user, _, ok1 := str(40, 42)      // ibUserName / cchUserName
	_, pass, ok2 := str(44, 46)      // ibPassword / cchPassword (raw obfuscated bytes)
	db, _, ok3 := str(68, 70)        // ibDatabase / cchDatabase
	if !ok1 || !ok2 || !ok3 {
		return Login7Info{}, false
	}
	return Login7Info{User: user, Database: db, PassField: pass}, true
}
