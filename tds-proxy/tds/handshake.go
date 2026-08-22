package tds

import (
	"encoding/binary"
	"hash/fnv"
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

// ENCRYPTION option values in a PRELOGIN option table (MS-TDS §2.2.6.5). The client advertises what it
// supports/wants; the server answers with what it will do.
const (
	EncryptOff    byte = 0x00 // encryption available, off unless the peer requires it
	EncryptOn     byte = 0x01 // encryption available and on (historically: login packet only)
	EncryptNotSup byte = 0x02 // no encryption available (the plaintext path)
	EncryptReq    byte = 0x03 // encryption REQUIRED — all traffic after the handshake stays TLS
)

// preloginOptEncryption is the ENCRYPTION option token in a PRELOGIN option table.
const preloginOptEncryption = 0x01

// BuildPreloginResponse synthesizes a server PRELOGIN response advertising no encryption support
// (ENCRYPT_NOT_SUP), so the client proceeds in plaintext — matching Babelfish's TDS-no-TLS reality and
// SQL Server with ForceEncryption off. The proxy answers the client's PRELOGIN with this itself, before
// it has seen the credentials, so it can pick a pooled backend by identity from the LOGIN7 that follows.
// One packet, type 0x04 (server reply), EOM set.
func BuildPreloginResponse() []byte { return BuildPreloginResponseEnc(EncryptNotSup) }

// BuildPreloginResponseEnc is BuildPreloginResponse with a chosen ENCRYPTION answer — EncryptNotSup for
// the plaintext path, EncryptReq to require TLS for the rest of the session (encrypt=on/strict).
func BuildPreloginResponseEnc(enc byte) []byte {
	// Option table: VERSION(0x00) + ENCRYPTION(0x01) + TERMINATOR(0xFF); each non-terminator entry is
	// token(1) offset(2, big-endian) length(2, big-endian). Data follows the table.
	const verOff = 11 // 5 (version entry) + 5 (encryption entry) + 1 (terminator)
	const encOff = verOff + 6
	payload := []byte{
		0x00, 0x00, verOff, 0x00, 0x06, // VERSION  @11 len 6
		0x01, 0x00, encOff, 0x00, 0x01, // ENCRYPTION @17 len 1
		0xFF,                               // TERMINATOR
		0x10, 0x00, 0x03, 0xE8, 0x00, 0x00, // version 16.0.1000.0
		enc, // the ENCRYPTION answer
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

// BuildClientPrelogin synthesizes a minimal CLIENT PRELOGIN request (type 0x12) advertising
// ENCRYPT_NOT_SUP. When the proxy terminates the client's TLS (encrypt=on/strict) it must still open the
// backend in PLAINTEXT (the managed engine is TDS-no-TLS), so it sends the backend this rather than
// replaying the client's encryption-advertising PRELOGIN. The backend's PRELOGIN reply is discarded, so
// only validity + the NOT_SUP answer matter.
func BuildClientPrelogin() []byte {
	pkt := BuildPreloginResponseEnc(EncryptNotSup)
	pkt[0] = TypePreLogin // 0x12 client request (BuildPreloginResponseEnc emits 0x04 server reply)
	return pkt
}

// PreloginEncryption reads the ENCRYPTION option a client advertised in its PRELOGIN (EncryptOff/On/
// NotSup/Req). Defaults to EncryptNotSup when the option is absent or the table is malformed — i.e. treat
// an unreadable prelogin as "no encryption", never as "encryption on", so a parse slip fails safe to the
// existing plaintext path rather than into a half-built TLS handshake.
func PreloginEncryption(body []byte) byte {
	for i := 0; i < len(body); {
		tok := body[i]
		if tok == 0xFF { // TERMINATOR
			return EncryptNotSup
		}
		if i+5 > len(body) {
			return EncryptNotSup
		}
		off := int(body[i+1])<<8 | int(body[i+2]) // big-endian offset from payload start
		ln := int(body[i+3])<<8 | int(body[i+4])
		if tok == preloginOptEncryption {
			if ln >= 1 && off >= 0 && off < len(body) {
				return body[off]
			}
			return EncryptNotSup
		}
		i += 5
	}
	return EncryptNotSup
}

// preloginOptMARS is the MARS option token in a PRELOGIN option table (MS-TDS §2.2.6.5).
const preloginOptMARS = 0x04

// PreloginRequestsMARS reports whether a client PRELOGIN asked for MARS (Multiple Active Result Sets) —
// option token 0x04 with value 1. The pool does NOT grant MARS: its synthesized PRELOGIN response omits
// the option, so the client falls back to one active request per connection, which is what keeps the
// pool's synchronous request/response model correct. Counting how many clients *ask* is the visibility no
// pooler — AWS RDS Proxy included — surfaces: a MARS-heavy fleet is one a future per-transaction
// multiplexer would have to pin or specially handle, and knowing the number turns that from a guess into
// a measurement. This reads only the well-defined option table (no session-id/SMID offset guessing).
func PreloginRequestsMARS(body []byte) bool {
	for i := 0; i < len(body); {
		tok := body[i]
		if tok == 0xFF { // TERMINATOR
			return false
		}
		if i+5 > len(body) {
			return false
		}
		off := int(body[i+1])<<8 | int(body[i+2]) // big-endian offset from payload start
		ln := int(body[i+3])<<8 | int(body[i+4])
		if tok == preloginOptMARS {
			return ln >= 1 && off >= 0 && off < len(body) && body[off] == 0x01
		}
		i += 5
	}
	return false
}

// Login7Info is what the pool needs from a client LOGIN7: the identity to key a backend pool on, plus
// the raw obfuscated password field (used only to prove a reusing client presents the same credentials —
// TDS password obfuscation is deterministic and unsalted, so equal plaintext ⇒ equal bytes). Integrated
// reports SSPI/Windows integrated security (fIntegratedSecurity): such logins carry NO password (the
// identity is in a per-connection SSPI blob). FedAuth reports federated/Azure AD auth (a FEDAUTH token in
// the FeatureExt block): the principal is in the token, not the (empty) password field. Neither can be
// keyed or pooled by credential — the pool refuses both rather than risk collapsing distinct principals
// onto one shared backend.
type Login7Info struct {
	User       string
	Database   string
	PassField  []byte
	Integrated bool
	FedAuth    bool
	Profile    uint64 // wire-format fingerprint (see LoginProfile) — part of the pool key
}

// LoginProfile hashes the LOGIN7 fields that determine the wire format of the backend's RESPONSES — TDS
// version, packet size, the option/type flags, the LCID, and the requested FeatureExt features. The pool
// MUST fold this into its key: the backend's response format is fixed by whichever client's LOGIN7 the
// proxy replayed (the cold opener), and RESETCONNECTION does NOT renegotiate it. So handing a backend
// opened by driver A to a driver B that negotiated a different packet size or FeatureExt set makes B
// mis-parse A's-format responses — observed as an intermittent token desync when Microsoft.Data.SqlClient
// reused a pyodbc/ODBC-opened backend (different packet size + COLUMNENCRYPTION/GLOBALTRANSACTIONS feats).
// Per-client noise that does NOT affect format (ClientProgVer, ClientPID, ConnectionID, timezone, and the
// host/user/app strings) is deliberately excluded so two connections from the SAME driver still share a
// backend.
func LoginProfile(body []byte) uint64 {
	h := fnv.New64a()
	if len(body) >= 36 {
		h.Write(body[4:12])  // TDSVersion (4:8) + PacketSize (8:12)
		h.Write(body[24:28]) // OptionFlags1, OptionFlags2, TypeFlags, OptionFlags3
		h.Write(body[32:36]) // ClientLCID
	}
	// FeatureExt features (id + len + data) — UTF8_SUPPORT, COLUMNENCRYPTION, etc. change result framing.
	if len(body) >= 58 && body[27]&0x10 != 0 { // OptionFlags3 fExtension
		ptr := int(binary.LittleEndian.Uint16(body[56:])) // ExtensionOffset → a DWORD
		if ptr >= 0 && ptr+4 <= len(body) {
			blk := int(binary.LittleEndian.Uint32(body[ptr:]))
			for p := blk; p >= 0 && p < len(body); {
				if body[p] == 0xFF { // FEATUREEXT_TERMINATOR
					h.Write([]byte{0xFF})
					break
				}
				if p+5 > len(body) {
					break
				}
				dl := int(binary.LittleEndian.Uint32(body[p+1:]))
				if dl < 0 || p+5+dl > len(body) {
					break
				}
				h.Write(body[p : p+5+dl])
				p += 5 + dl
			}
		}
	}
	return h.Sum64()
}

// fedAuth reports whether a LOGIN7 carries a FEDAUTH feature (Azure AD / federated auth) in its FeatureExt
// block. Federated auth puts the real principal in a token inside FeatureExt, not the (empty) password
// field, so the pool's user+db+password key cannot tell two federated principals apart — exactly the
// identity collapse the pool must never allow. Fail-safe: once fExtension announces a FeatureExt block, any
// parse ambiguity returns true (refuse) rather than risk a silent collapse; with fExtension clear there is
// no block and it returns false. Bit/offset/id values per MS-TDS §2.2.6.4 (OptionFlags3 fExtension=0x10 at
// byte 27; ExtensionOffset uint16 at byte 56 → a DWORD pointing at the block; FEATUREEXT ids FEDAUTH=0x02,
// TERMINATOR=0xFF; each non-terminator feature is id(1)+len(4)+data).
func fedAuth(body []byte) bool {
	const fExtension = 0x10 // OptionFlags3 (byte 27) bit
	if len(body) < 58 || body[27]&fExtension == 0 {
		return false // no FeatureExt block announced
	}
	ptr := int(binary.LittleEndian.Uint16(body[56:])) // ExtensionOffset → a 4-byte DWORD
	if ptr < 0 || ptr+4 > len(body) {
		return true
	}
	block := int(binary.LittleEndian.Uint32(body[ptr:])) // DWORD → FeatureExt block offset
	if block < 0 || block >= len(body) {
		return true
	}
	for p := block; p < len(body); {
		switch body[p] {
		case 0xFF: // FEATUREEXT_TERMINATOR
			return false
		case 0x02: // FEATUREEXT_FEDAUTH
			return true
		}
		if p+5 > len(body) { // truncated feature header (id + 4-byte len)
			return true
		}
		dlen := int(binary.LittleEndian.Uint32(body[p+1:]))
		if dlen < 0 || p+5+dlen > len(body) {
			return true
		}
		p += 5 + dlen
	}
	return true // ran off the end with no terminator — malformed, fail safe
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
	user, _, ok1 := str(40, 42) // ibUserName / cchUserName
	_, pass, ok2 := str(44, 46) // ibPassword / cchPassword (raw obfuscated bytes)
	db, _, ok3 := str(68, 70)   // ibDatabase / cchDatabase
	if !ok1 || !ok2 || !ok3 {
		return Login7Info{}, false
	}
	// OptionFlags2 is byte 25; fIntegratedSecurity is its high bit (0x80). When set, the credentials are a
	// per-connection SSPI blob, not the (empty) password field — such a login must not be pooled by credential.
	integrated := body[25]&0x80 != 0
	return Login7Info{User: user, Database: db, PassField: pass, Integrated: integrated, FedAuth: fedAuth(body), Profile: LoginProfile(body)}, true
}
