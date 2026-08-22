package tds

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildLogin7 encodes a minimal LOGIN7 payload with the given user/password/db in the offset block.
func buildLogin7(user string, pass []byte, db string) []byte {
	const fixed = 94 // through cbSSPILong; data starts here
	u := utf16le(user)
	d := utf16le(db)
	body := make([]byte, fixed)
	put := func(ibOff int, data []byte, cch int) int {
		ib := len(body)
		binary.LittleEndian.PutUint16(body[ibOff:], uint16(ib))
		binary.LittleEndian.PutUint16(body[ibOff+2:], uint16(cch))
		body = append(body, data...)
		return ib
	}
	put(40, u, len(user))      // ibUserName/cchUserName
	put(44, pass, len(pass)/2) // ibPassword/cchPassword (cch = chars)
	put(68, d, len(db))        // ibDatabase/cchDatabase
	binary.LittleEndian.PutUint32(body[0:], uint32(len(body)))
	return body
}

func utf16le(s string) []byte {
	var b []byte
	for _, r := range s {
		var c [2]byte
		binary.LittleEndian.PutUint16(c[:], uint16(r))
		b = append(b, c[:]...)
	}
	return b
}

func TestParseLogin7(t *testing.T) {
	pass := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06} // 3 UCS-2 chars, obfuscated bytes as-is
	body := buildLogin7("sa", pass, "master")
	info, ok := ParseLogin7(body)
	if !ok {
		t.Fatal("ParseLogin7 returned ok=false")
	}
	if info.User != "sa" {
		t.Errorf("user = %q, want sa", info.User)
	}
	if info.Database != "master" {
		t.Errorf("db = %q, want master", info.Database)
	}
	if !bytes.Equal(info.PassField, pass) {
		t.Errorf("passfield = %x, want %x", info.PassField, pass)
	}
}

// withFeatureExt appends a FeatureExt block (MS-TDS §2.2.6.4) to a LOGIN7 body: it sets the fExtension
// bit, points ExtensionOffset at a DWORD, and lays out each feature as id(1)+len(4)+data followed by the
// 0xFF terminator — matching what a driver writes for FEDAUTH/UTF8/etc.
func withFeatureExt(body []byte, feats map[byte][]byte) []byte {
	body[27] |= 0x10                                               // OptionFlags3 fExtension
	dwordAt := len(body)                                           // the 4-byte DWORD lives here
	binary.LittleEndian.PutUint16(body[56:], uint16(dwordAt))      // ExtensionOffset → the DWORD
	body = append(body, 0, 0, 0, 0)                                // reserve the DWORD
	blockAt := len(body)                                           // FeatureExt block starts here
	binary.LittleEndian.PutUint32(body[dwordAt:], uint32(blockAt)) // DWORD → the block
	for id, data := range feats {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(data)))
		body = append(body, id)
		body = append(body, l[:]...)
		body = append(body, data...)
	}
	body = append(body, 0xFF) // FEATUREEXT_TERMINATOR
	binary.LittleEndian.PutUint32(body[0:], uint32(len(body)))
	return body
}

func TestParseLogin7_FedAuth(t *testing.T) {
	// A plain SQL-auth login (no FeatureExt) is not federated.
	if info, ok := ParseLogin7(buildLogin7("sa", []byte{0x01, 0x02}, "master")); !ok || info.FedAuth {
		t.Fatalf("SQL-auth login must not be flagged FedAuth (ok=%v fedauth=%v)", ok, info.FedAuth)
	}
	// A FeatureExt carrying only benign features (UTF8_SUPPORT 0x0A) — as modern drivers send on ordinary
	// SQL-auth connects — must NOT be refused, or every real connection breaks.
	benign := withFeatureExt(buildLogin7("sa", []byte{0x01, 0x02}, "master"), map[byte][]byte{0x0A: {0x01}})
	if info, ok := ParseLogin7(benign); !ok || info.FedAuth {
		t.Fatalf("benign FeatureExt (UTF8) must not be flagged FedAuth (ok=%v fedauth=%v)", ok, info.FedAuth)
	}
	// A FeatureExt carrying FEDAUTH (0x02) — even alongside a benign feature — is federated → refuse.
	fed := withFeatureExt(buildLogin7("", nil, "master"), map[byte][]byte{0x0A: {0x01}, 0x02: {0x01, 0x00}})
	if info, ok := ParseLogin7(fed); !ok || !info.FedAuth {
		t.Fatalf("FEDAUTH FeatureExt must be flagged FedAuth (ok=%v fedauth=%v)", ok, info.FedAuth)
	}
	// Fail-safe: fExtension set but the extension pointer is off the end → refuse rather than miss it.
	bad := buildLogin7("", nil, "master")
	bad[27] |= 0x10
	binary.LittleEndian.PutUint16(bad[56:], uint16(len(bad)+50))
	if info, ok := ParseLogin7(bad); !ok || !info.FedAuth {
		t.Fatalf("malformed FeatureExt pointer must fail safe to FedAuth (ok=%v fedauth=%v)", ok, info.FedAuth)
	}
}

func TestParseLogin7_TooShort(t *testing.T) {
	if _, ok := ParseLogin7(make([]byte, 40)); ok {
		t.Fatal("expected ok=false for a truncated payload")
	}
}

func TestParseLogin7_Integrated(t *testing.T) {
	// SQL auth (a password present, fIntegratedSecurity clear) is not integrated.
	if info, ok := ParseLogin7(buildLogin7("sa", []byte{0x01, 0x02}, "master")); !ok || info.Integrated {
		t.Fatalf("SQL-auth login must not be flagged integrated (ok=%v integrated=%v)", ok, info.Integrated)
	}
	// Setting fIntegratedSecurity (OptionFlags2 bit 0x80, byte 25) flags it.
	body := buildLogin7("corp\\alice", nil, "master")
	body[25] |= 0x80
	if info, ok := ParseLogin7(body); !ok || !info.Integrated {
		t.Fatalf("expected Integrated=true (ok=%v integrated=%v)", ok, info.Integrated)
	}
}

func TestWithResetConnection(t *testing.T) {
	raw := make([]byte, headerLen+4)
	raw[0] = TypeSQLBatch
	raw[1] = statusEOM // 0x01
	out := WithResetConnection(raw)
	if out[1]&statusResetConnection == 0 {
		t.Fatal("RESETCONNECTION bit not set on first packet")
	}
	if out[1]&statusEOM == 0 {
		t.Fatal("EOM bit must be preserved")
	}
	if raw[1]&statusResetConnection != 0 {
		t.Fatal("original raw must not be mutated")
	}
}

// buildPrelogin encodes a PRELOGIN option table with VERSION + MARS(marsOn) + terminator.
func buildPrelogin(marsOn bool) []byte {
	const verOff = 11 // 5 (version) + 5 (mars) + 1 (terminator)
	const marsOff = verOff + 6
	marsVal := byte(0x00)
	if marsOn {
		marsVal = 0x01
	}
	return []byte{
		0x00, 0x00, verOff, 0x00, 0x06, // VERSION @11 len 6
		0x04, 0x00, marsOff, 0x00, 0x01, // MARS @17 len 1
		0xFF,                               // TERMINATOR
		0x10, 0x00, 0x03, 0xE8, 0x00, 0x00, // version data
		marsVal, // MARS data
	}
}

func TestPreloginRequestsMARS(t *testing.T) {
	if !PreloginRequestsMARS(buildPrelogin(true)) {
		t.Error("MARS=1 prelogin should be detected as requesting MARS")
	}
	if PreloginRequestsMARS(buildPrelogin(false)) {
		t.Error("MARS=0 prelogin must not be reported as requesting MARS")
	}
	// A prelogin with no MARS option at all (just the response builder's shape) must be false, not panic.
	if PreloginRequestsMARS(BuildPreloginResponse()[headerLen:]) {
		t.Error("a prelogin without a MARS option must report false")
	}
	if PreloginRequestsMARS(nil) || PreloginRequestsMARS([]byte{0xFF}) {
		t.Error("empty / terminator-only prelogin must report false")
	}
}

func TestBuildPreloginResponse(t *testing.T) {
	pkt := BuildPreloginResponse()
	p, err := ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("prelogin response is not a well-formed packet: %v", err)
	}
	if p.Type != TypeTabular {
		t.Errorf("type = 0x%02x, want 0x04 (reply)", p.Type)
	}
	if !p.EOM() {
		t.Error("prelogin response must set EOM")
	}
	// The ENCRYPTION option value (last data byte) must be ENCRYPT_NOT_SUP (0x02).
	if pkt[len(pkt)-1] != 0x02 {
		t.Errorf("encryption byte = 0x%02x, want 0x02 (NOT_SUP)", pkt[len(pkt)-1])
	}
}
