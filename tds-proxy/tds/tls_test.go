package tds

import (
	"bytes"
	"net"
	"testing"
)

// PreloginEncryption round-trips against the option table BuildPreloginResponseEnc emits (same table
// shape a client sends), for every ENCRYPTION value — and fails safe to NotSup on a malformed table.
func TestPreloginEncryption(t *testing.T) {
	for _, enc := range []byte{EncryptOff, EncryptOn, EncryptNotSup, EncryptReq} {
		pkt := BuildPreloginResponseEnc(enc)
		if got := PreloginEncryption(pkt[headerLen:]); got != enc {
			t.Errorf("PreloginEncryption = 0x%02x, want 0x%02x", got, enc)
		}
	}
	if got := PreloginEncryption([]byte{0x01, 0x00}); got != EncryptNotSup {
		t.Errorf("malformed table: got 0x%02x, want NotSup (fail-safe)", got)
	}
	if got := PreloginEncryption(nil); got != EncryptNotSup {
		t.Errorf("empty: got 0x%02x, want NotSup", got)
	}
}

// BuildClientPrelogin is a client-typed (0x12) PRELOGIN advertising NotSup — what the proxy sends the
// plaintext backend when it has terminated the client's TLS.
func TestBuildClientPrelogin(t *testing.T) {
	pkt := BuildClientPrelogin()
	if pkt[0] != TypePreLogin {
		t.Fatalf("type = 0x%02x, want 0x12 (client PRELOGIN)", pkt[0])
	}
	if got := PreloginEncryption(pkt[headerLen:]); got != EncryptNotSup {
		t.Fatalf("encryption = 0x%02x, want NotSup", got)
	}
}

// FramePrelogin wraps a payload in exactly one EOM PRELOGIN (0x12) packet whose body is the payload.
func TestFramePrelogin(t *testing.T) {
	pkt := FramePrelogin([]byte("clienthello"))
	p, err := ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypePreLogin || !p.EOM() || string(p.Body) != "clienthello" {
		t.Fatalf("framed packet type=0x%02x eom=%v body=%q", p.Type, p.EOM(), p.Body)
	}
}

// bufConn is a minimal net.Conn backed by two buffers, for exercising tdsHandshakeConn's framing.
type bufConn struct {
	net.Conn
	r *bytes.Buffer
	w *bytes.Buffer
}

func (b *bufConn) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *bufConn) Write(p []byte) (int, error) { return b.w.Write(p) }

// During the handshake, tdsHandshakeConn Write wraps records in TDS packets and Read unwraps them; after
// SetDone it passes through raw (post-handshake TLS rides the bare stream).
func TestTDSHandshakeConnFramingThenPassthrough(t *testing.T) {
	// Read: a TDS packet on the wire yields its payload.
	in := &bufConn{r: bytes.NewBuffer(FramePrelogin([]byte("serverhello"))), w: &bytes.Buffer{}}
	hc := NewTDSHandshakeConn(in)
	got := make([]byte, 32)
	n, err := hc.Read(got)
	if err != nil || string(got[:n]) != "serverhello" {
		t.Fatalf("wrapped read = %q (err %v), want serverhello", got[:n], err)
	}
	// Write: bytes go out wrapped in a TDS packet.
	if _, err := hc.Write([]byte("finished")); err != nil {
		t.Fatal(err)
	}
	p, _ := ReadPacket(bytes.NewReader(in.w.Bytes()))
	if p.Type != TypePreLogin || string(p.Body) != "finished" {
		t.Fatalf("wrapped write body = %q type 0x%02x", p.Body, p.Type)
	}
	// After SetDone, I/O is raw passthrough (no TDS framing).
	hc.SetDone()
	raw := &bufConn{r: bytes.NewBufferString("rawappdata"), w: &bytes.Buffer{}}
	hc2 := NewTDSHandshakeConn(raw)
	hc2.SetDone()
	n, _ = hc2.Read(got)
	if string(got[:n]) != "rawappdata" {
		t.Fatalf("passthrough read = %q, want rawappdata", got[:n])
	}
	hc2.Write([]byte("out"))
	if raw.w.String() != "out" {
		t.Fatalf("passthrough write = %q, want out (no framing)", raw.w.String())
	}
}
