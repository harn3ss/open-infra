package tds

import (
	"bufio"
	"net"
)

// TLS-in-TDS termination helpers (issue #6). TDS negotiates TLS *inside* the wire protocol, so a
// listener-level terminator can't do it; the proxy must be the TLS peer. Two client shapes:
//
//   - TDS 8.0 "strict": TLS-first — the client opens with a normal TLS ClientHello (record type 0x16),
//     then speaks TDS inside TLS. Detected by peeking the first byte (PrefaceConn); handled with a
//     plain tls.Server on the raw conn.
//   - legacy "encrypt=on/mandatory" (TDS 7.x): the client sends a plaintext PRELOGIN, then the TLS
//     handshake records are carried INSIDE TDS PRELOGIN (0x12) packets until the handshake completes,
//     after which TLS rides the bare TCP stream. tdsHandshakeConn does that framing for tls.Server
//     during the handshake, then passes through raw.

// PrefaceConn buffers the client conn so the first byte can be peeked (TLS ClientHello 0x16 vs TDS
// PRELOGIN 0x12) without consuming it — the returned conn replays everything.
type PrefaceConn struct {
	net.Conn
	r *bufio.Reader
}

func NewPrefaceConn(c net.Conn) *PrefaceConn {
	return &PrefaceConn{Conn: c, r: bufio.NewReader(c)}
}

// Peek returns the next n bytes without consuming them.
func (p *PrefaceConn) Peek(n int) ([]byte, error) { return p.r.Peek(n) }

func (p *PrefaceConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// tdsHandshakeConn carries a TLS handshake inside TDS PRELOGIN (0x12) packets. It is the io.ReadWriter
// tls.Server uses DURING the handshake only: Read unwraps one TDS packet's payload (the peer's TLS
// records), Write frames the given TLS records into a TDS packet. Once SetDone is called (after
// tls.Handshake returns) it passes through raw, because post-handshake TLS records travel on the bare
// TCP stream, not wrapped in TDS packets.
type tdsHandshakeConn struct {
	net.Conn
	rbuf []byte // leftover decoded payload from the last TDS packet
	done bool
}

// NewTDSHandshakeConn wraps c for the tunneled (legacy encrypt=on) TLS handshake.
func NewTDSHandshakeConn(c net.Conn) *tdsHandshakeConn { return &tdsHandshakeConn{Conn: c} }

// SetDone switches to raw passthrough — call it once tls.Handshake has returned.
func (c *tdsHandshakeConn) SetDone() { c.done = true }

func (c *tdsHandshakeConn) Read(b []byte) (int, error) {
	if c.done {
		return c.Conn.Read(b)
	}
	if len(c.rbuf) == 0 {
		p, err := ReadPacket(c.Conn)
		if err != nil {
			return 0, err
		}
		c.rbuf = p.Body
	}
	n := copy(b, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *tdsHandshakeConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	// A TLS record is <= ~16KB, well under the 65535 TDS packet-length ceiling, so one packet per Write.
	if _, err := c.Conn.Write(FramePrelogin(b)); err != nil {
		return 0, err
	}
	return len(b), nil
}

// FramePrelogin wraps payload in a single TDS PRELOGIN (0x12) packet with the EOM bit set — the envelope
// used to carry TLS handshake records in the legacy tunneled handshake.
func FramePrelogin(payload []byte) []byte {
	total := headerLen + len(payload)
	pkt := make([]byte, total)
	pkt[0] = TypePreLogin // 0x12
	pkt[1] = statusEOM
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[6] = 1 // packet id
	copy(pkt[headerLen:], payload)
	return pkt
}
