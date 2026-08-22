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
	wbuf []byte // accumulated handshake output, flushed as one framed flight
	done bool
}

// NewTDSHandshakeConn wraps c for the tunneled (legacy encrypt=on) TLS handshake.
func NewTDSHandshakeConn(c net.Conn) *tdsHandshakeConn { return &tdsHandshakeConn{Conn: c} }

// SetDone flushes any buffered handshake output (the server's final CCS+Finished flight, written after
// tls.Handshake's last Read) and switches to raw passthrough. Call it once tls.Handshake has returned.
func (c *tdsHandshakeConn) SetDone() error {
	err := c.flush()
	c.done = true
	return err
}

func (c *tdsHandshakeConn) Read(b []byte) (int, error) {
	if c.done {
		return c.Conn.Read(b)
	}
	// Flush our accumulated flight as ONE TDS message before blocking on the peer's next flight — a
	// handshake flight is several TLS records (ServerHello/Certificate/…) written separately; a client
	// that respects EOM (mssql-jdbc) must see the whole flight under a single EOM, not one EOM per record.
	if err := c.flush(); err != nil {
		return 0, err
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

// handshakePacketSize is the TDS packet size while tunneling the TLS handshake. LOGIN7 (where a larger
// size could be negotiated) hasn't happened yet, so the default 4096 applies — and stricter clients
// (mssql-jdbc) REJECT a PRELOGIN packet larger than this, so a big server flight (ServerHello +
// Certificate) must be SPLIT across packets, not sent as one oversized packet.
const handshakePacketSize = 4096
const maxHandshakePayload = handshakePacketSize - headerLen

// Write buffers the handshake output; the flight is framed + sent by flush (on the next Read or SetDone),
// so all records of one flight go under a single EOM.
func (c *tdsHandshakeConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.wbuf = append(c.wbuf, b...)
	return len(b), nil
}

// flush sends the buffered flight as one TDS message: <=4096-byte PRELOGIN (0x12) packets, EOM on the
// last packet only.
func (c *tdsHandshakeConn) flush() error {
	if len(c.wbuf) == 0 {
		return nil
	}
	b := c.wbuf
	c.wbuf = nil
	for off := 0; ; {
		end := off + maxHandshakePayload
		if end >= len(b) {
			end = len(b)
		}
		if _, err := c.Conn.Write(framePrelogin(b[off:end], end >= len(b))); err != nil {
			return err
		}
		off = end
		if off >= len(b) {
			return nil
		}
	}
}

// FramePrelogin wraps payload in a single EOM TDS PRELOGIN (0x12) packet.
func FramePrelogin(payload []byte) []byte { return framePrelogin(payload, true) }

// framePrelogin builds one TDS PRELOGIN (0x12) packet, setting the EOM bit only when eom is true, so a
// multi-packet flight marks just its final packet.
func framePrelogin(payload []byte, eom bool) []byte {
	total := headerLen + len(payload)
	pkt := make([]byte, total)
	pkt[0] = TypePreLogin // 0x12
	if eom {
		pkt[1] = statusEOM
	}
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[6] = 1 // packet id
	copy(pkt[headerLen:], payload)
	return pkt
}
