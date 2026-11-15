// Package guac speaks the Guacamole protocol to guacd, the remote desktop proxy behind Fleet Manager's
// Remote Desktop: it reads and writes instructions and performs the handshake that starts an RDP
// connection. The protocol is text: an instruction is its opcode and arguments, each written as its
// length in Unicode characters, a period and the value, separated by commas and ended by a semicolon
// ("4.size,4.1024,3.768;").
package guac

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Instruction is one Guacamole instruction.
type Instruction struct {
	Opcode string
	Args   []string
}

// New is the instruction opcode(args...).
func New(opcode string, args ...string) Instruction { return Instruction{Opcode: opcode, Args: args} }

// String is the instruction encoded for the wire.
func (i Instruction) String() string {
	var b strings.Builder
	writeElement(&b, i.Opcode)
	for _, a := range i.Args {
		b.WriteByte(',')
		writeElement(&b, a)
	}
	b.WriteByte(';')
	return b.String()
}

func writeElement(b *strings.Builder, v string) {
	b.WriteString(strconv.Itoa(utf8.RuneCountInString(v)))
	b.WriteByte('.')
	b.WriteString(v)
}

// Internal is the opcode of the tunnel's own instructions (the empty opcode), which the tunnel uses to
// carry its UUID and keep-alive pings and which never reach guacd.
const Internal = ""

// MaxElement is the longest element a Reader accepts, in characters: guacd splits image data into blobs
// far smaller than this, so anything longer is a broken or hostile peer.
const MaxElement = 1 << 20

// ErrMalformed is a byte stream that is not Guacamole instructions.
var ErrMalformed = errors.New("guac: malformed instruction")

// Reader reads instructions from a stream.
type Reader struct{ r *bufio.Reader }

// NewReader reads instructions from r.
func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReaderSize(r, 64<<10)} }

// Read is the next instruction and its encoded form, as it was on the wire.
func (rd *Reader) Read() (Instruction, string, error) {
	var raw strings.Builder
	var elems []string
	for {
		n := 0
		digits := 0
		for {
			c, err := rd.r.ReadByte()
			if err != nil {
				if err == io.EOF && (digits > 0 || len(elems) > 0) {
					err = io.ErrUnexpectedEOF
				}
				return Instruction{}, "", err
			}
			if c == '.' {
				break
			}
			if c < '0' || c > '9' || digits >= 8 {
				return Instruction{}, "", ErrMalformed
			}
			n = n*10 + int(c-'0')
			digits++
		}
		if digits == 0 || n > MaxElement {
			return Instruction{}, "", ErrMalformed
		}
		var v strings.Builder
		for k := 0; k < n; k++ {
			r, _, err := rd.r.ReadRune()
			if err != nil {
				return Instruction{}, "", io.ErrUnexpectedEOF
			}
			v.WriteRune(r)
		}
		elems = append(elems, v.String())
		raw.WriteString(strconv.Itoa(n))
		raw.WriteByte('.')
		raw.WriteString(v.String())
		end, err := rd.r.ReadByte()
		if err != nil {
			return Instruction{}, "", io.ErrUnexpectedEOF
		}
		raw.WriteByte(end)
		switch end {
		case ',':
			continue
		case ';':
			return Instruction{Opcode: elems[0], Args: elems[1:]}, raw.String(), nil
		default:
			return Instruction{}, "", ErrMalformed
		}
	}
}

// ParseAll parses a run of whole instructions (a websocket message from the browser's tunnel).
func ParseAll(s string) ([]Instruction, error) {
	rd := NewReader(strings.NewReader(s))
	var out []Instruction
	for {
		in, _, err := rd.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
}

// Status codes guacd and the tunnel report in an error instruction (Guacamole's protocol status codes).
const (
	StatusServerError         = 0x0200
	StatusUpstreamTimeout     = 0x0202
	StatusUpstreamError       = 0x0203
	StatusUpstreamNotFound    = 0x0207
	StatusUpstreamUnavailable = 0x0208
	StatusSessionTimeout      = 0x020A
	StatusSessionClosed       = 0x020B
	StatusClientBadRequest    = 0x0300
	StatusClientUnauthorized  = 0x0301
	StatusClientForbidden     = 0x0303
	StatusClientTimeout       = 0x0308
	StatusClientTooMany       = 0x031D
)

// Error is the error instruction that tells the browser why its connection ended.
func Error(message string, status int) Instruction {
	return New("error", message, strconv.Itoa(status))
}

// Size is the display the browser asks for.
type Size struct{ Width, Height, DPI int }

// Handshake starts a connection over guacd: it selects protocol, answers the parameters guacd asks for
// from params (absent ones empty), declares the client's display and image formats, and waits for
// guacd's ready. It answers the connection's id.
func Handshake(rw io.ReadWriter, rd *Reader, protocol string, params map[string]string, size Size, timezone string) (string, error) {
	send := func(i Instruction) error {
		_, err := io.WriteString(rw, i.String())
		return err
	}
	if err := send(New("select", protocol)); err != nil {
		return "", err
	}
	args, _, err := rd.Read()
	if err != nil {
		return "", fmt.Errorf("guacd did not answer select: %w", err)
	}
	if args.Opcode == "error" {
		return "", fmt.Errorf("guacd refused %s: %s", protocol, strings.Join(args.Args, " "))
	}
	if args.Opcode != "args" {
		return "", fmt.Errorf("guacd answered select with %q", args.Opcode)
	}
	if size.DPI <= 0 {
		size.DPI = 96
	}
	for _, i := range []Instruction{
		New("size", strconv.Itoa(size.Width), strconv.Itoa(size.Height), strconv.Itoa(size.DPI)),
		New("audio"),
		New("video"),
		New("image", "image/png", "image/jpeg", "image/webp"),
		New("timezone", timezone),
	} {
		if err := send(i); err != nil {
			return "", err
		}
	}
	values := make([]string, len(args.Args))
	for k, name := range args.Args {
		if k == 0 && strings.HasPrefix(name, "VERSION_") {
			values[k] = ProtocolVersion
			continue
		}
		values[k] = params[name]
	}
	if err := send(New("connect", values...)); err != nil {
		return "", err
	}
	ready, _, err := rd.Read()
	if err != nil {
		return "", fmt.Errorf("guacd did not answer connect: %w", err)
	}
	if ready.Opcode == "error" {
		return "", fmt.Errorf("guacd refused the connection: %s", strings.Join(ready.Args, " "))
	}
	if ready.Opcode != "ready" || len(ready.Args) == 0 {
		return "", fmt.Errorf("guacd answered connect with %q", ready.Opcode)
	}
	return ready.Args[0], nil
}

// ProtocolVersion is the protocol version this side speaks, answered to guacd's version argument.
const ProtocolVersion = "VERSION_1_5_0"

// Buffered is how many bytes the reader holds already read from the stream (more instructions waiting).
func (rd *Reader) Buffered() int { return rd.r.Buffered() }
