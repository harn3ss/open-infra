package guac

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
)

// Lengths are Unicode characters, not bytes, both ways.
func TestEncodeDecode(t *testing.T) {
	in := New("name", "café", "", "a,b;c")
	s := in.String()
	if s != "4.name,4.café,0.,5.a,b;c;" {
		t.Fatalf("encoded %q", s)
	}
	got, raw, err := NewReader(strings.NewReader(s + "3.nop;")).Read()
	if err != nil || raw != s || got.Opcode != "name" || len(got.Args) != 3 || got.Args[0] != "café" || got.Args[2] != "a,b;c" {
		t.Fatalf("decoded %+v %q %v", got, raw, err)
	}
	all, err := ParseAll("3.nop;4.sync,3.123;")
	if err != nil || len(all) != 2 || all[1].Opcode != "sync" || all[1].Args[0] != "123" {
		t.Fatalf("parse all: %+v %v", all, err)
	}
}

func TestMalformed(t *testing.T) {
	for _, s := range []string{"x.nop;", "3.nop:", ".nop;", "999999999.x;", "3.no"} {
		if _, err := ParseAll(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
	if _, _, err := NewReader(strings.NewReader("")).Read(); err != io.EOF {
		t.Errorf("empty stream: %v", err)
	}
}

// The handshake answers each parameter guacd asks for, its version argument with ours, and returns the
// connection id from ready.
func TestHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	got := make(chan []Instruction, 1)
	go func() {
		defer server.Close()
		rd := NewReader(server)
		var seen []Instruction
		sel, _, _ := rd.Read()
		seen = append(seen, sel)
		io.WriteString(server, New("args", "VERSION_1_5_0", "hostname", "port", "password").String())
		for {
			i, _, err := rd.Read()
			if err != nil {
				break
			}
			seen = append(seen, i)
			if i.Opcode == "connect" {
				io.WriteString(server, New("ready", "$abc").String())
				break
			}
		}
		got <- seen
	}()
	id, err := Handshake(client, NewReader(client), "rdp", map[string]string{"hostname": "10.0.0.1", "port": "3389", "unused": "x"},
		Size{Width: 1024, Height: 768}, "UTC")
	if err != nil || id != "$abc" {
		t.Fatalf("handshake: %q %v", id, err)
	}
	seen := <-got
	var ops []string
	for _, i := range seen {
		ops = append(ops, i.Opcode)
	}
	if strings.Join(ops, " ") != "select size audio video image timezone connect" {
		t.Fatalf("sent %v", ops)
	}
	if seen[1].Args[2] != "96" {
		t.Errorf("default DPI: %v", seen[1].Args)
	}
	c := seen[len(seen)-1]
	if strings.Join(c.Args, "|") != "VERSION_1_5_0|10.0.0.1|3389|" {
		t.Errorf("connect values: %v", c.Args)
	}
}

func TestHandshakeError(t *testing.T) {
	var out bytes.Buffer
	rw := struct {
		io.Reader
		io.Writer
	}{strings.NewReader(""), &out}
	if _, err := Handshake(rw, NewReader(strings.NewReader(Error("no such protocol", StatusServerError).String())), "rdp", nil, Size{}, ""); err == nil ||
		!strings.Contains(err.Error(), "no such protocol") {
		t.Fatalf("error answer: %v", err)
	}
}
