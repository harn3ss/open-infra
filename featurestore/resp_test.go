package main

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) any {
	t.Helper()
	v, err := readReply(bufio.NewReader(strings.NewReader(s)))
	if err != nil {
		t.Fatalf("readReply(%q): %v", s, err)
	}
	return v
}

func TestReadReplyTypes(t *testing.T) {
	if v := parse(t, "+OK\r\n"); v != "OK" {
		t.Fatalf("simple string = %v", v)
	}
	if v := parse(t, ":42\r\n"); v != int64(42) {
		t.Fatalf("integer = %v", v)
	}
	if v := parse(t, "$5\r\nhello\r\n"); v != "hello" {
		t.Fatalf("bulk = %v", v)
	}
	if v := parse(t, "$-1\r\n"); v != nil {
		t.Fatalf("nil bulk = %v", v)
	}
	// bulk with an embedded CRLF (length-prefixed, not line-delimited)
	if v := parse(t, "$7\r\na\r\nb\r\nc\r\n"); v != "a\r\nb\r\nc" {
		t.Fatalf("bulk with CRLF = %q", v)
	}
}

func TestReadReplyArrayAndError(t *testing.T) {
	v := parse(t, "*4\r\n$2\r\nid\r\n$3\r\n123\r\n$5\r\nscore\r\n$3\r\n0.9\r\n")
	want := []any{"id", "123", "score", "0.9"}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("array = %v want %v", v, want)
	}
	if _, err := readReply(bufio.NewReader(strings.NewReader("-WRONGTYPE oops\r\n"))); err == nil {
		t.Fatal("expected error reply to be an error")
	}
}

func TestHGetAllParsing(t *testing.T) {
	// Simulate what hgetall does with an array reply: pair up into a map.
	arr := []any{"id", "123", "amount", "42.5"}
	out := map[string]string{}
	for i := 0; i+1 < len(arr); i += 2 {
		out[arr[i].(string)] = arr[i+1].(string)
	}
	if out["id"] != "123" || out["amount"] != "42.5" {
		t.Fatalf("hgetall pairing wrong: %v", out)
	}
}

func TestToStr(t *testing.T) {
	if toStr("abc") != "abc" {
		t.Fatal("string")
	}
	if toStr(float64(123)) != "123" {
		t.Fatalf("float int-valued = %q", toStr(float64(123)))
	}
	if toStr(true) != "true" {
		t.Fatal("bool")
	}
}
