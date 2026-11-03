package main

import (
	"strings"
	"testing"
)

// A segment carries at most max bytes of complete lines, so a run's memory is bounded however much of
// the log is unshipped (a large log after a rotation restarts at 0 used to be read whole, and the job
// was OOM-killed every run).
func TestReadSegment_BoundedCompleteLines(t *testing.T) {
	log := "aaaa\nbbbb\ncccc\ndddd\npartial"
	r := strings.NewReader(log)
	var got []string
	off := int64(0)
	for i := 0; i < 10; i++ {
		lines, consumed, err := readSegment(r, off, 11, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if consumed == 0 {
			break
		}
		if consumed > 11 {
			t.Fatalf("segment %d spans %d bytes, more than the 11-byte bound", i, consumed)
		}
		got = append(got, lines...)
		off += consumed
	}
	if strings.Join(got, ",") != "aaaa,bbbb,cccc,dddd" {
		t.Fatalf("lines = %v, want the four complete lines in order (the partial last line waits)", got)
	}
	if off != int64(len("aaaa\nbbbb\ncccc\ndddd\n")) {
		t.Fatalf("stopped at %d, want the end of the last complete line", off)
	}
}

// A single record longer than the bound is read through to its end, never cut or skipped.
func TestReadSegment_LongLineReadWhole(t *testing.T) {
	long := strings.Repeat("x", 100)
	r := strings.NewReader(long + "\nnext\n")
	lines, consumed, err := readSegment(r, 0, 16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 || lines[0] != long || consumed < int64(len(long)+1) {
		t.Fatalf("lines=%d consumed=%d, want the whole 100-byte record", len(lines), consumed)
	}
	// Beyond the hard limit it is an error, not a silent skip.
	if _, _, err := readSegment(strings.NewReader(long+"\n"), 0, 16, 32); err == nil {
		t.Fatal("a record longer than the hard limit must be an error")
	}
	// Blank lines are dropped; a file with no complete line yet yields nothing.
	if lines, c, _ := readSegment(strings.NewReader("\n\nabc"), 0, 64, 1<<20); len(lines) != 0 || c != 2 {
		t.Fatalf("blank lines: lines=%v consumed=%d, want none and 2", lines, c)
	}
	if _, c, _ := readSegment(strings.NewReader("unfinished"), 0, 64, 1<<20); c != 0 {
		t.Fatalf("no complete line: consumed=%d, want 0", c)
	}
}
