package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// makeZip builds an in-memory .zip from name->content for the tests.
func makeZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return b.Bytes()
}

func fileByPath(files []codeFile, p string) (codeFile, bool) {
	for _, f := range files {
		if f.Path == p {
			return f, true
		}
	}
	return codeFile{}, false
}

func TestUnpackZip_TextAndBinary(t *testing.T) {
	src := []byte("def handler(event, ctx):\n    return {'ok': True}\n")
	binary := []byte{0x00, 0x01, 0x02, 0xff, 0xfe}
	z := makeZip(t, map[string][]byte{
		"lambda_function.py": src,
		"vendor/lib.so":      binary,
		"nested/":            nil, // a directory entry must be skipped
	})

	files, note, err := unpackZipBytes(z)
	if err != nil {
		t.Fatalf("unpackZipBytes: %v", err)
	}
	if note != "" {
		t.Errorf("unexpected note: %q", note)
	}
	// The directory entry must not appear as a file.
	for _, f := range files {
		if strings.HasSuffix(f.Path, "/") {
			t.Errorf("directory entry leaked into files: %q", f.Path)
		}
	}

	py, ok := fileByPath(files, "lambda_function.py")
	if !ok {
		t.Fatal("lambda_function.py missing from unpacked files")
	}
	if py.Binary {
		t.Error("python source misclassified as binary")
	}
	if py.Content != string(src) {
		t.Errorf("python content mismatch:\n got %q\nwant %q", py.Content, src)
	}

	so, ok := fileByPath(files, "vendor/lib.so")
	if !ok {
		t.Fatal("vendor/lib.so missing from unpacked files")
	}
	if !so.Binary {
		t.Error("binary file not flagged binary")
	}
	if so.Content != "" {
		t.Error("binary file must not return inline content")
	}
}

func TestUnpackZip_PerFileTruncation(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxCodeFileDisplay+4096)
	z := makeZip(t, map[string][]byte{"big.txt": big})
	files, _, err := unpackZipBytes(z)
	if err != nil {
		t.Fatalf("unpackZipBytes: %v", err)
	}
	f, ok := fileByPath(files, "big.txt")
	if !ok {
		t.Fatal("big.txt missing")
	}
	if !f.Truncated {
		t.Error("oversized file should be marked truncated")
	}
	if len(f.Content) != maxCodeFileDisplay {
		t.Errorf("truncated content = %d bytes, want %d", len(f.Content), maxCodeFileDisplay)
	}
	if f.Size != int64(len(big)) {
		t.Errorf("reported size = %d, want full %d", f.Size, len(big))
	}
}

func TestUnpackZip_NotAZip(t *testing.T) {
	if _, _, err := unpackZipBytes([]byte("this is not a zip archive")); err == nil {
		t.Error("expected an error for non-zip input")
	}
}

func TestIsBinary(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", nil, false},
		{"ascii", []byte("hello world"), false},
		{"utf8", []byte("café — déjà"), false},
		{"nul byte", []byte("ok\x00then"), true},
		{"invalid utf8", []byte{0xff, 0xfe, 0xfd}, true},
	}
	for _, c := range cases {
		if got := isBinary(c.in); got != c.want {
			t.Errorf("isBinary(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCleanZipPath(t *testing.T) {
	cases := map[string]string{
		"lambda_function.py":   "lambda_function.py",
		"./app.py":             "app.py",
		"nested\\win\\file.js": "nested/win/file.js",
		"a/../b.py":            "b.py",
	}
	for in, want := range cases {
		if got := cleanZipPath(in); got != want {
			t.Errorf("cleanZipPath(%q) = %q, want %q", in, got, want)
		}
	}
}
