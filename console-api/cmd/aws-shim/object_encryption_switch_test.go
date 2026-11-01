package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The platform's object-encryption switch is a mounted ConfigMap key: "true" turns BucketEncryption on,
// anything else (missing, empty, "false") leaves it refused.
func TestFileSaysTrue(t *testing.T) {
	dir := t.TempDir()
	on := filepath.Join(dir, "on")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(on, []byte("true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, []byte("false"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{on: true, off: false, filepath.Join(dir, "missing"): false, "": false} {
		if got := fileSaysTrue(path); got != want {
			t.Errorf("fileSaysTrue(%q) = %v, want %v", path, got, want)
		}
	}
}
