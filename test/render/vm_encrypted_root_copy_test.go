package render

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gptImage builds a GPT disk image of size bytes, as a cloud image is built: a protective MBR, the
// primary header and entries at its start, one partition holding data, and the backup entries and header
// in its last sectors (the backup header's LBA is what the primary header's alternate-LBA field records).
func gptImage(t *testing.T, size int) []byte {
	t.Helper()
	if size%512 != 0 {
		t.Fatalf("image size %d is not whole sectors", size)
	}
	b := make([]byte, size)
	last := uint64(size/512 - 1)
	// Protective MBR: one partition of type 0xEE covering the disk.
	b[446+4] = 0xee
	binary.LittleEndian.PutUint32(b[446+8:], 1)
	binary.LittleEndian.PutUint32(b[446+12:], uint32(last))
	b[510], b[511] = 0x55, 0xaa
	// One partition entry (LBA 2..33 hold the 128 entries), spanning LBA 2048 to the last usable LBA.
	entries := make([]byte, 128*128)
	copy(entries[0:16], bytes.Repeat([]byte{0x11}, 16)) // type GUID (any non-zero)
	copy(entries[16:32], bytes.Repeat([]byte{0x22}, 16))
	binary.LittleEndian.PutUint64(entries[32:], 2048)
	binary.LittleEndian.PutUint64(entries[40:], last-33)
	header := func(my, alt, entriesLBA uint64) []byte {
		h := make([]byte, 92)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], my)
		binary.LittleEndian.PutUint64(h[32:], alt)
		binary.LittleEndian.PutUint64(h[40:], 34)
		binary.LittleEndian.PutUint64(h[48:], last-33)
		binary.LittleEndian.PutUint64(h[72:], entriesLBA)
		binary.LittleEndian.PutUint32(h[80:], 128)
		binary.LittleEndian.PutUint32(h[84:], 128)
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(entries))
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
		return h
	}
	copy(b[512:], header(1, last, 2))
	copy(b[1024:], entries)
	copy(b[(last-32)*512:], entries)
	copy(b[last*512:], header(last, 1, last-32))
	// The partition's data: non-zero runs with a zero run between them (zeros inside a filesystem
	// matter: a FAT's free-cluster entries are zero), ending right before the backup entries.
	p0, p1 := 2048*512, int(last-32)*512
	for i := p0; i < p1; i++ {
		if (i-p0)/(64<<10)%3 != 1 {
			b[i] = byte(i*7 + 1)
		}
	}
	return b
}

// busyboxApplets is a PATH directory that resolves the copy's tools to busybox's applets, as on a
// busybox-based image ("" when busybox is not installed).
func busyboxApplets(t *testing.T) string {
	t.Helper()
	bb, err := exec.LookPath("busybox")
	if err != nil {
		return ""
	}
	dir := t.TempDir()
	for _, a := range []string{"dd", "od", "tr", "stat", "blockdev", "sync"} {
		if err := os.Symlink(bb, filepath.Join(dir, a)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// encRootCopyScript is the encrypted root's copy script, from a render where the image import is done.
func encRootCopyScript(t *testing.T) string {
	t.Helper()
	out := render(t, extractInlineTemplate(t, vmCompositionPath), withImportDone(encRootCtx(nil)))
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		if m := digMap(d, "spec", "forProvider", "manifest"); m != nil && m["kind"] == "Pod" {
			var s []string
			scriptTexts(m, "copy", &s)
			if len(s) == 1 {
				return strings.TrimPrefix(s[0], "copy: ")
			}
		}
	}
	t.Fatalf("copy script not found:\n%s", grepCtx(out, "root-populate"))
	return ""
}

// The copy writes the image CDI imported, not the zeros CDI appended to grow it to the volume's size: a
// GPT image is copied up to its backup header (the image as built, rounded up to a MiB), byte for byte,
// zeros included, and the rest of the encrypted root is left as it was. Anything it cannot trust (no
// GPT, a header that does not fit the file, a value too large for the shell's arithmetic) copies the
// whole file. Run under every shell, with the host's tools and with busybox's applets.
func TestVM_EncryptedRoot_CopiesOnlyTheImage(t *testing.T) {
	script := encRootCopyScript(t)
	const mib = 1 << 20
	built := 6*mib + 5*512 // the image as built: not a whole MiB
	resized := func(b []byte, n int) []byte { // CDI's resize: zeros appended
		return append(append([]byte{}, b...), make([]byte, n-len(b))...)
	}
	type tc struct {
		name string
		img  []byte
		want int // bytes copied
	}
	gpt := gptImage(t, built)
	tooBig := append([]byte{}, gpt...)
	binary.LittleEndian.PutUint64(tooBig[512+32:], 1<<63) // an alternate LBA with the top bit set
	notGPT := resized(bytes.Repeat([]byte{0xcd}, 2*mib), 9*mib)
	notGPT[510], notGPT[511] = 0x55, 0xaa
	cases := []tc{
		{"a resized GPT image is copied up to its backup header", resized(gpt, 32*mib), 7 * mib},
		{"a GPT image that was not resized is copied whole", gpt, built},
		{"a GPT header pointing past the file copies the whole file", gpt[:5*mib], 5 * mib},
		{"an alternate LBA too large for the shell copies the whole file", resized(tooBig, 16*mib), 16 * mib},
		{"an image without a GPT header is copied whole", notGPT, 9 * mib},
	}
	if _, err := exec.LookPath("sgdisk"); err == nil {
		p := filepath.Join(t.TempDir(), "img")
		if err := os.WriteFile(p, make([]byte, 5*mib), 0o600); err != nil {
			t.Fatal(err)
		}
		if o, err := exec.Command("sgdisk", "-n", "1:2048:+1M", "-t", "1:ef00", "-n", "2:0:0", "-t", "2:8300", p).CombinedOutput(); err != nil {
			t.Fatalf("sgdisk: %v\n%s", err, o)
		}
		b, _ := os.ReadFile(p)
		for i := 3 * mib; i < 4*mib; i++ { // data in the second partition
			b[i] = 0x5a
		}
		cases = append(cases, tc{"an sgdisk-built GPT image, resized, is copied up to its backup header", resized(b, 24*mib), 5 * mib})
	}
	type run struct {
		name string
		argv []string
		path string
	}
	var runs []run
	for _, sh := range posixShells(t) {
		runs = append(runs, run{shellName(sh), sh, ""})
	}
	if p := busyboxApplets(t); p != "" {
		runs = append(runs, run{"busybox-applets", []string{"busybox", "sh"}, p})
	}
	for _, r := range runs {
		for _, c := range cases {
			dir := t.TempDir()
			img, dev := filepath.Join(dir, "disk.img"), filepath.Join(dir, "dev")
			noise := make([]byte, len(c.img)+mib)
			_, _ = rand.Read(noise)
			noise[510], noise[511] = 0x12, 0x34 // no boot record: a fresh encrypted disk
			if err := os.WriteFile(img, c.img, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dev, noise, 0o600); err != nil {
				t.Fatal(err)
			}
			s := strings.ReplaceAll(strings.ReplaceAll(script, "/src/disk.img", img), "/dev/openinfra-root", dev)
			cmd := exec.Command(r.argv[0], append(append([]string{}, r.argv[1:]...), "-c", s)...)
			if r.path != "" {
				cmd.Env = append(os.Environ(), "PATH="+r.path+":"+os.Getenv("PATH"))
			}
			o, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("%s/%s: copy failed: %v\n%s", r.name, c.name, err, o)
				continue
			}
			if want := fmt.Sprintf("copied the OS image (%d of its file's %d bytes)", c.want, len(c.img)); !strings.Contains(string(o), want) {
				t.Errorf("%s/%s: output lacks %q:\n%s", r.name, c.name, want, o)
			}
			got, _ := os.ReadFile(dev)
			if len(got) != len(noise) {
				t.Errorf("%s/%s: the device changed size (%d -> %d)", r.name, c.name, len(noise), len(got))
				continue
			}
			if !bytes.Equal(got[:c.want], c.img[:c.want]) {
				t.Errorf("%s/%s: the device's first %d bytes are not the image's", r.name, c.name, c.want)
			}
			if !bytes.Equal(got[c.want:], noise[c.want:]) {
				t.Errorf("%s/%s: the device was written past the %d bytes copied", r.name, c.name, c.want)
			}
		}
	}
}
