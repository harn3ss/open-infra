package render

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// install.sh includes exactly one backup store: storage/backup-store.yaml (the main MinIO) by default,
// storage/minio-backup.yaml (a MinIO of its own on a longhorn-bulk volume) with storage.backupStore: hdd.
// Both define the Service minio/backup-store, so including both would make the root app own it twice.
func TestBackupStore_InstallIncludesExactlyOne(t *testing.T) {
	src, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	a := strings.Index(s, "# Backup store (storage.backupStore)")
	b := strings.Index(s[a:], `case "$EXCLUDES" in`)
	if a < 0 || b < 0 {
		t.Fatal("install.sh: the backup store section is missing")
	}
	block := s[a : a+b]
	for want, excluded := range map[string]string{"": "storage/minio-backup.yaml", "hdd": "storage/backup-store.yaml"} {
		script := "yget() { [ \"$1\" = storage.backupStore ] && printf '%s' '" + want + "'; }\nLOG() { :; }\nEXCLUDES='base'\n" + block + "\necho \"$EXCLUDES\"\n"
		out, err := exec.Command("bash", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("backupStore=%q: %v\n%s", want, err, out)
		}
		got := strings.TrimSpace(string(out))
		other := map[string]string{"storage/minio-backup.yaml": "storage/backup-store.yaml", "storage/backup-store.yaml": "storage/minio-backup.yaml"}[excluded]
		if !strings.Contains(got, excluded) || strings.Contains(got, other) {
			t.Errorf("backupStore=%q: EXCLUDES=%q, want %s excluded and %s included", want, got, excluded, other)
		}
	}
	for _, f := range []string{"../../platform/storage/backup-store.yaml", "../../platform/storage/minio-backup.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(b), "name: backup-store") {
			t.Errorf("%s must define the Service backup-store", f)
		}
	}
}
