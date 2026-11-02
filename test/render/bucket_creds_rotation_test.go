package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mint_scoped_user: credentials left by an earlier instance of the same claim (deleted and created again)
// are rotated by the new instance's setup, never reused — and the same instance keeps its key.
func TestMintScopedUser_RotatesAnEarlierInstancesCredentials(t *testing.T) {
	lib := extractDataScript(t, providerSetupPath, "bucket-ownership.sh")
	stubs := `
LOG="$STUB/calls"
kubectl() {
  echo "kubectl $*" >> "$LOG"
  case "$*" in
    *"jsonpath={.data.MINIO_SECRET_KEY}"*) printf '%s' "$(printf oldkey | base64)" ;;
    *"jsonpath={.metadata.annotations.openinfra\.dev/instance}"*) printf '%s' "$WAS" ;;
    "create secret generic"*) printf 'kind: Secret\n' ;;
    *) cat >/dev/null 2>&1 || true ;;
  esac
  return 0
}
MC_() { echo "mc $*" >> "$LOG"; return 0; }
MC=MC_
OWN_NS=openinfra-bucket-creds
OWNER_REF=Bucket/team-a/data
`
	for _, c := range []struct {
		name, was    string
		wantRotation bool
	}{
		{"same instance keeps its key", xrCreated, false},
		{"an earlier instance's key is rotated", "2026-09-01T00:00:00Z", true},
		{"unmarked credentials are left as they are", "", false},
	} {
		for _, sh := range posixShells(t) {
			dir := t.TempDir()
			pol := filepath.Join(dir, "pol.json")
			if err := os.WriteFile(pol, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			script := lib + "\n" + stubs + "\nmint_scoped_user app-team-a-data " + pol + "\n"
			args := append(append([]string{}, sh[1:]...), "-c", script)
			cmd := exec.Command(sh[0], args...)
			cmd.Env = append(os.Environ(), "STUB="+dir, "WAS="+c.was, "XR_CREATED="+xrCreated)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s/%s: %v\n%s", shellName(sh), c.name, err, out)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			rotated := strings.Contains(string(calls), "kubectl create secret generic app-team-a-data")
			reused := strings.Contains(string(calls), "mc admin user add m app-team-a-data oldkey")
			if rotated != c.wantRotation || reused == c.wantRotation {
				t.Errorf("%s/%s: rotated=%v reused-old-key=%v, want rotation %v\ncalls:\n%s", shellName(sh), c.name, rotated, reused, c.wantRotation, calls)
			}
		}
	}
}
