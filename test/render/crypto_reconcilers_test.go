package render

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The encryption reconcilers (platform/security/volume-crypto.yaml, encryptionkey-reconciler.yaml)
// are shell scripts embedded in CronJobs. These tests extract each script exactly as the container's
// `/bin/sh -ceu` receives it and RUN it against stub kubectl/vault binaries, under every POSIX shell
// available (busybox ash — what the alpine/k8s image runs — and dash), asserting what it writes and
// deletes. They need jq (the scripts use it); without it they skip.

const (
	volumeCryptoPath  = "../../platform/security/volume-crypto.yaml"
	encKeyReconPath   = "../../platform/security/encryptionkey-reconciler.yaml"
	reconcilerTimeout = 60 * time.Second
)

// extractArgsScript returns the `args: - |` block scalar of the manifest's container, dedented.
func extractArgsScript(t *testing.T, path string) string {
	t.Helper()
	lines := strings.Split(mustRead(t, path), "\n")
	start, keyIndent := -1, 0
	for i := 0; i+1 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "args:" && strings.TrimSpace(lines[i+1]) == "- |" {
			start = i + 2
			ln := lines[i+1]
			keyIndent = len(ln) - len(strings.TrimLeft(ln, " "))
			break
		}
	}
	if start < 0 {
		t.Fatalf("no `args: - |` script block in %s", filepath.Base(path))
	}
	contentIndent := -1
	var out []string
	for _, ln := range lines[start:] {
		if strings.TrimSpace(ln) == "" {
			out = append(out, "")
			continue
		}
		ind := len(ln) - len(strings.TrimLeft(ln, " "))
		if ind <= keyIndent {
			break
		}
		if contentIndent < 0 {
			contentIndent = ind
		}
		if ind < contentIndent {
			break
		}
		out = append(out, ln[contentIndent:])
	}
	return strings.Join(out, "\n") + "\n"
}

// posixShells lists the shells to run the scripts under: busybox ash first (the runtime shell),
// then dash, then whatever `sh` is. At least one always exists.
func posixShells(t *testing.T) [][]string {
	t.Helper()
	var shells [][]string
	if _, err := exec.LookPath("busybox"); err == nil {
		shells = append(shells, []string{"busybox", "sh"})
	}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, []string{"dash"})
	}
	if len(shells) == 0 {
		shells = append(shells, []string{"sh"})
	}
	return shells
}

func shellName(sh []string) string { return strings.Join(sh, "-") }

func needJQ(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed — the reconciler scripts need it")
	}
}

// Both scripts must at least parse under every shell.
func TestCryptoReconcilers_ScriptsParse(t *testing.T) {
	for _, p := range []string{volumeCryptoPath, encKeyReconPath, destroyerPath} {
		script := extractArgsScript(t, p)
		for _, sh := range posixShells(t) {
			cmd := exec.Command(sh[0], append(sh[1:], "-n", "-c", script)...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s does not parse under %s: %v\n%s", filepath.Base(p), shellName(sh), err, out)
			}
		}
	}
}

// stubKubectl serves fixtures from $STUB and records every write. Only the invocations the two
// reconcilers make are handled; anything else fails loudly (exit 99), so a new kubectl call in a
// script must be modeled here.
const stubKubectl = `#!/bin/sh
echo "kubectl $*" >> "$STUB/calls.log"
count() { n=$(cat "$STUB/$1.count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STUB/$1.count"; echo "$n"; }
serve() { # serve <base>: <base>.next.json from the second call on, if present
  n=$(count "$1")
  if [ "$n" -ge 2 ] && [ -f "$STUB/$1.next.json" ]; then cat "$STUB/$1.next.json"; else cat "$STUB/$1.json"; fi
}
case "$*" in
  "get configmap -n open-infra-console -l openinfra.dev/destruction -o json")
    [ -f "$STUB/fail-dcm-list" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    if [ -f "$STUB/dcms.json" ]; then cat "$STUB/dcms.json"; else echo '{"items":[]}'; fi ;;
  "get secret -n "*" -l openinfra.dev/volume-crypto -o json")
    jq --arg ns "$4" '{items: [.items[] | select(.metadata.namespace == $ns and .metadata.labels["openinfra.dev/volume-crypto"] != null)]}' "$STUB/secrets.json" ;;
  "get configmap "*" -n "*" -o name")
    grep -qxF "  name: $3" "$STUB/applied.yaml" 2>/dev/null && echo "configmap/$3" ;;
  "get configmap "*" -n "*" -o jsonpath={.data.erased}") exit 1 ;;
  "get pvc -A -o json")
    [ -f "$STUB/fail-pvc-list" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    serve pvcs ;;
  "get secret -A -l openinfra.dev/volume-crypto -o jsonpath="*)
    jq -r '.items[] | select(.metadata.labels["openinfra.dev/volume-crypto"] != null) | .metadata.namespace + "/" + .metadata.name' "$STUB/secrets.json" ;;
  "get secret -A -l openinfra.dev/volume-crypto -o json")
    jq '{items: [.items[] | select(.metadata.labels["openinfra.dev/volume-crypto"] != null)]}' "$STUB/secrets.json" ;;
  "get pv -o json") cat "$STUB/pvs.json" ;;
  "get pvc "*" -n "*" --ignore-not-found -o name")
    jq -r --arg n "$3" --arg ns "$5" '.items[] | select(.metadata.name==$n and .metadata.namespace==$ns) | "persistentvolumeclaim/" + .metadata.name' "$STUB/pvcs.json" ;;
  "get secret "*" -n "*" -o json")
    jq -e --arg n "$3" --arg ns "$5" '.items[] | select(.metadata.name==$n and .metadata.namespace==$ns)' "$STUB/secrets.json" ;;
  "get secret "*" -n "*)
    jq -e --arg n "$3" --arg ns "$5" 'any(.items[]; .metadata.name==$n and .metadata.namespace==$ns)' "$STUB/secrets.json" >/dev/null ;;
  "create secret generic "*)
    name=$4; shift 4; ns=""; data='{}'
    while [ $# -gt 0 ]; do
      case "$1" in
        -n) ns=$2; shift 2 ;;
        --from-literal=*) kv=${1#--from-literal=}; data=$(printf '%s' "$data" | jq --arg k "${kv%%=*}" --arg v "${kv#*=}" '.[$k] = ($v | @base64)'); shift ;;
        *) shift ;;
      esac
    done
    jq -n --arg n "$name" --arg ns "$ns" --argjson d "$data" '{apiVersion: "v1", kind: "Secret", metadata: {name: $n, namespace: $ns, creationTimestamp: null}, data: $d, type: "Opaque"}' ;;
  "create -f -") # like the API server: AlreadyExists on a duplicate, else store it
    obj=$(jq -c .)
    ns=$(printf '%s' "$obj" | jq -r .metadata.namespace); n=$(printf '%s' "$obj" | jq -r .metadata.name)
    if jq -e --arg n "$n" --arg ns "$ns" 'any(.items[]; .metadata.name==$n and .metadata.namespace==$ns)' "$STUB/secrets.json" >/dev/null; then
      echo "Error from server (AlreadyExists): secrets \"$n\" already exists" >&2; exit 1
    fi
    printf '%s\n' "$obj" >> "$STUB/created.jsonl"
    jq --argjson o "$obj" '.items += [$o]' "$STUB/secrets.json" > "$STUB/secrets.json.new" && mv "$STUB/secrets.json.new" "$STUB/secrets.json" ;;
  "delete secret "*" -n "*" --ignore-not-found") echo "$5/$3" >> "$STUB/deleted.txt" ;;
  "get xencryptionkeys.openinfra.dev -o json")
    [ -f "$STUB/fail-xek-list" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    serve xenckeys ;;
  "get configmap "*" -o jsonpath={.data.lastRotatedEpoch}") exit 1 ;;
  "create configmap "*)
    printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\ndata:\n' "$3"
    for a in "$@"; do case "$a" in --from-literal=*) kv=${a#--from-literal=}; printf '  %s: "%s"\n' "${kv%%=*}" "${kv#*=}" ;; esac; done ;;
  "label --local -f - "*) cat ;;
  "apply -f -") cat >> "$STUB/applied.yaml"; echo "---" >> "$STUB/applied.yaml" ;;
  *) echo "stub kubectl: unhandled: $*" >&2; exit 99 ;;
esac
`

// stubVault: a Kubernetes-auth login always succeeds; Transit keys exist iff $STUB/keys/<name> does.
const stubVault = `#!/bin/sh
echo "vault $*" >> "$STUB/calls.log"
case "$*" in
  "write -field=token auth/kubernetes/login "*) echo "s.stub-token" ;;
  "write -f -format=json transit/datakey/plaintext/"*)
    k=${4#transit/datakey/plaintext/}
    [ -e "$STUB/keys/$k" ] || { echo "encryption key not found" >&2; exit 2; }
    printf '{"data":{"plaintext":"PLAIN-%s","ciphertext":"vault:v1:WRAP-%s"}}\n' "$k" "$k" ;;
  "read -format=json transit/keys/"*) printf '{"data":{"latest_version":1}}\n' ;;
  "read transit/keys/"*) [ -e "$STUB/keys/${2#transit/keys/}" ] ;;
  "write -f transit/keys/"*"/rotate") : ;;
  "write -f transit/keys/"*) k=${3#transit/keys/}; touch "$STUB/keys/$k"; echo "$k" >> "$STUB/vault-created.txt" ;;
  "write transit/keys/"*"/config deletion_allowed=true") k=${2#transit/keys/}; echo "${k%/config}" >> "$STUB/vault-deletable.txt" ;;
  "delete transit/keys/"*) k=${2#transit/keys/}; rm -f "$STUB/keys/$k"; echo "$k" >> "$STUB/vault-deleted.txt" ;;
  *) echo "stub vault: unhandled: $*" >&2; exit 99 ;;
esac
`

type stubEnv struct {
	dir  string // $STUB: fixtures + records
	path string // PATH with the stubs first
	tmp  string // TMPDIR for the script's mktemp
}

func newStubEnv(t *testing.T, fixtures map[string]any, keys ...string) stubEnv {
	t.Helper()
	root := t.TempDir()
	e := stubEnv{dir: filepath.Join(root, "stub"), tmp: filepath.Join(root, "tmp")}
	bin := filepath.Join(root, "bin")
	for _, d := range []string{e.dir, e.tmp, bin, filepath.Join(e.dir, "keys")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": stubKubectl, "vault": stubVault} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, v := range fixtures {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(e.dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range keys {
		if err := os.WriteFile(filepath.Join(e.dir, "keys", k), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	return e
}

// run executes the script under sh with /bin/sh -ceu semantics; returns stderr and the error.
func (e stubEnv) run(t *testing.T, sh []string, script string, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), reconcilerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh[0], append(sh[1:], "-ceu", script)...)
	cmd.Env = append([]string{"PATH=" + e.path, "STUB=" + e.dir, "TMPDIR=" + e.tmp, "HOME=" + e.tmp,
		"CONSOLE_NS=open-infra-console"}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

func (e stubEnv) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(e.dir, name))
	return string(b)
}

func (e stubEnv) created(t *testing.T) []map[string]any {
	t.Helper()
	var objs []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(e.read("created.jsonl")), "\n") {
		if ln == "" {
			continue
		}
		var o map[string]any
		if err := json.Unmarshal([]byte(ln), &o); err != nil {
			t.Fatalf("created object is not JSON: %v\n%s", err, ln)
		}
		objs = append(objs, o)
	}
	return objs
}

// xek is an EncryptionKey composite claimed as <ns>/<name> that has recorded Transit path <path> ("" =
// not rendered yet; ns "" = a composite with no claim).
func xek(ns, name, path string) map[string]any {
	o := map[string]any{"metadata": map[string]any{"name": name + "-x7k2p"},
		"spec": map[string]any{"keyType": "aes256-gcm96", "rotationDays": 0}}
	if ns != "" {
		o["spec"].(map[string]any)["claimRef"] = map[string]any{"namespace": ns, "name": name}
	}
	if path != "" {
		o["status"] = map[string]any{"vaultKeyPath": path}
	}
	return o
}

func pvc(ns, name, uid, sc, key string, deleting bool) map[string]any {
	md := map[string]any{"namespace": ns, "name": name, "uid": uid}
	if key != "" {
		md["annotations"] = map[string]any{"openinfra.dev/encryption-key": key}
	}
	if deleting {
		md["deletionTimestamp"] = "2026-01-01T00:00:00Z"
	}
	return map[string]any{"metadata": md, "spec": map[string]any{"storageClassName": sc}, "status": map[string]any{"phase": "Pending"}}
}

func cryptoSecret(ns, name, label, ownerUID string) map[string]any {
	md := map[string]any{"namespace": ns, "name": name}
	if label != "" {
		md["labels"] = map[string]any{"openinfra.dev/volume-crypto": label}
	}
	if ownerUID != "" {
		md["ownerReferences"] = []any{map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "name": strings.TrimSuffix(name, "-crypto"), "uid": ownerUID}}
	}
	return map[string]any{"metadata": md, "type": "Opaque", "data": map[string]any{
		"CRYPTO_KEY_VALUE": "eA==", "WRAPPED_KEY": "eA==", "OPENINFRA_ENCRYPTION_KEY": "eA=="}}
}

func items(objs ...map[string]any) map[string]any {
	l := make([]any, len(objs))
	for i, o := range objs {
		l[i] = o
	}
	return map[string]any{"items": l}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// CDI fills an encrypted DataVolume (a VM data disk) through a "prime" PVC it owns from the target PVC.
// Longhorn provisions the prime with the prime's crypto Secret, so the prime gets a copy of the
// target's passphrase (the same volume, so the same key), owned by the prime so GC removes it with it.
func TestVolumeCrypto_CDIPrimeGetsTargetsPassphrase(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	prime := map[string]any{
		"metadata": map[string]any{"namespace": "team", "name": "prime-abc", "uid": "uid-prime",
			"annotations":     map[string]any{"cdi.kubevirt.io/storage.populator.kind": "VolumeImportSource"},
			"ownerReferences": []any{map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "name": "disk", "uid": "uid-disk"}}},
		"spec": map[string]any{"storageClassName": "longhorn-encrypted"}, "status": map[string]any{"phase": "Pending"},
	}
	stray := map[string]any{ // an encrypted-class PVC owned by a PVC but NOT a CDI prime: left alone
		"metadata": map[string]any{"namespace": "team", "name": "other", "uid": "uid-other",
			"ownerReferences": []any{map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "name": "disk", "uid": "uid-disk"}}},
		"spec": map[string]any{"storageClassName": "longhorn-encrypted"},
	}
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := newStubEnv(t, map[string]any{
				"pvcs.json":     items(pvc("team", "disk", "uid-disk", "longhorn-encrypted", "k1", false), prime, stray),
				"secrets.json":  items(),
				"pvs.json":      items(),
				"xenckeys.json": items(xek("team", "k1", "transit/keys/ek_team_k1")),
			}, "ek_team_k1")
			out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
			if err != nil {
				t.Fatalf("reconcile run failed: %v\n%s", err, out)
			}
			byName := map[string]map[string]any{}
			for _, c := range e.created(t) {
				byName[c["metadata"].(map[string]any)["name"].(string)] = c
			}
			if len(byName) != 2 || byName["disk-crypto"] == nil || byName["prime-abc-crypto"] == nil {
				t.Fatalf("want disk-crypto and prime-abc-crypto, got %v\nlog:\n%s", e.read("created.jsonl"), out)
			}
			td, _ := byName["disk-crypto"]["data"].(map[string]any)
			pd, _ := byName["prime-abc-crypto"]["data"].(map[string]any)
			if td["CRYPTO_KEY_VALUE"] == nil || td["CRYPTO_KEY_VALUE"] != pd["CRYPTO_KEY_VALUE"] || td["WRAPPED_KEY"] != pd["WRAPPED_KEY"] {
				t.Errorf("the prime must carry the target's exact passphrase: target=%v prime=%v", td, pd)
			}
			md := byName["prime-abc-crypto"]["metadata"].(map[string]any)
			refs, _ := md["ownerReferences"].([]any)
			if len(refs) != 1 || refs[0].(map[string]any)["uid"] != "uid-prime" {
				t.Errorf("the prime's copy must be owned by the prime PVC (uid-prime): %v", md["ownerReferences"])
			}
			if l, _ := md["labels"].(map[string]any); l["openinfra.dev/volume-crypto"] != "prime-abc" {
				t.Errorf("label must name the prime: %v", md["labels"])
			}
		})
	}
}

// One reconcile pass: keys exactly the encrypted PVC that needs it — owned by that PVC, by UID —
// skips a claim being deleted, a non-encrypted claim, an already-keyed one (labeled or not) and one
// whose EncryptionKey has no Transit key yet; and sweeps exactly the ownerless crypto Secret whose
// claim AND volume are gone.
func TestVolumeCrypto_KeysOwnedSkipsDeletingSweepsOrphans(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := newStubEnv(t, map[string]any{
				"pvcs.json": items(
					pvc("team", "data", "uid-data", "longhorn-encrypted", "k1", false),        // → keyed
					pvc("team", "going", "uid-going", "longhorn-encrypted", "k1", true),       // deleting → skip
					pvc("team", "plain", "uid-plain", "longhorn", "", false),                  // not encrypted
					pvc("team", "keyed", "uid-keyed", "longhorn-encrypted", "k1", false),      // has a Secret
					pvc("team", "unlabeled", "uid-unl", "longhorn-encrypted", "k1", false),    // unlabeled Secret exists
					pvc("team", "nokey", "uid-nokey", "longhorn-encrypted", "missing", false), // no Transit key yet
					pvc("team", "legacy-live", "uid-ll", "longhorn-encrypted", "k1", false),   // ownerless Secret, live claim
				),
				"secrets.json": items(
					cryptoSecret("team", "keyed-crypto", "keyed", "uid-keyed"),
					cryptoSecret("team", "unlabeled-crypto", "", ""),
					cryptoSecret("team", "legacy-live-crypto", "legacy-live", ""),
					cryptoSecret("team", "legacy-gone-crypto", "legacy-gone", ""), // claim + volume gone → swept
					cryptoSecret("team", "legacy-pv-crypto", "legacy-pv", ""),     // claim gone, PV remains → kept
					cryptoSecret("team", "owned-gone-crypto", "owned-gone", "uid-x"),
					cryptoSecret("team", "foreign-crypto", "something-else", ""), // label ≠ name → not ours
				),
				"pvs.json": items(map[string]any{"spec": map[string]any{
					"claimRef": map[string]any{"namespace": "team", "name": "legacy-pv"}}}),
				"xenckeys.json": items(xek("team", "k1", "transit/keys/ek_team_k1")),
			}, "ek_team_k1")
			out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
			if err != nil {
				t.Fatalf("reconcile run failed: %v\n%s", err, out)
			}

			created := e.created(t)
			if len(created) != 1 {
				t.Fatalf("want exactly one crypto Secret created (team/data-crypto), got %d:\n%s\nlog:\n%s", len(created), e.read("created.jsonl"), out)
			}
			s := created[0]
			md := s["metadata"].(map[string]any)
			if md["name"] != "data-crypto" || md["namespace"] != "team" {
				t.Errorf("created %v/%v, want team/data-crypto", md["namespace"], md["name"])
			}
			if l, _ := md["labels"].(map[string]any); l["openinfra.dev/volume-crypto"] != "data" {
				t.Errorf("crypto Secret must carry openinfra.dev/volume-crypto=data; labels=%v", md["labels"])
			}
			refs, _ := md["ownerReferences"].([]any)
			if len(refs) != 1 {
				t.Fatalf("crypto Secret must have exactly one ownerReference (its PVC); got %v", md["ownerReferences"])
			}
			ref := refs[0].(map[string]any)
			if ref["kind"] != "PersistentVolumeClaim" || ref["name"] != "data" || ref["uid"] != "uid-data" || ref["apiVersion"] != "v1" {
				t.Errorf("ownerReference must name the PVC by UID (v1 PersistentVolumeClaim data uid-data); got %v", ref)
			}
			if _, ok := ref["blockOwnerDeletion"]; ok {
				t.Errorf("ownerReference must not set blockOwnerDeletion (the claim's deletion must never wait on it); got %v", ref)
			}
			if s["type"] != "Opaque" {
				t.Errorf("crypto Secret type = %v, want Opaque (the admission policy allows only Opaque)", s["type"])
			}
			d := s["data"].(map[string]any)
			for k, want := range map[string]string{
				"CRYPTO_KEY_VALUE": "PLAIN-ek_team_k1", "WRAPPED_KEY": "vault:v1:WRAP-ek_team_k1", "OPENINFRA_ENCRYPTION_KEY": "k1",
				"OPENINFRA_VAULT_KEY_PATH": "transit/keys/ek_team_k1",
				"CRYPTO_KEY_PROVIDER":      "secret", "CRYPTO_KEY_CIPHER": "aes-xts-plain64", "CRYPTO_KEY_HASH": "sha256",
			} {
				if d[k] != b64(want) {
					t.Errorf("crypto Secret %s = %v, want base64(%q)", k, d[k], want)
				}
			}

			if got := strings.TrimSpace(e.read("deleted.txt")); got != "team/legacy-gone-crypto" {
				t.Errorf("sweep must delete exactly team/legacy-gone-crypto (ownerless, claim and volume gone); deleted:\n%s", got)
			}
			if !strings.Contains(out, "waiting on team/nokey") {
				t.Errorf("a claim whose EncryptionKey has no Transit key must be reported as waiting; log:\n%s", out)
			}
		})
	}
}

// A failed claim list fails the run (it retries) and writes nothing — never read as "no claims".
func TestVolumeCrypto_ListFailureFailsRun(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	sh := posixShells(t)[0]
	e := newStubEnv(t, map[string]any{
		"pvcs.json":     items(pvc("team", "data", "uid-data", "longhorn-encrypted", "k1", false)),
		"secrets.json":  items(),
		"pvs.json":      items(),
		"xenckeys.json": items(xek("team", "k1", "transit/keys/ek_team_k1")),
	}, "ek_team_k1")
	if err := os.WriteFile(filepath.Join(e.dir, "fail-pvc-list"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
	if err == nil {
		t.Fatalf("a run whose PVC list failed must exit non-zero; log:\n%s", out)
	}
	if e.read("created.jsonl") != "" || e.read("deleted.txt") != "" {
		t.Errorf("a failed list must write nothing; created=%q deleted=%q", e.read("created.jsonl"), e.read("deleted.txt"))
	}
}

// The watch: a claim created AFTER the first pass is keyed within the same run, not at the next.
func TestVolumeCrypto_WatchKeysNewClaimWithinRun(t *testing.T) {
	needJQ(t)
	t.Parallel()
	script := extractArgsScript(t, volumeCryptoPath)
	sh := posixShells(t)[0]
	e := newStubEnv(t, map[string]any{
		"pvcs.json":      items(),
		"pvcs.next.json": items(pvc("team", "late", "uid-late", "longhorn-encrypted", "k1", false)),
		"secrets.json":   items(),
		"pvs.json":       items(),
		"xenckeys.json":  items(xek("team", "k1", "transit/keys/ek_team_k1")),
	}, "ek_team_k1")
	out, err := e.run(t, sh, script, "WATCH_SECONDS=3", "POLL_SECONDS=1")
	if err != nil {
		t.Fatalf("reconcile run failed: %v\n%s", err, out)
	}
	created := e.created(t)
	if len(created) != 1 || created[0]["metadata"].(map[string]any)["name"] != "late-crypto" {
		t.Fatalf("the watch must key a claim created after the first pass (team/late-crypto); created:\n%s\nlog:\n%s", e.read("created.jsonl"), out)
	}
}

// The encryptionkey reconciler's watch provisions a key created after the full pass within the same
// run, and does not re-sync keys the full pass already handled.
func TestEncryptionKeyReconciler_WatchProvisionsNewKey(t *testing.T) {
	needJQ(t)
	t.Parallel()
	script := extractArgsScript(t, encKeyReconPath)
	sh := posixShells(t)[0]
	old := xek("team", "old", "transit/keys/old") // created before namespacing: keeps its bare path
	e := newStubEnv(t, map[string]any{
		"xenckeys.json":      items(old),
		"xenckeys.next.json": items(old, xek("team", "new", "transit/keys/ek_team_new")),
	}, "old")
	out, err := e.run(t, sh, script, "WATCH_SECONDS=3", "POLL_SECONDS=1")
	if err != nil {
		t.Fatalf("reconcile run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(e.read("vault-created.txt")); got != "ek_team_new" {
		t.Errorf("the watch must create exactly the new Transit key (ek_team_new); created:\n%s\nlog:\n%s", got, out)
	}
	applied := e.read("applied.yaml")
	if strings.Count(applied, "name: openinfra-enckey-state-old\n") != 1 || strings.Count(applied, "name: openinfra-enckey-state-team.new\n") != 1 {
		t.Errorf("each key's state must be written exactly once per run (old by the full pass, new by the watch); applied:\n%s", applied)
	}
}

// The admission policy that confines the volume-crypto ServiceAccount must match exactly that
// identity, and gate exactly the verbs its ClusterRole grants as writes (create, delete).
func TestVolumeCrypto_SecretWritesConfinedByAdmission(t *testing.T) {
	m := mustRead(t, volumeCryptoPath)
	for _, want := range []string{
		"kind: ValidatingAdmissionPolicy",
		"kind: ValidatingAdmissionPolicyBinding",
		"policyName: openinfra-volume-crypto-secrets",
		"validationActions: [Deny]",
		`operations: ["CREATE", "DELETE"]`,
		"request.userInfo.username == 'system:serviceaccount:crossplane-system:volume-crypto'",
		"object.type == 'Opaque'",
		"object.metadata.name.endsWith('-crypto')",
		"'openinfra.dev/volume-crypto' in oldObject.metadata.labels",
		"resources: [secrets]\n    verbs: [get, list, create, delete]\n",
		// The console-namespace ConfigMap grant is confined to the erasure receipts.
		"policyName: openinfra-volume-crypto-receipts",
		`operations: ["CREATE", "UPDATE", "DELETE"]`,
		"request.name.startsWith('openinfra-volume-erasure-')",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("volume-crypto.yaml missing %q", want)
		}
	}
	// No write verb on Secrets beyond what the policy gates: update/patch would bypass it.
	if strings.Count(m, "resources: [secrets]") != 1 {
		t.Errorf("volume-crypto.yaml must grant Secrets in exactly one rule (get, list, create, delete)")
	}
}

// Two namespaces' EncryptionKeys of the same name are two Transit keys with two state records; a
// composite with no claim or no recorded path yet is not provisioned; a recorded path that is not a
// plain transit/keys/<name> is never addressed (the run fails visibly, the other keys still sync).
func TestEncryptionKeyReconciler_SameNameInTwoNamespacesIsTwoKeys(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, encKeyReconPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := newStubEnv(t, map[string]any{"xenckeys.json": items(
				xek("team-a", "app", "transit/keys/ek_team-a_app"),
				xek("team-b", "app", "transit/keys/ek_team-b_app"),
				xek("", "unclaimed", "transit/keys/ek_unclaimed"),
				xek("team-c", "rendering", ""),
				xek("team-d", "odd", "transit/keys/../sys/x"),
			)})
			out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
			if err == nil {
				t.Errorf("a key with an unusable recorded path must fail the run (visibly); log:\n%s", out)
			}
			created := strings.Fields(e.read("vault-created.txt"))
			if strings.Join(created, ",") != "ek_team-a_app,ek_team-b_app" {
				t.Errorf("want Transit keys ek_team-a_app and ek_team-b_app only, created %v\nlog:\n%s", created, out)
			}
			applied := e.read("applied.yaml")
			for _, want := range []string{"name: openinfra-enckey-state-team-a.app\n", "name: openinfra-enckey-state-team-b.app\n"} {
				if strings.Count(applied, want) != 1 {
					t.Errorf("want exactly one %q; applied:\n%s", strings.TrimSpace(want), applied)
				}
			}
			if strings.Contains(e.read("calls.log"), "transit/keys/app") || strings.Contains(e.read("calls.log"), "sys/x") {
				t.Errorf("the reconciler addressed a bare-name or unrecorded path; calls:\n%s", e.read("calls.log"))
			}
		})
	}
}

// A claim is keyed only under the EncryptionKey of its name IN ITS OWN NAMESPACE: naming another
// namespace's key gets nothing (it waits), and the Secret records the exact Transit path used.
func TestVolumeCrypto_KeyResolvesOnlyInClaimsNamespace(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := newStubEnv(t, map[string]any{
				"pvcs.json": items(
					pvc("team-a", "data", "uid-a", "longhorn-encrypted", "k1", false),       // own key → keyed
					pvc("team-b", "steal", "uid-b", "longhorn-encrypted", "k1", false),      // team-b has no k1 → waits
					pvc("team-a", "odd", "uid-o", "longhorn-encrypted", "team-b/k2", false), // not a key name → waits
				),
				"secrets.json":  items(),
				"pvs.json":      items(),
				"xenckeys.json": items(xek("team-a", "k1", "transit/keys/ek_team-a_k1"), xek("team-b", "k2", "transit/keys/ek_team-b_k2")),
			}, "ek_team-a_k1", "ek_team-b_k2", "k1")
			out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
			if err != nil {
				t.Fatalf("reconcile run failed: %v\n%s", err, out)
			}
			created := e.created(t)
			if len(created) != 1 {
				t.Fatalf("want exactly team-a/data-crypto, got:\n%s\nlog:\n%s", e.read("created.jsonl"), out)
			}
			md := created[0]["metadata"].(map[string]any)
			d := created[0]["data"].(map[string]any)
			if md["namespace"] != "team-a" || md["name"] != "data-crypto" ||
				d["CRYPTO_KEY_VALUE"] != b64("PLAIN-ek_team-a_k1") || d["OPENINFRA_VAULT_KEY_PATH"] != b64("transit/keys/ek_team-a_k1") {
				t.Errorf("team-a/data must be keyed under team-a's k1 (ek_team-a_k1); got %v %v", md, d)
			}
			for _, want := range []string{"waiting on team-b/steal: no EncryptionKey 'k1' in namespace team-b", "waiting on team-a/odd"} {
				if !strings.Contains(out, want) {
					t.Errorf("log missing %q:\n%s", want, out)
				}
			}
			calls := e.read("calls.log")
			if strings.Contains(calls, "transit/datakey/plaintext/k1") || strings.Contains(calls, "ek_team-b") {
				t.Errorf("a data key was requested under a bare name or another namespace's key; calls:\n%s", calls)
			}
		})
	}
}

// A failed EncryptionKey list fails the pass: nothing is keyed under a guessed path.
func TestVolumeCrypto_KeyListFailureKeysNothing(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	sh := posixShells(t)[0]
	e := newStubEnv(t, map[string]any{
		"pvcs.json":     items(pvc("team", "data", "uid-data", "longhorn-encrypted", "k1", false)),
		"secrets.json":  items(),
		"pvs.json":      items(),
		"xenckeys.json": items(xek("team", "k1", "transit/keys/ek_team_k1")),
	}, "ek_team_k1", "k1")
	if err := os.WriteFile(filepath.Join(e.dir, "fail-xek-list"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
	if err == nil {
		t.Fatalf("a run whose EncryptionKey list failed must exit non-zero; log:\n%s", out)
	}
	if e.read("created.jsonl") != "" || strings.Contains(e.read("calls.log"), "transit/datakey") {
		t.Errorf("a failed key list must key nothing; created=%q calls:\n%s", e.read("created.jsonl"), e.read("calls.log"))
	}
}

const destroyerPath = "../../platform/security/destruction-reconciler.yaml"

// stubKubectlDestroyer models the API calls the destroyer makes, with ConfigMaps stored as
// $STUB/cms/<name>.json (so state written in one step is read back in the next).
const stubKubectlDestroyer = `#!/bin/sh
echo "kubectl $*" >> "$STUB/calls.log"
cm="$STUB/cms/$3.json"
case "$*" in
  "get secret audit-offsite-minio-creds -n monitoring -o jsonpath="*) printf 'YWs=' ;;
  "get xencryptionkeys.openinfra.dev -o json") cat "$STUB/xenckeys.json" ;;
  "get destructions.openinfra.dev -A -o json") cat "$STUB/destructions.json" ;;
  "get configmaps -n "*" -l openinfra.dev/destruction -o json")
    jq -s '{items: [.[] | select((.metadata.labels // {})["openinfra.dev/destruction"] != null)]}' "$STUB"/cms/*.json 2>/dev/null || echo '{"items":[]}' ;;
  "get persistentvolumeclaims -A -o json")
    [ -f "$STUB/fail-pvc-list" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    if [ -f "$STUB/pvcs.json" ]; then cat "$STUB/pvcs.json"; else echo '{"items":[]}'; fi ;;
  "get configmap "*" -n "*" --ignore-not-found -o name") [ ! -f "$cm" ] || echo "configmap/$3" ;;
  "get configmap "*" -n "*" -o json") [ -f "$cm" ] && cat "$cm" ;;
  "get configmap "*" -n "*" -o jsonpath="*)
    [ -f "$cm" ] || { echo "NotFound" >&2; exit 1; }
    f=${7#jsonpath=\{.data.}; f=${f%\}}
    jq -r --arg k "$f" '.data[$k] // ""' "$cm" ;;
  "create configmap "*)
    name=$3; shift 3; ns=""; data='{}'
    while [ $# -gt 0 ]; do
      case "$1" in
        -n) ns=$2; shift 2 ;;
        --from-literal=*) kv=${1#--from-literal=}; data=$(printf '%s' "$data" | jq --arg k "${kv%%=*}" --arg v "${kv#*=}" '.[$k] = $v'); shift ;;
        *) shift ;;
      esac
    done
    jq -n --arg n "$name" --arg ns "$ns" --argjson d "$data" '{apiVersion: "v1", kind: "ConfigMap", metadata: {name: $n, namespace: $ns}, data: $d}' ;;
  "label --local -f - "*) kv=$5; jq --arg k "${kv%%=*}" --arg v "${kv#*=}" '.metadata.labels = ((.metadata.labels // {}) + {($k): $v})' ;;
  "apply -f -") o=$(cat); n=$(printf '%s' "$o" | jq -r .metadata.name)
    if [ -f "$STUB/cms/$n.json" ]; then o=$(jq --argjson o "$o" '.data = $o.data | .metadata.labels = $o.metadata.labels' "$STUB/cms/$n.json"); fi
    printf '%s' "$o" > "$STUB/cms/$n.json" ;;
  "create -f -") o=$(cat); n=$(printf '%s' "$o" | jq -r .metadata.name)
    [ ! -f "$STUB/cms/$n.json" ] || { echo "AlreadyExists" >&2; exit 1; }
    printf '%s' "$o" | jq '.metadata.creationTimestamp = "2026-11-01T00:00:00Z"' > "$STUB/cms/$n.json"; echo "$n" >> "$STUB/cm-created.txt" ;;
  "patch configmap "*" -n "*" --type merge -p "*)
    [ -f "$cm" ] || exit 1
    jq --argjson p "$9" 'def mp($p): if ($p | type) == "object" then (if type == "object" then . else {} end) as $t
        | reduce ($p | keys[]) as $k ($t; if $p[$k] == null then del(.[$k]) else .[$k] = (.[$k] | mp($p[$k])) end) else $p end;
      mp($p)' "$cm" > "$cm.new" && mv "$cm.new" "$cm" ;;
  *) echo "stub kubectl: unhandled: $*" >&2; exit 99 ;;
esac
`

// stubMC: the WORM store. A certificate is "present" iff it was copied in this run.
const stubMC = `#!/bin/sh
echo "mc $*" >> "$STUB/calls.log"
case "$1" in
  alias) : ;;
  stat) grep -qxF "$2" "$STUB/mc-certs.txt" 2>/dev/null ;;
  cp) echo "$3" >> "$STUB/mc-certs.txt"; cp "$2" "$STUB/cert-$(echo "$3" | tr '/' '_')" ;;
  retention) : ;;
  *) echo "stub mc: unhandled: $*" >&2; exit 99 ;;
esac
`

func destroyerEnv(t *testing.T, fixtures map[string]any, cms map[string]map[string]any, keys ...string) stubEnv {
	t.Helper()
	e := newStubEnv(t, fixtures, keys...)
	bin := strings.SplitN(e.path, string(os.PathListSeparator), 2)[0]
	for name, body := range map[string]string{"kubectl": stubKubectlDestroyer, "mc": stubMC} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(e.dir, "cms"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Unless a test sets the destroyer's config itself, every fixture Destruction may skip the waiting
	// period (the administrator's immediate list), so a test of what is destroyed need not wait 30 days;
	// the waiting-period tests set the config.
	if _, set := cms["openinfra-destruction-config"]; !set {
		var immediate []string
		if d, ok := fixtures["destructions.json"].(map[string]any); ok {
			l, _ := d["items"].([]any)
			for _, it := range l {
				md, _ := it.(map[string]any)["metadata"].(map[string]any)
				immediate = append(immediate, fmt.Sprint(md["namespace"])+"/"+fmt.Sprint(md["name"]))
			}
		}
		cms = maps.Clone(cms)
		if cms == nil {
			cms = map[string]map[string]any{}
		}
		cms["openinfra-destruction-config"] = map[string]any{"metadata": map[string]any{"name": "openinfra-destruction-config", "namespace": "open-infra-console"},
			"data": map[string]any{"immediate": strings.Join(immediate, ",")}}
	}
	for name, obj := range cms {
		b, _ := json.Marshal(obj)
		if err := os.WriteFile(filepath.Join(e.dir, "cms", name+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func destruction(ns, name, key, created string) map[string]any {
	return map[string]any{"metadata": map[string]any{"namespace": ns, "name": name, "creationTimestamp": created},
		"spec": map[string]any{"encryptionKey": key, "confirm": key, "reason": "test"}}
}

func (e stubEnv) cm(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "cms", name+".json"))
	if err != nil {
		return nil
	}
	var o map[string]any
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("configmap %s: %v", name, err)
	}
	return o
}

func cmData(o map[string]any) map[string]any {
	if o == nil {
		return nil
	}
	d, _ := o["data"].(map[string]any)
	return d
}

var destroyerEnvVars = []string{"MINIO_URL=http://minio.invalid", "AUDIT_BUCKET=audit", "RETENTION_DAYS=1"}

// A Destruction destroys only a key of its OWN namespace — the path that key's composite records —
// never another namespace's same-named key, and never a bare-name key. Naming a key its namespace
// does not have destroys nothing and issues no certificate.
func TestDestroyer_DestroysOnlyItsOwnNamespacesKey(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json": items(xek("team-a", "app", "transit/keys/ek_team-a_app"), xek("team-b", "app", "transit/keys/ek_team-b_app")),
				"destructions.json": items(
					destruction("team-b", "erase-app", "app", "2026-11-01T00:00:00Z"),
					destruction("team-c", "steal", "app", "2026-11-01T00:00:00Z"),
				),
			}, receipts(map[string]string{"team-b.erase-app": "transit/keys/ek_team-b_app"}), "ek_team-a_app", "ek_team-b_app", "app")
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(e.read("vault-deleted.txt")); got != "ek_team-b_app" {
				t.Fatalf("must destroy exactly team-b's key ek_team-b_app; deleted %q\nlog:\n%s", got, out)
			}
			b := cmData(e.cm(t, "openinfra-destruction-state-team-b.erase-app"))
			if b["phase"] != "Destroyed" || b["vaultKeyPath"] != "transit/keys/ek_team-b_app" || b["namespace"] != "team-b" {
				t.Errorf("team-b's state = %v", b)
			}
			cert, _ := b["certificate"].(string)
			if !strings.HasPrefix(cert, "certificates/team-b/app-") {
				t.Errorf("certificate path %q, want certificates/team-b/app-<epoch>.json", cert)
			}
			var c map[string]any
			if err := json.Unmarshal([]byte(e.read("cert-"+strings.ReplaceAll("audit/audit/"+cert, "/", "_"))), &c); err != nil {
				t.Fatalf("certificate not written as JSON: %v\nlog:\n%s", err, out)
			}
			if c["vaultKeyPath"] != "transit/keys/ek_team-b_app" || c["namespace"] != "team-b" || c["encryptionKey"] != "app" {
				t.Errorf("certificate must name the exact key destroyed; got %v", c)
			}
			s := cmData(e.cm(t, "openinfra-destruction-state-team-c.steal"))
			if s["phase"] != "Error" || !strings.Contains(s["message"].(string), "no EncryptionKey app in namespace team-c") || s["certificate"] != "" {
				t.Errorf("team-c names a key it does not have: must Error, destroy nothing, certify nothing; got %v", s)
			}
		})
	}
}

// A key created before namespacing (bare path) is destroyed at that path; a key whose EncryptionKey
// was deleted is still found through the key reconciler's record of exactly that namespace + name (and
// only that); a finished pre-namespacing destruction record is adopted by the Destruction it was
// written for — never re-run — and NOT by a same-named Destruction created later in another namespace.
func TestDestroyer_LegacyKeysAndRecords(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	legacyDone := map[string]any{"metadata": map[string]any{"name": "openinfra-destruction-state-enc-verify",
		"namespace": "open-infra-console", "creationTimestamp": "2026-08-25T04:20:03Z",
		"labels": map[string]any{"openinfra.dev/destruction": "enc-verify"}},
		"data": map[string]any{"destruction": "enc-verify", "encryptionKey": "enc-verify", "phase": "Destroyed",
			"certificate": "certificates/enc-verify-1.json"}}
	stateRec := func(name, ns, n, path string) map[string]any {
		return map[string]any{"metadata": map[string]any{"name": name, "namespace": "open-infra-console"},
			"data": map[string]any{"exists": "true", "namespace": ns, "name": n, "vaultKeyPath": path}}
	}
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json": items(xek("open-infra-cfn", "ebs-default", "transit/keys/ebs-default")),
				"destructions.json": items(
					destruction("other", "enc-verify", "enc-verify", "2026-11-01T00:00:00Z"), // newer than the record
					destruction("default", "enc-verify", "enc-verify", "2026-08-25T04:19:00Z"),
					destruction("open-infra-cfn", "erase-ebs", "ebs-default", "2026-11-01T00:00:00Z"),
					destruction("team-d", "erase-gone", "gone", "2026-11-01T00:00:00Z"),
					destruction("team-y", "erase-gone2", "gone2", "2026-11-01T00:00:00Z"),
				),
			}, map[string]map[string]any{
				"openinfra-destruction-state-enc-verify": legacyDone,
				"openinfra-enckey-state-team-d.gone":     stateRec("openinfra-enckey-state-team-d.gone", "team-d", "gone", "transit/keys/ek_team-d_gone"),
				"openinfra-enckey-state-gone2":           stateRec("openinfra-enckey-state-gone2", "team-x", "gone2", "transit/keys/gone2"),
			}, "ebs-default", "ek_team-d_gone", "gone2", "enc-verify")
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := strings.Fields(e.read("vault-deleted.txt")); strings.Join(got, ",") != "ebs-default,ek_team-d_gone" {
				t.Fatalf("want ebs-default (legacy path) and ek_team-d_gone (deleted key, own namespace) destroyed; got %v\nlog:\n%s", got, out)
			}
			adopted := cmData(e.cm(t, "openinfra-destruction-state-default.enc-verify"))
			if adopted["phase"] != "Destroyed" || adopted["namespace"] != "default" || adopted["certificate"] != "certificates/enc-verify-1.json" {
				t.Errorf("default/enc-verify must adopt its finished record (not re-run); got %v\nlog:\n%s", adopted, out)
			}
			old := e.cm(t, "openinfra-destruction-state-enc-verify")
			if d := cmData(old); d["namespace"] != "default" || d["phase"] != "Destroyed" {
				t.Errorf("the original record must be kept, stamped with its namespace; got %v", d)
			}
			if l, _ := old["metadata"].(map[string]any)["labels"].(map[string]any); l["openinfra.dev/destruction"] != nil {
				t.Errorf("the original record must lose its label (counted once, as the adopted copy); labels %v", l)
			}
			o := cmData(e.cm(t, "openinfra-destruction-state-other.enc-verify"))
			if o["phase"] != "Error" {
				t.Errorf("other/enc-verify (newer than the old record) must not inherit it, and has no key: Error; got %v", o)
			}
			if g := cmData(e.cm(t, "openinfra-destruction-state-team-y.erase-gone2")); g["phase"] != "Error" {
				t.Errorf("team-y must not reach team-x's deleted key through its record; got %v", g)
			}
		})
	}
}

// A Transit key that more than one live EncryptionKey records (two same-named keys created before
// namespacing shared one) is never destroyed by one namespace's Destruction: that would erase the
// other namespace's data too.
func TestDestroyer_RefusesASharedPreNamespacingKey(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	sh := posixShells(t)[0]
	e := destroyerEnv(t, map[string]any{
		"xenckeys.json":     items(xek("team-a", "app", "transit/keys/app"), xek("team-b", "app", "transit/keys/app")),
		"destructions.json": items(destruction("team-a", "erase-app", "app", "2026-11-01T00:00:00Z")),
	}, nil, "app")
	out, err := e.run(t, sh, script, destroyerEnvVars...)
	if err != nil {
		t.Fatalf("destroyer run failed: %v\n%s", err, out)
	}
	if got := e.read("vault-deleted.txt"); got != "" {
		t.Fatalf("a shared key must not be destroyed; deleted %q\nlog:\n%s", got, out)
	}
	if d := cmData(e.cm(t, "openinfra-destruction-state-team-a.erase-app")); d["phase"] != "Error" ||
		!strings.Contains(d["message"].(string), "shared with another namespace (1 other EncryptionKey(s), 0 encrypted volume(s)") || d["certificate"] != "" {
		t.Errorf("want Error naming the sharing, no certificate; got %v", d)
	}
}

// The off-by-one the shared-key check had: when the Destruction's OWN EncryptionKey was already
// deleted (its path found through the key reconciler's record), the one other namespace still on that
// pre-namespacing key was the only one counted, so "more than one" never held and the erase went
// ahead. Other keys are counted now, never this Destruction's own.
func TestDestroyer_RefusesASharedKeyWhenItsOwnKeyIsGone(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json":     items(xek("team-b", "app", "transit/keys/app")), // team-a's key is gone
				"destructions.json": items(destruction("team-a", "erase-app", "app", "2026-11-01T00:00:00Z")),
			}, map[string]map[string]any{
				"openinfra-enckey-state-team-a.app": {"metadata": map[string]any{"name": "openinfra-enckey-state-team-a.app",
					"namespace": "open-infra-console"},
					"data": map[string]any{"exists": "true", "namespace": "team-a", "name": "app", "vaultKeyPath": "transit/keys/app"}},
			}, "app")
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := e.read("vault-deleted.txt"); got != "" {
				t.Fatalf("team-b is still on transit/keys/app: it must not be destroyed; deleted %q\nlog:\n%s", got, out)
			}
			if d := cmData(e.cm(t, "openinfra-destruction-state-team-a.erase-app")); d["phase"] != "Error" ||
				!strings.Contains(d["message"].(string), "1 other EncryptionKey(s)") || d["certificate"] != "" {
				t.Errorf("want Error naming the other key, no certificate; got %v\nlog:\n%s", d, out)
			}
		})
	}
}

// Data outlives its EncryptionKey object: another namespace's encrypted volume that may still be under
// the key (its own EncryptionKey deleted, nothing records where it pointed, and the key is the
// pre-namespacing one of that name) stops the erase. Volumes keyed elsewhere, and the Destruction's
// own namespace's volumes (the data it means to erase), do not.
func TestDestroyer_RefusesWhileAnotherNamespacesVolumesAreUnderTheKey(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json": items(
					xek("team-a", "app", "transit/keys/app"),           // pre-namespacing
					xek("team-c", "app", "transit/keys/ek_team-c_app"), // namespaced: never this key
					xek("team-a", "logs", "transit/keys/ek_team-a_logs"),
				),
				"pvcs.json": items(
					pvc("team-a", "data", "u1", "longhorn-encrypted", "app", false),  // own data: erased
					pvc("team-b", "data", "u2", "longhorn-encrypted", "app", false),  // key gone, may be under transit/keys/app
					pvc("team-c", "data", "u3", "longhorn-encrypted", "app", false),  // keyed under ek_team-c_app
					pvc("team-d", "data", "u4", "longhorn", "app", false),            // not encrypted
					pvc("team-e", "data", "u5", "longhorn-encrypted", "logs", false), // a different key name
				),
				"destructions.json": items(
					destruction("team-a", "erase-app", "app", "2026-11-01T00:00:00Z"),
					destruction("team-a", "erase-logs", "logs", "2026-11-01T00:00:00Z"),
				),
			}, receipts(map[string]string{"team-a.erase-logs": "transit/keys/ek_team-a_logs"}), "app", "ek_team-a_logs")
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(e.read("vault-deleted.txt")); got != "ek_team-a_logs" {
				t.Fatalf("want only ek_team-a_logs destroyed (transit/keys/app may hold team-b's data); deleted %q\nlog:\n%s", got, out)
			}
			if d := cmData(e.cm(t, "openinfra-destruction-state-team-a.erase-app")); d["phase"] != "Error" ||
				!strings.Contains(d["message"].(string), "0 other EncryptionKey(s), 1 encrypted volume(s)") || d["certificate"] != "" {
				t.Errorf("want Error naming the one other namespace's volume, no certificate; got %v\nlog:\n%s", d, out)
			}
			if d := cmData(e.cm(t, "openinfra-destruction-state-team-a.erase-logs")); d["phase"] != "Destroyed" {
				t.Errorf("team-a's own namespaced key has no other namespace's data under it: must be destroyed; got %v\nlog:\n%s", d, out)
			}
		})
	}
}

// No volume list, no erase: a key is never destroyed on a guess about whose data is under it.
func TestDestroyer_VolumeListFailureDestroysNothing(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	sh := posixShells(t)[0]
	e := destroyerEnv(t, map[string]any{
		"xenckeys.json":     items(xek("team-a", "app", "transit/keys/ek_team-a_app")),
		"destructions.json": items(destruction("team-a", "erase-app", "app", "2026-11-01T00:00:00Z")),
		"fail-pvc-list":     "",
	}, nil, "ek_team-a_app")
	out, err := e.run(t, sh, script, destroyerEnvVars...)
	if err == nil {
		t.Fatalf("a run whose volume list failed must exit non-zero; log:\n%s", out)
	}
	if got := e.read("vault-deleted.txt"); got != "" {
		t.Fatalf("a failed volume list must destroy nothing; deleted %q", got)
	}
}

// receipts are the volume-crypto reconciler's erasure receipts, by <namespace>.<destruction>: every
// passphrase under the key erased, checked after any deletion time a test produces.
func receipts(paths map[string]string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for id, path := range paths {
		n := "openinfra-volume-erasure-" + id
		out[n] = map[string]any{"metadata": map[string]any{"name": n, "namespace": "open-infra-console"},
			"data": map[string]any{"vaultKeyPath": path, "erased": "2", "remaining": "0", "checkedAt": "2999-01-01T00:00:00Z"}}
	}
	return out
}

// Destroying the Transit key alone leaves an encrypted volume readable: its passphrase is in plain
// text in its <pvc>-crypto Secret. So the erase is certified only once the volume-crypto reconciler's
// receipt, from after the key was destroyed, shows every passphrase under it erased. Until then the
// Destruction stays InProgress (key destroyed, deletion time recorded) and the next run resumes; a
// receipt from before the deletion, one for another key, or one with passphrases left, is not enough.
func TestDestroyer_CertifiesOnlyOnceVolumePassphrasesAreErased(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json":     items(xek("team-a", "app", "transit/keys/ek_team-a_app")),
				"destructions.json": items(destruction("team-a", "erase-app", "app", "2026-11-01T00:00:00Z")),
			}, nil, "ek_team-a_app")
			state := "openinfra-destruction-state-team-a.erase-app"
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(e.read("vault-deleted.txt")); got != "ek_team-a_app" {
				t.Fatalf("the key is destroyed first; deleted %q\nlog:\n%s", got, out)
			}
			d := cmData(e.cm(t, state))
			if d["phase"] != "InProgress" || d["destroyedAt"] == "" || d["certificate"] == "" || e.read("mc-certs.txt") != "" {
				t.Fatalf("without a receipt: InProgress with the deletion time, no certificate written; got %v\nlog:\n%s", d, out)
			}
			gone := d["destroyedAt"].(string)
			rc := filepath.Join(e.dir, "cms", "openinfra-volume-erasure-team-a.erase-app.json")
			put := func(data map[string]any) {
				b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "openinfra-volume-erasure-team-a.erase-app"}, "data": data})
				if err := os.WriteFile(rc, b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range map[string]map[string]any{
				"from before the deletion": {"vaultKeyPath": "transit/keys/ek_team-a_app", "erased": "1", "remaining": "0", "checkedAt": "2000-01-01T00:00:00Z"},
				"for another key":          {"vaultKeyPath": "transit/keys/ek_team-a_other", "erased": "1", "remaining": "0", "checkedAt": "2999-01-01T00:00:00Z"},
				"with passphrases left":    {"vaultKeyPath": "transit/keys/ek_team-a_app", "erased": "1", "remaining": "1", "checkedAt": "2999-01-01T00:00:00Z"},
			} {
				put(data)
				out, err := e.run(t, sh, script, destroyerEnvVars...)
				if err != nil {
					t.Fatalf("destroyer run failed: %v\n%s", err, out)
				}
				if d := cmData(e.cm(t, state)); d["phase"] != "InProgress" || e.read("mc-certs.txt") != "" {
					t.Fatalf("a receipt %s must not complete the erase; got %v\nlog:\n%s", name, d, out)
				}
			}
			put(map[string]any{"vaultKeyPath": "transit/keys/ek_team-a_app", "erased": "3", "remaining": "0", "checkedAt": "2999-01-01T00:00:00Z"})
			out, err = e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			d = cmData(e.cm(t, state))
			if d["phase"] != "Destroyed" || d["destroyedAt"] != gone {
				t.Fatalf("with the receipt: Destroyed at the recorded deletion time %s; got %v\nlog:\n%s", gone, d, out)
			}
			var c map[string]any
			if err := json.Unmarshal([]byte(e.read("cert-"+strings.ReplaceAll("audit/audit/"+d["certificate"].(string), "/", "_"))), &c); err != nil {
				t.Fatalf("certificate not written as JSON: %v\nlog:\n%s", err, out)
			}
			if c["volumePassphrasesErased"] != float64(3) || c["destroyedAt"] != gone {
				t.Errorf("the certificate records the passphrases erased and the deletion time; got %v", c)
			}
			if got := strings.TrimSpace(e.read("vault-deleted.txt")); got != "ek_team-a_app" {
				t.Errorf("the key is destroyed once; deleted %q", got)
			}
		})
	}
}

// cryptoSecretUnder is a reconciler-written passphrase Secret under Transit path <path> of EncryptionKey
// <key> ("" path = written before Secrets recorded one), created at <created>.
func cryptoSecretUnder(ns, pvcName, key, path, created string) map[string]any {
	d := map[string]any{"CRYPTO_KEY_VALUE": b64("PLAIN"), "WRAPPED_KEY": b64("vault:v1:WRAP"), "OPENINFRA_ENCRYPTION_KEY": b64(key)}
	if path != "" {
		d["OPENINFRA_VAULT_KEY_PATH"] = b64(path)
	}
	return map[string]any{"type": "Opaque", "data": d, "metadata": map[string]any{"namespace": ns, "name": pvcName + "-crypto",
		"creationTimestamp": created, "labels": map[string]any{"openinfra.dev/volume-crypto": pvcName},
		"ownerReferences": []any{map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "name": pvcName, "uid": "uid-" + pvcName}}}}
}

func destructionState(ns, name, key, path, phase, destroyedAt string) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": "openinfra-destruction-state-" + ns + "." + name,
		"labels": map[string]any{"openinfra.dev/destruction": name}},
		"data": map[string]any{"namespace": ns, "destruction": name, "encryptionKey": key, "vaultKeyPath": path,
			"phase": phase, "destroyedAt": destroyedAt}}
}

func pvcAt(ns, name, uid, key, created string) map[string]any {
	o := pvc(ns, name, uid, "longhorn-encrypted", key, false)
	o["metadata"].(map[string]any)["creationTimestamp"] = created
	return o
}

// When a Destruction destroys a key, every passphrase Secret under it in the Destruction's namespace is
// deleted (including one written before Secrets recorded their path, which names the key), and the
// receipt the destroyer certifies from says so. Kept: another key's, another namespace's (a Destruction
// reaches only its own), and one created after the destruction under a new key of that name. A claim
// from before the destruction is never keyed again; one created since is.
func TestVolumeCrypto_ErasesPassphrasesUnderADestroyedKey(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	const at = "2026-11-02T00:00:00Z"
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := newStubEnv(t, map[string]any{
				"pvcs.json": items(
					pvcAt("team", "erased", "uid-1", "k1", "2026-11-01T00:00:00Z"), // its Secret is gone: never re-keyed
					pvcAt("team", "fresh", "uid-2", "k1", "2026-11-03T00:00:00Z"),  // created since, under the new k1
					pvcAt("team", "busy", "uid-3", "k3", "2026-11-01T00:00:00Z"),   // its key is being destroyed
				),
				"secrets.json": items(
					cryptoSecretUnder("team", "a", "k1", "transit/keys/ek_team_k1", "2026-11-01T00:00:00Z"),
					cryptoSecretUnder("team", "legacy", "k1", "", "2026-10-01T00:00:00Z"),
					cryptoSecretUnder("team", "other-key", "k2", "transit/keys/ek_team_k2", "2026-11-01T00:00:00Z"),
					cryptoSecretUnder("team", "later", "k1", "transit/keys/ek_team_k1", "2026-11-03T00:00:00Z"),
					cryptoSecretUnder("elsewhere", "a", "k1", "transit/keys/ek_team_k1", "2026-11-01T00:00:00Z"),
					cryptoSecretUnder("team", "c", "k3", "transit/keys/ek_team_k3", "2026-11-02T12:00:00Z"),
				),
				"pvs.json": items(),
				"dcms.json": items(
					destructionState("team", "erase-k1", "k1", "transit/keys/ek_team_k1", "Destroyed", at),
					destructionState("team", "erase-k3", "k3", "transit/keys/ek_team_k3", "InProgress", ""),
					destructionState("team", "refused", "k2", "transit/keys/ek_team_k2", "Refused", ""),
				),
				"xenckeys.json": items(xek("team", "k1", "transit/keys/ek_team_k1"), xek("team", "k3", "transit/keys/ek_team_k3")),
			}, "ek_team_k1", "ek_team_k3")
			out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
			if err != nil {
				t.Fatalf("reconcile run failed: %v\n%s", err, out)
			}
			deleted := strings.Fields(e.read("deleted.txt"))
			if strings.Join(deleted, ",") != "team/a-crypto,team/legacy-crypto,team/c-crypto" {
				t.Errorf("want exactly team/a-crypto, team/legacy-crypto (k1) and team/c-crypto (k3) erased; deleted %v\nlog:\n%s", deleted, out)
			}
			applied := e.read("applied.yaml")
			for _, want := range []string{
				"  name: openinfra-volume-erasure-team.erase-k1\ndata:\n  destructionState: \"openinfra-destruction-state-team.erase-k1\"\n  namespace: \"team\"\n  vaultKeyPath: \"transit/keys/ek_team_k1\"\n  erased: \"2\"\n  remaining: \"0\"\n",
				"  name: openinfra-volume-erasure-team.erase-k3\ndata:\n  destructionState: \"openinfra-destruction-state-team.erase-k3\"\n  namespace: \"team\"\n  vaultKeyPath: \"transit/keys/ek_team_k3\"\n  erased: \"1\"\n  remaining: \"0\"\n",
			} {
				if !strings.Contains(applied, want) {
					t.Errorf("receipt missing:\n%s\napplied:\n%s", want, applied)
				}
			}
			if strings.Contains(applied, "erasure-team.refused") {
				t.Errorf("a refused Destruction erased nothing and gets no receipt; applied:\n%s", applied)
			}
			created := e.created(t)
			if len(created) != 1 || created[0]["metadata"].(map[string]any)["name"] != "fresh-crypto" {
				t.Fatalf("only team/fresh (created after the destruction) is keyed; created:\n%s\nlog:\n%s", e.read("created.jsonl"), out)
			}
			if l, _ := created[0]["metadata"].(map[string]any)["labels"].(map[string]any); l["velero.io/exclude-from-backup"] != "true" {
				t.Errorf("a passphrase Secret is kept out of the namespace backups; labels %v", l)
			}
			for _, want := range []string{"not keying team/erased", "not keying team/busy"} {
				if !strings.Contains(out, want) {
					t.Errorf("log missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// No Destruction records, no keying: a claim is never keyed under a key that may have been destroyed.
func TestVolumeCrypto_DestructionListFailureKeysNothing(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, volumeCryptoPath)
	sh := posixShells(t)[0]
	e := newStubEnv(t, map[string]any{
		"pvcs.json":     items(pvc("team", "data", "uid-data", "longhorn-encrypted", "k1", false)),
		"secrets.json":  items(),
		"pvs.json":      items(),
		"xenckeys.json": items(xek("team", "k1", "transit/keys/ek_team_k1")),
		"fail-dcm-list": "",
	}, "ek_team_k1")
	out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
	if err == nil {
		t.Fatalf("a run that cannot read the Destruction records must exit non-zero; log:\n%s", out)
	}
	if e.read("created.jsonl") != "" {
		t.Errorf("nothing may be keyed; created %q", e.read("created.jsonl"))
	}
}

// A key a Destruction destroyed is never re-created for the EncryptionKey that was destroyed (its
// state says destroyed); one being destroyed is left alone; a new EncryptionKey of that name, created
// after the destruction, gets a new key.
func TestEncryptionKeyReconciler_NeverRecreatesADestroyedKey(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, encKeyReconPath)
	at := func(o map[string]any, ts string) map[string]any {
		o["metadata"].(map[string]any)["creationTimestamp"] = ts
		return o
	}
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := newStubEnv(t, map[string]any{
				"xenckeys.json": items(
					at(xek("team", "gone", "transit/keys/ek_team_gone"), "2026-11-01T00:00:00Z"),
					at(xek("team", "again", "transit/keys/ek_team_again"), "2026-11-03T00:00:00Z"), // recreated since
					at(xek("team", "busy", "transit/keys/ek_team_busy"), "2026-11-01T00:00:00Z"),
					at(xek("other", "gone", "transit/keys/ek_other_gone"), "2026-11-01T00:00:00Z"), // another namespace
				),
				"dcms.json": items(
					destructionState("team", "d1", "gone", "transit/keys/ek_team_gone", "Destroyed", "2026-11-02T00:00:00Z"),
					destructionState("team", "d2", "again", "transit/keys/ek_team_again", "Destroyed", "2026-11-02T00:00:00Z"),
					destructionState("team", "d3", "busy", "transit/keys/ek_team_busy", "InProgress", ""),
				),
			}, "ek_team_busy")
			out, err := e.run(t, sh, script, "WATCH_SECONDS=0", "POLL_SECONDS=1")
			if err != nil {
				t.Fatalf("reconcile run failed: %v\n%s", err, out)
			}
			created := strings.Fields(e.read("vault-created.txt"))
			if strings.Join(created, ",") != "ek_team_again,ek_other_gone" {
				t.Errorf("want only ek_team_again (a new key) and ek_other_gone created; got %v\nlog:\n%s", created, out)
			}
			if strings.Contains(e.read("calls.log"), "ek_team_busy/rotate") {
				t.Errorf("a key being destroyed is never rotated")
			}
			applied := e.read("applied.yaml")
			if !strings.Contains(applied, "  name: openinfra-enckey-state-team.gone\ndata:\n  exists: \"false\"\n  destroyed: \"true\"\n") {
				t.Errorf("the destroyed key's state must say so; applied:\n%s", applied)
			}
			if strings.Contains(applied, "openinfra-enckey-state-team.busy") {
				t.Errorf("a key being destroyed gets no state write; applied:\n%s", applied)
			}
		})
	}
}

// destructionIn is a Destruction created ago before now, with a waiting period of window days (0: the
// default).
func destructionIn(ns, name, key string, ago time.Duration, window int) map[string]any {
	d := destruction(ns, name, key, time.Now().UTC().Add(-ago).Format(time.RFC3339))
	if window > 0 {
		d["spec"].(map[string]any)["pendingWindowInDays"] = window
	}
	return d
}

// #348: a Destruction waits out its pendingWindowInDays (AWS KMS ScheduleKeyDeletion: 7-30, default 30)
// before the key is destroyed: until then it is PendingDeletion with its deletion date, and nothing is
// destroyed. One whose window has passed is destroyed; the administrator's immediate list skips the window.
func TestDestroyer_WaitsOutThePendingWindow(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	noImmediate := map[string]map[string]any{"openinfra-destruction-config": {"metadata": map[string]any{"name": "openinfra-destruction-config"},
		"data": map[string]any{"immediate": "team-c/erase-now"}}}
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json": items(xek("team-a", "app", "transit/keys/ek_team-a_app"), xek("team-b", "old", "transit/keys/ek_team-b_old"),
					xek("team-c", "now", "transit/keys/ek_team-c_now")),
				"destructions.json": items(
					destructionIn("team-a", "erase-app", "app", 24*time.Hour, 0),   // default 30 days: waits
					destructionIn("team-b", "erase-old", "old", 8*24*time.Hour, 7), // 7 days, 8 days old: due
					destructionIn("team-c", "erase-now", "now", time.Minute, 0),    // the administrator's immediate entry
				),
			}, noImmediate, "ek_team-a_app", "ek_team-b_old", "ek_team-c_now")
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := strings.Fields(e.read("vault-deleted.txt")); strings.Join(got, ",") != "ek_team-b_old,ek_team-c_now" {
				t.Fatalf("want only the due and the immediate keys destroyed; got %v\nlog:\n%s", got, out)
			}
			a := cmData(e.cm(t, "openinfra-destruction-state-team-a.erase-app"))
			want := time.Now().UTC().Add(-24*time.Hour + 30*24*time.Hour)
			when, perr := time.Parse(time.RFC3339, fmt.Sprint(a["deletionDate"]))
			if a["phase"] != "PendingDeletion" || perr != nil || when.Sub(want).Abs() > 2*time.Minute {
				t.Fatalf("team-a must be PendingDeletion until %s; got %v\nlog:\n%s", want.Format(time.RFC3339), a, out)
			}
			if !strings.Contains(fmt.Sprint(a["message"]), "delete this Destruction before then to cancel") {
				t.Errorf("the pending state must say how to cancel; got %v", a["message"])
			}
		})
	}
}

// Deleting a Destruction before its deletion date cancels it (CancelKeyDeletion): its state becomes
// Cancelled and its key is never destroyed.
func TestDestroyer_DeletedBeforeTheDateIsCancelled(t *testing.T) {
	needJQ(t)
	script := extractArgsScript(t, destroyerPath)
	pending := map[string]any{"metadata": map[string]any{"name": "openinfra-destruction-state-team-a.erase-app", "namespace": "open-infra-console",
		"labels": map[string]any{"openinfra.dev/destruction": "erase-app"}},
		"data": map[string]any{"destruction": "erase-app", "namespace": "team-a", "encryptionKey": "app", "phase": "PendingDeletion",
			"vaultKeyPath": "transit/keys/ek_team-a_app", "deletionDate": "2026-12-01T00:00:00Z"}}
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			e := destroyerEnv(t, map[string]any{
				"xenckeys.json":     items(xek("team-a", "app", "transit/keys/ek_team-a_app")),
				"destructions.json": items(),
			}, map[string]map[string]any{"openinfra-destruction-state-team-a.erase-app": pending}, "ek_team-a_app")
			out, err := e.run(t, sh, script, destroyerEnvVars...)
			if err != nil {
				t.Fatalf("destroyer run failed: %v\n%s", err, out)
			}
			if got := e.read("vault-deleted.txt"); strings.TrimSpace(got) != "" {
				t.Fatalf("a cancelled destruction destroyed %q", got)
			}
			if d := cmData(e.cm(t, "openinfra-destruction-state-team-a.erase-app")); d["phase"] != "Cancelled" {
				t.Fatalf("want Cancelled; got %v\nlog:\n%s", d, out)
			}
		})
	}
}
