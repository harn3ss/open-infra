package render

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	for _, p := range []string{volumeCryptoPath, encKeyReconPath} {
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
  "get encryptionkeys.openinfra.dev -A -o json") serve enckeys ;;
  "get configmap "*" -o jsonpath={.data.lastRotatedEpoch}") exit 1 ;;
  "create configmap "*) printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n' "$3" ;;
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
			}, "k1")
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
				"CRYPTO_KEY_VALUE": "PLAIN-k1", "WRAPPED_KEY": "vault:v1:WRAP-k1", "OPENINFRA_ENCRYPTION_KEY": "k1",
				"CRYPTO_KEY_PROVIDER": "secret", "CRYPTO_KEY_CIPHER": "aes-xts-plain64", "CRYPTO_KEY_HASH": "sha256",
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
		"pvcs.json":    items(pvc("team", "data", "uid-data", "longhorn-encrypted", "k1", false)),
		"secrets.json": items(),
		"pvs.json":     items(),
	}, "k1")
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
	}, "k1")
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
	ek := func(names ...string) map[string]any {
		var objs []map[string]any
		for _, n := range names {
			objs = append(objs, map[string]any{"metadata": map[string]any{"name": n, "namespace": "team"}, "spec": map[string]any{}})
		}
		return items(objs...)
	}
	e := newStubEnv(t, map[string]any{
		"enckeys.json":      ek("old"),
		"enckeys.next.json": ek("old", "new"),
	}, "old")
	out, err := e.run(t, sh, script, "WATCH_SECONDS=3", "POLL_SECONDS=1")
	if err != nil {
		t.Fatalf("reconcile run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(e.read("vault-created.txt")); got != "new" {
		t.Errorf("the watch must create exactly the new Transit key; created:\n%s\nlog:\n%s", got, out)
	}
	applied := e.read("applied.yaml")
	if strings.Count(applied, "name: openinfra-enckey-state-old") != 1 || strings.Count(applied, "name: openinfra-enckey-state-new") != 1 {
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
		"verbs: [get, list, create, delete]",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("volume-crypto.yaml missing %q", want)
		}
	}
	// No write verb beyond what the policy gates: update/patch on Secrets would bypass it.
	for _, bad := range []string{"verbs: [get, list, create, delete, update", "patch]"} {
		if strings.Contains(m, bad) {
			t.Errorf("volume-crypto.yaml grants a Secret write verb the admission policy does not gate (%q)", bad)
		}
	}
}
