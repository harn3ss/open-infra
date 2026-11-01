package render

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Regression guard: a VM with NO dataDisks must render exactly as before — one root DataVolume, no
// blank volumes, no extra disks. The data-disk feature must be a true no-op for every existing VM
// (the composition re-renders for all VMs on reconcile).
func TestVM_NoDataDisks_Unchanged(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if !strings.Contains(out, "name: myvm-root") {
		t.Fatalf("root DataVolume must still render:\n%s", grepCtx(out, "dataVolumeTemplates"))
	}
	if strings.Contains(out, "blank: {}") {
		t.Errorf("a VM with no dataDisks must emit no blank data volume; got:\n%s", grepCtx(out, "blank"))
	}
	if strings.Contains(out, "myvm-data1") || strings.Contains(out, "name: data1") {
		t.Errorf("a VM with no dataDisks must emit no data disk; got:\n%s", grepCtx(out, "data1"))
	}
}

// A Linux VM with two data disks: the first unnamed (→ data1), the second named. Each renders a
// blank DataVolume, a virtio disk, and a volume binding — in order, on the non-HA storage class.
func TestVM_DataDisks_ProvisionInOrder(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"size": "50Gi"},
			map[string]any{"name": "extra", "size": "30Gi"},
		},
	}))
	for _, want := range []string{
		"name: myvm-root",  // root still present
		"name: myvm-data1", // unnamed → data1 (DataVolume)
		"name: myvm-extra", // named disk (DataVolume)
		"blank: {}",        // data disks are blank-sourced
		"storage: 50Gi",
		"storage: 30Gi",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("data-disk render missing %q; got:\n%s", want, grepCtx(out, "dataVolumeTemplates"))
		}
	}
	// A virtio disk device and a volume binding for each (name appears in devices.disks AND volumes).
	if strings.Count(out, "name: data1") < 2 {
		t.Errorf("data1 must appear as both a disk device and a volume; got:\n%s", grepCtx(out, "data1"))
	}
	if strings.Count(out, "name: extra") < 2 {
		t.Errorf("extra must appear as both a disk device and a volume; got:\n%s", grepCtx(out, "extra"))
	}
	// Non-HA → local-path, no Block mode on the data disks.
	if !strings.Contains(out, "storageClassName: local-path") {
		t.Errorf("non-HA data disks must use local-path; got:\n%s", grepCtx(out, "storageClassName"))
	}
}

// An encrypted data disk renders as a longhorn-encrypted RWO Block volume carrying the
// openinfra.dev/encryption-key annotation (what the volume-crypto reconciler selects on), regardless
// of the VM's HA policy — there is no encrypted+migratable class.
func TestVM_DataDisks_Encrypted(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"name": "db", "size": "100Gi", "encrypted": true, "encryptionKey": "db-key"},
		},
	}))
	for _, want := range []string{
		"name: myvm-db",
		"storageClassName: longhorn-encrypted",
		"openinfra.dev/encryption-key: \"db-key\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("encrypted data disk missing %q; got:\n%s", want, grepCtx(out, "db"))
		}
	}
	// An encrypted disk is RWO even though nothing forced HA here (no RWX migratable encrypted class).
	if strings.Contains(grepCtx(out, "myvm-db"), "ReadWriteMany") {
		t.Errorf("an encrypted data disk must be RWO, not RWX; got:\n%s", grepCtx(out, "myvm-db"))
	}
	// It is a plain Block PVC attached by claim name — NOT a CDI DataVolume (CDI's non-root importer
	// cannot open a dm-crypt device, and a blank disk needs no import).
	for _, want := range []string{
		"composition-resource-name: datadisk-db",
		"kind: PersistentVolumeClaim",
		"claimName: myvm-db",
		"volumeMode: Block",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("encrypted data disk must render as an attached PVC; missing %q", want)
		}
	}
	if strings.Contains(out, "blank: {}") {
		t.Errorf("an encrypted data disk must not be a blank DataVolume; got:\n%s", grepCtx(out, "blank"))
	}
}

// Encrypted and unencrypted data disks on one VM: the unencrypted one stays a blank DataVolume, the
// encrypted one is an attached PVC.
func TestVM_DataDisks_MixedEncryption(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"name": "logs", "size": "5Gi"},
			map[string]any{"name": "db", "size": "10Gi", "encrypted": true, "encryptionKey": "db-key"},
		},
	}))
	if strings.Count(out, "blank: {}") != 1 {
		t.Errorf("exactly the unencrypted disk is a blank DataVolume; got:\n%s", grepCtx(out, "blank"))
	}
	if !regexp.MustCompile(`dataVolume:\s*\n\s*name: myvm-logs`).MatchString(out) {
		t.Errorf("the unencrypted disk must be bound as a dataVolume; got:\n%s", grepCtx(out, "myvm-logs"))
	}
	if !strings.Contains(out, "claimName: myvm-db") {
		t.Errorf("the encrypted disk must be bound by claimName")
	}
}

// A UserData script is EXEC'd (its shebang honored), not passed to `sh` — otherwise a `#!/bin/bash`
// script with the standard `set -euxo pipefail` opener would run under dash and die on line 1.
func TestVM_UserData_ExecNotSh(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"userData": "#!/bin/bash\nset -euxo pipefail\necho hi\n"}))
	if !strings.Contains(out, "exec /opt/openinfra-userdata") {
		t.Errorf("UserData must be exec'd directly (honoring its shebang); got:\n%s", grepCtx(out, "openinfra-userdata"))
	}
	if strings.Contains(out, "/bin/sh, /opt/openinfra-userdata") {
		t.Errorf("UserData must NOT be passed to /bin/sh (that ignores #!/bin/bash); got:\n%s", grepCtx(out, "openinfra-userdata"))
	}
}

// Data disks get AWS Nitro device-name aliases so an unmodified lift-and-shift UserData script that
// formats/mounts /dev/nvme1n1 works on KubeVirt virtio disks (/dev/vdb). The composition drops a udev
// rules file and triggers udev before the user's script runs.
func TestVM_DataDisks_NitroDeviceNameAliases(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"size": "50Gi"},                  // → /dev/vdb → nvme1n1
			map[string]any{"name": "extra", "size": "30Gi"}, // → /dev/vdc → nvme2n1
		},
	}))
	for _, want := range []string{
		"99-openinfra-aws-device-names.rules",
		`KERNEL=="vdb", SYMLINK+="nvme1n1"`,
		`KERNEL=="vdb[0-9]*", SYMLINK+="nvme1n1p%n"`, // partitions too
		`KERNEL=="vdc", SYMLINK+="nvme2n1"`,
		`KERNEL=="vda", SYMLINK+="nvme0n1"`, // root alias
		"udevadm",                           // udev is reloaded/triggered before UserData
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Nitro device-name aliasing missing %q; got:\n%s", want, grepCtx(out, "nvme"))
		}
	}
	// A VM with NO data disks must not carry the alias rules file.
	none := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if strings.Contains(none, "aws-device-names") {
		t.Errorf("a VM with no data disks must not emit the Nitro alias rules; got:\n%s", grepCtx(none, "device-names"))
	}
}

// spec.instanceRole wires the VM's workload identity: a per-VM ServiceAccount (annotated with the
// role), its token projected onto an "identity" serviceAccount disk and copied ROOT-ONLY into the
// guest, and the metadata agent serving the role's credentials over IMDS and the loopback
// container-credentials endpoint. No instanceRole → none of the identity wiring.
func TestVM_InstanceRole_WorkloadIdentityWiring(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	with := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"}))
	for _, want := range []string{
		"kind: ServiceAccount",                  // the per-VM SA object
		"name: vm-myvm",                         // SA named for the VM
		"openinfra.dev/instance-role: app-role", // SA annotation the shim reads
		"serviceAccountName: vm-myvm",           // the projected SA volume
		"serial: SATOKEN",                       // the identity disk's stable serial
		// cloud-init lives in a Secret (KubeVirt's 2048-byte inline cap), referenced by the VMI:
		"secretRef",
		"name: myvm-cloudinit",
		// The credentials endpoint is the agent's LOOPBACK listener (botocore/JS reject a non-loopback
		// host), in /etc/environment, the boot-script env file, and a systemd Manager drop-in:
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:16349/v1/vm-credentials\\n",
		"DefaultEnvironment=AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:16349/v1/vm-credentials",
		"path: /etc/openinfra-aws.env",
		// The agent is started before the boot script runs.
		"[ systemctl, enable, --now, openinfra-metadata.service ]",
		// The token is stripped of whitespace and materialized root-only (0600 in a 0700 dir).
		"tr -d '[:space:]' < /mnt/openinfra-identity/token > /run/openinfra-identity/token.tmp",
		"chmod 0600 /run/openinfra-identity/token.tmp",
		"chmod 0700 /run/openinfra-identity",
		"umask 077",
		"/dev/disk/by-id/virtio-SATOKEN", // the boot-time mount
	} {
		if !strings.Contains(with, want) {
			t.Errorf("instanceRole wiring missing %q; got:\n%s", want, grepCtx(with, "identity"))
		}
	}
	// #347 item 13: the agent adds the Authorization header itself, so no token env var is rendered
	// (old SDKs don't know *_TOKEN_FILE, and a token file every process can read is a credential leak),
	// and the socket-proxy relay is gone.
	for _, absent := range []string{
		"TOKEN_FILE", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "systemd-socket-proxyd", "openinfra-aws-creds",
		"chmod 0644 /run/openinfra-identity",
	} {
		if strings.Contains(with, absent) {
			t.Errorf("instanceRole VM must not render %q; got:\n%s", absent, grepCtx(with, absent))
		}
	}
	// A VM with no instanceRole still uses the cloud-init Secret (Linux) and still runs the metadata
	// agent (IMDS serves instance identity and user-data without a role, as on EC2), but carries none
	// of the workload-identity wiring and no credentials endpoint.
	without := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if !strings.Contains(without, "name: myvm-cloudinit") {
		t.Errorf("every Linux VM should render a cloud-init Secret; got:\n%s", grepCtx(without, "cloudinit"))
	}
	for _, absent := range []string{"vm-myvm", "SATOKEN", "AWS_CONTAINER_CREDENTIALS_FULL_URI=", "openinfra.dev/instance-role:", "openinfra-identity/token.tmp"} {
		if strings.Contains(without, absent) {
			t.Errorf("a VM with no instanceRole must not render %q; got:\n%s", absent, grepCtx(without, absent))
		}
	}
	cfg := vmAgentConfig(t, without)
	if cfg["role"] != "" {
		t.Errorf("no instanceRole → agent config role must be empty, got %#v", cfg["role"])
	}
	if relay, _ := cfg["relay"].(map[string]any); relay["enabled"] != false {
		t.Errorf("no instanceRole → the credentials endpoint must be off, got %#v", relay)
	}
}

// ---- #347 item 14: the in-guest instance metadata agent (EC2 IMDS on 169.254.169.254) ----

const vmComposition = "../../platform/abstraction/vm-composition.yaml"

// vmWriteFileBlock returns the dedented `content: |` body of the cloud-init write_files entry for path
// (in rendered output, or in the raw composition file), or "" if absent.
func vmWriteFileBlock(s, path string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "- path: "+path {
			continue
		}
		for j := i + 1; j < len(lines) && j < i+4; j++ {
			if strings.TrimSpace(lines[j]) != "content: |" {
				continue
			}
			keyIndent := len(lines[j]) - len(strings.TrimLeft(lines[j], " "))
			var out []string
			for _, b := range lines[j+1:] {
				if strings.TrimSpace(b) == "" {
					out = append(out, "")
					continue
				}
				if len(b)-len(strings.TrimLeft(b, " ")) <= keyIndent {
					break
				}
				out = append(out, b[keyIndent+2:])
			}
			for len(out) > 0 && out[len(out)-1] == "" {
				out = out[:len(out)-1]
			}
			return strings.Join(out, "\n") + "\n"
		}
	}
	return ""
}

// vmAgentConfig decodes the rendered /etc/openinfra/metadata-agent.json (a JSON document embedded
// as a JSON-quoted YAML scalar).
func vmAgentConfig(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "- path: /etc/openinfra/metadata-agent.json" {
			continue
		}
		for j := i + 1; j < len(lines) && j < i+4; j++ {
			c := strings.TrimSpace(lines[j])
			if !strings.HasPrefix(c, "content: ") {
				continue
			}
			var doc string
			if err := json.Unmarshal([]byte(strings.TrimPrefix(c, "content: ")), &doc); err != nil {
				t.Fatalf("agent config is not a JSON-quoted scalar: %v\n%s", err, c)
			}
			var cfg map[string]any
			if err := json.Unmarshal([]byte(doc), &cfg); err != nil {
				t.Fatalf("agent config is not JSON: %v\n%s", err, doc)
			}
			return cfg
		}
	}
	t.Fatalf("no /etc/openinfra/metadata-agent.json in the rendered cloud-init:\n%s", grepCtx(out, "write_files"))
	return nil
}

// Every Linux VM runs the metadata agent: the script, its config and a Type=notify unit enabled before
// UserData. The agent body must render VERBATIM (no template actions inside it), because
// test/vm-creds runs the body it extracts from the composition file.
func TestVM_MetadataAgent_Rendered(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role", "userData": "#!/bin/bash\necho hi\n"}))
	for _, want := range []string{
		"path: /usr/local/lib/openinfra/metadata-agent.py",
		"path: /etc/openinfra/metadata-agent.json",
		"path: /etc/systemd/system/openinfra-metadata.service",
		"Type=notify",
		"Restart=on-failure",           // a clean exit (boot-only mode) is not restarted
		"/usr/libexec/platform-python", // RHEL 8 family fallback interpreter
		"[ systemctl, enable, --now, openinfra-metadata.service ]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata agent render missing %q; got:\n%s", want, grepCtx(out, "metadata"))
		}
	}
	// The agent starts BEFORE the user's UserData script runs.
	if a, u := strings.Index(out, "openinfra-metadata.service ]"), strings.Index(out, "exec /opt/openinfra-userdata"); a < 0 || u < 0 || a > u {
		t.Errorf("the metadata agent must be enabled before UserData runs (agent@%d, userdata@%d)", a, u)
	}

	raw, err := os.ReadFile(vmComposition)
	if err != nil {
		t.Fatal(err)
	}
	src := vmWriteFileBlock(string(raw), "/usr/local/lib/openinfra/metadata-agent.py")
	if !strings.HasPrefix(src, "#!/usr/bin/env python3\n") || len(src) < 1000 {
		t.Fatalf("could not extract the agent body from the composition file (got %d bytes)", len(src))
	}
	if strings.Contains(src, "{{") {
		t.Errorf("the agent body must contain no template actions (it is run verbatim by test/vm-creds)")
	}
	if got := vmWriteFileBlock(out, "/usr/local/lib/openinfra/metadata-agent.py"); got != src {
		t.Errorf("the rendered agent differs from the composition source (%d vs %d bytes)", len(got), len(src))
	}

	cfg := vmAgentConfig(t, out)
	if id, _ := cfg["instanceId"].(string); !strings.HasPrefix(id, "i-") || len(id) != 19 {
		t.Errorf("instanceId must be an EC2-shaped i-<17 hex>, got %q", id)
	}
	if id, _ := cfg["imageId"].(string); !strings.HasPrefix(id, "ami-") || len(id) != 21 {
		t.Errorf("imageId must be an ami-<17 hex>, got %q", id)
	}
	imds, _ := cfg["imds"].(map[string]any)
	relay, _ := cfg["relay"].(map[string]any)
	for k, want := range map[string]any{
		"imds.address": "169.254.169.254", "imds.port": float64(80), "imds.netns": "openinfra-imds",
		"imds.httpTokens": "optional", "imds.hopLimit": float64(2), "imds.enabled": true,
		"relay.address": "127.0.0.1", "relay.port": float64(16349), "relay.enabled": true,
	} {
		m, key := imds, strings.TrimPrefix(k, "imds.")
		if strings.HasPrefix(k, "relay.") {
			m, key = relay, strings.TrimPrefix(k, "relay.")
		}
		if m[key] != want {
			t.Errorf("agent config %s = %#v, want %#v", k, m[key], want)
		}
	}
	if cfg["role"] != "app-role" || cfg["userDataFile"] != "/opt/openinfra-userdata" || cfg["tokenFile"] != "/run/openinfra-identity/token" {
		t.Errorf("agent config role/userDataFile/tokenFile wrong: %#v %#v %#v", cfg["role"], cfg["userDataFile"], cfg["tokenFile"])
	}
	if cfg["credentialsUrl"] != "https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567/v1/vm-credentials" {
		t.Errorf("agent must fetch credentials from the shim's in-cluster TLS port, got %#v", cfg["credentialsUrl"])
	}
	// #347 item 15: the guest trusts the platform root CA from its own spec (never fetched).
	if cfg["trustPlatformCA"] != true || cfg["caFile"] != "/etc/openinfra/platform-root-ca.pem" {
		t.Errorf("agent must trust the platform CA from its caFile, got %#v %#v", cfg["trustPlatformCA"], cfg["caFile"])
	}
	if _, ok := cfg["caBundleUrl"]; ok {
		t.Errorf("the agent must not fetch the CA over the network (caBundleUrl rendered: %#v)", cfg["caBundleUrl"])
	}
}

// testRootPEM stands in for the platform root CA the openinfra-platform-ca EnvironmentConfig carries.
const testRootPEM = "-----BEGIN CERTIFICATE-----\nMIIBfakeRootForRenderTestsOnly\n-----END CERTIFICATE-----\n"

func withPlatformCA(ctx map[string]any) map[string]any {
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"platformRootCA": testRootPEM}}
	return ctx
}

// Item 4 (transport): the platform root CA reaches the guest in its own spec — the cloud-init Secret,
// from the EnvironmentConfig — and the agent calls the shim's TLS port only. No plaintext shim URL is
// rendered anywhere, so neither the token nor the trust anchor ever crosses the network in clear text.
// Without the EnvironmentConfig (no aws-shim) no CA file is written: the guest trusts no platform CA and
// gets no credentials (fail closed), but the agent still knows where the file would be.
func TestVM_PlatformCA_FromEnvironment(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	const caPath = "/etc/openinfra/platform-root-ca.pem"
	with := render(t, tmpl, withPlatformCA(vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"})))
	if got := vmWriteFileScalar(t, with, caPath); got != testRootPEM {
		t.Errorf("the cloud-init must write the platform root CA from the environment to %s; got %q", caPath, got)
	}
	if cfg := vmAgentConfig(t, with); cfg["caFile"] != caPath {
		t.Errorf("agent caFile = %#v, want %s", cfg["caFile"], caPath)
	}
	for _, absent := range []string{"http://aws-shim", ":4566", "/v1/ca-bundle"} {
		if strings.Contains(with, absent) {
			t.Errorf("a VM must never be pointed at the plaintext shim (%q rendered):\n%s", absent, grepCtx(with, absent))
		}
	}

	without := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"}))
	if strings.Contains(without, "- path: "+caPath) {
		t.Errorf("no EnvironmentConfig → no CA file (fail closed); got:\n%s", grepCtx(without, caPath))
	}
	if cfg := vmAgentConfig(t, without); cfg["caFile"] != caPath || cfg["trustPlatformCA"] != true {
		t.Errorf("without a CA the agent still looks for it at %s, got %#v %#v", caPath, cfg["caFile"], cfg["trustPlatformCA"])
	}

	win := render(t, tmpl, withPlatformCA(vmCtx("windows-server-2022", "")))
	if strings.Contains(win, "BEGIN CERTIFICATE") {
		t.Errorf("Windows guests run no metadata agent and get no CA file")
	}

	// The composition reads the CA through an Optional environment step (no aws-shim = no config, no error).
	raw, err := os.ReadFile(vmComposition)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: crossplane-contrib-function-environment-configs", "resolution: Optional", "name: openinfra-platform-ca"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("vm-composition.yaml must read openinfra-platform-ca via an Optional environment step (missing %q)", want)
		}
	}
	// The agent drops 169.254.169.254-bound packets arriving on the guest's own NICs (item 5).
	src := vmWriteFileBlock(string(raw), "/usr/local/lib/openinfra/metadata-agent.py")
	for _, want := range []string{"def guard_forwarded_imds(", "self.guard = guard_forwarded_imds(", "def vm_nics(", "priority -300"} {
		if !strings.Contains(src, want) {
			t.Errorf("the agent must guard IMDS against forwarded traffic (missing %q)", want)
		}
	}
}

// httpEndpoint: disabled serves no metadata, so the guest gets no identity token at all (no token disk,
// no boot-time copy); the VM's ServiceAccount stays. Hop limit: 1 when metadataOptions is given without
// one (EC2's default), 2 when the VM has no metadataOptions.
func TestVM_MetadataOptions_IdentityAndHopDefaults(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	off := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"instanceRole":    "app-role",
		"metadataOptions": map[string]any{"httpEndpoint": "disabled"},
	}))
	for _, absent := range []string{"serial: SATOKEN", "serviceAccountName: vm-myvm", "openinfra-identity/token.tmp"} {
		if strings.Contains(off, absent) {
			t.Errorf("httpEndpoint: disabled must not put the identity token in the guest (%q rendered)", absent)
		}
	}
	if !strings.Contains(off, "name: vm-myvm") {
		t.Errorf("httpEndpoint: disabled keeps the VM's ServiceAccount")
	}
	on := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"}))
	for _, want := range []string{"serial: SATOKEN", "serviceAccountName: vm-myvm", "openinfra-identity/token.tmp"} {
		if !strings.Contains(on, want) {
			t.Errorf("an enabled metadata service needs the identity token in the guest (missing %q)", want)
		}
	}

	hop := func(ctx map[string]any) any {
		imds, _ := vmAgentConfig(t, render(t, tmpl, ctx))["imds"].(map[string]any)
		return imds["hopLimit"]
	}
	if got := hop(vmCtxFW("ubuntu-24.04", map[string]any{"metadataOptions": map[string]any{"httpTokens": "required"}})); got != float64(1) {
		t.Errorf("metadataOptions without a hop limit → 1 (EC2's default), got %#v", got)
	}
	if got := hop(vmCtx("ubuntu-24.04", "")); got != float64(2) {
		t.Errorf("no metadataOptions → hop limit 2, got %#v", got)
	}
}

// spec.metadataOptions maps onto the agent: httpTokens + the PUT response hop limit go into its config;
// httpTokens: required also turns off the loopback credentials endpoint (a plain GET is IMDSv1-
// equivalent); httpEndpoint: disabled serves no metadata — the agent then only trusts the platform CA at
// boot and exits.
func TestVM_MetadataOptions(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)

	req := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"instanceRole":    "app-role",
		"metadataOptions": map[string]any{"httpTokens": "required", "httpPutResponseHopLimit": float64(3)},
	}))
	imds, _ := vmAgentConfig(t, req)["imds"].(map[string]any)
	if imds["httpTokens"] != "required" || imds["hopLimit"] != float64(3) {
		t.Errorf("metadataOptions must render into the agent config, got %#v", imds)
	}
	if relay, _ := vmAgentConfig(t, req)["relay"].(map[string]any); relay["enabled"] != false {
		t.Errorf("httpTokens: required must disable the credentials endpoint, got %#v", relay)
	}
	if strings.Contains(req, "AWS_CONTAINER_CREDENTIALS_FULL_URI=") {
		t.Errorf("httpTokens: required must not advertise the container-credentials endpoint; got:\n%s", grepCtx(req, "FULL_URI"))
	}
	if !strings.Contains(req, "openinfra-metadata.service ]") {
		t.Errorf("httpTokens: required still runs the agent (IMDSv2 only)")
	}

	off := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"instanceRole":    "app-role",
		"metadataOptions": map[string]any{"httpEndpoint": "disabled"},
	}))
	if strings.Contains(off, "AWS_CONTAINER_CREDENTIALS_FULL_URI=") {
		t.Errorf("httpEndpoint: disabled must not advertise the container-credentials endpoint; got:\n%s", grepCtx(off, "FULL_URI"))
	}
	offCfg := vmAgentConfig(t, off)
	if imds, _ := offCfg["imds"].(map[string]any); imds["enabled"] != false {
		t.Errorf("httpEndpoint: disabled must turn the IMDS listener off, got %#v", imds)
	}
	if relay, _ := offCfg["relay"].(map[string]any); relay["enabled"] != false {
		t.Errorf("httpEndpoint: disabled must turn the credentials endpoint off, got %#v", relay)
	}
	if offCfg["trustPlatformCA"] != true || !strings.Contains(off, "openinfra-metadata.service ]") {
		t.Errorf("httpEndpoint: disabled still runs the agent once at boot to trust the platform CA")
	}
	if !strings.Contains(off, "name: vm-myvm") {
		t.Errorf("httpEndpoint: disabled leaves the VM's identity (ServiceAccount) in place")
	}

	// Omitted metadataOptions = the defaults: optional tokens, hop limit 2, agent on.
	def := vmAgentConfig(t, render(t, tmpl, vmCtx("debian-12", "")))
	if imds, _ := def["imds"].(map[string]any); imds["httpTokens"] != "optional" || imds["hopLimit"] != float64(2) {
		t.Errorf("default metadataOptions must be httpTokens optional + hop limit 2, got %#v", imds)
	}
}

// vmWriteFileScalar returns the decoded `content: "<json-quoted>"` of the write_files entry for path, or
// "" when the entry is absent.
func vmWriteFileScalar(t *testing.T, out, path string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "- path: "+path {
			continue
		}
		for j := i + 1; j < len(lines) && j < i+4; j++ {
			c := strings.TrimSpace(lines[j])
			if !strings.HasPrefix(c, "content: ") {
				continue
			}
			var s string
			if err := json.Unmarshal([]byte(strings.TrimPrefix(c, "content: ")), &s); err != nil {
				t.Fatalf("%s content is not a JSON-quoted scalar: %v\n%s", path, err, c)
			}
			return s
		}
	}
	return ""
}

// #347 item 15: SDKs that ship their own CA store (aws-cli v2, boto3 with certifi, Node) ignore the
// system trust store, so every Linux guest gets AWS_CA_BUNDLE (and NODE_EXTRA_CA_CERTS) naming the path
// the agent keeps pointing at the FULL system bundle — in the same three places as the credentials env.
func TestVM_AWSCABundleEnv(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	const link = "/etc/openinfra/ca-bundle.pem"
	check := func(name string, out string, wantURI bool) {
		t.Helper()
		if got := vmAgentConfig(t, out)["caBundleLink"]; got != link {
			t.Errorf("%s: the agent must maintain %s (the path AWS_CA_BUNDLE names), got %#v", name, link, got)
		}
		dropIn := grepCtx(out, "DefaultEnvironment=")
		for _, f := range []string{"/etc/environment", "/etc/openinfra-aws.env"} {
			env := vmWriteFileScalar(t, out, f)
			for _, want := range []string{"AWS_CA_BUNDLE=" + link + "\n", "NODE_EXTRA_CA_CERTS=" + link + "\n"} {
				if !strings.Contains(env, want) {
					t.Errorf("%s: %s must carry %q; got %q", name, f, want, env)
				}
			}
			if has := strings.Contains(env, "AWS_CONTAINER_CREDENTIALS_FULL_URI="); has != wantURI {
				t.Errorf("%s: %s FULL_URI present=%v, want %v; got %q", name, f, has, wantURI, env)
			}
		}
		if !strings.Contains(dropIn, "AWS_CA_BUNDLE="+link) || !strings.Contains(dropIn, "NODE_EXTRA_CA_CERTS="+link) {
			t.Errorf("%s: the systemd DefaultEnvironment drop-in must carry the CA bundle env; got:\n%s", name, dropIn)
		}
		if has := strings.Contains(dropIn, "AWS_CONTAINER_CREDENTIALS_FULL_URI="); has != wantURI {
			t.Errorf("%s: drop-in FULL_URI present=%v, want %v", name, has, wantURI)
		}
	}
	check("no role", render(t, tmpl, vmCtx("ubuntu-24.04", "")), false)
	check("role", render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"})), true)
	check("metadata disabled", render(t, tmpl, vmCtxFW("centos-stream-9", map[string]any{
		"instanceRole": "app-role", "metadataOptions": map[string]any{"httpEndpoint": "disabled"},
	})), false)
	if win := render(t, tmpl, vmCtxFW("windows-server-2022", map[string]any{"instanceRole": "app-role"})); strings.Contains(win, "AWS_CA_BUNDLE") {
		t.Errorf("a Windows VM must not render the CA bundle env")
	}
}

// The env reaches a `#!/bin/bash` UserData process: run the EXACT wrapper command the composition renders
// (only its two file paths re-pointed at temp files) on the EXACT env file and script it renders.
func TestVM_UserDataGetsAWSEnv(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	tmpl := extractInlineTemplate(t, vmComposition)
	script := "#!/bin/bash\nset -euo pipefail\nprintf '%s\\n' \"$AWS_CA_BUNDLE\" \"$NODE_EXTRA_CA_CERTS\" \"$AWS_CONTAINER_CREDENTIALS_FULL_URI\" > \"$OUT\"\n"
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role", "userData": script}))

	var wrapper string
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "exec /opt/openinfra-userdata") {
			if i, j := strings.Index(ln, `"`), strings.LastIndex(ln, `"`); i >= 0 && j > i {
				wrapper = ln[i+1 : j]
			}
		}
	}
	if wrapper == "" {
		t.Fatalf("no UserData wrapper in runcmd:\n%s", grepCtx(out, "openinfra-userdata"))
	}
	dir := t.TempDir()
	envFile, udFile, outFile := filepath.Join(dir, "openinfra-aws.env"), filepath.Join(dir, "userdata"), filepath.Join(dir, "out")
	if err := os.WriteFile(envFile, []byte(vmWriteFileScalar(t, out, "/etc/openinfra-aws.env")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(udFile, []byte(vmWriteFileScalar(t, out, "/opt/openinfra-userdata")), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := strings.NewReplacer("/etc/openinfra-aws.env", envFile, "/opt/openinfra-userdata", udFile).Replace(wrapper)
	run := exec.Command(bash, "-c", cmd)
	run.Env = []string{"PATH=" + os.Getenv("PATH"), "OUT=" + outFile} // nothing AWS-related inherited
	if b, err := run.CombinedOutput(); err != nil {
		t.Fatalf("UserData wrapper failed: %v\n%s", err, b)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "/etc/openinfra/ca-bundle.pem\n/etc/openinfra/ca-bundle.pem\nhttp://127.0.0.1:16349/v1/vm-credentials\n"
	if string(got) != want {
		t.Errorf("the #!/bin/bash UserData script must see the AWS SDK env; got %q, want %q", got, want)
	}
}

// Windows guests are untouched: no cloud-init, so no metadata agent and no token disk.
func TestVM_MetadataAgent_WindowsUnaffected(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	out := render(t, tmpl, vmCtxFW("windows-server-2022", map[string]any{
		"instanceRole":    "app-role",
		"metadataOptions": map[string]any{"httpTokens": "required"},
	}))
	for _, absent := range []string{"metadata-agent", "openinfra-metadata", "SATOKEN", "AWS_CONTAINER", "cloudinit"} {
		if strings.Contains(out, absent) {
			t.Errorf("a Windows VM must not render %q; got:\n%s", absent, grepCtx(out, absent))
		}
	}
}

// The agent config the composition renders is pinned by a golden file that test/vm-creds runs the real
// agent against — so the agent is always tested on exactly the config shape the guest receives.
func TestVM_MetadataAgent_GoldenConfig(t *testing.T) {
	const golden = "../vm-creds/testdata/metadata-agent.golden.json"
	tmpl := extractInlineTemplate(t, vmComposition)
	ctx := vmCtxFW("ubuntu-24.04", map[string]any{
		"instanceRole":   "app-role",
		"userData":       "#!/bin/bash\necho hi\n",
		"securityGroups": []any{"web"},
	})
	meta := ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["metadata"].(map[string]any)
	meta["creationTimestamp"] = "2026-10-31T12:00:00Z" // the instance's launch time (identity document pendingTime)
	got := vmAgentConfig(t, render(t, tmpl, ctx))
	b, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v", golden, err)
	}
	var want map[string]any
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("%s: %v", golden, err)
	}
	if !reflect.DeepEqual(got, want) {
		pretty, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("rendered agent config drifted from %s — if intended, update it to:\n%s", golden, pretty)
	}
}

// An HA VM's data disks must follow the root's storage policy — longhorn-migratable RWX Block — so
// they live-migrate with the VM (a local-path data disk would pin the VM and break migration).
func TestVM_DataDisks_FollowHAStoragePolicy(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"highAvailability": true,
		"dataDisks":        []any{map[string]any{"name": "db", "size": "100Gi"}},
	}))
	if !strings.Contains(out, "name: myvm-db") {
		t.Fatalf("HA data disk must render; got:\n%s", grepCtx(out, "dataVolumeTemplates"))
	}
	// root + 1 data disk both on longhorn-migratable Block.
	if n := strings.Count(out, "storageClassName: longhorn-migratable"); n < 2 {
		t.Errorf("HA root + data disk must both be longhorn-migratable (>=2); got %d:\n%s", n, grepCtx(out, "storageClassName"))
	}
	if n := strings.Count(out, "volumeMode: Block"); n < 2 {
		t.Errorf("HA root + data disk must both be Block mode (>=2); got %d:\n%s", n, grepCtx(out, "volumeMode"))
	}
}

// status.lanIp surfaces the VM's LAN IP (#347): read back from the observed <name>-lan LoadBalancer
// Service once MetalLB assigns it, emitted on the composite's status — what the claim (and a
// CloudFormation Output for an Elastic IP / an instance's PublicIp) reads. Empty while unassigned and
// when the VM is not exposed, even if a stale observed Service lingers.
func TestVM_StatusLanIP(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	observedLB := func(ctx map[string]any, ingress []any) map[string]any {
		ctx["observed"].(map[string]any)["resources"] = map[string]any{
			"vm-lan": map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{
				"manifest": map[string]any{"status": map[string]any{"loadBalancer": map[string]any{"ingress": ingress}}},
			}}}},
		}
		return ctx
	}
	statusDoc := func(out string) string {
		i := strings.Index(out, "kind: XVirtualMachine")
		if i < 0 {
			t.Fatalf("the composite status document (kind: XVirtualMachine) must always render:\n%s", grepCtx(out, "vm-lan"))
		}
		return out[i:]
	}

	// Exposed + assigned: the LoadBalancer's first ingress IP.
	got := statusDoc(render(t, tmpl, observedLB(vmCtxFW("ubuntu-24.04", map[string]any{"expose": true}),
		[]any{map[string]any{"ip": "192.0.2.40"}})))
	if !strings.Contains(got, `lanIp: "192.0.2.40"`) {
		t.Errorf("an exposed VM with an assigned LoadBalancer IP must surface it as status.lanIp; got:\n%s", got)
	}
	// spec.ports alone also exposes the VM.
	got = statusDoc(render(t, tmpl, observedLB(vmCtxFW("ubuntu-24.04", map[string]any{"ports": []any{map[string]any{"port": 443}}}),
		[]any{map[string]any{"ip": "192.0.2.41"}})))
	if !strings.Contains(got, `lanIp: "192.0.2.41"`) {
		t.Errorf("spec.ports implies expose, so its LAN IP must surface; got:\n%s", got)
	}
	// Exposed but not yet assigned (no Service observed, or an empty ingress list): empty.
	for name, ctx := range map[string]map[string]any{
		"no observed Service": vmCtxFW("ubuntu-24.04", map[string]any{"expose": true}),
		"empty ingress":       observedLB(vmCtxFW("ubuntu-24.04", map[string]any{"expose": true}), []any{}),
	} {
		if got := statusDoc(render(t, tmpl, ctx)); !strings.Contains(got, `lanIp: ""`) {
			t.Errorf("%s: an unassigned LAN IP must render empty; got:\n%s", name, got)
		}
	}
	// Not exposed: empty — even if a previously observed Service is still in the observed set.
	got = statusDoc(render(t, tmpl, observedLB(vmCtx("ubuntu-24.04", ""), []any{map[string]any{"ip": "192.0.2.42"}})))
	if !strings.Contains(got, `lanIp: ""`) || strings.Contains(got, "192.0.2.42") {
		t.Errorf("a VM that is not exposed must report no LAN IP; got:\n%s", got)
	}
}
