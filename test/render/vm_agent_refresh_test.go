package render

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #347 item 4 (existing guests): write_files runs once per instance, so a guest created before an agent
// change kept the old agent - one that sent its token over plain HTTP - and the root CA it was created
// with. A per-boot bootcmd refreshes the agent's own files from the VM's current spec (the NoCloud disk
// KubeVirt rebuilds from the cloud-init Secret at every start). This runs the rendered bootcmd program
// against the rendered user-data, as a guest would at boot.

// vmUserData is the rendered #cloud-config (the <vm>-cloudinit Secret's userdata block).
func vmUserData(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "userdata: |" {
			continue
		}
		key := len(ln) - len(strings.TrimLeft(ln, " "))
		var body []string
		for _, b := range lines[i+1:] {
			if strings.TrimSpace(b) == "" {
				body = append(body, "")
				continue
			}
			if len(b)-len(strings.TrimLeft(b, " ")) <= key {
				break
			}
			body = append(body, b[key+2:])
		}
		return strings.TrimRight(strings.Join(body, "\n"), "\n") + "\n"
	}
	t.Fatalf("no userdata block in the rendered output")
	return ""
}

// vmRefreshProgram is the Python program the refresh bootcmd runs (the block after its argv[0] name).
func vmRefreshProgram(t *testing.T, userData string) string {
	t.Helper()
	lines := strings.Split(userData, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "- openinfra-agent-refresh" || i+1 >= len(lines) || strings.TrimSpace(lines[i+1]) != "- |" {
			continue
		}
		key := len(lines[i+1]) - len(strings.TrimLeft(lines[i+1], " "))
		var body []string
		for _, b := range lines[i+2:] {
			if strings.TrimSpace(b) == "" {
				body = append(body, "")
				continue
			}
			if len(b)-len(strings.TrimLeft(b, " ")) <= key {
				break
			}
			body = append(body, b[key+2:])
		}
		return strings.Join(body, "\n")
	}
	t.Fatalf("no openinfra-agent-refresh bootcmd in the rendered user-data:\n%s", grepCtx(userData, "bootcmd"))
	return ""
}

func needPyYAML(t *testing.T) {
	t.Helper()
	if err := exec.Command("python3", "-c", "import yaml").Run(); err != nil {
		t.Skip("python3 with PyYAML (cloud-init's own dependency) is needed to run the refresh program")
	}
}

func runRefresh(t *testing.T, prog, src, root string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-c", prog)
	cmd.Env = append(os.Environ(), "OPENINFRA_REFRESH_SRC="+src, "OPENINFRA_REFRESH_ROOT="+root)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("the refresh program must never fail the boot: %v\n%s", err, buf.String())
	}
	return buf.String()
}

func TestVM_AgentFilesRefreshEveryBoot(t *testing.T) {
	needPyYAML(t)
	tmpl := extractInlineTemplate(t, vmComposition)
	out := render(t, tmpl, withPlatformCA(vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"})))
	ud := vmUserData(t, out)
	if n := strings.Count(ud, "\nbootcmd:\n"); n != 1 {
		t.Fatalf("one bootcmd key (the identity token copy and the refresh share it), got %d:\n%s", n, grepCtx(ud, "bootcmd"))
	}
	if !strings.Contains(ud, "openinfra-identity/token.tmp") {
		t.Fatalf("the identity token copy must stay in bootcmd")
	}
	prog := vmRefreshProgram(t, ud)

	src, root := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "user-data"), []byte(ud), 0o644); err != nil {
		t.Fatal(err)
	}
	log := runRefresh(t, prog, src, root)
	want := map[string]struct {
		content string
		mode    os.FileMode
	}{
		"/usr/local/lib/openinfra/metadata-agent.py":     {vmWriteFileBlock(ud, "/usr/local/lib/openinfra/metadata-agent.py"), 0o755},
		"/etc/openinfra/metadata-agent.json":             {vmWriteFileScalar(t, ud, "/etc/openinfra/metadata-agent.json"), 0o644},
		"/etc/openinfra/platform-root-ca.pem":            {testRootPEM, 0o644},
		"/etc/systemd/system/openinfra-metadata.service": {vmWriteFileBlock(ud, "/etc/systemd/system/openinfra-metadata.service"), 0o644},
	}
	for path, w := range want {
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Errorf("%s not refreshed: %v\n%s", path, err, log)
			continue
		}
		if string(b) != w.content {
			t.Errorf("%s refreshed with other content than the spec's write_files entry", path)
		}
		if st, _ := os.Stat(filepath.Join(root, path)); st.Mode().Perm() != w.mode {
			t.Errorf("%s mode %o, want %o", path, st.Mode().Perm(), w.mode)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc/environment")); err == nil {
		t.Errorf("/etc/environment is an append entry: a per-boot refresh would grow it every boot")
	}
	if !strings.Contains(log, "refreshed from this VM's current spec") {
		t.Errorf("the refresh must say what it rewrote:\n%s", log)
	}
	if again := runRefresh(t, prog, src, root); strings.Contains(again, "refreshed") {
		t.Errorf("an unchanged spec rewrites nothing:\n%s", again)
	}
	// A guest created before an agent change: its agent and CA are rewritten from the spec as it is now.
	if err := os.WriteFile(filepath.Join(root, "usr/local/lib/openinfra/metadata-agent.py"), []byte("# an older agent\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/openinfra/platform-root-ca.pem"), []byte("an older root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log = runRefresh(t, prog, src, root)
	if !strings.Contains(log, "/usr/local/lib/openinfra/metadata-agent.py") || !strings.Contains(log, "/etc/openinfra/platform-root-ca.pem") ||
		strings.Contains(log, "metadata-agent.json") {
		t.Errorf("exactly the changed files are refreshed:\n%s", log)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "usr/local/lib/openinfra/metadata-agent.py")); string(b) != want["/usr/local/lib/openinfra/metadata-agent.py"].content {
		t.Errorf("the older agent must be replaced by the spec's")
	}
	// No readable spec: nothing is touched and the boot goes on.
	empty := t.TempDir()
	if log := runRefresh(t, prog, empty, t.TempDir()); !strings.Contains(log, "stay as they are") {
		t.Errorf("an unreadable spec must leave the files alone, and say so:\n%s", log)
	}

	// Every Linux guest refreshes its agent, with or without an instance role.
	plain := vmUserData(t, render(t, tmpl, vmCtx("debian-12", "")))
	if strings.Count(plain, "\nbootcmd:\n") != 1 || vmRefreshProgram(t, plain) != prog {
		t.Errorf("a VM without an instance role must run the same refresh at boot:\n%s", grepCtx(plain, "bootcmd"))
	}
	// The identity token is copied with or without a role (the signed identity document needs it).
	if !strings.Contains(plain, "openinfra-identity/token.tmp") {
		t.Errorf("a VM without an instance role still copies its identity token (for its signed identity document)")
	}
	// No metadata service, no token.
	off := vmUserData(t, render(t, tmpl, vmCtxFW("debian-12", map[string]any{"metadataOptions": map[string]any{"httpEndpoint": "disabled"}})))
	if strings.Count(off, "\nbootcmd:\n") != 1 || vmRefreshProgram(t, off) != prog || strings.Contains(off, "openinfra-identity/token.tmp") {
		t.Errorf("httpEndpoint: disabled runs the refresh but copies no identity token:\n%s", grepCtx(off, "bootcmd"))
	}
}
