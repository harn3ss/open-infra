package render

import (
	"strings"
	"testing"
)

// launchedOn sets a VM composite's creation time (when it was launched).
func launchedOn(ctx map[string]any, ts string) map[string]any {
	md := ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["metadata"].(map[string]any)
	md["creationTimestamp"] = ts
	return ctx
}

// A Windows instance runs the launch agent, as an EC2 Windows AMI runs EC2Launch v2: Windows Setup's specialize
// pass installs it from the launch CD (its Secret carries the agent, its configuration, the user data and the
// platform's CAs), and the identity token comes on a CD of its own. An instance launched before the agent
// existed, or booted from a migrated disk, gets none of it.
func TestVM_WindowsLaunchAgent(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, withPlatformCA(vmCtxFW("windows-server-2022", map[string]any{
		"instanceRole": "build-instance", "userData": "<powershell>\nWrite-Output hi\n</powershell>"})))
	for _, want := range []string{
		"name: myvm-launch", "composition-resource-name: launch", "openinfra-launch.ps1: |", "launch-config.json:",
		`\"role\":\"build-instance\"`, `\"credentialsUrl\":\"https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567/v1/vm-credentials\"`,
		`user-data: "\u003cpowershell\u003e\nWrite-Output hi\n\u003c/powershell\u003e"`, "platform-root-ca.pem:",
		`<settings pass="specialize">`, `openinfra-launch.ps1 -Install`,
		"secretName: myvm-launch", "serviceAccountName: vm-myvm",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a Windows instance's launch wiring lacks %s", want)
		}
	}
	if strings.Count(out, "bus: sata") < 3 {
		t.Errorf("the sysprep, identity and launch CDs are SATA CD-ROMs:\n%s", grepCtx(out, "cdrom"))
	}
	if strings.Contains(out, "SATOKEN") || strings.Contains(out, "#!/bin/sh") || strings.Contains(out, "cloudInitNoCloud") {
		t.Errorf("a Windows instance gets none of the Linux guest's wiring")
	}
	for name, ctx := range map[string]map[string]any{
		"launched before the agent": launchedOn(vmCtx("windows-server-2022", ""), "2026-01-01T00:00:00Z"),
		"booted from a migrated disk": vmCtxFW("windows-server-2022", map[string]any{"existingRootClaim": "migrated-root",
			"firmware": map[string]any{"mode": "bios"}}),
	} {
		o := render(t, tmpl, ctx)
		if strings.Contains(o, "myvm-launch") || strings.Contains(o, `pass="specialize"`) || strings.Contains(o, "name: identity") {
			t.Errorf("a Windows instance %s gets no launch agent:\n%s", name, grepCtx(o, "launch"))
		}
	}
}

// The launch Secret carries files/windows-launch-agent.ps1 exactly (platform/abstraction/files/embed.py
// writes it in); the embedded copy never drifts from the file the tests run.
func TestVM_WindowsLaunchAgent_EmbedsTheAgent(t *testing.T) {
	agent := mustRead(t, "../../platform/abstraction/files/windows-launch-agent.ps1")
	comp := mustRead(t, "../../platform/abstraction/vm-composition.yaml")
	const begin, end = "# BEGIN windows-launch-agent.ps1\n", "# END windows-launch-agent.ps1"
	i, j := strings.Index(comp, begin), strings.Index(comp, end)
	if i < 0 || j < i {
		t.Fatal("the composition has no windows-launch-agent.ps1 block")
	}
	pad := comp[strings.LastIndex(comp[:i], "\n")+1 : i]
	var got strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(comp[i+len(begin):j], pad), "\n") {
		got.WriteString(strings.TrimPrefix(line, pad) + "\n")
	}
	want := strings.TrimRight(agent, "\n") + "\n"
	if strings.TrimRight(got.String(), "\n")+"\n" != want {
		t.Fatal("the composition's windows-launch-agent.ps1 is stale: run python3 platform/abstraction/files/embed.py")
	}
	if strings.Contains(agent, "{{") || strings.Contains(agent, "}}") {
		t.Fatal("windows-launch-agent.ps1 must not contain {{ or }} (the composition is a Go template)")
	}
}

// A Windows instance running the launch agent takes a root larger than 100Gi (the agent extends C: to it);
// a smaller request, or an instance launched before the agent existed, gets the fixed 100Gi.
func TestVM_WindowsRootDiskSize(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	size := func(ctx map[string]any) string {
		out := render(t, tmpl, ctx)
		for _, want := range []string{"100Gi", "200Gi"} {
			if strings.Contains(out, "storage: "+want) || strings.Contains(out, `storage: "`+want+`"`) {
				return want
			}
		}
		t.Logf("%s", grepCtx(out, "Gi"))
		return ""
	}
	for want, ctx := range map[string]map[string]any{
		"200Gi": vmCtxFW("windows-server-2022", map[string]any{"diskSize": "200Gi"}),
		"100Gi": vmCtxFW("windows-server-2022", map[string]any{"diskSize": "20Gi"}),
	} {
		if got := size(ctx); got != want {
			t.Errorf("want a %s root, got %q", want, got)
		}
	}
	if got := size(launchedOn(vmCtxFW("windows-server-2022", map[string]any{"diskSize": "200Gi"}), "2026-01-01T00:00:00Z")); got != "100Gi" {
		t.Errorf("an earlier Windows instance keeps its 100Gi root, got %q", got)
	}
}
