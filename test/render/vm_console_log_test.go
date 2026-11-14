package render

import (
	"strings"
	"testing"
)

// Every VM keeps its serial console output (KubeVirt's guest-console-log container), which EC2's "Get
// system log" (GetConsoleOutput) reads: Linux and Windows alike.
func TestVirtualMachine_LogsSerialConsole(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	for _, os := range []string{"ubuntu-24.04", "windows-server-2022"} {
		out := render(t, tmpl, vmCtx(os, ""))
		if !strings.Contains(out, "logSerialConsole: true") {
			t.Errorf("%s: the VM must log its serial console", os)
		}
	}
}
