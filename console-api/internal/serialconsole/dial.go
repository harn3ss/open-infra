package serialconsole

import (
	"io"

	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

// Dial connects to VM ns/name's serial console (KubeVirt's console subresource of its
// VirtualMachineInstance) with cfg's identity: a stream of the guest's serial port, both ways. KubeVirt
// lets one connection in at a time and drops the earlier one, so callers hold the instance's session
// (Acquire) first.
func Dial(cfg *rest.Config, ns, name string) (io.ReadWriteCloser, error) {
	return vmconsole.DialSubresource(cfg, ns, name, "console")
}
