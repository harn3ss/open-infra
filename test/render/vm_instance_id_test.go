package render

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// #347 item 23: the instance id the guest's instance metadata reports (the agent's config) and the
// composite's status.instanceId are one value, i- and the first 17 hex digits of sha256("<XR uid>-instance"),
// so CloudFormation's Ref of the instance and the aws-shim's EC2 and SSM APIs name the instance the guest
// sees. The aws-shim derives the same value for a composite rendered before status.instanceId existed.
func TestVM_StatusInstanceID(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	ctx := vmCtx("ubuntu-24.04", "")
	uid := ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["metadata"].(map[string]any)["uid"].(string)
	sum := sha256.Sum256([]byte(uid + "-instance"))
	want := "i-" + hex.EncodeToString(sum[:])[:17]

	out := render(t, tmpl, ctx)
	i := strings.Index(out, "kind: XVirtualMachine")
	if i < 0 {
		t.Fatalf("the composite status document must always render")
	}
	if !strings.Contains(out[i:], `instanceId: "`+want+`"`) {
		t.Errorf("status.instanceId: want %s; got:\n%s", want, out[i:])
	}
	// The agent's config (JSON, quoted again as the file's content) carries the same id.
	if !strings.Contains(out, `\"instanceId\":\"`+want+`\"`) {
		t.Errorf("the metadata agent's config must report instance id %s", want)
	}
	// Another VM (another UID) has another id.
	ctx2 := vmCtx("ubuntu-24.04", "")
	ctx2["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["metadata"].(map[string]any)["uid"] = "11111111-0000-0000-0000-0000000000vm"
	if strings.Contains(render(t, tmpl, ctx2), want) {
		t.Errorf("a VM with another UID must get another instance id")
	}
}
