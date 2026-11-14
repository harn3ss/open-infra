package serialconsole

import (
	"context"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// Access starts off, as AWS's does; it is turned on and off per account, and one account's setting is
// not another's.
func TestAccessPerAccount(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	const a, b = "111122223333", "444455556666"
	if on, err := Enabled(ctx, cs, "shim", a); err != nil || on {
		t.Fatalf("a new account: %v %v, want off", on, err)
	}
	if err := SetEnabled(ctx, cs, "shim", a, false); err != nil {
		t.Fatalf("turning off what is off: %v", err)
	}
	if err := SetEnabled(ctx, cs, "shim", a, true); err != nil {
		t.Fatal(err)
	}
	if on, _ := Enabled(ctx, cs, "shim", a); !on {
		t.Error("enabled account reads off")
	}
	if on, _ := Enabled(ctx, cs, "shim", b); on {
		t.Error("another account reads on")
	}
	if err := SetEnabled(ctx, cs, "shim", b, true); err != nil {
		t.Fatal(err)
	}
	if err := SetEnabled(ctx, cs, "shim", a, false); err != nil {
		t.Fatal(err)
	}
	if on, _ := Enabled(ctx, cs, "shim", a); on {
		t.Error("disabled account reads on")
	}
	if on, _ := Enabled(ctx, cs, "shim", b); !on {
		t.Error("disabling one account turned off another")
	}
	if err := SetEnabled(ctx, cs, "shim", "not-an-account", true); err == nil {
		t.Error("a malformed account id was accepted")
	}
}
