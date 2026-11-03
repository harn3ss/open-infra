package cfn

import (
	"context"
	"testing"
)

// #348: a REST v1 API provisioned just before the process dies is torn down by the recovery. The engine
// chooses the API's id and records it (write-ahead) before provisioning, so the record names the API even
// when the process died before it could record the provisioning's result.
func TestRecover_RestV1ProvisionedBeforeTheProcessDiedIsTornDown(t *testing.T) {
	f := &fakeApplier{}
	chosen := ""
	opts := deployOpts()
	opts.ProvisionRestAPI = func(_ context.Context, spec map[string]any) (string, error) {
		chosen, _ = spec["apiId"].(string)
		// The API now exists; the process dies before anything more is written.
		f.dieAfter, f.mutations = 1, 1
		return chosen, nil
	}
	if _, err := Deploy(context.Background(), []byte(restV1Stack), opts, f); err == nil {
		t.Fatal("test premise: the create dies mid-flight")
	}
	if len(chosen) != 10 {
		t.Fatalf("the plan handed to the hook carries no engine-chosen API id: %q", chosen)
	}
	f.dieAfter, f.mutations = 0, 0 // a new front door
	var deprovisioned []string
	opts.DeprovisionRestAPI = func(_ context.Context, id string) error {
		deprovisioned = append(deprovisioned, id)
		return nil
	}
	rec, err := RecoverInterrupted(context.Background(), opts, f, interruptedReason)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Status != "ROLLBACK_COMPLETE" {
		t.Errorf("status = %s, want ROLLBACK_COMPLETE", rec.Status)
	}
	if len(deprovisioned) != 1 || deprovisioned[0] != chosen {
		t.Fatalf("deprovisioned %v, want the API provisioned before the process died (%s)", deprovisioned, chosen)
	}
}
