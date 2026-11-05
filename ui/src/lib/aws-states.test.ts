// Run: npm test (node --experimental-strip-types --test). No bundler needed: the module's only imports are
// type-only, which type stripping erases.
import { test } from "node:test";
import assert from "node:assert/strict";
import { awsState, lifecycleOf } from "./aws-states.ts";

type Cond = { type: string; status: "True" | "False" | "Unknown"; reason?: string; message?: string };
const obj = (conditions: Cond[] | undefined, deleting = false) => ({
  metadata: deleting ? { deletionTimestamp: "2026-11-04T00:00:00Z" } : {},
  status: conditions ? { conditions } : undefined,
});

test("a ready resource is Available, or its service's own word", () => {
  const ready = obj([{ type: "Ready", status: "True" }, { type: "Synced", status: "True" }]);
  assert.equal(awsState(ready).label, "Available");
  assert.equal(awsState(ready, "function").label, "Active");
  assert.equal(awsState(ready, "statemachine").label, "Active");
  assert.equal(awsState(ready, "featuregroup").label, "Created");
  assert.equal(awsState(ready, "scheduledjob").label, "Enabled");
  assert.equal(awsState(ready).tone, "success");
});

test("Kubernetes and Crossplane words never reach the label", () => {
  const cases = [
    obj(undefined),
    obj([]),
    obj([{ type: "Ready", status: "False", reason: "Creating" }]),
    obj([{ type: "Ready", status: "False", reason: "Unavailable", message: "pod crash-looping" }]),
    obj([{ type: "Synced", status: "False", reason: "ReconcileError", message: "cannot compose resources" }]),
    obj([{ type: "Ready", status: "True" }], true),
  ];
  for (const c of cases) {
    const { label } = awsState(c);
    for (const k8s of ["Ready", "Synced", "ReconcileError", "Terminating", "Provisioning", "Unavailable"]) {
      assert.notEqual(label, k8s, `label ${label}`);
    }
  }
});

test("creating is not a failure; a failure keeps its reason as detail", () => {
  assert.equal(lifecycleOf(obj([{ type: "Ready", status: "False", reason: "Creating" }])).lifecycle, "creating");
  assert.equal(awsState(obj([{ type: "Ready", status: "False", reason: "Creating" }]), "function").label, "Pending");
  const failed = awsState(obj([{ type: "Synced", status: "False", reason: "ReconcileError", message: "quota exceeded" }]));
  assert.equal(failed.label, "Failed");
  assert.equal(failed.tone, "destructive");
  assert.equal(failed.detail, "quota exceeded");
  assert.equal(awsState(obj([{ type: "Synced", status: "False" }]), "featuregroup").label, "Create failed");
});

test("deleting, pending and creating", () => {
  assert.equal(awsState(obj([{ type: "Ready", status: "True" }], true)).label, "Deleting");
  assert.equal(awsState(obj([])).label, "Pending");
  assert.equal(awsState(obj([{ type: "Synced", status: "True" }])).label, "Creating");
});
