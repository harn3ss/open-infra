// Run: npm test (node --experimental-strip-types --test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { EC2_INSTANCE_TYPES, findInstanceType, matchInstanceType } from "./instance-types.ts";

test("g4dn.xlarge sets the instance's GPU with its vCPUs and memory", () => {
  assert.deepEqual(findInstanceType(EC2_INSTANCE_TYPES, "g4dn.xlarge")?.values, { cpu: 4, memory: "16Gi", gpus: 1 });
});

test("a GPU instance is its g4dn type, and an instance without GPUs never is", () => {
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi", gpus: 1 })?.id, "g4dn.xlarge");
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi" })?.id, "t3.xlarge");
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi", gpus: 0 })?.id, "t3.xlarge");
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 2, memory: "2Gi", gpus: 1 }), undefined);
});

test("a g5 instance is its g5 type: its GPU family tells it from a g4dn of the same shape", () => {
  assert.deepEqual(findInstanceType(EC2_INSTANCE_TYPES, "g5.xlarge")?.values, { cpu: 4, memory: "16Gi", gpus: 1, gpuFamily: "g5" });
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi", gpus: 1, gpuFamily: "g5" })?.id, "g5.xlarge");
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi", gpus: 1, gpuFamily: "g4dn" })?.id, "g4dn.xlarge");
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi", gpus: 1 })?.id, "g4dn.xlarge");
  assert.equal(matchInstanceType(EC2_INSTANCE_TYPES, { cpu: 4, memory: "16Gi", gpuFamily: "g5" })?.id, "t3.xlarge");
});
