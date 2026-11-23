// Run: npm test (node --experimental-strip-types --test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { publicPorts, reachability } from "./vm-reachability.ts";
import type { SecurityGroup } from "@/types/k8s";

const sg = (name: string, ingress?: NonNullable<SecurityGroup["spec"]>["ingress"]): SecurityGroup =>
  ({ apiVersion: "openinfra.dev/v1", kind: "SecurityGroup", metadata: { name }, spec: ingress ? { ingress } : {} }) as SecurityGroup;

test("viewing an instance writes nothing: the Network tab only reads", () => {
  // The tab once rewrote the instance's ports from its security groups whenever it was opened, giving an
  // instance a public address because someone looked at it. It must hold no way to write.
  const src = readFileSync(new URL("../features/vms/vm-network.tsx", import.meta.url), "utf8");
  for (const w of ["useMutation", "k8sReplace", "k8sPatch", "k8sCreate", "k8sDelete", "k8sApply", "fetch(", "mutate"]) {
    assert.ok(!src.includes(w), `vm-network.tsx must not use ${w}`);
  }
});

test("an instance that is not exposed has no public address, whatever its security groups allow", () => {
  assert.deepEqual(publicPorts({ securityGroups: ["web"] }, 22), []);
  assert.deepEqual(publicPorts(undefined, 22), []);
});

test("an exposed instance's public address carries its access port and its own ports, each once", () => {
  assert.deepEqual(publicPorts({ expose: true }, 22), [{ port: 22, protocol: "TCP" }]);
  assert.deepEqual(
    publicPorts({ ports: [{ port: 9000, protocol: "UDP" }, { port: 3389 }, { port: 3389, protocol: "TCP" }] }, 3389),
    [{ port: 3389, protocol: "TCP" }, { port: 9000, protocol: "UDP" }],
  );
});

test("only an address-range source reaches the public address: a self- or group-sourced rule does not", () => {
  const groups = new Map([
    ["app", sg("app", [
      { protocol: "UDP", ports: [9000], from: [{ securityGroup: "app" }] },
      { protocol: "UDP", ports: [9000], from: [{ cidr: "192.0.2.10/32" }, { namespace: "other" }] },
      { protocol: "TCP", ports: [3389], from: [{ securityGroup: "admins" }] },
    ])],
  ]);
  const ports = publicPorts({ ports: [{ port: 9000, protocol: "UDP" }] }, 3389);
  const [rdp, app] = reachability(ports, 3389, ["app"], groups);
  assert.equal(rdp.access, true);
  assert.equal(rdp.open, false);
  assert.deepEqual(rdp.sources, []);
  assert.deepEqual(app.sources, [{ group: "app", cidr: "192.0.2.10/32", description: undefined }]);
});

test("a rule's protocol and ports must match: ALL and an empty port list cover the port", () => {
  const groups = new Map([
    ["a", sg("a", [{ protocol: "TCP", ports: [80], from: [{ cidr: "0.0.0.0/0" }] }])],
    ["b", sg("b", [{ protocol: "ALL", from: [{ cidr: "198.51.100.0/24" }] }])],
    ["c", sg("c", [{ protocol: "UDP", from: [{ cidr: "203.0.113.0/24" }] }])],
  ]);
  const [http, dns] = reachability([{ port: 80, protocol: "TCP" }, { port: 53, protocol: "UDP" }], 22, ["a", "b", "c"], groups);
  assert.deepEqual(http.sources.map((s) => s.cidr), ["0.0.0.0/0", "198.51.100.0/24"]);
  assert.deepEqual(dns.sources.map((s) => s.cidr), ["198.51.100.0/24", "203.0.113.0/24"]);
});

test("with no security group, or one that restricts no inbound, every source may use the ports", () => {
  const ports = publicPorts({ expose: true }, 22);
  assert.equal(reachability(ports, 22, [], new Map())[0].open, true);
  assert.equal(reachability(ports, 22, ["open"], new Map([["open", sg("open")]]))[0].open, true);
  assert.equal(reachability(ports, 22, ["shut"], new Map([["shut", sg("shut", [])]]))[0].open, false);
});
