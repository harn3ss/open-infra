// Run: npm test (node --experimental-strip-types --test). nav-visibility.ts has no runtime imports; the
// nav table (nav-items.ts, which imports icons) is checked as source text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inheritGates, navGateOpen } from "./nav-visibility.ts";

test("an ungated entry is always shown", () => {
  assert.equal(navGateOpen({}, {}), true);
  assert.equal(navGateOpen({}, {}, { operator: false }), true);
});

test("a flag-gated entry needs its flag", () => {
  assert.equal(navGateOpen({ flag: "chaosUiEnabled" }, {}), false);
  assert.equal(navGateOpen({ flag: "chaosUiEnabled" }, { chaosUiEnabled: false }), false);
  assert.equal(navGateOpen({ flag: "chaosUiEnabled" }, { chaosUiEnabled: true }), true);
});

test("an operator entry needs the session's operator capability, and is hidden without one", () => {
  const gate = { requires: "operator" as const };
  assert.equal(navGateOpen(gate, {}), false); // no capabilities passed: hidden
  assert.equal(navGateOpen(gate, {}, {}), false); // a session that reports none (signed out, an older server)
  assert.equal(navGateOpen(gate, {}, { operator: false }), false);
  assert.equal(navGateOpen(gate, {}, { operator: true }), true);
});

test("both gates must open", () => {
  const gate = { flag: "chaosUiEnabled" as const, requires: "operator" as const };
  assert.equal(navGateOpen(gate, { chaosUiEnabled: true }, { operator: false }), false);
  assert.equal(navGateOpen(gate, { chaosUiEnabled: false }, { operator: true }), false);
  assert.equal(navGateOpen(gate, { chaosUiEnabled: true }, { operator: true }), true);
});

test("a sub-nav entry carries its service's gates, its own winning", () => {
  assert.deepEqual(inheritGates({ to: "/a" }, { requires: "operator" }), { to: "/a", requires: "operator" });
  assert.deepEqual(inheritGates({ to: "/a" }, { flag: "chaosUiEnabled" }), { to: "/a", flag: "chaosUiEnabled" });
  assert.deepEqual(inheritGates({ to: "/a" }, {}), { to: "/a" });
});

test("every Platform operations view requires the operator", () => {
  const src = readFileSync(new URL("../components/layout/nav-items.ts", import.meta.url), "utf8");
  const rows = src.split("\n").filter((l) => /category:\s*"Platform operations"/.test(l));
  assert.ok(rows.length >= 3, "the Platform operations services have moved or changed shape");
  for (const row of rows) {
    assert.match(row, /requires:\s*"operator"/, `not gated on the operator: ${row.trim()}`);
  }
  for (const to of ["/workloads", "/nodes", "/network"]) {
    assert.ok(rows.some((r) => r.includes(`to: "${to}"`)), `${to} is not a Platform operations view`);
  }
});

test("every navigation surface passes the session's capabilities", () => {
  const files = [
    "../components/layout/sidebar.tsx",
    "../components/layout/command-palette.tsx",
    "../features/dashboard/services-launcher-widget.tsx",
    "../features/dashboard/use-recently-visited.ts",
  ];
  for (const f of files) {
    const src = readFileSync(new URL(f, import.meta.url), "utf8");
    const calls = src.match(/\b(?:navItemVisible|serviceVisible)\([^()]*(?:\([^()]*\)[^()]*)*\)/g) ?? [];
    assert.ok(calls.length > 0, `${f} no longer filters navigation entries`);
    for (const c of calls) {
      assert.match(c, /,\s*caps\s*\)$/, `${f}: ${c} does not pass the capabilities`);
    }
  }
});
