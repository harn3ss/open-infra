// Run: npm test (node --experimental-strip-types --test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { deprecatedRuntimes } from "./lambda-runtimes.ts";

test("the runtimes AWS has deprecated on a day, from their deprecation date", () => {
  const before2026Deprecations = ["nodejs16", "nodejs18", "python3.8", "python3.9"];
  assert.deepEqual(deprecatedRuntimes(new Date("2026-04-29T23:59:59Z")), before2026Deprecations);
  assert.deepEqual(deprecatedRuntimes(new Date("2026-11-08T12:00:00Z")), ["nodejs16", "nodejs18", "nodejs20", "python3.10", "python3.8", "python3.9"]);
  assert.deepEqual(deprecatedRuntimes(new Date("2026-11-10T00:00:00Z")), ["dotnet8", "nodejs16", "nodejs18", "nodejs20", "python3.10", "python3.8", "python3.9"]);
  assert.deepEqual(deprecatedRuntimes(new Date("2024-01-01T00:00:00Z")), []);
  // dotnet10 replaces dotnet8: offered until its own deprecation date (#409).
  assert.ok(!deprecatedRuntimes(new Date("2026-11-10T00:00:00Z")).includes("dotnet10"));
  assert.ok(deprecatedRuntimes(new Date("2028-11-14T00:00:00Z")).includes("dotnet10"));
});
