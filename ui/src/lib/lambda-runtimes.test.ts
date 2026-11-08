// Run: npm test (node --experimental-strip-types --test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { deprecatedRuntimes } from "./lambda-runtimes.ts";

test("the runtimes AWS has deprecated on a day, from their deprecation date", () => {
  assert.deepEqual(deprecatedRuntimes(new Date("2026-11-08T12:00:00Z")), ["nodejs20"]);
  assert.deepEqual(deprecatedRuntimes(new Date("2026-11-10T00:00:00Z")), ["dotnet8", "nodejs20"]);
  assert.deepEqual(deprecatedRuntimes(new Date("2026-04-29T23:59:59Z")), []);
});
