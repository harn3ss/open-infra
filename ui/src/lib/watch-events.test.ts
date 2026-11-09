import { test } from "node:test";
import assert from "node:assert/strict";
import { applyWatchEvents, newestFirst } from "./watch-events.ts";

type Obj = { metadata: { name: string; namespace?: string; uid?: string; resourceVersion?: string }; v?: number };
const list = (items: Obj[], rv = "1") => ({ apiVersion: "v1", kind: "List", metadata: { resourceVersion: rv }, items });
const o = (uid: string, v: number, rv: string): Obj => ({ metadata: { name: uid, uid, resourceVersion: rv }, v });

test("a batch upserts by uid, removes, and advances the resourceVersion, in order", () => {
  const prev = list([o("a", 1, "1"), o("b", 1, "1"), o("c", 1, "1")]);
  const next = applyWatchEvents(prev as never, [
    { type: "MODIFIED", object: o("b", 2, "5") },
    { type: "ADDED", object: o("d", 1, "6") },
    { type: "DELETED", object: o("a", 1, "7") },
    { type: "MODIFIED", object: o("d", 2, "8") },
  ] as never);
  assert.deepEqual(next.items.map((x: Obj) => `${x.metadata.uid}${x.v}`), ["b2", "c1", "d2"]);
  assert.equal(next.metadata.resourceVersion, "8");
  assert.deepEqual(prev.items.map((x) => x.metadata.uid), ["a", "b", "c"], "the cached list is not mutated");
});

test("a deleted object added again in the same batch is back, once", () => {
  const next = applyWatchEvents(list([o("a", 1, "1")]) as never, [
    { type: "DELETED", object: o("a", 1, "2") },
    { type: "ADDED", object: o("a", 3, "3") },
  ] as never);
  assert.deepEqual(next.items.map((x: Obj) => `${x.metadata.uid}${x.v}`), ["a3"]);
});

test("a bookmark advances the resourceVersion and adds no row, keeping the same items", () => {
  const prev = list([o("a", 1, "1")]);
  const next = applyWatchEvents(prev as never, [{ type: "BOOKMARK", object: { metadata: { resourceVersion: "9" } } }] as never);
  assert.equal(next.metadata.resourceVersion, "9");
  assert.equal(next.items, prev.items);
});

test("newestFirst keeps the newest n, newest first, with a missing time last", () => {
  const ev = (n: string, t?: string) => ({ n, t });
  const out = newestFirst([ev("old", "2026-01-01T00:00:00Z"), ev("none"), ev("new", "2026-03-01T00:00:00Z"), ev("mid", "2026-02-01T00:00:00Z")], 3, (e) => e.t);
  assert.deepEqual(out.map((e) => e.n), ["new", "mid", "old"]);
});
