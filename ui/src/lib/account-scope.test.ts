// Run: npm test (node --experimental-strip-types --test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readdirSync } from "node:fs";
import {
  createNamespace,
  isAccountScoped,
  isNamespaceColumn,
  placementChoices,
  withAccountScope,
  withoutNamespaceColumns,
} from "./account-scope.ts";

test("a list path asks for the account", () => {
  assert.equal(withAccountScope("/apis/openinfra.dev/v1/buckets"), "/apis/openinfra.dev/v1/buckets?scope=account");
  assert.equal(
    withAccountScope("/apis/openinfra.dev/v1/functions?labelSelector=a%3Db"),
    "/apis/openinfra.dev/v1/functions?labelSelector=a%3Db&scope=account",
  );
  assert.equal(withAccountScope(withAccountScope("/api/v1/pods")), "/api/v1/pods?scope=account");
  assert.equal(isAccountScoped(withAccountScope("/api/v1/pods")), true);
  assert.equal(isAccountScoped("/api/v1/pods"), false);
});

test("the namespace column is recognized by id, accessor or header", () => {
  assert.equal(isNamespaceColumn({ id: "namespace" }), true);
  assert.equal(isNamespaceColumn({ accessorKey: "metadata.namespace" }), true);
  assert.equal(isNamespaceColumn({ header: "Namespace" }), true);
  assert.equal(isNamespaceColumn({ header: "Namespaces" }), true);
  assert.equal(isNamespaceColumn({ id: "name", header: "Name" }), false);
  assert.equal(isNamespaceColumn({ header: "Collector namespace" }), false);
  const cols = [{ id: "name" }, { id: "namespace" }, { header: "Status" }];
  assert.deepEqual(withoutNamespaceColumns(cols), [{ id: "name" }, { header: "Status" }]);
});

test("a new resource lands in the account: the one asked if it is the account's, else its home", () => {
  const acct = { homeNamespace: "team-a", namespaces: ["team-a", "team-a-data"] };
  assert.equal(createNamespace(acct, undefined), "team-a");
  assert.equal(createNamespace(acct, "team-a-data"), "team-a-data");
  assert.equal(createNamespace(acct, "kube-system"), "team-a"); // never outside the account
  assert.equal(createNamespace({}, "team-x"), "team-x"); // an older server: what was asked
  assert.equal(createNamespace(null, undefined), "default");
});

test("only the operator is offered a placement, and only among the account's own namespaces", () => {
  const names = ["team-a", "team-a-data"];
  assert.deepEqual(placementChoices({ namespaces: names, capabilities: { operator: true } }), names);
  assert.deepEqual(placementChoices({ namespaces: names }), []); // an AWS user: no namespace field
  assert.deepEqual(placementChoices({ namespaces: names, capabilities: { operator: false } }), []);
  assert.deepEqual(placementChoices({ namespaces: ["team-a"], capabilities: { operator: true } }), []); // nothing to choose
  assert.deepEqual(placementChoices(null), []);
});

test("no create page offers the cluster's namespaces; only the operator's switcher lists them", () => {
  const root = new URL("../", import.meta.url);
  const hits: string[] = [];
  const walk = (dir: URL) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const u = new URL(e.name + (e.isDirectory() ? "/" : ""), dir);
      if (e.isDirectory()) walk(u);
      else if (/\.tsx?$/.test(e.name) && !/\.test\./.test(e.name) && readFileSync(u, "utf8").includes("corePaths.namespaces()"))
        hits.push(u.pathname.slice(root.pathname.length));
    }
  };
  walk(root);
  assert.deepEqual(hits, ["components/layout/namespace-switcher.tsx"]);
});

test("the shared table lists the account and shows no namespace column", () => {
  const src = readFileSync(new URL("../components/common/resource-table-page.tsx", import.meta.url), "utf8");
  assert.match(src, /accountScope:\s*true/, "ResourceTablePage does not list the account");
  assert.match(src, /withoutNamespaceColumns\(/, "ResourceTablePage shows the namespace column");
});

test("the top bar is the account and region context, not a namespace switcher", () => {
  const src = readFileSync(new URL("../components/layout/topbar.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(src, /NamespaceSwitcher/, "the top bar still has the namespace switcher");
  assert.match(src, /RegionContext/, "the top bar has no region context");
});
