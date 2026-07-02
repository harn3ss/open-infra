# CI & the correctness gate

open-infra's tests are an **enforced gate**, not a suggestion: no container image is
built, signed, or pushed unless the test suite passes on that exact ref.

## The suite (Stage A)

[`.github/workflows/test.yml`](../.github/workflows/test.yml) runs `go vet` +
`go test -race` across three modules, on every push to `main`, every PR, and whenever
it is called as a gate (below):

- **`apply-sink`** — pure-function unit tests for the CDC engine: driver dialects,
  cross-engine type mapping, and the temporal-coercion buckets behind the cross-engine
  `DATE` fix.
- **`console-api`** — the BFF handlers (crd, proxy).
- **`test/render`** — stdlib composition-render assertions (e.g. "Start" always writes
  `cnpg.io/hibernation: "off"`; HA renders `instances: 2` + anti-affinity).

Two heavier suites are **opt-in** (build-tagged, need a live DB/flow, kept out of the
fast lane):

- **MySQL HLC monotonicity** — `go test -tags integration` (needs `MYSQL_TEST_DSN`).
- **Multi-master convergence** — `go test -tags convergence` (see
  [convergence-harness.md](convergence-harness.md)).

Run it all locally:

```bash
(cd apply-sink   && go test -race ./...)
(cd console-api  && go test -race ./...)
(cd test/render  && go test -race ./...)
```

## The gate

`test.yml` is a **reusable workflow** (`on: workflow_call`). The three workflows that
publish images each run it as a `test` job that the build/package job `needs:`:

| Workflow | Trigger | Gated job |
|----------|---------|-----------|
| [`release.yml`](../.github/workflows/release.yml) | `v*` tag / dispatch | `package` (version-tag + cosign-sign console & apply-sink) |
| [`build-console.yml`](../.github/workflows/build-console.yml) | push to `main` (ui/console-api) | `build` (push `latest`) |
| [`build-apply-sink.yml`](../.github/workflows/build-apply-sink.yml) | push to `main` (apply-sink) | `build` (push `latest`) |

Because the gate is *inside* the publishing workflows, it holds **regardless of where a
tag points** — a tag can target any commit (they can even be force-moved), so branch
protection on `main` alone would not guarantee the tagged commit is green. The
`needs: test` dependency does.

> Concurrency note: the reusable test's group is keyed on `github.workflow` as well as
> `github.ref` (`test-${{ github.workflow }}-${{ github.ref }}`) — otherwise the
> release + both build workflows would share one group and `cancel-in-progress` would
> cancel sibling gates.

## Verifying the gate blocks (a real red rollout)

The gate was verified end-to-end with a deliberately failing build, not just by
reading the YAML. On a throwaway `ci/red-build-demo` branch, a test was made to fail
(`t.Fatal` in `apply-sink`), then `build-apply-sink` was dispatched against it:

- Run: <https://github.com/harn3ss/open-infra/actions/runs/28594973144> (2026-07-02)
- Result:
  - `test / apply-sink` → **failure** (`go test -race`)
  - `test / console-api` → success
  - `test / test/render` → success
  - `build` → **skipped**

No image was built, signed, or pushed. The branch was then deleted (the run history
persists as the record). This is the difference between "tests exist" and "a bad tag
cannot ship."
