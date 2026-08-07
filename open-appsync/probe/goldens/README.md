# open-appsync runtime goldens

This directory graduated the **runtime** from *documented-faithful* to *behavior-faithful*. The cases
here were **captured from real AWS AppSync** (via `evaluate-mapping-template`) and the CI diff is green
against them — so open-appsync's `$util`/VTL output is checked against what AppSync *does*, not just
what it documents. The capture surfaced two real divergences (AppSync emits `N` as a JSON number and
`NULL` as JSON `null`), which are now fixed in the engine.

Re-run `capture.sh` (below) to refresh against AWS whenever the corpus grows or to re-verify.

## The format

One JSON file per case:

```json
{
  "source": "documented",
  "description": "GetItem by id",
  "template": "getitem.request.vtl",
  "autoId": "11111111-2222-4333-8444-555555555555",
  "now": "2026-08-06T00:00:00Z",
  "context": { "args": { "id": "123" } },
  "expected": { "version": "2018-05-29", "operation": "GetItem", "key": { "id": { "S": "123" } } }
}
```

- `source` — `"documented"` (authored from AWS's published semantics — the state today) or
  `"aws-capture"` (the real request object captured from a live AppSync API — the graduation state).
- `template` — a file in `../corpus/`, rendered as-is.
- `autoId` / `now` — the values injected into the engine's `$util.autoId()` / `$util.time.*` providers
  so the render is deterministic. **This is why those providers are injectable.** For a capture, record
  the exact values AWS produced (the uuid `$util.autoId()` emitted, the timestamp), so *our* render and
  *AWS's* captured `expected` are byte-for-byte comparable rather than both random.
- `context` — the `$ctx` the template runs against.
- `expected` — the request object. JSON-semantic equality is asserted (structure + typed values, not
  Velocity whitespace).

`goldens_test.go` renders every case and diffs it; it is green today against the `documented` cases,
so the harness and CI wiring are proven now. `TestGoldens_GraduationStatus` reports how many cases are
still `documented` — that count is the runtime gate.

## Capturing (maintainer, once — needs a real AppSync account, never a user's)

This is the external step that graduates the runtime — now **one command**:

```
AWS_PROFILE=you AWS_REGION=us-east-1 ./capture.sh
```

`capture.sh` renders every golden's corpus template through real AppSync via the server-side
`aws appsync evaluate-mapping-template` API (no API/schema to deploy), rewrites each golden as
`source: aws-capture` with AWS's exact output as `expected`, and pins the generated `autoId` so the CI
diff is byte-exact. Then re-run `go test ./probe/`: every case now diffs against real AWS, and every
divergence is either fixed in the engine or written down as a known gap. (Doing it by hand — a throwaway
API + CloudWatch full-request logging, pasting each request object in — still works and is the fallback
if the evaluate API is unavailable for a template.)

The current set covers the deterministic, byte-comparable cases: GetItem (simple + composite key),
PutItem (single + multi-attribute, mixed types), the full `toDynamoDBJson` typed-marshalling surface
(nested map / list / null / bool / int / negative / float / string), and the response passthrough.
Two things are deliberately **out** of this byte-exact harness and covered by unit tests instead:
`$util.time.*` (non-deterministic — `evaluate-mapping-template` gives no way to pin the clock, so only
the *format* is checkable, which the VTL unit tests assert) and the `$util.error()` shape (the evaluate
API surfaces errors less structurally; the corpus probe asserts message + errorType directly).

**Status:** met — every golden is `aws-capture`, the diff is green, and the divergences found during
capture (`N` as number, `NULL` as null) are fixed in the engine. `TestGoldens_GraduationStatus` reports
all-captured. Keep it that way: any new corpus case is captured (not hand-authored) before it counts.
