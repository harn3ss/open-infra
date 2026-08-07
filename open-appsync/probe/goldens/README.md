# open-appsync runtime goldens

This directory is the machinery that graduates the **runtime** from *documented-faithful* to
*behavior-faithful* — the **only** thing that lets the word **"experimental"** come off the runtime.
Nothing else touches that word.

Today the corpus probe asserts against what AWS **documents**. These goldens assert against what AWS
**does**: the exact request objects a real AppSync API emits for the same templates, captured once and
diffed against forever.

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

**Bar to delete "experimental" from the runtime:** every golden is `aws-capture`, the diff is green,
and each divergence found during capture is fixed or documented. Until then the runtime stays
experimental — the goldens are seeded from docs, not yet from AWS.
