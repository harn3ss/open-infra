# open-appsync APPSYNC_JS runtime goldens

The behavior-faithful diff for the **JavaScript** runtime, the sibling of `../goldens/` (which does the
same for VTL). Each `*.js` here is a **real APPSYNC_JS module** — `import { util } from
'@aws-appsync/utils'` + `export function request/response` — the exact shape AWS requires. `jsruntime`
accepts that shape unmodified (it strips the ES-module framing goja can't parse and injects `util` as a
global), so **the same source runs on AWS and on open-appsync**.

Each golden JSON names its `code` module, which handler to run (`function`: `request`|`response`), the
`$ctx` (`context`), a pinned `autoId`, and the `expected` output. `TestJSGoldens_MatchCode` runs our
engine and diffs; the cases were captured from real AWS AppSync via `capture.sh` (the `evaluate-code`
API) and are `source: aws-capture`.

## Capturing (maintainer, once)

```
AWS_PROFILE=you AWS_REGION=us-east-1 ./capture.sh
```

Needs `appsync:EvaluateCode` on the IAM principal (add it alongside `appsync:EvaluateMappingTemplate` on
the same capture user; both are read-only and create nothing). Then `go test ./probe/`.

**Status:** captured from real AWS, diff green. The JS runtime is behavior-faithful (not just
implementable) — the same finding the VTL goldens proved, for the second tenant. Any new case is
captured, not hand-authored, before it counts.
