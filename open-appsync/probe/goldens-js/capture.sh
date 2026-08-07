#!/usr/bin/env bash
# Turnkey APPSYNC_JS goldens capture: evaluate each real APPSYNC_JS module through real AWS AppSync
# (the `evaluate-code` API) and rewrite the golden as source:aws-capture. Run ONCE, by the maintainer,
# against your own AWS account — this is what makes the JS runtime behavior-faithful.
#
#   AWS_PROFILE=you AWS_REGION=us-east-1 ./capture.sh
#
# Needs `appsync:EvaluateCode` on the IAM principal (add it to the same OpenAppsyncGoldenCapture policy
# that already has appsync:EvaluateMappingTemplate). It creates nothing and costs effectively nothing.
# Each golden names its code module + which handler to evaluate (request|response); the golden's $ctx is
# remapped to AWS's context shape (args → arguments) and autoId is pinned from the emitted key so the CI
# diff is byte-exact.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
command -v aws >/dev/null || { echo "aws CLI required" >&2; exit 1; }

captured=0
for g in "$HERE"/*.json; do
  [ -e "$g" ] || continue
  code="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["code"])' "$g")"
  fn="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["function"])' "$g")"
  ctx="$(python3 -c 'import json,sys
c=json.load(open(sys.argv[1]))["context"]
if "args" in c: c["arguments"]=c.pop("args")
print(json.dumps(c))' "$g")"
  cfile="$HERE/$code"
  [ -f "$cfile" ] || { echo "!! $code not found — skipping $(basename "$g")" >&2; continue; }

  echo "▸ capturing $(basename "$g")  ($code :: $fn)"
  result="$(aws appsync evaluate-code \
    --runtime name=APPSYNC_JS,runtimeVersion=1.0.0 \
    --function "$fn" \
    --code "file://$cfile" \
    --context "$ctx" \
    --output json)"

  python3 - "$g" "$result" <<'PY'
import json, sys
gpath, raw = sys.argv[1], sys.argv[2]
g = json.load(open(gpath))
res = json.loads(raw)
if res.get("error"):
    print("   AWS returned an error for", gpath, ":", res["error"], file=sys.stderr); sys.exit(1)
rendered = res["evaluationResult"]
try:
    expected = json.loads(rendered)
except Exception:
    expected = rendered
g["expected"] = expected
g["source"] = "aws-capture"
try:
    aid = expected.get("key", {}).get("id", {}).get("S")
    if isinstance(aid, str) and len(aid) == 36 and aid.count("-") == 4:
        g["autoId"] = aid
except Exception:
    pass
json.dump(g, open(gpath, "w"), indent=2)
open(gpath, "a").write("\n")
PY
  captured=$((captured+1))
done

echo "✓ captured $captured JS golden(s) from real AppSync. Now: (cd $HERE/../.. && go test ./probe/)"
