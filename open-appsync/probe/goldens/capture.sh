#!/usr/bin/env bash
# Turnkey runtime-goldens capture for open-appsync: render every golden's corpus template through
# REAL AWS AppSync and rewrite the golden as source:aws-capture. Run ONCE, by the maintainer, against
# your own AWS account — this is the external step that removes "experimental" from the runtime.
#
# AWS_PROFILE=you AWS_REGION=us-east-1 ./capture.sh
#
# It uses AppSync's server-side `evaluate-mapping-template` API, so NO API/schema needs to be deployed:
# each corpus template is evaluated against its golden's context and the exact request object AWS
# produces is captured as `expected`. Non-determinism is pinned back into the golden's `autoId` (the
# uuid AppSync generated is read out of the result), so open-appsync's injectable AutoID reproduces it
# and the CI diff (goldens_test.go) is exact. After running, re-run `go test ./probe/` — every case now
# diffs against real AWS; any divergence is a real fidelity gap to fix or document.
#
# The minimum set worth capturing (where documented and actual most plausibly diverge; add a
# golden + a corpus template for any not yet present before deleting the label):
# - GetItem (typed key), PutItem (autoId + mixed S/N), response passthrough, a validation PutItem;
# - $util.dynamodb.toDynamoDBJson on nested map / list / null / bool / number-vs-string;
# - the exact $util.error error shape; $util.time.* formats; a multi-attribute PutItem with mixed types.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CORPUS="$(cd "$HERE/../corpus" && pwd)"
command -v aws >/dev/null || { echo "aws CLI required" >&2; exit 1; }

captured=0
for g in "$HERE"/*.json; do
  [ -e "$g" ] || continue
  tmpl="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["template"])' "$g")"
  ctx="$(python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))["context"]))' "$g")"
  tfile="$CORPUS/$tmpl"
  [ -f "$tfile" ] || { echo "!! $tmpl not found in corpus — skipping $(basename "$g")" >&2; continue; }

  echo "▸ capturing $(basename "$g")  ($tmpl)"
  result="$(aws appsync evaluate-mapping-template \
    --template "file://$tfile" \
    --context "$ctx" \
    --output json)"

  # evaluationResult is the rendered document (a JSON string). Fold it into the golden as `expected`,
  # flip source to aws-capture, and pin autoId from the emitted key.id.S when the template used it.
  python3 - "$g" "$result" <<'PY'
import json, sys
gpath, raw = sys.argv[1], sys.argv[2]
g = json.load(open(gpath))
res = json.loads(raw)
err = res.get("error")
if err:
    print("   AWS returned an error for", gpath, ":", err, file=sys.stderr); sys.exit(1)
rendered = res["evaluationResult"]
try:
    expected = json.loads(rendered)
except Exception:
    expected = rendered  # non-JSON (e.g. a scalar passthrough)
g["expected"] = expected
g["source"] = "aws-capture"
# Pin the generated id (read from the emitted key) so our injectable AutoID reproduces AWS's output.
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

echo "✓ captured $captured golden(s) from real AppSync. Now: (cd $HERE/../.. && go test ./probe/)"
echo "  TestGoldens_GraduationStatus should now report all-captured; fix or document any diff failures."
