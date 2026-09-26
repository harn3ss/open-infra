#!/usr/bin/env bash
# Pin the first-party TOOL images to their immutable multi-arch INDEX digest (polyhedron#165 part 1).
#
# The reconcile-time setup Jobs consume `open-infra-mc` / `open-infra-nats-box` — pinning them by :latest
# means "what runs today ≠ what ran last week, and nothing records which digest provisioned what". This
# resolves each image's :latest to its index digest (which preserves multi-arch: amd64+arm64 both resolve
# under the index) and rewrites every consuming reference in the platform manifests + Go sources to
# `…@sha256:<digest>`.
#
# It is IDEMPOTENT and re-runnable — this IS the bump mechanism. After a `build-mc` / `build-nats-box`
# rebuild pushes a new :latest (e.g. for CVEs), re-run this to repin the manifests to the new digest and
# commit; until then the cluster keeps running the pinned, known digest (the point of pinning).
#
#   ./hack/pin-tool-image-digests.sh            # pin all tool images
#   IMAGES="open-infra-mc" ./hack/pin-tool-image-digests.sh   # just one
set -euo pipefail

OWNER="${OWNER:-harn3ss}"
IMAGES="${IMAGES:-open-infra-mc open-infra-nats-box}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# indexDigest <image> -> the multi-arch index digest of :latest (anonymous ghcr token flow; public images).
indexDigest() {
  local img="$1" tok
  tok="$(curl -fsSL "https://ghcr.io/token?scope=repository:${OWNER}/${img}:pull&service=ghcr.io" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')"
  curl -fsSI \
    -H "Authorization: Bearer ${tok}" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://ghcr.io/v2/${OWNER}/${img}/manifests/latest" \
    | grep -i '^docker-content-digest:' | tr -d '\r' | awk '{print $2}'
}

changed=0
for img in ${IMAGES}; do
  d="$(indexDigest "${img}")"
  case "${d}" in
    sha256:*) : ;;
    *) echo "ERROR: could not resolve an index digest for ${OWNER}/${img} (got '${d}')" >&2; exit 1 ;;
  esac
  echo "pinning ghcr.io/${OWNER}/${img} -> ${d}"
  # Rewrite BOTH :latest and any existing @sha256 pin -> the new digest, across manifests + Go sources.
  # NUL-safe file list; only files that actually reference this image are touched.
  mapfile -d '' -t files < <(grep -rlZ -E "ghcr\.io/${OWNER}/${img}(:latest|@sha256:[a-f0-9]{64})" \
    "${ROOT}/platform" "${ROOT}/console-api" --include='*.yaml' --include='*.go' 2>/dev/null || true)
  for f in "${files[@]}"; do
    sed -i -E "s#ghcr\.io/${OWNER}/${img}(:latest|@sha256:[a-f0-9]{64})#ghcr.io/${OWNER}/${img}@${d}#g" "${f}"
    echo "  pinned in ${f#${ROOT}/}"
    changed=1
  done
done

[ "${changed}" = "1" ] && echo "done — review 'git diff' and commit." || echo "no references found to pin."
