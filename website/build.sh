#!/usr/bin/env bash
# Builds the open-infra.dev site into website/dist: the page, plus the platform's generated coverage registry
# (probe/registry/registry.json, which CI keeps in step with the code and the probes). Every service, count
# and maturity tier the site shows is read from that registry at deploy time, so the site carries no copy
# of its own to drift: a push to main that changes what the platform serves changes the site with it.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf website/dist
mkdir -p website/dist
cp website/index.html website/favicon.svg website/dist/
cp probe/registry/registry.json website/dist/registry.json
echo "website/dist built from $(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"
