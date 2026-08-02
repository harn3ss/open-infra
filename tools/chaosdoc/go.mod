// Self-contained (stdlib only) generator: chaos/scenarios.json -> docs/chaos-scenarios.md.
// Run from the repo root:  go run ./tools/chaosdoc
// It renders one Mermaid chain diagram per scenario (chain + fault marker + oracle badge),
// grouped by batch, so the public gallery can never drift from the source-of-truth.
module openinfra/tools/chaosdoc

go 1.24
