# open-infra OpenAPI specs

OpenAPI 3 descriptions of open-infra's callable interfaces, for GovStack Architecture Blueprint
conformance (building-block interfaces must be OpenAPI-described so blocks interoperate).

- **`openinfra-platform.openapi.yaml`** — the **platform resource API**: the `openinfra.dev` custom
  resources a building block provisions infrastructure through (list/create/get/delete per kind).
  **Generated** from `platform/abstraction/*-xrd.yaml` (the CRD source of truth) — never hand-edit.

## Regenerate

```
python3 docs/openapi/generate.py          # refresh the spec
python3 docs/openapi/generate.py --check  # CI drift gate: fail if the committed spec is stale
```

The generator reads every XRD's `openAPIV3Schema`, so the spec always matches the running API. CI runs
`--check` so a CRD change that isn't reflected here fails the build.

## Not yet covered

- The console BFF (`/api/...`) and the AWS-SDK shim are human/SDK-facing surfaces; their OpenAPI is a
  follow-up (they have no typed schema registry to reflect, so they need hand-authored request/response
  schemas per endpoint).
- Reconciliation to the **GovStack Architecture Blueprint** shapes requires the Blueprint spec (a human
  must supply the version/section). See [`docs/govstack-conformance.md`](../govstack-conformance.md).
