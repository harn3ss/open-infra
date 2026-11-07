## What this changes

<!-- What a user (or operator) can do after this that they could not before, or what is fixed. -->

## AWS-shaped from day one

A customer-facing change lands with all five, in this PR. Tick each, or say why it does not apply
(an internal refactor, an operator-only change). See AGENTS.md.

- [ ] **AWS API shape** — the AWS service, operations, ARNs and error codes as AWS names them; or a
      platform extra (`openinfra:*`) the operator approved, recorded in `probe/registry/surface.yaml`.
- [ ] **IAM, with a deny case** — every new door asks the one evaluator for an IAM action on an ARN, and a
      test shows a principal without it refused.
- [ ] **Coverage registry** — `probe/shim-services.yaml` and `probe/registry/` updated: ran
      `python3 probe/shimgen.py` and committed what it wrote (including `docs/customer-surface.md`).
- [ ] **AWS vocabulary** — no namespaces, claims, `kubectl` or Kubernetes errors on a customer surface
      (console, user docs, API errors).
- [ ] **Live probe with a denial** — `probe/aws-shim-<name>.sh` asserts at least one call refused with
      AWS's access-denied; until it has passed live it is listed as `pending`.

## How it was verified

<!-- Tests run, gates run (`probe/shimgen.py --check`, `docs/openapi/generate.py --check`), probes run live. -->
