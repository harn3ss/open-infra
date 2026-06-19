# Contributing to open-infra

Thanks for helping build free infra for everyone. open-infra's value is **glue
and developer experience** on top of proven CNCF projects — so most
contributions are manifests, installer logic, docs, and examples, not new
distributed systems.

## Ground rules

1. **Keep the repo public-safe.** Never commit anything that describes a real
   deployment: hostnames, LAN subnets, NAS paths, node inventories, tokens, or
   kubeconfigs. Those belong in `config.yaml` (gitignored). If you add a new
   class of private value, add a pattern to `.gitignore` in the same PR.
2. **The `infra.yaml` schema is the public API.** Changing the user-facing
   `Application` spec (`platform/abstraction/`) is a breaking change — discuss in
   an issue first and bump the API version deliberately.
3. **Lean on upstream.** Prefer wiring an existing Helm chart / operator over
   hand-rolling. Pin chart versions.
4. **Idempotency.** `install.sh` and the CLI must be safe to run repeatedly.
5. **Document as you go.** A feature without a doc/example is unfinished. The
   "deploy your first app in 10 minutes" tutorial is a first-class deliverable.

## Dev loop

- Bring up a throwaway single-node cluster in `dev` mode (`mode: dev` in
  `config.yaml`) — sslip.io DNS + self-signed TLS, no external dependencies.
- Each phase has an **exit test** (see `docs/roadmap.md`); add/extend one when
  you land a phase.

## Commit / PR conventions

- Conventional-commit-ish subjects (`feat:`, `fix:`, `docs:`, `chore:`).
- One logical change per PR; keep platform-component bumps separate from glue.
- CI must pass: manifest lint (`kubeconform`), shellcheck, schema validation.

## License

By contributing you agree your contributions are licensed under
[Apache-2.0](LICENSE).
