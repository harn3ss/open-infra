# Profile conformance gate

A behavioural conformance suite for the profile-fidelity contract: it runs the **same**
assertions against a deployed profile and reports whether that profile behaves as promised. A
profile MAY vary durability, scale, and compliance machinery; it MAY NEVER vary **semantics** —
the API surface, authorization behaviour, and resolver/engine behaviour. This gate is what makes
that rule mechanical instead of a promise, so a reduced (e.g. `dev`) profile cannot silently drift
from the full one — the "fake-green factory" a low-fidelity dev profile would otherwise be.

## Run it

```
python3 conformance/run_conformance.py        # deploys the fixture, runs the rows, tears down
python3 conformance/run_conformance.py --keep # leave the fixture up for inspection
```

Needs `kubectl` pointed at the target cluster and the Python `websockets` package (for the
subscription row). It deploys `fixture.yaml` (a representative AppSync app on a `memory` data
source), exercises it over HTTP and WebSocket, and tears it down.

## Exit convention (mirrors the chaos suite)

| Exit | Meaning |
|---|---|
| `0`  | PASS — every assertion that ran held on this profile. |
| `1`  | REAL-FAILURE — a ran assertion failed: a real semantic divergence. |
| `42` | INCONCLUSIVE — nothing was proven (couldn't deploy / reach the API). Never a pass. |

## The rows

Behavioural (run live, must pass on every profile): Dynamo resolver create / read / update /
delete / list; `@aws_api_key` positive; a fail-closed **unauthenticated** request; a subscription
push (`@aws_subscribe`).

Recorded **not-run** (honest, never faked, never green) until their live blockers clear:

- **field-level SAR authorization** (a reader denied a write) — currently blocked by a real bug
  this gate surfaced: the engine pod's ServiceAccount cannot create SubjectAccessReviews, so every
  `auth:`-gated field fails closed regardless of the caller. Must be fixed before this row runs.
- **`@aws_iam` (SigV4)** and **`@aws_cognito_user_pools`/`@aws_oidc` (JWT)** — need the aws-shim in
  front of the engine (a real signed request / real token), not stood up in this gate yet.

## Status

Phase 1 of the fidelity contract: the gate exists, runs live, and is **green on the full profile**
(the rows it runs). Still to come: expressing profiles as bundles over `components.*`, a misuse
guard so a reduced profile loudly self-identifies, running the gate per-profile in CI, and closing
the not-run rows above.
