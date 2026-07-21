# Console authentication

> AWS equivalent: signing in to the console. A **root user** is created at install; IAM-style
> users and per-user permissions follow (see [Roadmap](#roadmap)).

Every `/api` route requires a signed session. This matters more than it might sound: the console
proxies the Kubernetes API at `/api/k8s/*` **using the pod's ServiceAccount**, so without a gate
anyone who could reach the console had effective admin over the cluster.

## Choosing a backend at install time

Set `AUTH_MODE` on the console Deployment (`platform/console/manifests/deployment.yaml`):

| Mode | Behaviour |
|---|---|
| `local` | **Default.** Users live in the `console-auth` Secret, passwords bcrypt-hashed. |
| `ldap` / `oidc` | Reserved — next phase (LDAP binds against your `kind: Directory` AD). |
| `none` | **No authentication.** Only for throwaway dev clusters; logs a loud warning at boot. |

The default is `local`, so a fresh install is never accidentally wide open.

## First sign-in (root)

On first start with no `console-auth` Secret, the console generates a session-signing key and a
random **root** password, printing it **once**:

```console
$ kubectl logs -n open-infra-console deploy/console | grep -A2 'ROOT CREDENTIALS'
════════ open-infra console: ROOT CREDENTIALS (shown once) ════════
root user created  username=root  password=…
```

Store it. It is not recoverable — **rotate** by deleting the Secret and restarting:

```console
$ kubectl delete secret console-auth -n open-infra-console
$ kubectl rollout restart deploy/console -n open-infra-console
```

Like AWS root, this account is for break-glass and initial setup, not daily work.

## Adding users (local mode)

Users are a JSON map in the `console-auth` Secret's `users` key:

```json
{ "root":  { "hash": "$2a$10$…", "role": "root" },
  "alice": { "hash": "$2a$10$…", "role": "admin" } }
```

Generate a hash with any bcrypt tool (e.g. `htpasswd -bnBC 10 "" 'password' | tr -d ':\n'`).
Changes take effect immediately — the Secret is re-read on every sign-in.

## How it works

- **Session**: an HMAC-SHA256–signed token in an `HttpOnly`, `SameSite=Lax` cookie (`Secure`
  when served over TLS), valid 12h. The signing key lives in the `console-auth` Secret.
- **Gate**: chi middleware on the whole `/api` router; only `/api/auth/*` is exempt. `/healthz`
  stays public for probes.
- **CSRF**: state-changing requests (`POST`/`PUT`/`PATCH`/`DELETE`) must carry
  `X-Openinfra-Console`. `SameSite=Lax` already blocks cross-site form posts; this closes the
  simple-request gap. The console's API client sends it automatically.
- **Failed sign-ins are logged** with the username and remote address.
- Unknown usernames still run a bcrypt comparison, so timing doesn't reveal which users exist.

## Honest limits (today)

- **This is a gate, not per-user authorization.** Every signed-in user currently acts with the
  console ServiceAccount's full rights — there is no read-only user yet. Treat every account as
  an admin account until the next phase lands.
- Sessions are stateless: signing out clears the cookie, but a stolen token stays valid until it
  expires (12h). Rotating the Secret's `sessionKey` invalidates all sessions.
- `local` mode has no password policy, lockout, or MFA.

## Roadmap

1. **Per-user authorization** — map identities to Kubernetes users/groups and have the BFF
   **impersonate** them, so RBAC is enforced by Kubernetes, with managed roles mirroring AWS
   (Administrator / PowerUser / ReadOnly) and a declarative `kind: User`.
2. **LDAP** against your `kind: Directory` (Samba AD), and **OIDC** (Dex/Keycloak/GitHub).

## See also

- [`console.md`](console.md) — the console UI.
- [`directory.md`](directory.md) — the AD directory that will back LDAP mode.
