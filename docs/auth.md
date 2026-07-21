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
| `ldap` | Authenticates against a directory — typically the Samba AD from `kind: Directory`. |
| `oidc` | Reserved — not implemented yet (returns 501). |
| `none` | **No authentication.** Only for throwaway dev clusters; logs a loud warning at boot. |

The default is `local`, so a fresh install is never accidentally wide open.

### LDAP / Active Directory (`AUTH_MODE=ldap`)

Point the console at the AD DC that `kind: Directory` provisions, so your own directory is the
console's identity provider:

| Variable | Purpose |
|---|---|
| `LDAP_HOST` | DC hostname or Service DNS name |
| `LDAP_DOMAIN` | e.g. `EXAMPLE.COM` — builds the UPN and default base DN |
| `LDAP_BIND_USER` / `LDAP_BIND_PASSWORD` | account used to look users up |
| `LDAP_USER_BASE_DN` | optional; defaults to the domain's base DN |
| `LDAP_ADMIN_GROUP` | AD group → `admin` (default `openinfra-admins`) |
| `LDAP_POWERUSER_GROUP` | AD group → `poweruser` (default `openinfra-powerusers`) |
| `LDAP_READONLY_GROUP` | AD group → `readonly` (default `openinfra-readers`) |

Sign-in binds as the lookup account, finds the user by `sAMAccountName` or UPN, then **binds as
that user** to verify the password. Group membership picks the role; **no matching group means
read-only**, so merely existing in the directory never grants write access. LDAPS is tried first
and falls back to plain LDAP (Samba's self-signed cert is normal on a private network).

> **Break-glass:** local accounts in the `console-auth` Secret keep working in *every* mode, so a
> directory outage can never lock you out. Keep the `root` password somewhere safe.

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

## Roles ("IAM")

Each user has a `role`. The console does **not** decide what a role may do — it signs the user
in, then proxies their Kubernetes calls with impersonation headers so **Kubernetes RBAC**
enforces the rules and the audit log attributes every action to a person:

```
Impersonate-User:  openinfra:alice
Impersonate-Group: openinfra:powerusers
```

| Role | Group | Can |
|---|---|---|
| `root`, `admin` | `openinfra:admins` | everything the console can do |
| `poweruser` | `openinfra:powerusers` | manage open-infra resources; **not** Secrets or RBAC |
| `readonly` | `openinfra:readers` | `get`/`list`/`watch` only; **no Secrets** |

Anything unrecognised falls back to read-only (least privilege). Bindings live in
`platform/console/manifests/rbac-roles.yaml` — edit those ClusterRoles to reshape a role.

Two things make this real rather than cosmetic:

- The proxy **strips any client-supplied `Impersonate-*` headers** before setting its own, so a
  browser can't ask to be someone else.
- A read-only user is blocked from the BFF's *own* mutating endpoints too (the handlers that act
  with the ServiceAccount rather than going through the proxy), so there's no side door.

## Honest limits (today)

- **The BFF's own endpoints still act as the ServiceAccount**, not as you. Read-only users are
  blocked from mutating them, but a `poweruser` calling e.g. the snapshot API is not further
  restricted by Kubernetes RBAC on that path. Only `/api/k8s/*` is fully RBAC-governed.
- Sessions are stateless: signing out clears the cookie, but a stolen token stays valid until it
  expires (12h). Rotating the Secret's `sessionKey` invalidates all sessions.
- `local` mode has no password policy, lockout, or MFA.
- Roles are assigned by editing the `console-auth` Secret; there is no `kind: User` CRD yet.

## Roadmap

1. **LDAP** against your `kind: Directory` (Samba AD), and **OIDC** (Dex/Keycloak/GitHub).
2. A declarative **`kind: User`** so accounts and role bindings are GitOps-managed like
   everything else, instead of a JSON blob in a Secret.

## See also

- [`console.md`](console.md) — the console UI.
- [`directory.md`](directory.md) — the AD directory that will back LDAP mode.
