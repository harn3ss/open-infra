# Console authentication

> AWS equivalent: signing in to the console. A **root user** is created at install, and
> IAM-style users are declarative resources — see [`iam.md`](iam.md).

Every `/api` route requires a signed session. This matters more than it might sound: the console
proxies the Kubernetes API at `/api/k8s/*` **using the pod's ServiceAccount**, so without a gate
anyone who could reach the console had effective admin over the cluster.

## Choosing a backend at install time

Set `AUTH_MODE` on the console Deployment (`platform/console/manifests/deployment.yaml`):

| Mode | Behaviour |
|---|---|
| `local` | **Default.** Users are `kind: User` resources, or entries in the `console-auth` Secret. Passwords are bcrypt-hashed either way. |
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

The normal way is a **`kind: User`**, so accounts are GitOps-managed like everything else.
The password is never in the resource — it points at a Secret holding a bcrypt hash:

```yaml
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: alice, namespace: open-infra-console }
spec:
  displayName: Alice Example
  source: local
  groups: [admins]          # what she may do comes from kind: Group
  passwordSecretRef: { name: alice-pw, key: hash }
```

```console
$ htpasswd -bnBC 10 "" 'her-password' | tr -d ':\n'    # generate the hash
$ kubectl -n open-infra-console create secret generic alice-pw --from-literal=hash='$2a$10$…'
```

`spec.groups` become the impersonation groups **directly** — they are not re-derived from a
role keyword — so authority comes from the ClusterRoleBindings that `kind: Group` creates.
Empty `groups` means "can sign in, authorized for nothing" rather than defaulting to a role.

> ⚠️ A `kind: Group` only takes effect if its name is listed in the impersonator
> ClusterRole's `resourceNames`. That pin is what stops the console impersonating
> `system:masters`, so widening it is deliberately an operator action. Prefer the built-in
> `admins` / `powerusers` / `readers` and vary what they mean via `spec.clusterRole`. Full
> explanation in [`iam.md`](iam.md).

### The Secret (break-glass)

The `console-auth` Secret is still read **first**, before any `kind: User`. That ordering is
the point: if the CRDs are missing, a Composition is broken, or someone deletes their own
User, `root` still works. Losing the console because the thing that defines who may use the
console is broken would be the worst possible failure.

```json
{ "root": { "hash": "$2a$10$…", "role": "root" } }
```

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

The console does **not** decide what anyone may do. It signs the user in, then proxies their
Kubernetes calls with impersonation headers, so **Kubernetes RBAC** enforces the rules and the
audit log attributes every action to a person:

```
Impersonate-User:  openinfra:alice
Impersonate-Group: openinfra:powerusers
```

For a `kind: User`, the groups come straight from `spec.groups`. For a Secret-backed account
the `role` maps to a fixed set:

| Role | Group | Can |
|---|---|---|
| `root`, `admin` | `openinfra:admins` | everything the console can do |
| `poweruser` | `openinfra:powerusers` | manage open-infra resources; **not** Secrets or RBAC |
| `readonly` | `openinfra:readers` | `get`/`list`/`watch` only; **no Secrets** |

Everyone also lands in `openinfra:users`. Anything unrecognised falls back to read-only
(least privilege). Bindings live in `platform/console/manifests/rbac-roles.yaml` — edit those
ClusterRoles to reshape a role.

Two things make this real rather than cosmetic:

- The proxy **strips any client-supplied `Impersonate-*` headers** before setting its own, so a
  browser can't ask to be someone else.
- The BFF's *own* endpoints — the handlers that act with the ServiceAccount rather than going
  through the proxy — ask the API server whether **you** may do it, via a
  `SubjectAccessReview` issued as your impersonated identity, and fail closed on any error.
  So there is no side door around RBAC.

## Honest limits (today)

- The BFF's own endpoints **perform** their work as the ServiceAccount, but they now
  **authorize** as you first (`SubjectAccessReview`), so RBAC governs them as well as
  `/api/k8s/*`. What remains: that check maps an action to a verb/resource pair by hand, so a
  new BFF endpoint is only covered once it is wired up.
- Sessions are stateless: signing out clears the cookie, but a stolen token stays valid until it
  expires (12h). Rotating the Secret's `sessionKey` invalidates all sessions.
- `local` mode has no password policy, lockout, or MFA.
- The console **Users** and **Groups** pages (Security & Identity) manage `kind: User` /
  `kind: Group` and passwords, gated so only admins can (a `SubjectAccessReview` per action).
  The break-glass `root` account is still edited in the Secret, not there.
- Group names beyond the built-in three need an operator to widen the impersonator
  ClusterRole (see above); the console cannot do it for you, by design.

## Roadmap

1. ~~A declarative **`kind: User`**~~ — shipped; see [`iam.md`](iam.md).
2. **OIDC** (Dex/Keycloak/GitHub); LDAP already works against your `kind: Directory`.
3. ~~**Users and Groups screens** in the console~~ — shipped.
4. `kind: Policy` / `kind: Role`, then `Deny` via ValidatingAdmissionPolicy — staged plan in
   [`iam.md`](iam.md).

## See also

- [`console.md`](console.md) — the console UI.
- [`iam.md`](iam.md) — `kind: User` / `kind: Group`, and the staged plan for policies.
- [`architecture.md`](architecture.md) — where `kind: Directory` (the AD DC backing LDAP mode)
  fits in.
