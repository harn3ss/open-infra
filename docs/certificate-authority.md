# Private certificate authority — `kind: CertificateAuthority`

A managed **private CA** — the ACM-Private-CA-shaped primitive. A `CertificateAuthority` is a Vault
PKI secrets mount: it holds a CA certificate and issues short-lived leaf certificates for names under
the domains you allow (NIST SP 800-53 **SC-12**, **SC-13**, **SC-17**). You can stand up a self-signed
**root**, or an **intermediate** signed by a root you already run, and then issue and revoke leaf certs
against it from the console.

> **Opt-in, off by default, experimental.** This is the `pki` component. It **requires the
> [`encryption`](encryption.md) component** because it reuses that stack's Vault and its Kubernetes-auth
> wiring. Enable both with `components.encryption: true` and `components.pki: true`, then re-run
> `install.sh`. It is shipped built + reviewed but **not** live-verified in this repo's reference
> environment; treat the PKI-init steps below as an **operator runbook**.

## `kind: CertificateAuthority`

A self-signed root:

```yaml
apiVersion: openinfra.dev/v1
kind: CertificateAuthority
metadata: { name: corp-root, namespace: platform }
spec:
  commonName: "Corp Root CA"
  hierarchy: root                 # self-signed
  keyType: rsa-4096
  maxTtl: "87600h"                # 10y — the CA cert's own lifetime / max leaf TTL
  allowedDomains: ["corp.example.lan", "svc.corp.example.lan"]
```

An intermediate signed by that root:

```yaml
apiVersion: openinfra.dev/v1
kind: CertificateAuthority
metadata: { name: corp-issuing, namespace: platform }
spec:
  commonName: "Corp Issuing CA"
  hierarchy: intermediate
  parent: corp-root               # the name of the parent CertificateAuthority
  keyType: rsa-4096
  maxTtl: "8760h"                 # 1y leaf ceiling
  allowedDomains: ["corp.example.lan"]
```

### Spec fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `commonName` | string (required) | — | The CA certificate's subject CN. |
| `hierarchy` | enum `root` \| `intermediate` | `root` | `root` self-signs; `intermediate` is signed by `parent`. |
| `parent` | string | — | Name of the parent `CertificateAuthority`, required when `hierarchy: intermediate`. |
| `keyType` | enum `rsa-2048` \| `rsa-4096` \| `ec-256` \| `ec-384` | `rsa-4096` | Key algorithm for the CA. |
| `maxTtl` | string | `"8760h"` | Ceiling on the CA cert's lifetime and on issued leaf TTLs (Go duration). |
| `allowedDomains` | array of string | — | Domains the `issuer` role may issue for; subdomains are allowed. |

### Status

The reconciler reports readiness on the resource:

| Field | Meaning |
|---|---|
| `ready` | The Vault PKI mount is provisioned and the CA cert exists. |
| `pkiMount` | The Vault mount path, `pki-<name>`. |
| `caCertPem` | The CA certificate, PEM. Distribute this to trust stores. |
| `serial` | The CA certificate's serial number. |
| `notAfter` | The CA certificate's expiry. |

## How it works

```
CertificateAuthority (claim)
   └─ composition renders  ConfigMap openinfra-ca-<name>        (spec mirror, read by the BFF)
   ca-reconciler ──────────▶ Vault: enable pki-<name>, generate root/intermediate CA,
                              write the `issuer` role + config/urls
                            ConfigMap openinfra-ca-state-<name> (ready / caCertPem / serial / notAfter)
   ca-issuer (Deployment) ─▶ Vault: pki-<name>/issue/issuer, pki-<name>/revoke  (leaf certs only)
   console BFF /api/ca ────▶ reads the two ConfigMaps; proxies issue/revoke to ca-issuer (SAR-gated)
```

Each CA gets its **own Vault PKI mount**, `pki-<name>`, and a single Vault PKI **role named `issuer`**
whose `allowed_domains` come from `spec.allowedDomains` with `allow_subdomains=true`. Leaf certificates
are always issued through that role, so the allow-list is enforced by Vault, not by the caller.

Two ConfigMaps in `open-infra-console` carry the CA's state to the console (the console SA never talks
to Vault):

- **`openinfra-ca-<name>`** — the spec mirror the composition renders (`commonName`, `hierarchy`,
  `parent`, `keyType`, `maxTtl`, `allowedDomains` comma-joined, `pkiMount`), labelled
  `openinfra.dev/ca=<name>`.
- **`openinfra-ca-state-<name>`** — written by `ca-reconciler` (`ready`, `pkiMount`, `caCertPem`,
  `serial`, `notAfter`).

## The two Vault identities (the security crux)

Provisioning a CA and issuing leaf certificates are **different privileges**, so they run as **two
ServiceAccounts** in `crossplane-system`, each bound to a least-privilege Vault policy via Kubernetes
auth — the same pattern as the encryption stack's reconciler/destroyer. Neither identity stores a Vault
credential: both log in with their own SA token.

As in the Transit policies, **`+` matches exactly one path segment**. That is the whole trick: a grant
on `pki-+/issue/issuer` reaches every CA's issue endpoint but can never widen to `pki-+/root/generate`,
and a recursive `*` would hand over exactly the powers each identity must lack.

### `ca-provisioner` — provisions CAs, cannot issue leaves

Used by `ca-reconciler`. It may enable and tune PKI mounts, generate root/intermediate CAs, set the
signed intermediate, and write the `issuer` role and URL config.

```hcl
# enable / tune a per-CA PKI mount (and read sys/mounts to check its own work)
path "sys/mounts/pki-+"          { capabilities = ["create", "update", "read"] }
path "sys/mounts/pki-+/tune"     { capabilities = ["update"] }
path "sys/mounts"                { capabilities = ["read"] }
# generate a root, or an intermediate CSR + import its signed cert
path "pki-+/root/generate/+"          { capabilities = ["create", "update"] }
path "pki-+/root/sign-intermediate"   { capabilities = ["create", "update"] }
path "pki-+/intermediate/generate/+"  { capabilities = ["create", "update"] }
path "pki-+/intermediate/set-signed"  { capabilities = ["create", "update"] }
# the issuing role + CRL/issuer URLs
path "pki-+/roles/+"             { capabilities = ["create", "update", "read"] }
path "pki-+/config/urls"         { capabilities = ["create", "update", "read"] }
```

It **cannot** `issue`/`revoke` leaf certificates, cannot delete or tune-lease anything outside `pki-*`,
and has **no access to `transit/*`** — it cannot reach the encryption stack's customer keys.

### `ca-issuer` — issues/revokes leaves, cannot provision

Used by the `ca-issuer` Deployment. It may only issue against the `issuer` role, revoke, rotate the
CRL, and read `sys/mounts` to discover the mounts.

```hcl
path "pki-+/issue/issuer"        { capabilities = ["create", "update"] }
path "pki-+/revoke"              { capabilities = ["create", "update"] }
path "pki-+/crl/rotate"          { capabilities = ["read"] }
path "sys/mounts"                { capabilities = ["read"] }
```

It **cannot** generate a root or intermediate and **cannot** write roles — a compromised issuer can
mint leaf certs only for names the `issuer` role already allows, and can never mint a new CA or widen
the allow-list.

Each policy is bound to its SA by a Kubernetes-auth role (mirroring the `encryptionkey-reconciler` /
`encryptionkey-destroyer` roles in `platform/security/vault.yaml`):

```sh
vault write auth/kubernetes/role/ca-provisioner \
  bound_service_account_names=ca-provisioner \
  bound_service_account_namespaces=crossplane-system \
  token_policies=ca-provisioner token_ttl=20m

vault write auth/kubernetes/role/ca-issuer \
  bound_service_account_names=ca-issuer \
  bound_service_account_namespaces=crossplane-system \
  token_policies=ca-issuer token_ttl=10m
```

## Bringing PKI up (operator, one-time)

PKI rides on the encryption stack's Vault, so bring Vault up first
([docs/encryption.md → Bringing Vault up](encryption.md#bringing-vault-up-operator-one-time)):
initialize + unseal Vault and give the setup Job its short-lived `vault-bootstrap` token. With
`components.pki: true`, the setup step also enables a PKI mount per CA and writes the two policies and
their Kubernetes-auth roles above. As with Transit, **revoke and delete `vault-bootstrap`** once setup
succeeds — it is a root/admin token needed only for bootstrap.

After that, apply `CertificateAuthority` resources. Roots are self-signed in one step; an intermediate
is generated as a CSR, signed by its `parent`'s mount, and imported with `set-signed` — so the parent
CA must be `ready` first.

## Issuing and revoking certificates

Issue and revoke happen **synchronously** through the console, never by the console touching Vault:

1. The console calls the BFF: `POST /api/ca/{namespace}/{name}/issue` (or `/revoke`).
2. The BFF runs a **SubjectAccessReview** for the caller, then reverse-proxies the request to the
   `ca-issuer` Service (`ca-issuer:8080` in `crossplane-system`).
3. `ca-issuer` logs into Vault as the `ca-issuer` SA and calls `pki-<ca>/issue/issuer` (or
   `pki-<ca>/revoke`).

`POST /issue` takes `{ ca, commonName, ttl, altNames[] }` and returns
`{ certificate, issuingCa, caChain[], privateKey, serialNumber }`. The private key is generated by
Vault, streamed to the caller once, and **never logged or persisted** by `ca-issuer` — if you don't
capture it on that response you must re-issue. `POST /revoke` takes `{ ca, serialNumber }`.

`GET /api/ca` lists CAs by reading the `openinfra-ca-*` and `openinfra-ca-state-*` ConfigMaps — it does
not call Vault at all.

## High availability

`ca-issuer` is a **shared control-plane component** — one issuer serves every CA — so it runs HA by
default: **two replicas** (`ca-issuer.yaml`), spread across nodes, with a PodDisruptionBudget keeping
one available through a drain/upgrade. Issue/revoke is stateless — every replica logs into Vault with
the same SA and reads CA state from Vault — so the replicas need no coordination and there is no leader.
(There is deliberately no per-CA replica knob: one CA's setting could not sensibly scale a Deployment
shared by all of them.)

The CA certificate itself is generated **once** by `ca-reconciler` and then lives in Vault; its
durability is Vault's, not the issuer Deployment's. Issuer HA does not replicate the CA — it keeps the
issue endpoint reachable while a node is down.

## Honesty status

- **Shipped + reviewed, not live-verified here.** The composition, reconciler, `ca-issuer`, BFF routes
  and console pages are built and wired; the reference environment does not have Vault initialized, so
  the end-to-end issue/revoke path has not been exercised in this repo.
- **Requires Vault (the `encryption` component).** Without an initialized, unsealed Vault there is no
  KMS to hold the CA, and applying a `CertificateAuthority` will sit `ready: false`.
- **Trust distribution is yours.** open-infra issues certificates; getting `caCertPem` into the trust
  stores of the machines that must trust it is an operator step (like any private CA).
- **Root key storage is Vault's default.** Keys live in the PKI mount; open-infra does not add an HSM
  or offline-root ceremony. For a high-assurance root, generate it offline and bring up only an
  `intermediate` here.

## Control mapping

- **SC-12 / SC-13** cryptographic key establishment & management — per-CA Vault PKI mount.
- **SC-17** public key infrastructure certificates — issue/revoke against a private CA with a
  Vault-enforced domain allow-list.
- **AC-6 / least privilege** — split `ca-provisioner` (mint CAs) and `ca-issuer` (mint leaves) so
  neither identity holds both privileges; see [the two Vault identities](#the-two-vault-identities-the-security-crux).

## See also

- [Encryption with customer-owned keys](encryption.md) — the Vault stack this reuses.
- [Security & compliance](security-and-compliance.md) — how the control mappings fit together.
