# OpenBao: the platform's key and secrets service

> **Operator guide.** This page is for the operator who runs the cluster, so it uses Kubernetes terms
> (namespaces, pods, `kubectl`). Customers never see OpenBao: they use KMS, Secrets Manager and the other
> AWS APIs, which the platform serves on top of it.

OpenBao keeps the platform's keys: the keys behind KMS, Secrets Manager, Parameter Store secure values,
`kind: EncryptionKey`, encrypted volumes and the STS sealing key, with the CAs and signing keys still in
Kubernetes Secrets to follow (#359). It is the Linux Foundation's
MPL-2.0 fork of HashiCorp Vault, chosen because Vault 1.15 and later are under the BUSL, which does not
suit a project that is given away.

**Status: live; opt-in, off by default** (`components.openbao`, which the `encryption` component needs).
Every client of the key service uses it ([`encryption.md`](encryption.md)). On an install that ran the
single-node HashiCorp Vault before it, the keys moved by storage copy (below): every key, version and
ciphertext as it was.

## Shape

| | |
|---|---|
| Members | three, sharing integrated Raft storage; one is active and the other two forward to it |
| Placement | one per node, on three nodes the operator names, each a different physical machine with a solid-state disk |
| Unsealing | automatic, by an OpenBao outside the cluster (the *unseal host*); see below |
| API | TLS 1.3 only. Clients use `https://openbao-active.openbao.svc:8200`, the active member: a standby answers some requests from its own copy, which trails the active member by milliseconds, so a key created and used at once through a standby can be reported missing. The certificate comes from the platform CA and renews without a restart |
| Network | only the members reach one another; each client that moves onto OpenBao is admitted by name |
| Audit | every request and response, sensitive fields HMAC'd, written to the members' logs and so to Loki |
| Changes | roll one member at a time, each unsealed before the next; at most one member is down for maintenance |

Losing one member does not interrupt service: another member becomes active within seconds, and the lost
one rejoins and unseals itself when it comes back. Losing two at once stops service until one returns,
since Raft needs two of three to agree.

## The unseal plan

A member starts **sealed**: its data is encrypted under a root key that it cannot read until it is
unsealed. Here the members unseal themselves by asking the unseal host to decrypt their root key with a
key that never leaves the unseal host (OpenBao's *transit* seal). The cluster holds only a token that can
encrypt and decrypt with that key and do nothing else (secret `openbao/openbao-seal`).

The unseal host is a small OpenBao on a machine outside the cluster.
[`scripts/openbao-unseal-host.ps1`](../scripts/openbao-unseal-host.ps1) sets one up on a Windows PC and
operates it afterwards (unseal, status, a new cluster token, certificate renewal, backup, restore). The
machine must:

- not be a cluster node, nor a machine that an automation agent works on;
- have a fixed address that every node can reach on TCP 8200 (the script's firewall rule admits only the
  cluster's subnet);
- be on whenever a member might start, and have its disk encrypted.

The unseal host has its own unseal keys (three, any two of which unseal it). Like the cluster's
**recovery keys** (below), they are handed to the operator once and are never stored on the cluster,
the issue tracker, a shared drive or anywhere an agent can read. After the PC restarts, the operator
unseals it with two keys; the members are not affected while they keep running.

## When the unseal host is down

OpenBao fails closed. It never falls back to a static key, a dev mode or an unsealed start.

- **Members that are running keep working.** They need the unseal host only to unseal.
- **A member that starts while the host is down stays sealed and serves nothing.** It waits (or exits
  and is restarted) until the host answers, then unseals itself. In the rehearsal, a member restarted
  while the host was unreachable kept its API closed for as long as the host was away, the other two
  went on serving, and it was unsealed and Ready 29 seconds after the host came back, with no restart.
- **If every member restarts while the host is down**, the key service is unavailable until the host is
  back and unsealed, and so is everything that depends on it.
- **If the PC is lost**, rebuild the unseal host on another machine from its latest backup and two of its
  unseal keys (`-Action Restore`). It comes back with the same key and the same CA, so the cluster needs
  no change.
- **If the backup and the unseal keys are both lost**, the members cannot unseal after their next
  restart, and their data cannot be recovered. The cluster's recovery keys authorize operations on a
  running cluster; they cannot decrypt the root key. Keep at least one backup off the PC and the keys apart
  from it.

## Turning it on

1. **Set up the unseal host** on the PC, in an administrator PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\openbao-unseal-host.ps1 -ListenIp <the PC's address> -ClusterSubnet <the nodes' subnet>
   ```

   It shows the unseal keys, an admin token and the cluster token once, and prints two lines at the end:
   the address for the cluster and its CA's SHA-256 fingerprint.

2. **Give the cluster its token.** Run the two `kubectl` commands the script prints, in your own terminal
   on a machine with cluster access, and paste the cluster token at the hidden prompt. They create
   `secret/openbao-seal` in namespace `openbao`; nothing else stores the token.

3. **Fill in `config.yaml`:**

   ```yaml
   components:
     openbao: true
   openbao:
     nodes: "<node-a>,<node-b>,<node-c>"   # three different physical machines
     unsealHost:
       address: "https://192.0.2.10:8200"   # the script's "address, for the cluster"
       caFingerprint: "AB:CD:…"             # its "CA SHA-256 fingerprint"
   ```

4. **Run `./install.sh`.** It fetches the unseal host's CA, accepts it only if its fingerprint matches,
   records it and the host's address in namespace `openbao`, labels the three nodes
   `openinfra.dev/openbao=true`, and syncs the component. The members start and wait to be initialized.

5. **Initialize it once**, in your own terminal:

   ```sh
   kubectl -n openbao exec -it openbao-0 -c openbao -- bao operator init -recovery-shares=3 -recovery-threshold=2
   ```

   This prints the cluster's three recovery keys and an initial root token, once. Keep the recovery keys
   like the unseal host's keys: apart from one another, offline. Keep the root token offline with them
   until the one-time configuration that comes with moving the keys, which replaces it with a narrowly
   scoped identity and revokes it (as [`encryption.md`](encryption.md) does for Vault). Do not revoke it
   before then: OpenBao generates a new root token only for a caller already authorized to.

   The other two members join and unseal on their own. Check with:

   ```sh
   ./probe/openbao-ha.sh
   ```

## Operating it

- **Status.** `./probe/openbao-ha.sh` checks the three members, their nodes, that each is unsealed by the
  unseal host, that exactly one is active, and that their Raft indexes agree. It uses no token.
  `./probe/openbao-ha.sh --drill` also deletes the active member and checks that another takes over and the
  deleted one comes back unsealed.
- **A member or its node restarts.** Nothing to do: it rejoins and unseals itself.
- **A member's node is gone for good.** Name a replacement node in `openbao.nodes` and re-run
  `./install.sh` (it labels the new node and never unlabels the old one). Remove the old member from Raft
  (`bao operator raft remove-peer openbao-<n>`, with an administrative token), delete its claim
  (`kubectl -n openbao delete pvc data-openbao-<n>`) and its pod: it starts on the new node, joins and
  unseals.
- **The PC restarts.** Unseal it: `bao operator unseal`, twice, one key each time.
- **A root token, once.** OpenBao keeps no root token. When configuration needs one (the first run of the
  configuration Job, the platform CAs' one-time setup), `scripts/openbao-root-access.sh mint` makes one from
  two recovery keys typed at hidden prompts and puts it straight into Secret `openbao/openbao-bootstrap`;
  `scripts/openbao-root-access.sh revoke` revokes it with itself and deletes the Secret. Recovery keys reach
  OpenBao only through each member's loopback recovery listener (`127.0.0.1:8202`, through
  `kubectl port-forward`): OpenBao refuses root-token generation and rekeying on its API listener.
- **A new cluster token.** On the PC, `-Action NewClusterToken` revokes the current token and prints a new
  one with the commands that replace the Secret. Run them, then restart the members one at a time
  (`kubectl -n openbao rollout restart statefulset openbao`), since a member reads the token when it
  starts.
- **The members' certificate** renews itself (yearly, three months before expiry) and is picked up live.
  The unseal host's certificate is renewed on the PC (`-Action RenewCertificate`); its CA does not change.
- **Backups.** The unseal host is backed up from the PC (`-Action Backup`). Velero's daily backup copies
  the members' volumes (at file level, while they run); a restored copy opens only through the unseal
  host's key. Scheduled Raft snapshots, which are consistent by construction, are not configured yet.

## The rehearsals

The component was rehearsed twice on the live cluster before it shipped, in namespace `openbao`, with
the real unseal host, and removed afterwards (volumes included). Each rehearsal initialized a throwaway
cluster whose keys were never displayed.

| Check | Result |
|---|---|
| members placed | three members on three different machines, Raft voters, one active |
| unsealing | each member unsealed by the unseal host at start, with nothing typed |
| the active member deleted | another member active within 3 to 21 seconds; the deleted one back, unsealed and Ready in 18 to 44 seconds |
| writes during that failover | none failed (the `bao` client retries a failed request twice, which can hide a sub-second blip) |
| the unseal host unreachable | a restarted member stayed sealed with its API closed; the others kept serving; it recovered 29 seconds after the host returned |
| a configuration change | rolled one member at a time, each unsealed before the next, in 69 seconds |
| the listener certificate reissued | all three members served the new certificate without a restart |
| audit | requests and responses recorded, with the client token as an HMAC |
| network | a pod in the same namespace that is not a member could not connect |
| a key created, then used at once, through a standby | reported missing when the calls came back to back; found after 50 ms, and always found through the active member |
| a wrong CA fingerprint in `config.yaml` | refused by `install.sh`, nothing changed |

## Moving the keys from Vault

An install that ran the `encryption` component has its keys in a single HashiCorp Vault. They move to
OpenBao once, by copying Vault's storage, so every key, version and ciphertext stays as it is: Vault's
Transit keys are not exportable, and re-encrypting would put customer data through the move.
[`scripts/vault-to-openbao.sh`](../scripts/vault-to-openbao.sh) does it from a temporary pod.

**What it needs from the operator:** Vault's root token and three of its unseal keys (piped from wherever
they are kept, never typed where they show), and the root token OpenBao's initialization printed.

**Expect** the keys to be unavailable for a few minutes: from the moment Vault is sealed until the clients
use OpenBao, KMS, Secrets Manager, Parameter Store secure values, and creating keys or encrypted volumes
fail. Existing encrypted volumes and running applications are not affected.

1. **Prepare** (no credentials, changes nothing): `scripts/vault-to-openbao.sh prepare` creates the
   `openbao-move` pod and checks the tools, Vault, a dry copy of its storage, OpenBao's members, the TLS
   path and the unseal host.
2. **Run** the move, in your own terminal, from the directory that holds the credentials file:

   ```sh
   { grep -E '^(export )?VAULT_(ROOT_TOKEN|UNSEAL_KEY_[123])=' .env
     read -rsp "OpenBao root token (hidden): " t </dev/tty; echo >&2; printf 'OPENBAO_ROOT_TOKEN=%s\n' "$t"; unset t
   } | kubectl -n openbao exec -i openbao-move -c move -- python3 /cfg/move.py run
   ```

   It seals Vault, copies its storage, converts it with Vault's own `vault operator migrate`, opens the copy
   in a temporary OpenBao, moves its seal to the unseal host's key, replaces the recovery keys with three
   new ones (proving two of them work), checks every key version round-trips, force-restores the copy into
   the cluster, restarts the members, checks every key version again, and revokes the root tokens the copy
   carried. If a step fails before the clients switch, it unseals Vault again: nothing has moved.
3. **Switch the clients:** merge the change that points them at `openbao-active` (VAULT_ADDR, VAULT_CACERT,
   the `openbao-client` label), let it sync, then `scripts/vault-to-openbao.sh kes` for KES's config.
4. **Finish**, in your own terminal:
   `kubectl -n openbao exec -it openbao-move -c move -- python3 /cfg/move.py finish` shows the new recovery
   keys once, waits until you confirm they are stored, and revokes the temporary root token. OpenBao then
   has no root token.
5. **Clean up:** `scripts/vault-to-openbao.sh cleanup`. Vault stays sealed with the keys' last copy until it
   is retired; then delete its volume and the credentials it no longer needs.

**Rollback:** before the clients switch, unseal Vault (the run does this itself when it stops). After, revert
the switch and unseal Vault with its keys; anything created in OpenBao since is not in Vault.

The procedure was rehearsed on synthetic data end to end (both failure paths included: a refused token
stops it before Vault is touched, and a failed copy unseals Vault again at once), and the copy itself was
rehearsed on a restored backup of real data: every Transit key version round-tripped.

## The platform's CAs

The platform has two root CAs: the platform root, which every platform certificate chains to, and the guest
AWS-endpoints root, which signs the AWS endpoint names guests reach. Clients trust these roots and nothing
else, so everything below changes where the signing keys are, never what a client trusts.

With `openbao.platformCAs: true`, the roots are **offline** and OpenBao signs through intermediates:

| ClusterIssuer | signs through | its key |
|---|---|---|
| `openinfra-ca` | `openinfra/pki-platform`, role `platform` | an intermediate OpenBao generated, signed by the platform root |
| `openinfra-aws-endpoints` | `openinfra/pki-aws-endpoints`, role `aws-endpoints` | an intermediate OpenBao generated, signed by the AWS-endpoints root |
| `openinfra-acm` | `openinfra/pki-acm`, role `acm` | the validated-domain CA, imported as it was (same certificate, name-constrained to `certificates.validatedDomains`) |

OpenBao never exports these keys. The issuers keep their names, so every Certificate that names them keeps
working.
- **Login.** Each issuer logs in with a short-lived token of ServiceAccount `cert-manager/openbao-issuer`,
  and OpenBao's role for it allows only its own signing path.
- **Published roots.** They come from ConfigMap `cert-manager/openinfra-roots`, written when the CAs moved,
  and nothing about them changes for clients.

### Moving them (once)

1. Set `openbao.platformCAs: true` in `config.yaml`, and run `scripts/openbao-root-access.sh mint`.
2. Run `scripts/openbao-pki.sh prepare`, then `run`. This does three things:
   - It creates each intermediate in OpenBao and has its root sign it through a temporary cert-manager
     Issuer, so the tool never reads a root key.
   - It imports the validated-domain CA, with the key moved by pipe.
   - It checks that each mount signs a throwaway certificate that chains to the same root.
3. Switch the issuers. A new install gets `security/openbao-issuers.yaml` in place of the CA-type issuers
   from `install.sh`. On a running install, exclude `networking/cluster-ca-root.yaml` and
   `aws-shim/guest-aws-endpoints-ca.yaml` from the root application and include
   `security/openbao-issuers.yaml`.
4. Renew the leaves (`cmctl renew --all -A`). Check that each one chains to its root.
5. Finish with `scripts/openbao-pki.sh cleanup` and `scripts/openbao-root-access.sh revoke`.

**Rollback**, while the root keys are still on the cluster: put the CA-type issuers back (undo step 3) and
renew the leaves. After step 6, restore the roots first.

### Step 6: the roots go offline

```sh
scripts/openbao-offline-roots.sh export ~/openinfra-roots.gpg
```

Run it in your own terminal. It asks for a passphrase (at least 16 characters) and writes both root keys
to the file, encrypted. The file is OpenPGP: AES-256, the passphrase stretched with salted, iterated SHA-512,
and integrity-protected, so any `gpg` opens it, including Gpg4win on Windows. The passphrase is not cached.

The command then opens the file again and checks that it matches the cluster's keys, showing each root's
subject and fingerprint. After you type `yes`, it deletes from the cluster:
- the two root keys;
- the validated-domain CA's old Secret and Certificate, whose key is now in OpenBao.

Then:
- Copy the file to two places away from the cluster, such as a USB drive you keep and your PC, and delete
  the original (`shred -u ~/openinfra-roots.gpg`).
- Keep the passphrase in a password manager, not with the file.
- Check a copy whenever you like: `scripts/openbao-offline-roots.sh check FILE` shows the same subjects and
  fingerprints.

If both the file and the passphrase are lost, the only fix is a new root, and every client has to trust it
again.

**Backups made earlier still hold the keys:**
- Velero's daily backups, until they expire (the `daily` schedule's TTL).
- k3s etcd snapshots. Scheduled ones roll off with `etcd-snapshot-retention`. Ones taken by hand stay until
  you delete them, locally and in S3: list them with `k3s etcd-snapshot ls` and remove them with
  `k3s etcd-snapshot delete NAME`.

### Rotating an intermediate

An intermediate is valid until 2031. Rotate it early if its key may have been exposed:

1. `scripts/openbao-offline-roots.sh restore FILE`
2. `scripts/openbao-root-access.sh mint`, then `scripts/openbao-pki.sh prepare`
3. Rotate one of the two:
   - `scripts/openbao-pki.sh rotate platform openinfra-root-ca-2`
   - `scripts/openbao-pki.sh rotate aws-endpoints openinfra-aws-endpoints-ca-1`
4. `scripts/openbao-offline-roots.sh unrestore`, `scripts/openbao-pki.sh cleanup`,
   `scripts/openbao-root-access.sh revoke`

The new intermediate becomes the mount's default issuer. Certificates renew through it on their own
schedule, or at once with `cmctl renew --all -A`. Those signed by the previous one keep verifying until
they expire.

**Client impact: none.** Clients trust the root, which does not change. Rehearsed live, a rotation took
6 seconds; a new leaf chained through the new intermediate, and an old one still verified.

### A change to the validated domains

The validated-domain CA is name-constrained to the list it was made for. `install.sh` warns when
`certificates.validatedDomains` changes. A certificate for a new domain needs a new CA, signed with the
offline platform root. That ceremony is not automated yet (see below).

## The aws-shim's signing keys

Three keys sign what the aws-shim issues. Each is a Transit key under `openinfra/transit`: RSA-2048, never
exportable, never backed up in plaintext. They sit in their own mount, so the tenant-key identities'
`transit/keys/+` grants cannot reach them.

| Key | Signs | Relied on for |
|---|---|---|
| `instance-identity` | EC2 instance identity documents ([Virtual machines](virtual-machines.md#signed-instance-identity-document)) | a document's lifetime, 1 hour |
| `cognito` | Cognito user pools' ID, access and refresh tokens (each pool's JWKS lists it) | a refresh token's lifetime, 30 days |
| `ecr-token` | ECR's `GetAuthorizationToken` credentials and registry tokens (the registry trusts its certificate) | a credential's lifetime, 12 hours |

**Who can use them.**
- The `openbao-setup` Job creates the keys. Its own identity can create them but cannot sign with them.
- The aws-shim signs through role `aws-shim-identity`. That role may sign with these keys (SHA-256) and read
  their public halves, and nothing else.
- ConfigMap `open-infra-aws-shim/openbao-signing-keys` tells the shim which keys to use. It exists only with
  `components.openbao`; without it, each key is kept in a Secret in the shim's namespace.

**Rotating a key.** Run `bao write -f openinfra/transit/keys/<key>/rotate` with an administrative token.
- The new version signs within a minute.
- The replaced version keeps verifying for the time in the table, then drops out of the certificates and
  the JWKS.
- After rotating `ecr-token`, restart the registries
  (`kubectl -n open-infra-ecr rollout restart deployment`): a registry reads the certificates it trusts only
  when it starts.

**Moving keys out of Secrets.** On an install that kept these keys in Secrets, the shim retires each old
key itself, the first time it runs with OpenBao:
1. It records the key's public half in a ConfigMap: `instance-identity-retired`, `cognito-retired` or
   `ecr-token-retired`, all public data.
2. Ten minutes later, once no replica of the previous version can still read the Secret, it deletes the
   Secret. A Secret holding a key the record does not is left alone.
3. What the old key signed keeps verifying from the record for the time in the table. Nobody has to sign in
   again.

Restart the registries once more after the switch, so they trust the new certificate.

## What it does not do yet

- **Vault is not retired yet.** The `encryption` component still deploys the old Vault server. On a new
  install it is unused; on an install whose keys moved, it is a sealed last copy kept as the rollback.
  Retiring it removes the server and its volume, and the setup Job moves to the `openbao` namespace with
  it.
- **Scheduled Raft snapshots** of the members are not configured yet; Velero's daily backup copies their
  volumes at file level.
- **A new validated-domain CA** for a changed `certificates.validatedDomains` list is not automated with
  the CAs in OpenBao: it needs a constrained CA signed with the restored platform root, then imported into
  `openinfra/pki-acm`.
