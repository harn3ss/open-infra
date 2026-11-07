# OpenBao: the platform's key and secrets service

> **Operator guide.** This page is for the operator who runs the cluster, so it uses Kubernetes terms
> (namespaces, pods, `kubectl`). Customers never see OpenBao: they use KMS, Secrets Manager and the other
> AWS APIs, which the platform serves on top of it.

OpenBao keeps the platform's keys: the keys behind KMS and Secrets Manager, `kind: EncryptionKey`, and
the CAs and signing keys being moved out of Kubernetes Secrets (#359). It is the Linux Foundation's
MPL-2.0 fork of HashiCorp Vault, chosen because Vault 1.15 and later are under the BUSL, which does not
suit a project that is given away.

**Status: built and rehearsed; opt-in, off by default** (`components.openbao`). The rehearsals below were
run on a live cluster. Today's keys still live in the single-node HashiCorp Vault
([`encryption.md`](encryption.md)). Moving them onto OpenBao is a separate step the operator approves, and
until then OpenBao holds nothing and nothing uses it.

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
- **A new cluster token.** On the PC, `-Action NewClusterToken` revokes the current token and prints a new
  one with the commands that replace the Secret. Run them, then restart the members one at a time
  (`kubectl -n openbao rollout restart statefulset openbao`), since a member reads the token when it
  starts.
- **The members' certificate** renews itself (yearly, three months before expiry) and is picked up live.
  The unseal host's certificate is renewed on the PC (`-Action RenewCertificate`); its CA does not change.
- **Backups.** The unseal host is backed up from the PC (`-Action Backup`). Scheduled Raft snapshots of the
  members come with the configuration step, when OpenBao first holds something to back up.

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

## What it does not do yet

It holds no keys. KMS, Secrets Manager, STS, `kind: EncryptionKey` and the private CAs still run on
Vault. Moving them is the next part of #359, in steps the operator approves one at a time, each announced
with a rollback: the keys themselves, the PKI intermediates and the cert-manager issuer, instance-identity
signing, and encryption of Kubernetes Secrets at rest.
