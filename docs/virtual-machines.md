# Virtual Machines (`kind: VirtualMachine`)

open-infra's **EC2**: a real virtual machine on the cluster, backed by
[KubeVirt](https://kubevirt.io) (VMs on Kubernetes) and
[CDI](https://github.com/kubevirt/containerized-data-importer) (disk imaging).
Pick an OS, get a persistent disk, first-boot login, and native access (SSH for
Linux, RDP for Windows).

## Requirements

- **Hardware virtualization** (`/dev/kvm`) on the nodes — Intel VT-x or AMD-V.
  Check: `grep -oE 'vmx|svm' /proc/cpuinfo` on each node should print something.
- `components.virtualization: true` in `config.yaml` (default). `install.sh`
  installs KubeVirt + CDI from the upstream release manifests.

## Quick start

```yaml
# infra.yaml
apiVersion: openinfra.dev/v1
kind: VirtualMachine
metadata:
  name: dev-box
spec:
  os: ubuntu-24.04          # see the catalog below
  cpu: 2
  memory: 4Gi
  diskSize: 30Gi
  sshKey: "ssh-ed25519 AAAA…"   # Linux login (omit -> generated password)
  expose: false             # true -> SSH/RDP on a LAN IP (MetalLB)
```

```sh
./cli/open-infra deploy        # or: create it from the console's "New VM"
```

The platform imports the OS image to a persistent disk (CDI), boots it on
KubeVirt, and creates a connection `Secret` (`<name>-vm`) with the login. The
console's **Virtual Machines** page shows status/IP, the credentials, Start/Stop,
and how to connect.

## The OS catalog

| `os` | Family | Source |
|---|---|---|
| `ubuntu-24.04`, `ubuntu-22.04` | Linux | cloud image (containerdisk), cached once per release by the [OS image cache](#os-image-cache-ubuntu) |
| `fedora-40` | Linux | cloud image |
| `debian-12` | Linux | cloud image |
| `centos-stream-9` | Linux | cloud image |
| `windows-server-2016`, `-2019`, `-2022`, `-2025` | Windows | **clones `<os>-golden`** — build it on the VM Images page (see below). `-2016` has no auto-fetchable eval ISO, so build it with `kind: VmImage` `spec.sourceUrl` (a supplied ISO) or `spec.existingGoldenClaim` (adopt an imported disk — the migration path) |

The catalog lives in two places that must stay in sync: the XRD enum
(`platform/abstraction/vm-xrd.yaml`) and the Composition's `$catalog`
(`platform/abstraction/vm-composition.yaml`). The console mirrors it in
`ui/src/features/vms/vm-shared.ts`.

> **Architecture:** this catalog is **x86 (amd64)**. VMs therefore do not run on **arm64** nodes
> even though KubeVirt itself is arm64-capable — an arm64 host cannot boot an x86 guest. On an
> arm64-only cluster a `VirtualMachine` claim is refused at admission. See
> [architecture-support.md](architecture-support.md).

## OS image cache (Ubuntu)

Each Ubuntu image in the catalog is imported **once**, by digest, into a platform-owned **base**, and
new VMs are made from that base rather than each pulling the image from the registry. A base is a
Longhorn backing image (namespace `longhorn-system`): one stored, SHA-512-checksummed, read-only copy,
the analog of the snapshot behind an AMI.

| Root | Made from the base by |
|---|---|
| default (non-HA) | a local copy onto the VM's `local-path` disk, from a thin volume on the base that sits on the same node. The root keeps the local disk's speed (a Longhorn volume is several times slower). The VM starts once the copy is done. |
| `highAvailability: true` | a **thin copy-on-write volume on the base** (its `-ha` class: replicated, live-migratable). The VM starts at once. |
| `rootDisk.encrypted: true` | the same local copy, onto the LUKS volume. An encrypted root cannot be a layer on a shared base: Longhorn would need the base encrypted with the root's own key, and every volume on it would then share one volume key, where AWS gives each volume encrypted from an unencrypted AMI its own data key. |

`kind: AutoScalingGroup` members clone the base too: a non-HA member clones the base's import onto its
`local-path` root, an HA member clones the base's pristine thin volume.

- **Isolation.** The base is read-only underneath every volume made from it; a VM's writes land in its
  own volume, never in the base or in another VM's disk.
- **Refresh.** The `vm-base-refresh` CronJob (namespace `openinfra-images`) resolves each catalog tag to
  its digest every hour. A new digest becomes a new base, recorded in the EnvironmentConfig
  `openinfra-vm-bases`, which VMs created from then on use. Running VMs are never changed. To refresh
  now: `kubectl -n openinfra-images create job --from=cronjob/vm-base-refresh vm-base-refresh-now`.
- **Deletion.** An old base is deleted only when nothing uses it: Longhorn refuses to delete a backing
  image while any volume (attached or not) is made from it, and the refresh leaves it in place.
- **Existing VMs** keep the root they were made with. `status.rootSource` records how a VM's root was
  made (`base` or `image`) and `status.rootBase` the base.
- **Without a base** (a fresh install's first hour, or an OS outside the cache, such as Fedora or
  Debian), a VM imports its image from the registry, as before.
- The catalog of cached images is the `vm-base-catalog` ConfigMap (`openinfra-images`).

## High availability & live migration

By default a VM's root disk is `local-path` (local NVMe) — fast, but **pinned to one
node**: if that node dies the VM can't restart elsewhere. Set `highAvailability: true`
to make the VM **node-independent**:

```yaml
spec:
  os: windows-server-2019
  highAvailability: true      # root disk on Longhorn (migratable RWX block) + LiveMigrate
  cpuModel: Broadwell-noTSX   # a CPU model ALL nodes support (see below)
```

What it does:
- Root disk is provisioned on **Longhorn** as a **migratable RWX block** volume (the
  `longhorn-migratable` StorageClass, replicated across nodes) instead of `local-path`.
- The VM gets `evictionStrategy: LiveMigrate`, so:
  - **Node dies** → the VM reschedules onto another node and boots from a Longhorn replica.
  - **Node drained** (planned maintenance) → the running VM **live-migrates** off it with
    zero downtime (`kubectl drain`, or a `VirtualMachineInstanceMigration`).

### `cpuModel` — required for portability on mixed-CPU clusters

Live migration and node-loss reschedule both need a target node whose CPU can run the
guest. The default (`host-model`) pins the VM to its source node's exact CPU — fine on a
uniform cluster, but on a cluster with **different CPUs per node** it blocks all movement.
Set `cpuModel` to the **newest model every node supports**. Find it with:

```sh
# intersection of cpu-model.node.kubevirt.io/* labels across your nodes
kubectl get nodes -o json | jq -r '...'   # newest common model, e.g. Broadwell-noTSX
```

HA VMs default to `Nehalem` (a universally-safe baseline) if `cpuModel` is unset.
Changing a running VM's CPU model requires a reboot, and Windows may re-detect hardware
(possible reactivation) — back up first.

### `existingRootClaim` — adopt a pre-existing disk (migration / restore)

Boot from an existing PVC instead of cloning a fresh disk from the image:

```yaml
spec: { existingRootClaim: my-restored-disk }   # no root DataVolume is provisioned
```

Used to migrate a VM onto a disk cloned to a new storage class (e.g. `local-path` →
Longhorn) without reinstalling. To migrate an existing VM's disk: clone it to a
`longhorn-migratable` block PVC, then set `highAvailability: true` + `existingRootClaim`
+ `cpuModel`. (When adopting a claim-managed VM's disk, orphan the old DataVolume first so
it isn't garbage-collected, and apply the volume swap + template removal atomically —
KubeVirt's webhook rejects a dataVolumeTemplate that's no longer referenced.)

### `firmware` — boot mode (BIOS vs UEFI / Secure Boot)

By default a VM boots **legacy BIOS** (SeaBIOS/MBR) — the catalog's Linux cloud images and the Windows
golden images are MBR. A disk installed under **UEFI** (GPT boot + an EFI system partition, common for
modern AMIs) will *not* boot under BIOS, so set the firmware explicitly:

```yaml
spec:
  firmware:
    mode: uefi          # bios (default) | uefi (OVMF/EFI)
    secureBoot: true    # optional; requires mode: uefi (enables SMM)
    tpm: true           # optional; ephemeral vTPM 2.0 (some Secure Boot / Windows 11 guests need it)
```

**A migrated disk must declare its boot mode.** When `existingRootClaim` is set, `firmware.mode` is
**required** — the platform refuses to guess, because guessing BIOS for a UEFI-installed disk yields an
unbootable VM. Set it to the mode the disk was actually installed under.

- `secureBoot: true` needs `mode: uefi`; it selects the OVMF secure-boot firmware and enables SMM. The
  guest image must itself be Secure-Boot compatible.
- `tpm` is **ephemeral** — not persisted across recreate (persistent vTPM needs the KubeVirt
  `VMPersistentState` feature gate).
- A **fresh** `windows-server-*` clone can only be `bios` (the golden images are MBR). To run a UEFI
  Windows VM, boot a UEFI disk via `existingRootClaim`, or build a UEFI golden via `kind: VmImage`.
- UEFI/Secure Boot require a KubeVirt build with the OVMF (secure-boot) firmware on your nodes — shipped
  by default.

## AWS workload identity (`instanceRole`) — credentials at boot, no static keys

Give a VM an AWS identity the way EC2 does — a role it assumes — so the AWS SDK inside the guest gets
**rotating, temporary credentials with no static keys on disk**:

```yaml
spec:
  os: ubuntu-24.04
  instanceRole: app-role   # a kind: Role (this namespace) the VM assumes
```

The named `kind: Role` must **trust the `vm` principal** (the analog of an AWS role trusting
`ec2.amazonaws.com`), and carries whatever data-plane Policies the workload needs:

```yaml
apiVersion: iam.openinfra.dev/v1
kind: Role
metadata: { name: app-role }
spec:
  trust: ["vm"]            # opt in to being instance-assumable
  policies: [app-s3-read]  # kind: Policy objects granting the access
```

Inside the VM, the AWS CLI and every SDK resolve the role's credentials with no configuration — at first
boot from `userData`, from systemd services, from login shells, and from containers running in the guest
(`docker run amazon/aws-cli …`) — and `aws sts get-caller-identity` against the aws-shim returns
`assumed-role/<role>/<vm>`. The role's permissions are enforced at the aws-shim exactly as for any
assumed-role session.

How it works: the VM gets a dedicated ServiceAccount whose token KubeVirt projects into the guest, where
it is readable by root only. An **instance metadata agent** (started by cloud-init before `userData`
runs) presents that token to the aws-shim, which verifies it with a Kubernetes TokenReview, reads the
role off the ServiceAccount, and mints temporary credentials. A token for the ServiceAccount is not
enough by itself: it must be bound to the VM's own launcher pod — the VirtualMachineInstance must list
that pod as active and mount the ServiceAccount — so no other pod running as the same ServiceAccount
can collect the role. (ServiceAccounts named `vm-<name>` are VM identities, so an `Application` named
`vm-*` cannot use `assumeRole`.) Identity travels in the token — the source
IP is never the credential, so one VM can never obtain another's role (masquerade VMs reach cluster
services through their node's gateway address, which every VM on the node shares). The agent calls the
shim's in-cluster TLS port (`https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567`) and verifies
its certificate against the platform root CA alone, which the VM carries in its own spec (see below). The
token is sent only once that certificate verifies, so it never crosses the network in clear text, and a
host that merely answers for the shim's name (a DNS or DHCP server on a LAN-attached VM's second NIC, for
one) never receives it. The shim refuses the credentials endpoint on its plaintext port. The agent caches the
credentials and replaces them well before they expire (when a third of their lifetime is left, between 5
and 20 minutes ahead), so callers always receive credentials with ample time remaining. It hands them out
on the two endpoints the AWS SDKs read:

- **EC2 instance metadata (IMDSv1 + IMDSv2) at `http://169.254.169.254`** — the instance-profile
  provider every SDK falls back to, and the one containers in the guest use.
- **The container-credentials endpoint `http://127.0.0.1:16349/v1/vm-credentials`**, advertised as
  `AWS_CONTAINER_CREDENTIALS_FULL_URI` in `/etc/environment` and in systemd's default environment. The
  agent adds the authorization to the shim itself, so the URI alone is enough — SDKs of any age that
  know the container-credentials provider pick it up, with no token variable and no readable token
  file. It is served only with `httpTokens: optional` (it is a plain GET, i.e. IMDSv1-equivalent).

Linux guests only; a Windows VM has no instance metadata service.

## Instance metadata (`metadataOptions`) — EC2 IMDS at 169.254.169.254

Every Linux VM serves EC2 instance metadata at `http://169.254.169.254`, as an EC2 instance does — with
or without an `instanceRole`. It answers the paths SDKs and lift-and-shift scripts use:

| Path (under `/latest/`) | Value |
|---|---|
| `api/token` (`PUT`) | IMDSv2 session token (`X-aws-ec2-metadata-token-ttl-seconds`: 1–21600) |
| `meta-data/instance-id`, `ami-id` | stable EC2-shaped ids (`i-…` from the VM's UID, `ami-…` from its catalog OS) |
| `meta-data/placement/region`, `placement/availability-zone` | `us-east-1`, `us-east-1a` (the aws-shim's region) |
| `meta-data/local-ipv4`, `mac`, `hostname`, `local-hostname`, `network/interfaces/macs/…` | the guest's primary interface |
| `meta-data/security-groups` | the VM's `securityGroups` |
| `meta-data/iam/info`, `iam/security-credentials/<role>` | the instance profile and the role's credentials (only with `instanceRole`) |
| `dynamic/instance-identity/document` | JSON: `accountId` and `region` (the install's AWS identity, [`aws-identity.yaml`](aws-shim.md#the-account-region-and-partition)), `availabilityZone`, `instanceId`, `imageId`, `privateIp`, `architecture`, `pendingTime` |
| `user-data` | the VM's `userData` (404 when there is none) |

The listener runs in its own network namespace, joined to the guest by a veth pair and routed one hop
off the guest — where EC2's metadata service sits relative to an instance. Port 80 in the guest stays
free for the workload, and the IMDSv2 hop limit is the real IP TTL of the token response, so it behaves
exactly as on EC2.

```yaml
spec:
  metadataOptions:            # the AWS::EC2::Instance MetadataOptions equivalent
    httpTokens: required      # optional (default) | required
    httpPutResponseHopLimit: 2  # 1..64; default 1
    httpEndpoint: enabled     # enabled (default) | disabled
```

- **`httpTokens`** — `optional` (default): IMDSv1 (plain GET) and IMDSv2 both work, and a VM with an
  `instanceRole` also gets the loopback container-credentials endpoint. `required`: IMDSv2 only — a
  request without a valid session token gets `401`, and the container-credentials endpoint is not
  served. `required` is the SSRF-hardened setting: a token can only be obtained with a `PUT` carrying
  the TTL header, and a `PUT` that arrives with `X-Forwarded-For` (i.e. through a proxy) is refused.
  Every AWS SDK released since late 2019 speaks IMDSv2.
- **`httpPutResponseHopLimit`** — the IP TTL of the token response. With `1`, processes in the guest
  (and host-network containers) get a session token; a container behind a bridge in the guest
  (docker's default network, a pod network) is one routing hop further and needs `2`; each further hop
  needs one more. The default is `1`, EC2's default, whether or not the VM has a `metadataOptions`
  block, so a containerized workload that uses IMDSv2 sets `2`, as on EC2. IMDSv1 requests are not
  hop-limited.
- **`httpEndpoint: disabled`** — no metadata service at all: nothing on `169.254.169.254`, no
  container-credentials endpoint and no identity token in the guest, so (as on EC2) the guest gets no
  `instanceRole` credentials. The guest still trusts the platform root CA (below).

Only the guest and its own containers reach `169.254.169.254`. A packet for it that the guest would
forward for another host is dropped, whatever it arrived on: a NIC, a VLAN, a bond, a tunnel (WireGuard,
OpenVPN tun or tap, GRE, VXLAN), or a bridge port that is not a container's. Containers are recognized by
the interface kind they come in on: a `veth` (or `netkit`) end, or a bridge such as `docker0` whose ports
are all container ends. With nftables the kernel matches the kind itself, so an interface created later
is covered at once. On a kernel whose nftables cannot match by kind, and with iptables, the agent names
the container interfaces instead, and a container on a bridge that also holds a NIC or a tap is refused
too. On a guest with neither tool, the metadata namespace answers only the guest's own address: processes
in the guest and containers it NATs still reach it, a routed (non-NAT) container does not.

The agent checks the guard every 5 seconds and puts it back if something removed it (`nft flush
ruleset`, a firewall reload, `iptables -F`). While no guard is in place the metadata service answers
`503` to every request and serves nothing; it never serves unguarded.

The agent, its configuration and the platform root CA are refreshed from the VM's current spec at every
boot (a cloud-init `bootcmd` reads the NoCloud disk KubeVirt builds from the VM's cloud-init Secret at each
start, and rewrites only the agent's own files, only when they differ). A change to the agent, to
`metadataOptions` or to the platform root reaches a running VM at its next restart, not only VMs created
after it. A guest whose cloud-init caches its configuration (`manual_cache_clean: true`) or that lacks
PyYAML (cloud-init's own dependency) keeps its files; reinstall the agent there by recreating the VM.

`cfn` maps an `AWS::EC2::Instance`'s `MetadataOptions` onto this block one-to-one. Not served: the IPv6
endpoint `fd00:ec2::254` (`HttpProtocolIpv6`), instance tags in metadata (`InstanceMetadataTags`),
`meta-data/instance-type` (a VM is sized by `cpu`/`memory`; the identity document's `instanceType` is
`null`), and the signed identity document (`dynamic/instance-identity/pkcs7`, `signature`).

The agent is a single Python 3 script (standard library only, Python 3.6+ — every cloud image ships
Python because cloud-init is Python; on the RHEL 8 family it uses `/usr/libexec/platform-python`) run by
`openinfra-metadata.service`; check it with `systemctl status openinfra-metadata` and
`journalctl -u openinfra-metadata`. Its settings are in `/etc/openinfra/metadata-agent.json`.

## The platform root CA is trusted by every Linux guest

The platform's TLS endpoints — the container registry's LAN address, S3's LAN host — present
certificates issued by the cluster's root CA (the `openinfra-ca` ClusterIssuer, which only platform
namespaces may use: tenants cannot get a certificate signed by it). Every Linux VM trusts
that root out of the box, the way an enterprise CA is baked into an AMI: an unmodified guest's
`docker login` / `docker pull` against the registry, `curl`, and the AWS SDKs verify those certificates
with no `--insecure`, no `--cacert`, and no per-registry `certs.d` file.

The root certificate travels in the VM's own spec, never over the network: the aws-shim's
`platform-ca-publisher` copies it from the root Certificate into the cluster's `openinfra-platform-ca`
EnvironmentConfig, and the VM composition writes it into the guest's cloud-init
(`/etc/openinfra/platform-root-ca.pem`). At every boot,
before cloud-init runs `userData`, the metadata agent checks that the file holds PEM CA certificates and
nothing else, and adds it to the system trust store with the distribution's own tool:

| Family | Anchor | Refreshed with | Full system bundle |
|---|---|---|---|
| Debian, Ubuntu | `/usr/local/share/ca-certificates/openinfra-root-ca.crt` | `update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` |
| RHEL, CentOS Stream, Fedora, Rocky | `/etc/pki/ca-trust/source/anchors/openinfra-root-ca.crt` | `update-ca-trust extract` | `/etc/pki/tls/certs/ca-bundle.crt` |
| SUSE | `/etc/pki/trust/anchors/openinfra-root-ca.crt` | `update-ca-certificates` | `/etc/ssl/ca-bundle.pem` |

**SDKs with their own CA store.** Some clients never read the system trust store: aws-cli v2 and boto3
(which ship their own CA bundle), and Node.js (compiled-in roots), so the AWS SDK for JavaScript. For
them every Linux guest's environment carries

```sh
AWS_CA_BUNDLE=/etc/openinfra/ca-bundle.pem
NODE_EXTRA_CA_CERTS=/etc/openinfra/ca-bundle.pem
```

in `/etc/environment` (login shells), systemd's default environment (every service), and the
environment `userData` runs with. `/etc/openinfra/ca-bundle.pem` is a link the agent keeps pointing at
the distribution's **full** system bundle — every public root plus the platform root (last column
above) — refreshed after the platform root is installed. `AWS_CA_BUNDLE` *replaces* an SDK's own
roots, so it names the full bundle, never the platform root alone: public AWS endpoints and any other
public TLS host keep verifying. `NODE_EXTRA_CA_CERTS` adds to Node's roots. The link always resolves to
the system bundle, including on a guest that carries no platform root (it then holds the public roots
only), so these variables never point at a missing file. The AWS SDKs for Go and Ruby
honor `AWS_CA_BUNDLE` too; Java reads the system store (`update-ca-certificates` /
`update-ca-trust` regenerate the JDK's `cacerts` when the distribution's Java CA package is installed).
A process started before the agent, or a container in the guest, has its own environment and store.

The anchor is rewritten (and the store refreshed) only when the certificate changes. A platform without
the aws-shim component publishes no CA: nothing is installed, and an `instanceRole` gets no credentials,
since the agent cannot verify a shim without the root. A VM created before the root was published (in
the first minutes of an install) carries none until it is recreated. The guest keeps the root it was
created with; a VM created after the root changes gets the new one. Programs that load the trust store once at startup — `dockerd` among them —
see the root when they start after the agent, which is the case for anything installed or started by
`userData`. To keep a guest from installing it, set `"trustPlatformCA": false` in
`/etc/openinfra/metadata-agent.json` (and remove the anchor file if it is already there). Linux guests
only.

## AWS endpoints inside the guest

On EC2 an unmodified `aws s3 cp s3://bucket/key .` in `userData` reaches AWS through the SDK's default
endpoints. A Linux guest here makes the same call reach the aws-shim with nothing in the template: its
environment (the same three places as `AWS_CA_BUNDLE` above) also carries

```sh
AWS_ENDPOINT_URL=https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567
```

the shim's in-cluster TLS port, which serves the whole AWS surface and verifies against the platform root
through `AWS_CA_BUNDLE`. aws-cli v2 2.13 and later, and current releases of the AWS SDKs, read it for
every service (no per-service `AWS_ENDPOINT_URL_<SERVICE>` is needed: one shim serves them all). botocore
uses path-style S3 addressing against it; the JavaScript SDK v3's default `S3Client` addresses the bucket
virtual-hosted, `<bucket>.aws-shim.open-infra-aws-shim.svc.cluster.local`, which the guest resolver below
answers and the shim's certificate covers.

**The distro aws CLI v1.** Ubuntu 22.04's `awscli` 1.22 (botocore 1.23) predates `AWS_ENDPOINT_URL` and
would call AWS's own endpoints. So the guest also carries a one-line aws-cli *plugin*: the agent ships
`/usr/local/lib/openinfra/awscli-plugins/openinfra_endpoint_plugin.py`, makes it importable by the system
Python the distro CLI runs on (a `.pth` in a site directory), and lists it in a CLI config at
`/etc/openinfra/aws-config` that the environment names through `AWS_CONFIG_FILE`:

```ini
[plugins]
openinfra_endpoint = openinfra_endpoint_plugin
```

On `top-level-args-parsed` the plugin sets the endpoint from `AWS_ENDPOINT_URL` when the command gave no
`--endpoint-url` (an explicit flag always wins). aws-cli **v2** reads the same config, but ignores
`[plugins]` unless `cli_legacy_plugin_path` is set — which is deliberately left out (v1 would try to
import it as a plugin and crash) — so under v2 the plugin never loads and its own native support stays in
charge. The agent merges only the `[plugins]` section and never touches `~/.aws/config`.

**Containers.** A container does not inherit the guest's environment, so the metadata agent configures
the container engines before `userData` runs, and every container gets the same three variables and a
read-only mount of `/etc/openinfra/ca-bundle.pem` unless it sets them itself:

- **Docker:** `/etc/docker/daemon.json` gains the runtime `openinfra-aws` (an OCI runtime wrapper,
  `/usr/local/lib/openinfra/oci-aws-env`, that adds the variables and the mount to the container's spec,
  then runs the real `runc`) and makes it the default runtime. Existing `daemon.json` settings are kept,
  a running daemon is reloaded, and a default runtime the guest set itself (e.g. `nvidia`) is left alone
  (`docker run --runtime openinfra-aws` still works).
- **Podman:** a drop-in, `/etc/containers/containers.conf.d/50-openinfra-aws.conf`.

A container with `OPENINFRA_AWS_ENV=off` in its environment is left as it is. Other engines (containerd
or CRI-O used directly, a Kubernetes inside the guest) are not configured. The container still gets its
role credentials from the instance metadata service through the default chain, which needs
`metadataOptions.httpPutResponseHopLimit: 2` as on EC2.

**AWS's own hostnames.** Some calls never consult `AWS_ENDPOINT_URL`: a URL the guest carries from its
AWS-side configuration (an SQS queue URL `https://sqs.<region>.amazonaws.com/<account>/<queue>` — the
JavaScript SDK v3 sends to the queue URL's host — an image named
`<account>.dkr.ecr.<region>.amazonaws.com/<repo>`, a bucket's `https://<bucket>.s3.<region>.amazonaws.com/`
URL, an API's `execute-api` invoke URL), and SDKs that ignore it (raw botocore/boto3 before ~1.27,
aws-sdk-go v1). With the aws-shim on, guests use a resolver of their own
(`platform/aws-shim/guest-aws-endpoints.yaml`; the VMI's `dnsConfig`, which KubeVirt's DHCP hands the
guest) that answers the `amazonaws.com` names of the services the shim serves with the shim's address and
`<account>.dkr.ecr.<region>.amazonaws.com` with the registry's, and forwards every other name to the
cluster DNS. The platform serves those names with certificates from the **AWS endpoints CA**, a root of
its own, name-constrained to `amazonaws.com`, that guests trust beside the platform root (the agent
installs it as a second anchor, so `/etc/openinfra/ca-bundle.pem` carries it). LAN workstations never
trust it: they import the platform root only. A guest that calls SQS by an AWS name is answered with queue
URLs in that shape; the queue is recorded under the shim's own URL, so no other caller is handed an
`amazonaws.com` URL.

The resolver takes effect when the VM next starts. `networking.guestAwsEndpoints: false` turns it off (the
cluster DNS again). Not covered: AWS names of services the shim does not serve (`ec2`, `ssmmessages`, and
so on resolve to AWS as before), S3's dash-region and dualstack names, and other partitions' domains —
those still leave the cluster unless guest egress to AWS is blocked. A guest cannot download anonymously
from a bucket on AWS (an agent installer in a public bucket): every `<bucket>.s3…amazonaws.com` name is
answered by the platform.

## Extra data disks (`dataDisks`) — the EC2 BlockDeviceMapping analog

Attach additional persistent disks at boot, beyond the root — e.g. a dedicated disk for a database:

```yaml
spec:
  diskSize: 20Gi
  dataDisks:
    - { name: pgdata, size: 100Gi }
    - { name: secrets, size: 10Gi, encrypted: true, encryptionKey: db-key }  # LUKS at rest
    - { name: sdf, size: 50Gi, deviceName: /dev/sdf }                         # also /dev/sdf, /dev/xvdf
```

Each is a blank block volume attached as a virtio device in order. The kernel names are virtio
(`/dev/vd*`), and the cloud-init seed disk is a virtio disk too, so `vd*` order does not say which disk is
which. Instead every disk carries a serial, and udev rules keyed by it **alias the AWS names** onto the
right disk:

| Alias | Disk |
|---|---|
| `/dev/nvme0n1` (+ `p1`, `p2`, …) | the root |
| `/dev/nvme1n1`, `/dev/nvme2n1`, … (+ partitions) | the data disks in order, then attached `volumes` |
| a disk's `deviceName` and its sd/xvd twin (`/dev/sdf` and `/dev/xvdf`, + `sdf1`, …) | that disk |

So a lift-and-shift `userData` script that formats/mounts by a hard-coded `/dev/nvme1n1` or `/dev/sdf`
path works unmodified (the aliases exist before the script runs). Tools that report kernel names
(`lsblk`, `/proc/mounts`) show `/dev/vd*`; you can also reference a disk by filesystem UUID/label. Each follows the root's storage policy (`highAvailability` → longhorn-migratable
RWX block so they live-migrate with the VM, else local-path) and is retained across reboots and
stop/start. The guest partitions/formats/mounts them.

**Encryption at rest.** Set `encrypted: true` + `encryptionKey: <kind: EncryptionKey name>` to put a
data disk on LUKS (Longhorn `longhorn-encrypted`), keyed by a Vault Transit data key wrapped by that
`EncryptionKey` — destroying the key crypto-erases the disk (the EC2 `Ebs.Encrypted` analog; `cfn` maps
an encrypted `BlockDeviceMapping` whose `KmsKeyId` references an in-stack `AWS::KMS::Key`). Requires the
opt-in encryption component. An encrypted disk is **RWO** (there is no encrypted+migratable class), so on
a `highAvailability` VM it pins live migration — keep encrypted data on a non-HA VM, or accept that the
VM won't live-migrate while it's attached.

**An encrypted root disk.** `rootDisk: { encrypted: true, encryptionKey: <kind: EncryptionKey name> }`
stores the root disk the same way: LUKS on `longhorn-encrypted`, keyed by that key (the EC2 root
`BlockDeviceMapping.Ebs.Encrypted` analog; `cfn` maps an encrypted root mapping, with no `KmsKeyId` to the
stack's default key). CDI cannot write an encrypted device, so the OS image is imported to a temporary
unencrypted disk (the pristine catalog image, never tenant data) and, once that import has succeeded, a
pod copies it onto the encrypted root (the boot record last, so an interrupted copy is simply redone);
the VM stays stopped until then (a few minutes on a 20Gi root), and `status.rootPopulated` records that
the copy is done so it never runs again. The temporary disk and the copy pod are deleted after the copy. An encrypted root is RWO, so it cannot be combined with `highAvailability` (no live migration)
or `existingRootClaim`, and `rootDisk` is fixed at creation.

## Access

- **Linux** — SSH as `openinfra`. Your `sshKey` is installed via cloud-init; a
  generated password is also set (revealable on the VM page) as a fallback.
- **Windows** — RDP as `Administrator` with a generated password (revealable on
  the VM page). Connect with `mstsc /v:<host>:3389`.
- **`expose: true`** publishes a `LoadBalancer` (MetalLB) so workstations on the
  LAN can reach SSH (22) / RDP (3389) directly. Otherwise use
  `kubectl port-forward svc/<name> <port>:<port>`. Once MetalLB assigns the address,
  the VM reports it as **`status.lanIp`**
  (`kubectl get virtualmachines.openinfra.dev <name> -o jsonpath='{.status.lanIp}'`);
  it is empty while unassigned and when the VM is not exposed.
- **`elasticIp: { allocationId: eipalloc-… }`** gives an exposed VM the address an Elastic IP
  allocation holds, instead of one of its own: a CloudFormation `AWS::EC2::EIP` allocated by another
  stack (see [CloudFormation](cloudformation.md), "An address kept in its own stack"). The allocation is a
  holder Service in the same namespace; the VM's LAN Service shares its address, so the address follows
  whichever VM names the allocation and stays with the allocation when the VM goes. Until the allocation
  reports its address, the VM gets no LAN Service at all.

Power: the console's **Start/Stop** flips `spec.running`, which the Composition
maps to KubeVirt `runStrategy` (`Always`/`Halted`). The disk is retained while
stopped. `status.powerState` is the VM's state as KubeVirt reports it (`Running`,
`Stopped`, `Starting`…), and `status.restartRequired` is true while the running VM was
started from an earlier spec: a change to its CPU, memory, user data or disks takes effect
when it is stopped and started (a CloudFormation update does that itself).

Delete: deleting a VM through the console (or `kubectl delete virtualmachines.openinfra.dev
<name>`) removes the whole stack — the KubeVirt VM, the disk (DataVolume/PVC), and any
**LAN `LoadBalancer`**, so the pool IP is released. ⚠️ The kind name `VirtualMachine` exists
in **both** `openinfra.dev` (the claim) and `kubevirt.io` (the composed VM), so a bare
`kubectl delete vm <name>` is ambiguous and may hit the kubevirt.io VM — which Crossplane
then recreates (and the LB is *not* released). Always delete via the console or the
fully-qualified `virtualmachines.openinfra.dev`.

> Web (in-browser) console is intentionally **not** provided — access is native
> SSH / RDP, so there is no extra in-cluster console dependency to run.

## Networking: NAT vs direct-LAN (macvtap)

`spec.network` controls how the VM attaches:

- **`masquerade`** (default) — the VM sits behind the pod network (NAT). Reach it
  in-cluster via its `Service`, or from the LAN via `expose: true` (a MetalLB
  LoadBalancer hands it a LAN IP). The pod overlay (`10.42/16`) is **not** routable
  from your LAN, which is why a raw pod IP isn't reachable from a workstation.
- **`macvtap`** — the VM joins the **physical LAN directly** via a macvtap device on
  the parent NIC and pulls a real **DHCP lease** from your router. It's a first-class
  LAN host — no MetalLB, no NAT — reachable on *every* port (e.g. SMB/445, which is
  outside the NodePort range), keeping a pod NIC (eth0) as well for in-cluster access.
- **`bridge`** — *legacy, does not work on this stack.* It tried to bind a macvlan
  sub-interface with KubeVirt's bridge binding, but a macvlan interface cannot be a
  KubeVirt bridge port (the VMI crash-loops `pod link is missing`). Use `macvtap`.

### Opening extra ports (masquerade)

A masquerade VM is reachable on its access port (SSH 22 / RDP 3389) plus whatever
its **security groups** allow — exposure follows the firewall, so there's a single
place to manage access (see [security-groups.md](security-groups.md)). To expose a
web server on 80, add an inbound `HTTP` rule to a `SecurityGroup` attached to the VM;
the platform publishes the matching LAN listener automatically (same MetalLB LAN IP
as SSH/RDP, no bridge needed). In the console this is the VM's **Network** tab: the
**Reachable ports** list is read-only and follows the rules, and you attach/edit
groups under **Security groups** — there's no separate "publish a port" control.

> Under the hood the LoadBalancer's listeners live in `spec.ports`; the console keeps
> that list in sync with the attached security groups (each specific inbound port
> becomes a listener). The guest must actually be listening on the port. For a *full*
> LAN host (every port, a real DHCP IP), use `network: macvtap` instead.

### Enabling direct-LAN (macvtap) mode

Direct-LAN mode needs Multus (a cluster CNI change), so it's opt-in — but it's a
config flag, not a manual step. In `config.yaml`:

```yaml
networking:
  vmLan:
    enabled: true
    interface: eno1     # your LAN NIC
```

then re-run the installer:

```sh
./install.sh            # idempotent
```

`install.sh` layers **Multus** on as the primary CNI (delegating the default network
to Cilium — this requires Cilium's `cni.exclusive=false`, which the installer sets),
installs the macvlan + **macvtap** plugins into the CNI bin dir, deploys the
**macvtap device plugin** (exposing the LAN NIC as `macvtap.network.kubevirt.io/<iface>`),
registers the **macvtap KubeVirt binding**, creates the
`default/openinfra-lan-macvtap` NetworkAttachmentDefinition, and **auto-labels every
node that actually has `interface`** with `openinfra.dev/vm-lan=true` (so direct-LAN
VMs schedule only where they can work — NIC names may differ per node). Then:

```yaml
spec:
  os: ubuntu-24.04
  network: macvtap       # real LAN IP via DHCP, first-class LAN host
```

> **Cilium note.** Cilium ships `cni.exclusive=true`, which evicts any other CNI
> config so Multus is bypassed and NADs never attach. The installer sets
> `cni.exclusive=false`; on a cluster where Cilium was installed before this, re-run
> `install.sh` (it flips the flag and tells you to `rollout restart ds/cilium`).

**Caveats**
- **NIC names may differ per node** (e.g. `eno1` vs `enp4s0`); the device plugin/NAD
  target one parent NIC, so only nodes that have it can host direct-LAN VMs.
  `install.sh` detects this and labels just those nodes `openinfra.dev/vm-lan=true`
  (the VM carries a matching node affinity) — no manual labelling.
- **macvtap limitation**: the *host node* cannot talk to its own macvtap VMs (other
  LAN hosts can) — a kernel macvtap/macvlan property. Announce MetalLB VIPs from a
  different node than the one hosting the VM if the VM must reach them.
- The VM still keeps a pod NIC (eth0) for in-cluster/Service access; the LAN lease
  lands on eth1.

## Windows: build the golden image (in the console)

Windows has no redistributable cloud image, so you build a reusable **golden
image** once per version, then every `os: windows-server-*` VM clones it (fast).
It's a click — no scripts.

### Licensing (read this)

- **Evaluation editions are free and legal for testing/non-production only.**
  Windows Server eval = 180 days.
  Download is handled for you from the [Microsoft Evaluation Center](https://www.microsoft.com/evalcenter).
- **Production Windows VDI/desktops require Microsoft licensing** (VDA / Windows
  Enterprise E3+ / RDS CALs). open-infra does not and cannot provide that — it is
  not open source. Linux VMs have no such constraint.

### Build it

Console → **Virtual Machines → VM Images** → pick a version (Server 2019 / 2022 /
2025) → **Build**. Or declaratively:

```yaml
apiVersion: openinfra.dev/v1
kind: VmImage
metadata: { name: windows-server-2022, namespace: openinfra-images }
spec:
  os: windows-server-2022       # sourceUrl: <override> if the catalog fwlink ever moves
```

The `VmImage` Composition (`platform/abstraction/vmimage-composition.yaml`):

1. CDI imports the official eval ISO (a verified Microsoft `fwlink`) + virtio-win.
2. A **sysprep ConfigMap** carries the unattended answer file (per-version edition
   + virtio driver path; FirstLogonCommands install virtio guest tools +
   **cloudbase-init** + RDP, then `sysprep /generalize /shutdown`).
3. An **installer VM** (`runStrategy: Once`) writes the golden disk and powers off
   after sysprep. The disk survives as `<os>-golden` in `openinfra-images`.

The VM Images page shows progress (Building → Ready); when Ready, that version
becomes selectable in **New VM** (it's greyed out until then). A build downloads
~5 GB and runs an unattended install — 20–40 minutes.

Goldens are stored on **Longhorn** (replicated), so provisioning a Windows VM —
which clones `<os>-golden` — doesn't depend on any single node being up. To move an
already-built golden to a different storage class without rebuilding, clone it to a
new PVC and set `existingGoldenClaim: <that-pvc>` on the `VmImage` — it adopts the
clone and skips the ISO/installer steps.

## Desktops & workspaces

open-infra's answer to **AWS WorkSpaces** is a VM, not a separate abstraction:

- **Windows desktop** — `os: windows-server-2022` (or 2019/2025) is the *Desktop Experience* edition.
  Connect with `mstsc /v:<host>:3389` as `Administrator` using the generated
  password shown on the VM's page. (Per the licensing note above, eval is
  non-production only.)
- **Linux desktop** — start from any Linux `os` and install a desktop + RDP on
  first boot, e.g. add to `infra.yaml`:
  ```yaml
  # (cloud-init runcmd — Ubuntu example)
  # apt-get install -y xubuntu-desktop xrdp && systemctl enable --now xrdp
  ```
  then RDP in (or just use SSH/X-forwarding).
- **Per-user** — give each person their own VM (one claim each); the disk
  persists across stop/start. Expose on the LAN (`expose: true`) or port-forward.

Access is **native** (RDP/SSH), so there's no in-browser desktop gateway to run.

## Troubleshooting

- **Disk stuck importing** — watch CDI: `kubectl get datavolume -n <ns> <name>-root -w`.
  First import of an OS pulls the cloud image (hundreds of MB); later VMs of the
  same OS reuse the CDI image cache.
- **VM Pending, never Running** — confirm `/dev/kvm` on the node and that
  KubeVirt is `Deployed`: `kubectl get kubevirt -n kubevirt`.
- **No IP shown** — the guest agent reports the IP; Linux installs
  `qemu-guest-agent` via cloud-init on first boot (give it a minute).
- **Windows VM won't boot** — its `<os>-golden` image must be built first (VM
  Images page → Build, wait for Ready).
