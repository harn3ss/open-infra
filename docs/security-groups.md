# Security Groups (`kind: SecurityGroup`)

open-infra's **AWS Security Group**: a named, reusable set of firewall rules you
define once and attach to resources (`Application`, `Function`, `VirtualMachine`)
by name. Like an AWS SG, it's **stateful** (return traffic is implied) and
**default-deny** on the directions you define — only what you allow gets through.

Enforced by **kube-ovn** (the cluster CNI) via OVN ACLs, so rules can match real
IP/CIDR ranges (including `ipBlock`/CIDR, which is enforced — verified), other
Security Groups, or whole namespaces.

## Quick start

```yaml
# infra.yaml — define a SecurityGroup, then attach it
apiVersion: openinfra.dev/v1
kind: SecurityGroup
metadata:
  name: web
spec:
  ingress:
    - protocol: TCP
      ports: [80, 443]
      from:
        - cidr: 0.0.0.0/0           # public HTTP/HTTPS
  egress:
    - protocol: TCP
      ports: [5432]
      to:
        - securityGroup: db         # may reach the "db" SG only (+ DNS, auto)
---
apiVersion: openinfra.dev/v1
kind: SecurityGroup
metadata:
  name: db
spec:
  ingress:
    - protocol: TCP
      ports: [5432]
      from:
        - securityGroup: web        # only the web tier may connect
---
apiVersion: openinfra.dev/v1
kind: Application
metadata:
  name: storefront
spec:
  image: ghcr.io/acme/storefront:latest
  port: 8080
  securityGroups: [web]             # attach — the app's pods become "web" members
```

## The rule model

A `SecurityGroup` has `ingress` (inbound) and/or `egress` (outbound) rules. Each
rule is a protocol + ports + a list of peers:

| Field | Meaning |
|---|---|
| `protocol` | `TCP` (default) or `UDP` |
| `ports` | list of ports to allow; **empty = all ports** |
| `from` / `to` | sources (ingress) / destinations (egress), OR'd together |

Each peer in `from`/`to` is exactly one of:

| Peer | Matches | Use for |
|---|---|---|
| `cidr: 192.0.2.0/24` | an IP range | **edge / LAN** sources (external clients) |
| `securityGroup: web` | members of another SG | **east-west** tiering (web→db) |
| `namespace: kube-system` | all pods in a namespace | east-west by namespace |

- **Omit `ingress`** → the SG doesn't restrict inbound. **Omit `egress`** → it
  doesn't restrict outbound. Define a direction (even empty) to default-deny it.
- **Egress + DNS**: if you set *any* egress rule, DNS (UDP/TCP 53 to `kube-system`)
  is **allowed automatically** so the workload can still resolve names.

## Attaching to resources

Add `securityGroups: [<name>, …]` to an `Application`, `Function`, or
`VirtualMachine`. The platform stamps each member pod with
`openinfra.dev/sg-<name>=""`, and the SG's NetworkPolicy selects that label —
so attaching/detaching is just editing the list.

**Changes apply live — no restart.** Like EC2, editing a *running* resource's
`securityGroups` takes effect within seconds. For Apps/Functions the Deployment
rolls; for **VMs** the launcher pod's labels are reconciled in place (a KubeVirt
launcher pod is only label-stamped at creation, so a background reconciler in the
console backend keeps a running VM's `openinfra.dev/sg-*` labels in sync with its
spec — the CNI then enforces the new rules without a reboot).

```yaml
kind: VirtualMachine
spec:
  os: ubuntu-24.04
  expose: true
  ports: [{ port: 22 }]
  securityGroups: [bastion-access]   # restrict who can reach SSH
```

## Enforcement semantics (read this)

Security Groups compile to Kubernetes **NetworkPolicies** enforced by kube-ovn
(OVN ACLs). Two behaviors matter:

1. **CIDR rules match by IP — edge *and* in-cluster.** kube-ovn enforces
   `ipBlock`/CIDR against the actual source IP (verified: a client inside an
   allowed CIDR reaches the target, one outside is blocked). Because kube-ovn
   gives pods real routable IPs from their `kind: Subnet`, a `cidr:` rule can also
   govern east-west between subnets. Still prefer `securityGroup:` / `namespace:`
   peers for pod-to-pod by label/identity (stable across pod IP churn) — CIDR is
   clearest for edge/LAN and for whole-subnet tiers, mirroring AWS's CIDR-for-edge,
   SG-to-SG-for-internal split. (Under the previous CNI, CIDR rules did not
   reliably match; that non-enforcement gap is closed under kube-ovn.)
2. **For real client-IP filtering at the edge**, the traffic must arrive with the
   client's source IP. A `VirtualMachine`/`Application` exposed via a MetalLB
   LoadBalancer preserves it (the platform sets `externalTrafficPolicy: Local`).
   HTTP that arrives through the Ingress controller is proxied, so the source seen
   is Traefik — filter those by hostname/Ingress, not pod CIDR.

SGs are **additive** to the platform's baseline isolation: an `Application`
already gets a tenant NetworkPolicy allowing same-namespace + the ingress
controller. Security Groups layer *additional* allowed sources and (the clean
win) **egress restrictions** on top.

## How it works

```
kind: SecurityGroup ──► Crossplane composition ──► NetworkPolicy
   from/to:                                          spec.podSelector:
     cidr          ─────────────────────────►          openinfra.dev/sg-<name>: ""
     securityGroup ─► podSelector(sg label)         spec.ingress/egress:
     namespace     ─► namespaceSelector                from/to peers + ports
   (egress set)    ─► auto DNS allow                 policyTypes from what you define
```

The member label (`openinfra.dev/sg-<name>`) is the join: resource compositions
stamp it on pods; the SecurityGroup's NetworkPolicy selects it. Cross-namespace
`securityGroup:` references resolve within the SG's own namespace (NetworkPolicy
podSelectors are namespace-local).

## In the console

Modelled on the EC2 experience — managed from **two sides that stay in sync**:

- **The security group** (Security Groups page → click a group): a detail page with
  **Inbound rules** / **Outbound rules** tabs, a **Used by** tab (which resources
  reference it), and **Edit rules**. Each rule is a **Type** (SSH, RDP, HTTP,
  PostgreSQL, … which fills in the protocol + port for you) plus a
  **Source/Destination** (Anywhere, a custom CIDR, another security group, or a
  namespace) and an optional **description**. Also **Copy to new** and Delete.
  Outbound left empty = all outbound allowed; add outbound rules to restrict it
  (DNS stays allowed).
- **The resource** (a VM / App / Function / **Database**'s **Security** tab): the attached groups
  plus the **aggregated inbound/outbound rules** across all of them — read-only,
  each row tagged with the group it came from — and **Change security groups** to
  attach/detach. Rule editing always happens on the group, so the resource view and
  the group view always agree. This mirrors AWS: the *instance* manages membership;
  the *security group* owns the rules.

## Default access on a new VM

Like the EC2 launch wizard, **New VM** opens the OS access port by default — it
creates a `<name>-access` security group allowing **SSH (22) for Linux / RDP (3389)
for Windows** (source defaults to *Anywhere*, with a warning — scope it for real
use), plus same-namespace traffic so the VM stays reachable in-cluster. Untick it
for a locked-down VM, or add HTTP/HTTPS. The group is a normal `SecurityGroup` you
can edit afterwards.

## Network isolation: identity-first, not address-range

open-infra's **primary isolation boundary is `kind: SecurityGroup` (workload identity), not a
VPC/subnet address range** — by design. AWS uses the VPC/subnet as the primary isolation boundary
because EC2 instances share a flat L2/L3 fabric that must be carved up. Kubernetes inverts that:
isolation is expressed by **policy over identity**, so an app in the `web` SG reaches the `db` SG
only if a rule says so, independent of where either pod lands. Reaching for an address partition to
express *isolation* would invent a boundary that reads real but isn't.

`kind: Vpc` and `kind: Subnet` **do** exist — kube-ovn provides per-tenant overlay networks and
subnets, used for genuine network segmentation, VLAN/LAN integration, and faithful estate mirrors.
They are the *networking substrate*, not the workload-isolation primitive: use them when you need
real separate networks, and Security Groups to say who may talk to whom.

So the AWS network-isolation model maps like this:

| AWS | open-infra | why |
|---|---|---|
| VPC / subnet *for isolation* | `kind: SecurityGroup` (SG-to-SG rules) | isolation is by workload identity, not address range — an app in the `web` SG reaches the `db` SG only if a rule says so, independent of where either pod lands |
| VPC / subnet *as a network* | `kind: Vpc` / `kind: Subnet` | kube-ovn per-tenant overlay networks + subnets, when you genuinely need separate address spaces |
| Security group (the SG itself) | `kind: SecurityGroup` | direct equivalent, enforced by the CNI (kube-ovn) |
| NACL / CIDR edge rules | `SecurityGroup` CIDR rules | CIDR matches **external** sources at the edge (see *Enforcement semantics* above) |
| Route tables / peering | `kind: Vpc` (`spec.routes` / `spec.peerings`) | `spec.routes` **is** the VPC route table (→ kube-ovn static routes); `spec.peerings` is VPC Peering (a /30 interconnect declared on both VPCs, non-transitive like AWS → kube-ovn `vpcPeerings`) |
| Transit gateway | `kind: TransitGateway` | transitive hub-and-spoke routing across VPCs |
| NAT / internet gateway | `kind: NatGateway` | the border device: it NATs private-subnet egress **and** fills the internet-gateway routing-hop role (a real hop that terminates + re-NATs, with EIP / floating-IP association). There is **no separate `InternetGateway` kind** — the NatGateway device is both |

> **Substrate dependency.** `kind: Vpc` / `Subnet` / `NatGateway` / `TransitGateway` and the VPC
> routes/peerings above require **kube-ovn** as the active CNI; they are **inert on the default
> Canal substrate** (the `platform/networking/kube-ovn/` manifests are not even synced there — see
> that directory's `README.md`). Which substrate a cluster runs is an operator decision. `kind:
> SecurityGroup` remains the portable isolation primitive; the address-plan kinds carry this CNI
> dependency.

For **workload isolation**, a migration should map `aws_vpc`/`aws_subnet` security boundaries to
Security Groups ("who may talk to whom"), not recreate the address plan. Where the estate needs the
actual networks reproduced, `kind: Vpc` / `kind: Subnet` (and the routing kinds above, on kube-ovn)
are the targets.

## See also

- [architecture.md](architecture.md) — where Security Groups sit in the AWS map.
- [virtual-machines.md](virtual-machines.md) — exposing VM ports on the LAN.
- [aws-migration.md](aws-migration.md) — the Terraform/open-transform resource mapping.
