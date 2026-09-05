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

## Why there is no VPC or Subnet (a deliberate non-goal)

open-infra has **no `Network`/`VPC` or `Subnet` kind, by design** — not an unfinished
feature. AWS uses the VPC/subnet as the primary isolation boundary because EC2 instances
share a flat L2/L3 fabric that must be carved up. Kubernetes inverts that: the cluster is
one flat pod network, and isolation is expressed by **policy over identity**, not by
address ranges. Faking a VPC/subnet onto a `NetworkPolicy` would mean inventing an address
partition that nothing actually enforces — a boundary that reads real but isn't.

So the AWS network-isolation model maps like this:

| AWS | open-infra | why |
|---|---|---|
| VPC / subnet segmentation | `kind: SecurityGroup` (SG-to-SG rules) | isolation is by workload identity, not address range — an app in the `web` SG reaches the `db` SG only if a rule says so, independent of where either pod lands |
| Security group (the SG itself) | `kind: SecurityGroup` | direct equivalent, enforced by Cilium |
| NACL / CIDR edge rules | `SecurityGroup` CIDR rules | CIDR matches **external** sources at the edge (see *Enforcement semantics* above) |
| Route tables / IGW / NAT / peering | *(no counterpart)* | cluster networking + egress are the substrate's job, not an app-level kind |

If a migration tool reports `aws_vpc` / `aws_subnet` as untranslatable, that is the
**correct** answer to surface to a human — the target is "model isolation with Security
Groups," not "recreate the VPC." This is a decided position, so the answer is *"open-infra
deliberately does not model subnets; use Security Groups"* rather than *"unsupported."*

## See also

- [architecture.md](architecture.md) — where Security Groups sit in the AWS map.
- [virtual-machines.md](virtual-machines.md) — exposing VM ports on the LAN.
- [aws-migration.md](aws-migration.md) — the Terraform/open-transform resource mapping, including this non-goal.
