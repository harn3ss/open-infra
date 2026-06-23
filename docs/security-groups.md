# Security Groups (`kind: SecurityGroup`)

open-infra's **AWS Security Group**: a named, reusable set of firewall rules you
define once and attach to resources (`Application`, `Function`, `VirtualMachine`)
by name. Like an AWS SG, it's **stateful** (return traffic is implied) and
**default-deny** on the directions you define — only what you allow gets through.

Enforced by **Cilium** (the cluster CNI), so rules can match real IP/CIDR ranges
at the edge, other Security Groups, or whole namespaces.

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

```yaml
kind: VirtualMachine
spec:
  os: ubuntu-24.04
  expose: true
  ports: [{ port: 22 }]
  securityGroups: [bastion-access]   # restrict who can reach SSH
```

## Enforcement semantics (read this)

Security Groups compile to Kubernetes **NetworkPolicies** enforced by Cilium.
Two behaviors matter:

1. **CIDR rules match *external* sources, not in-cluster pods.** Cilium identifies
   in-cluster pods by *identity*, so a `cidr:` rule governs edge/LAN traffic — use
   `securityGroup:` / `namespace:` peers to restrict pod-to-pod (east-west). This
   mirrors AWS, where CIDR is for the edge and SG-to-SG is for internal tiers.
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

The **Security Groups** page creates rule sets AWS-style: each rule is a **Type**
(SSH, RDP, HTTP, HTTPS, PostgreSQL, … — which fills in the protocol and port for
you) plus a **Source/Destination** (Anywhere, a custom CIDR, another security
group, or a namespace). Outbound left empty = all outbound allowed; add outbound
rules to restrict it (DNS stays allowed). Attach to a VM from its **Network** tab,
or to an app/function via `securityGroups` on create.

## Default access on a new VM

Like the EC2 launch wizard, **New VM** opens the OS access port by default — it
creates a `<name>-access` security group allowing **SSH (22) for Linux / RDP (3389)
for Windows** (source defaults to *Anywhere*, with a warning — scope it for real
use), plus same-namespace traffic so the VM stays reachable in-cluster. Untick it
for a locked-down VM, or add HTTP/HTTPS. The group is a normal `SecurityGroup` you
can edit afterwards.

## See also

- [architecture.md](architecture.md) — where Security Groups sit in the AWS map.
- [virtual-machines.md](virtual-machines.md) — exposing VM ports on the LAN.
