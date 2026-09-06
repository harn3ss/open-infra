# kube-ovn network abstractions (`kind: Vpc`, `kind: Subnet`)

Real topological network isolation — the AWS VPC/Subnet model as **enforced** objects, not a
NetworkPolicy simulation. `kind: Subnet` with `private: true` is enforced by OVN at the network
layer: a pod in one private subnet cannot reach another subnet unless explicitly allowed.

**These require the kube-ovn CNI and are inert on a Canal cluster.** That is why this directory sits
under `networking/kube-ovn/` — the root app-of-apps include glob is `networking/*.yaml`, which does
**not** match a subdirectory, so these are not synced to the current Canal-based platform. They are
enabled on the kube-ovn substrate.

- `subnet-xrd.yaml` / `subnet-composition.yaml` — `kind: Subnet` → a kube-ovn `Subnet` (via
  provider-kubernetes), `private`/`allowSubnets` → OVN-enforced isolation. `spec.acls` is the
  **Network ACL** (stateless subnet rules → `subnet.spec.acls`; structured direction/action/
  protocol/cidr/port compiled to an OVN match, or a raw `match`).
- `vpc-xrd.yaml` / `vpc-composition.yaml` — `kind: Vpc` → a kube-ovn `Vpc` (an isolated tenant
  network domain). `spec.routes` is the VPC route table (→ `staticRoutes`); `spec.peerings` is
  **VPC Peering** (→ `vpc.spec.vpcPeerings`, declared on both VPCs).
- `transitgateway-xrd.yaml` / `transitgateway-composition.yaml` — `kind: TransitGateway` → a
  subnet-less kube-ovn `Vpc` (a pure transit router) that peers every spoke and routes to each
  spoke's CIDR, giving **transitive** spoke↔spoke routing (the AWS Transit Gateway; the property
  plain peering lacks). Each spoke is also wired on its own `kind: Vpc` (a peering to the hub + a
  route to the other spokes via the hub).
- `natgateway-xrd.yaml` / `natgateway-composition.yaml` — `kind: NatGateway` → a kube-ovn
  `VpcNatGateway` (the border device). SNAT egress (AWS NAT-Gateway) via `spec.egress`; on a flat
  `/24` it also serves the Internet-Gateway role (a real routing hop that terminates + re-NATs, so a
  floating public IP reaches a private overlay pod and the return completes — which an L2 LoadBalancer
  VIP cannot).
- `elasticip-xrd.yaml` / `elasticip-composition.yaml` — `kind: ElasticIp` → a kube-ovn `IptablesEIP`
  plus an `IptablesFipRule` (`mode: fip`, 1:1 whole-IP) or `IptablesDnatRule`s (`mode: dnat`,
  per-port). The AWS Elastic IP.

## The AWS EIP + NAT/Internet-Gateway surface (#120)

The kube-ovn NAT family is dataplane-verified on a single flat `/24` (the case an L2 LoadBalancer VIP
can't crack): DNAT ingress, SNAT egress, and 1:1 FIP all complete their return path because the
`VpcNatGateway` is a real routing hop with its own conntrack + a macvlan external leg, and the VPC
default route (`kind: Vpc` `spec.routes` `0.0.0.0/0 → the gateway`) forces replies back through it.

Wiring a public front door:

1. `kind: Vpc` with a route `0.0.0.0/0 → <NatGateway internalIp>`.
2. a **public** `kind: Subnet` (`private: false`) for internet-facing workloads.
3. `kind: NatGateway` (`vpc`, `subnet`, `internalIp`; add `egress.sourceCidrs` for SNAT).
4. `kind: ElasticIp` (`natGateway`, `target`, `mode`) — the public IP + association.

**A DNAT/FIP target MUST sit on a public subnet** (`private: false`). The association preserves the
client source IP, so a private subnet's OVN isolation would drop the external-sourced ingress before
it reaches the target — the same rule AWS enforces by putting internet-facing instances in a public
subnet. Verified end-to-end 2026-09-06: a LAN client → a `kind: ElasticIp` → a private-VPC pod on a
public subnet, `[ASSURED]` bidirectional through the kind-created gateway.

These are verified live on the kube-ovn substrate (the full claim→composition→kube-ovn→dataplane
round-trip); they are inert on Canal.
