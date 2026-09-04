# kube-ovn network abstractions (`kind: Vpc`, `kind: Subnet`)

Real topological network isolation — the AWS VPC/Subnet model as **enforced** objects, not a
NetworkPolicy simulation. `kind: Subnet` with `private: true` is enforced by OVN at the network
layer: a pod in one private subnet cannot reach another subnet unless explicitly allowed.

**These require the kube-ovn CNI and are inert on a Canal cluster.** That is why this directory sits
under `networking/kube-ovn/` — the root app-of-apps include glob is `networking/*.yaml`, which does
**not** match a subdirectory, so these are not synced to the current Canal-based platform. They are
enabled on the kube-ovn substrate.

- `subnet-xrd.yaml` / `subnet-composition.yaml` — `kind: Subnet` → a kube-ovn `Subnet` (via
  provider-kubernetes), `private`/`allowSubnets` → OVN-enforced isolation.
- `vpc-xrd.yaml` / `vpc-composition.yaml` — `kind: Vpc` → a kube-ovn `Vpc` (an isolated tenant
  network domain).

Isolation itself is verified live on a kube-ovn eval cluster (cross-private-subnet traffic blocked,
same-subnet allowed); the composition renders that same verified object. Enabling the full
claim→kube-ovn round-trip requires the Crossplane abstraction stack on a kube-ovn cluster.
