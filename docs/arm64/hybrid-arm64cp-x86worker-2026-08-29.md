# #45 — hybrid arm64-control-plane + x86-worker: verifying the theorized Windows-VmImage path

**Run date:** 2026-08-29. **Status of the hypothesis: DISPROVEN as stated, but achievable with a fix.**

Issue #45 theorized (never run) that an **arm64 control plane** running Crossplane + KubeVirt, with an
**x86 worker** joined, should build and boot a Windows `VmImage` — because Crossplane only renders YAML
(arch-irrelevant) and KubeVirt would place the x86 VM on the x86 node on its own. This is the actual run.

## Topology (real, this run)

- **arm64 control plane:** a native aarch64 Lima VM on an Apple M2 Max (`lima-openinfra-arm64-cp`,
  `192.168.254.198`), k3s **v1.36.4+k3s1** server + a slim open-infra install (crossplane + KubeVirt/CDI +
  Longhorn; Cilium CNI). Separate cluster from the `.194` production cluster on the same LAN.
- **x86 worker:** `chaos-node-1` (amd64, `/dev/kvm` present), temporarily moved out of `.194` and joined
  to this cluster, no taint. Rejoined to `.194` at teardown.

## Predictions — which held, which were wrong

1. **"Crossplane renders arch-independently; its own arch is irrelevant to what it orchestrates."**
   ✅ **HELD.** Crossplane on the arm64 CP rendered the `vmimage` composition correctly — the three
   DataVolumes (winiso/virtio/golden), the sysprep ConfigMap, and the installer VirtualMachine, all into
   the `openinfra-images` namespace, byte-for-byte as on an all-amd64 cluster.

2. **"The build workload runs on the x86 worker."** ✅ **HELD.** Every CDI importer pod scheduled onto
   `chaos-node-1` (the x86 node), not the arm64 CP.

3. **"KubeVirt places the x86 VM on the x86 node on its own — Kubernetes doing what it's for."**
   ❌ **WRONG as stated — this is the headline finding.** KubeVirt's `virt-api` **validating webhook runs
   on the arm64 control plane and rejects the x86 `q35` machine type at ADMISSION**, before any
   scheduling: `spec.template.spec.domain.machine.type is not supported: q35 (allowed values: [virt*])`.
   The x86 installer VM is therefore never created and never reaches the x86 node. Crucially, the x86
   worker **does** advertise q35 (`machine-type.node.kubevirt.io/q35: true`, `kubevirt.io/schedulable:
   true`) — but virt-api's allowed machine types derive from the **control-plane architecture**, not the
   aggregate of node capabilities. So the naive hypothesis ("Kubernetes just handles it") is false:
   KubeVirt admission is arch-gated at the control plane.

   ✅ **BUT it CAN be made to work (proven this run).** Two changes lift the block:
   - Set `KubeVirt` CR `spec.configuration.architectureConfiguration.amd64` (emulatedMachines `q35*`,
     `pc-q35*`, machineType `q35`, ovmfPath).
   - Set the VM's `spec.template.spec.architecture: amd64` (open-infra's `vmimage` composition omitted
     this; it hardcoded `q35` with no architecture, so the arch was inferred as the CP's arm64).
   With both, a test `architecture: amd64` q35 VM (fedora) **admitted, scheduled on chaos-node-1, and
   reached Running** — a native x86 VM on the x86 worker, orchestrated from the arm64 CP. The Windows
   installer VM then did the same once the composition declared `architecture: amd64`.

4. **"Storage is the likely blocker; a Longhorn replica on the arm64 node breaks the x86 VM; fix = pin
   image storage to the x86 node."** ⚠️ **A storage blocker DID occur (prediction of a snag held), but the
   mechanism differed and the predicted FIX was exactly right.** Actual mechanism: Longhorn had **no disks
   at all** on the fresh cluster — open-infra sets `create-default-disk-labeled-nodes: true` (to fence
   chaos nodes off storage on `.194`) and no node carried the label, so every volume went `faulted`
   (0 replicas schedulable). Also, the arm64 CP's 60 GB can't hold the 64 Gi golden. **Fix (matches #45's
   prediction — pin image storage to the x86 node):** label only `chaos-node-1` for a Longhorn default
   disk + set `default-replica-count: 1`. The predicted "cross-arch replica breaks the VM" case never
   arose — and wouldn't, since Longhorn attaches via the engine on the workload's node regardless of
   replica placement.

## Other findings (environmental — not arch — but real, and cost real time)

- **Fresh-bootstrap deadlocks** (same class as #43): the app-of-apps sync dead-locked on (a) discovering
  `snapshot.storage.k8s.io/v1` before the external-snapshotter CRDs existed (fix: apply the CRDs first +
  restart the argocd application-controller to refresh its discovery cache), and (b) RBAC `auth reconcile`
  into namespaces of disabled components (fix: create the empty namespaces).
- **A real bug in #41's admission machinery.** The `kind-satisfiable` CronJob accumulates its per-kind
  result inside a piped `while` loop (a subshell), so the variable is empty after the loop and it writes an
  **empty** `openinfra-kind-satisfiable` ConfigMap. The `openinfra-arch-satisfiable` ValidatingAdmissionPolicy
  then **errors closed** — its `params.data == null` guard throws `no such key: data` on an
  exists-but-empty ConfigMap (`parameterNotFoundAction: Allow` only helps when the CM is absent). Worth
  fixing in the main repo (accumulate outside the pipe; guard `has(params.data)` in the CEL).
- **Node-repurposing leaves network residue that breaks pod egress.** Moving `chaos-node-1` between two
  Cilium clusters left a stale `/etc/cni/net.d/00-multus.conf` (→ `multus-shim` sandbox timeouts) and stale
  `OLD_CILIUM_*` iptables chains (→ **pods had no external egress**, so CDI couldn't fetch the ISO).
  `k3s-agent-uninstall.sh` cleans neither. Removing the multus config fixed sandboxing; a **node reboot**
  (a Cilium pod restart did not) cleared the iptables residue and restored pod egress.

## Done-when

- [x] Stand up the topology (arm64 CP + x86 worker joined).
- [x] `kind: VmImage` os: windows-server-2022 → the installer virt-launcher **scheduled on the x86 node**
  (`chaos-node-1`) — *after* the arch fix; before it, admission rejected q35.
- [x] golden build ran to sysprep-shutdown (installer VM `Stopped`/VMI `Succeeded` via runStrategy:Once)
  and `windows-server-2022-golden` survives (`VmImage` READY=True; golden PVC Bound) — with the
  `architecture: amd64` composition fix.
- [x] `kind: VirtualMachine` os: windows-server-2022 cloned the golden and **booted on the x86 node**
  (`chaos-node-1`): `phase=Running`, `arch=amd64`, `machine=pc-q35-rhel9.8.0`, guest agent connected,
  `guestOSInfo="Windows Server 2022 Standard Evaluation"`, **IP 10.42.1.149** — with the same
  `architecture: amd64` fix applied to the `vm` composition.
- [x] Storage recorded (above): no-disk faulting → pin to the x86 node.
- [x] This dated evidence file; predictions-held/wrong called out above.
- [x] Mac not returned (it is the Lima CP host, present for the whole run).

## Bottom line

#45's core hypothesis is **wrong out of the box**: an arm64 KubeVirt control plane refuses to admit an
x86 (`q35`) VirtualMachine, so the Windows build never starts — even with a capable x86 worker present.
It is **not** "Kubernetes doing what it is for."

But the end goal **is achievable, and was proven end-to-end this run** once two deliberate multi-arch
changes were applied live: (1) KubeVirt CR `spec.configuration.architectureConfiguration.amd64`, and
(2) `spec.template.spec.architecture: amd64` on the installer VM (`vmimage` comp) and the VM (`vm` comp).
With those, `kind: VmImage` built the **Windows Server 2022 golden** on the x86 worker and `kind:
VirtualMachine` **booted it** (`Running` on chaos-node-1, guest agent up, IP 10.42.1.149) — all
orchestrated from the arm64 control plane.

**Follow-up (not shipped here — #45 was verification, not implementation):** to make hybrid
arm64-CP + x86-worker a supported topology, open-infra would need to (a) set the KubeVirt amd64
`architectureConfiguration` at install time (`install.sh` / the KubeVirt CR) and (b) add
`architecture: {{ $vmArch }}` to the `vm`/`vmimage` compositions (harmless on single-arch amd64, since
that is the inferred arch anyway). The composition edits were applied only to this throwaway cluster and
are **not** committed to main; a dedicated issue should carry the full, tested feature.
