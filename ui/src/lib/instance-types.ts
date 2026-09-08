// AWS-style named instance types for the console's create flows (VM/EC2, Function/Lambda, ML jobs).
//
// AWS makes you pick a *named instance type* rather than typing raw vCPU/RAM; these catalogs give
// open-infra the same experience. Each entry carries the exact spec-field values the create page
// overlays when it is chosen — so the picker is the only sizing control the user touches, and the
// underlying Kubernetes resource requests (cpu/memory/gpu) are set for them.
//
// HONEST LIMITS — the correspondence is only the type's published vCPU/RAM (and, for GPU types, a
// single accelerator mapped to one of open-infra's two real GPU classes). open-infra does NOT model
// t-class burst credits, EBS-optimized throughput, network baselines, NVMe instance storage, or
// multi-GPU/NUMA topology. A type whose sizing open-infra cannot honestly schedule is not offered
// (e.g. multi-GPU ml.p*/ml.g5.12xlarge — the cluster has one A2000 + one RTX 3090, so gpu>1 would
// never schedule). Raw/arbitrary cpu/memory is still expressible via YAML / the Terraform provider.

/** One selectable instance type and the spec-field values choosing it applies. */
export interface InstanceType {
  /** Type name, e.g. "t3.medium", "ml.g4dn.xlarge", or a Lambda memory tier id "1024". */
  id: string;
  /** Human label for the option/trigger, e.g. "t3.medium — 2 vCPU, 8 GiB". */
  label: string;
  /**
   * The spec fields this type sets, with their exact types (VM cpu is an integer, ML cpu is a
   * quantity string, gpu is an integer, …). The create page overlays these verbatim.
   */
  values: Record<string, unknown>;
}

export interface InstanceTypeGroup {
  label: string;
  types: InstanceType[];
}

/** Look up a type by id across a set of groups (for the create page's overlay). */
export function findInstanceType(groups: InstanceTypeGroup[], id: string): InstanceType | undefined {
  for (const g of groups) {
    const t = g.types.find((t) => t.id === id);
    if (t) return t;
  }
  return undefined;
}

/**
 * Reverse lookup for detail/list views: the named type whose values EXACTLY match a resource's spec.
 * A type matches only when every field it sets is present on the spec with the same value (compared as
 * strings, so cpu 2 and "2" match). Returns undefined for a resource sized outside the catalog (raw
 * cpu/memory, or a field left at the XRD default) — callers fall back to the raw sizing.
 */
export function matchInstanceType(
  groups: InstanceTypeGroup[],
  spec: Record<string, unknown> | undefined | null,
): InstanceType | undefined {
  if (!spec) return undefined;
  for (const g of groups) {
    for (const t of g.types) {
      const keys = Object.keys(t.values);
      if (keys.every((k) => spec[k] !== undefined && spec[k] !== null && String(spec[k]) === String(t.values[k]))) {
        return t;
      }
    }
  }
  return undefined;
}

// ── EC2 (kind: VirtualMachine) ────────────────────────────────────────────────────────────────
// cpu is an integer (KubeVirt domain.cpu.cores); memory is a Kubernetes quantity. Root disk size
// (diskSize) is a separate control, like an EC2 root EBS volume — not part of the instance type.
export const EC2_INSTANCE_TYPES: InstanceTypeGroup[] = [
  {
    label: "General purpose — burstable (t3)",
    types: [
      { id: "t3.micro", label: "t3.micro — 2 vCPU, 1 GiB", values: { cpu: 2, memory: "1Gi" } },
      { id: "t3.small", label: "t3.small — 2 vCPU, 2 GiB", values: { cpu: 2, memory: "2Gi" } },
      { id: "t3.medium", label: "t3.medium — 2 vCPU, 4 GiB", values: { cpu: 2, memory: "4Gi" } },
      { id: "t3.large", label: "t3.large — 2 vCPU, 8 GiB", values: { cpu: 2, memory: "8Gi" } },
      { id: "t3.xlarge", label: "t3.xlarge — 4 vCPU, 16 GiB", values: { cpu: 4, memory: "16Gi" } },
      { id: "t3.2xlarge", label: "t3.2xlarge — 8 vCPU, 32 GiB", values: { cpu: 8, memory: "32Gi" } },
    ],
  },
  {
    label: "General purpose (m5)",
    types: [
      { id: "m5.large", label: "m5.large — 2 vCPU, 8 GiB", values: { cpu: 2, memory: "8Gi" } },
      { id: "m5.xlarge", label: "m5.xlarge — 4 vCPU, 16 GiB", values: { cpu: 4, memory: "16Gi" } },
      { id: "m5.2xlarge", label: "m5.2xlarge — 8 vCPU, 32 GiB", values: { cpu: 8, memory: "32Gi" } },
      { id: "m5.4xlarge", label: "m5.4xlarge — 16 vCPU, 64 GiB", values: { cpu: 16, memory: "64Gi" } },
    ],
  },
  {
    label: "Compute optimized (c5)",
    types: [
      { id: "c5.large", label: "c5.large — 2 vCPU, 4 GiB", values: { cpu: 2, memory: "4Gi" } },
      { id: "c5.xlarge", label: "c5.xlarge — 4 vCPU, 8 GiB", values: { cpu: 4, memory: "8Gi" } },
      { id: "c5.2xlarge", label: "c5.2xlarge — 8 vCPU, 16 GiB", values: { cpu: 8, memory: "16Gi" } },
      { id: "c5.4xlarge", label: "c5.4xlarge — 16 vCPU, 32 GiB", values: { cpu: 16, memory: "32Gi" } },
    ],
  },
  {
    label: "Memory optimized (r5)",
    types: [
      { id: "r5.large", label: "r5.large — 2 vCPU, 16 GiB", values: { cpu: 2, memory: "16Gi" } },
      { id: "r5.xlarge", label: "r5.xlarge — 4 vCPU, 32 GiB", values: { cpu: 4, memory: "32Gi" } },
      { id: "r5.2xlarge", label: "r5.2xlarge — 8 vCPU, 64 GiB", values: { cpu: 8, memory: "64Gi" } },
    ],
  },
];

// ── Lambda (kind: Function) ───────────────────────────────────────────────────────────────────
// AWS Lambda is sized by MEMORY alone; CPU is allocated proportionally by the platform. open-infra
// Function has a `memory` request (no cpu field) — so this is a memory-tier picker, mirroring the
// AWS Lambda memory presets. Values map an AWS memory tier (MB) to a Kubernetes quantity of the same
// magnitude in mebibytes (128 MB → "128Mi"; the two differ by <5%). GPU is an open-infra extension
// AWS Lambda lacks and is left as a separate control.
export const LAMBDA_MEMORY_TIERS: InstanceTypeGroup[] = [
  {
    label: "Memory",
    types: [
      { id: "128", label: "128 MB", values: { memory: "128Mi" } },
      { id: "256", label: "256 MB", values: { memory: "256Mi" } },
      { id: "512", label: "512 MB", values: { memory: "512Mi" } },
      { id: "1024", label: "1024 MB", values: { memory: "1024Mi" } },
      { id: "1769", label: "1769 MB (≈1 vCPU-equivalent on AWS)", values: { memory: "1769Mi" } },
      { id: "2048", label: "2048 MB", values: { memory: "2048Mi" } },
      { id: "3008", label: "3008 MB", values: { memory: "3008Mi" } },
      { id: "4096", label: "4096 MB", values: { memory: "4096Mi" } },
      { id: "5120", label: "5120 MB", values: { memory: "5120Mi" } },
      { id: "6144", label: "6144 MB", values: { memory: "6144Mi" } },
      { id: "8192", label: "8192 MB", values: { memory: "8192Mi" } },
      { id: "10240", label: "10240 MB (max)", values: { memory: "10240Mi" } },
    ],
  },
];

// ── SageMaker (kind: TrainingJob / ProcessingJob / BatchTransform) ─────────────────────────────
// ml.* instance types → cpu (quantity), memory (quantity), gpu (integer count), gpuTier (open-infra
// GPU class). gpu is ALWAYS set explicitly (TrainingJob's gpu defaults to 1, so a CPU type must send
// gpu:0). GPU types map their single accelerator to one of open-infra's two real classes:
//   ml.g4dn (NVIDIA T4)  → smallgpu (A2000 class)
//   ml.g5   (NVIDIA A10G) → largegpu (RTX 3090 class)
export const SAGEMAKER_INSTANCE_TYPES: InstanceTypeGroup[] = [
  {
    label: "Standard (ml.m5) — CPU",
    types: [
      { id: "ml.m5.large", label: "ml.m5.large — 2 vCPU, 8 GiB", values: { cpu: "2", memory: "8Gi", gpu: 0 } },
      { id: "ml.m5.xlarge", label: "ml.m5.xlarge — 4 vCPU, 16 GiB", values: { cpu: "4", memory: "16Gi", gpu: 0 } },
      { id: "ml.m5.2xlarge", label: "ml.m5.2xlarge — 8 vCPU, 32 GiB", values: { cpu: "8", memory: "32Gi", gpu: 0 } },
      { id: "ml.m5.4xlarge", label: "ml.m5.4xlarge — 16 vCPU, 64 GiB", values: { cpu: "16", memory: "64Gi", gpu: 0 } },
    ],
  },
  {
    label: "Compute optimized (ml.c5) — CPU",
    types: [
      { id: "ml.c5.xlarge", label: "ml.c5.xlarge — 4 vCPU, 8 GiB", values: { cpu: "4", memory: "8Gi", gpu: 0 } },
      { id: "ml.c5.2xlarge", label: "ml.c5.2xlarge — 8 vCPU, 16 GiB", values: { cpu: "8", memory: "16Gi", gpu: 0 } },
      { id: "ml.c5.4xlarge", label: "ml.c5.4xlarge — 16 vCPU, 32 GiB", values: { cpu: "16", memory: "32Gi", gpu: 0 } },
    ],
  },
  {
    label: "Accelerated — small GPU (ml.g4dn · T4 → A2000 class)",
    types: [
      { id: "ml.g4dn.xlarge", label: "ml.g4dn.xlarge — 4 vCPU, 16 GiB, 1 GPU (smallgpu)", values: { cpu: "4", memory: "16Gi", gpu: 1, gpuTier: "smallgpu" } },
      { id: "ml.g4dn.2xlarge", label: "ml.g4dn.2xlarge — 8 vCPU, 32 GiB, 1 GPU (smallgpu)", values: { cpu: "8", memory: "32Gi", gpu: 1, gpuTier: "smallgpu" } },
    ],
  },
  {
    label: "Accelerated — large GPU (ml.g5 · A10G → RTX 3090 class)",
    types: [
      { id: "ml.g5.xlarge", label: "ml.g5.xlarge — 4 vCPU, 16 GiB, 1 GPU (largegpu)", values: { cpu: "4", memory: "16Gi", gpu: 1, gpuTier: "largegpu" } },
      { id: "ml.g5.2xlarge", label: "ml.g5.2xlarge — 8 vCPU, 32 GiB, 1 GPU (largegpu)", values: { cpu: "8", memory: "32Gi", gpu: 1, gpuTier: "largegpu" } },
    ],
  },
];
