// RDS DB instance classes -> the CPU/memory an open-infra managed database requests.
//
// This is an EXACT mirror of `rdsInstanceClasses` in cfn/translate.go (#114). The console and
// CloudFormation MUST agree on the class -> cpu/memory correspondence, so both read the same table.
// If you add/change a class here, change it there too (and vice versa).
//
// HONEST LIMITS (identical to the Go table's contract): open-infra does NOT model t-class burst
// credits (a burstable class gets its full vCPU as a dedicated request — more, not less), nor
// EBS-optimized throughput, nor Aurora's distributed storage. The correspondence is only the
// class's published vCPU/RAM, requested as dedicated Kubernetes resources. A class not in this
// table is not offered — open-infra does not guess a class's sizing.

export interface RdsInstanceClass {
  /** RDS instance class name, e.g. "db.m5.large". */
  id: string;
  /** vCPU count, submitted as spec.database.cpu (e.g. "2"). */
  cpu: string;
  /** Memory, submitted as spec.database.memory (e.g. "8Gi"). */
  memory: string;
}

export interface RdsInstanceClassGroup {
  label: string;
  classes: RdsInstanceClass[];
}

/**
 * Grouped for the create-database dropdown, in the same order (and pairing) as the Go table.
 * Sentinel "default" (engine default, cpu/memory omitted) is handled by the form, not listed here.
 */
export const RDS_INSTANCE_CLASS_GROUPS: RdsInstanceClassGroup[] = [
  {
    // burstable general purpose (t3 / t4g) — vCPU/RAM mapped; burst-credit accounting does not apply
    label: "Burstable (t3 / t4g)",
    classes: [
      { id: "db.t3.micro", cpu: "2", memory: "1Gi" },
      { id: "db.t4g.micro", cpu: "2", memory: "1Gi" },
      { id: "db.t3.small", cpu: "2", memory: "2Gi" },
      { id: "db.t4g.small", cpu: "2", memory: "2Gi" },
      { id: "db.t3.medium", cpu: "2", memory: "4Gi" },
      { id: "db.t4g.medium", cpu: "2", memory: "4Gi" },
      { id: "db.t3.large", cpu: "2", memory: "8Gi" },
      { id: "db.t4g.large", cpu: "2", memory: "8Gi" },
      { id: "db.t3.xlarge", cpu: "4", memory: "16Gi" },
      { id: "db.t4g.xlarge", cpu: "4", memory: "16Gi" },
      { id: "db.t3.2xlarge", cpu: "8", memory: "32Gi" },
      { id: "db.t4g.2xlarge", cpu: "8", memory: "32Gi" },
    ],
  },
  {
    // general purpose (m5 / m6g / m6i)
    label: "General purpose (m5 / m6g / m6i)",
    classes: [
      { id: "db.m5.large", cpu: "2", memory: "8Gi" },
      { id: "db.m6g.large", cpu: "2", memory: "8Gi" },
      { id: "db.m6i.large", cpu: "2", memory: "8Gi" },
      { id: "db.m5.xlarge", cpu: "4", memory: "16Gi" },
      { id: "db.m6g.xlarge", cpu: "4", memory: "16Gi" },
      { id: "db.m6i.xlarge", cpu: "4", memory: "16Gi" },
      { id: "db.m5.2xlarge", cpu: "8", memory: "32Gi" },
      { id: "db.m6g.2xlarge", cpu: "8", memory: "32Gi" },
      { id: "db.m6i.2xlarge", cpu: "8", memory: "32Gi" },
      { id: "db.m5.4xlarge", cpu: "16", memory: "64Gi" },
      { id: "db.m6g.4xlarge", cpu: "16", memory: "64Gi" },
      { id: "db.m6i.4xlarge", cpu: "16", memory: "64Gi" },
    ],
  },
  {
    // memory optimized (r5 / r6g)
    label: "Memory optimized (r5 / r6g)",
    classes: [
      { id: "db.r5.large", cpu: "2", memory: "16Gi" },
      { id: "db.r6g.large", cpu: "2", memory: "16Gi" },
      { id: "db.r5.xlarge", cpu: "4", memory: "32Gi" },
      { id: "db.r6g.xlarge", cpu: "4", memory: "32Gi" },
      { id: "db.r5.2xlarge", cpu: "8", memory: "64Gi" },
      { id: "db.r6g.2xlarge", cpu: "8", memory: "64Gi" },
    ],
  },
];

/** Flat class-name -> {cpu, memory} lookup, mirroring the Go map. */
export const RDS_INSTANCE_CLASSES: Record<string, RdsInstanceClass> = Object.fromEntries(
  RDS_INSTANCE_CLASS_GROUPS.flatMap((g) => g.classes).map((c) => [c.id, c]),
);

/** Human label for a class option, e.g. "db.m5.large — 2 vCPU, 8 GiB". */
export function formatRdsInstanceClass(c: RdsInstanceClass): string {
  const gib = c.memory.replace(/Gi$/, "");
  return `${c.id} — ${c.cpu} vCPU, ${gib} GiB`;
}
