import type { IamPolicy } from "@/lib/api";

/** How a policy is classified in the list/detail Type column. */
export type PolicyTypeLabel = "Control plane" | "Data plane" | "Mixed" | "Empty";

/**
 * Classify a policy by which enforcement plane(s) it authors:
 *   - Control plane: RBAC statements (spec.statements) and/or the Cedar control-plane shadow block.
 *   - Data plane:    Cedar spec.dataPlane statements (S3/DynamoDB/Lambda at the aws-shim).
 */
export function policyType(p: IamPolicy): PolicyTypeLabel {
  const hasControl =
    (p.statements ?? []).some((s) => (s.actions ?? []).length > 0) ||
    (p.controlPlane?.statements ?? []).length > 0;
  const hasData = (p.dataPlane?.statements ?? []).length > 0;
  if (hasControl && hasData) return "Mixed";
  if (hasData) return "Data plane";
  if (hasControl) return "Control plane";
  return "Empty";
}
