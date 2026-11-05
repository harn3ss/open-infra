import type { Application, Condition } from "@/types/k8s";
import type { StatusTone } from "@/lib/format";
import { awsState } from "@/lib/aws-states";

export interface AppHealth {
  label: string;
  tone: StatusTone;
}

/**
 * An Application's status in AWS's words (lib/aws-states): Available / Creating / Pending / Deleting /
 * Failed, never the Kubernetes conditions underneath.
 */
export function applicationHealth(app: Application): AppHealth {
  const s = awsState(app);
  return { label: s.label, tone: s.tone };
}

export function conditionTone(c: Condition): StatusTone {
  if (c.status === "True") return "success";
  if (c.status === "False") return "destructive";
  return "muted";
}
