import type { Condition } from "@/types/k8s";
import type { StatusTone } from "@/lib/format";

/**
 * A resource's state in AWS's words. open-infra resources report Kubernetes-style `Ready` / `Synced`
 * conditions underneath; an AWS user reads a resource as Available / Creating / Deleting / Failed, and some
 * services have words of their own (a Lambda function is Active, a feature group Created). The console
 * shows those, never "Ready", "Synced", "ReconcileError" or "Terminating".
 */
export type Lifecycle = "available" | "creating" | "pending" | "deleting" | "failed";

export interface AwsState {
  label: string;
  tone: StatusTone;
  /** Where the resource is in its lifecycle, independent of the service's own word for it. */
  lifecycle: Lifecycle;
  /** Why it failed or is waiting, when its conditions say (for a tooltip or a detail row). */
  detail?: string;
}

type Words = Record<Lifecycle, string>;

const DEFAULT_WORDS: Words = {
  available: "Available",
  creating: "Creating",
  pending: "Pending",
  deleting: "Deleting",
  failed: "Failed",
};

/** Each service's own state names, as its AWS console and API show them. */
const SERVICE_WORDS: Record<string, Partial<Words>> = {
  // Lambda GetFunction State: Pending | Active | Inactive | Failed
  function: { available: "Active", creating: "Pending" },
  // Step Functions DescribeStateMachine status: ACTIVE | DELETING
  statemachine: { available: "Active" },
  // SageMaker DescribeFeatureGroup FeatureGroupStatus: Creating | Created | CreateFailed | Deleting | DeleteFailed
  featuregroup: { available: "Created", failed: "Create failed" },
  // SageMaker DescribeMonitoringSchedule MonitoringScheduleStatus: Pending | Failed | Scheduled | Stopped
  modelmonitor: { available: "Scheduled", creating: "Pending" },
  // EventBridge Scheduler GetSchedule State: ENABLED | DISABLED
  scheduledjob: { available: "Enabled" },
  // Directory Service Stage: Requested | Creating | Created | Active | Inoperable | Impaired | Failed
  directory: { available: "Active" },
  // SES identity VerificationStatus: Pending | Success | Failed (shown as Verified)
  emailsender: { available: "Verified", creating: "Pending" },
  // An Elastic IP has no state on AWS; it is allocated or it is not
  elasticip: { available: "Allocated" },
  // EC2 DescribeFlowLogs FlowLogStatus: ACTIVE
  flowlog: { available: "Active" },
  // VPCs, subnets, NAT and transit gateways: pending | available | deleting | failed
  network: { creating: "Pending" },
  // CloudFront distribution Status: InProgress | Deployed
  staticsite: { available: "Deployed", creating: "In progress", pending: "In progress" },
  // Kinesis StreamStatus: CREATING | DELETING | ACTIVE | UPDATING
  stream: { available: "Active" },
  // ACM Private CA Status: CREATING | PENDING_CERTIFICATE | ACTIVE | DELETED | DISABLED | EXPIRED | FAILED
  pki: { available: "Active" },
  // AppSync, Auto Scaling, RDS, EBS, EFS and the rest: Available / Creating / Deleting / Failed
};

const TONES: Record<Lifecycle, StatusTone> = {
  available: "success",
  creating: "warning",
  pending: "warning",
  deleting: "warning",
  failed: "destructive",
};

interface Stateful {
  metadata: { deletionTimestamp?: string };
  status?: unknown;
}

/** The lifecycle a resource's conditions describe, and the message behind it. */
export function lifecycleOf(obj: Stateful): { lifecycle: Lifecycle; detail?: string } {
  if (obj.metadata.deletionTimestamp) return { lifecycle: "deleting" };
  const conditions = ((obj.status as { conditions?: Condition[] } | undefined)?.conditions ?? []) as Condition[];
  const ready = conditions.find((c) => c.type === "Ready");
  const synced = conditions.find((c) => c.type === "Synced");
  // Some kinds also publish a plain status.ready flag (an email sender, a user pool).
  const flag = (obj.status as { ready?: boolean } | undefined)?.ready === true;
  if (ready?.status === "True" || flag) return { lifecycle: "available" };
  if (synced?.status === "False") return { lifecycle: "failed", detail: synced.message || synced.reason };
  if (ready?.status === "False") {
    // Crossplane says Ready=False both while a resource is being created ("Creating") and once it has
    // failed ("Unavailable" with a message); only the latter is a failure.
    if (ready.reason === "Creating" || ready.reason === "Deleting") {
      return { lifecycle: ready.reason === "Deleting" ? "deleting" : "creating" };
    }
    return { lifecycle: "failed", detail: ready.message || ready.reason };
  }
  if (conditions.length === 0) return { lifecycle: "pending" };
  return { lifecycle: "creating" };
}

/**
 * A resource's state in AWS's words. `service` picks the service's own state names (see SERVICE_WORDS);
 * without it the generic Available / Creating / Pending / Deleting / Failed apply.
 */
export function awsState(obj: Stateful, service?: string): AwsState {
  const { lifecycle, detail } = lifecycleOf(obj);
  const words = { ...DEFAULT_WORDS, ...(service ? SERVICE_WORDS[service] : undefined) };
  return { label: words[lifecycle], tone: TONES[lifecycle], lifecycle, detail };
}
