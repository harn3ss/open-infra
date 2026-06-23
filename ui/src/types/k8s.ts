/**
 * Minimal Kubernetes API typings — only the fields the console reads.
 * These intentionally avoid the full @kubernetes/client-node surface to keep
 * the bundle small and the types honest about what the BFF returns.
 */

export interface ObjectMeta {
  name: string;
  namespace?: string;
  uid?: string;
  resourceVersion?: string;
  creationTimestamp?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  deletionTimestamp?: string;
  ownerReferences?: { kind: string; name: string; uid: string }[];
}

export interface K8sObject<TSpec = unknown, TStatus = unknown> {
  apiVersion?: string;
  kind?: string;
  metadata: ObjectMeta;
  spec?: TSpec;
  status?: TStatus;
}

export interface ListMeta {
  resourceVersion?: string;
  continue?: string;
}

export interface K8sList<T extends K8sObject = K8sObject> {
  apiVersion?: string;
  kind?: string;
  metadata: ListMeta;
  items: T[];
}

/** A k8s watch event as delivered over the BFF's SSE channel. */
// BOOKMARK is a resourceVersion checkpoint (no real object payload) sent when
// the watch is opened with allowWatchBookmarks=true — never a list member.
export type WatchEventType = "ADDED" | "MODIFIED" | "DELETED" | "BOOKMARK";

export interface WatchEvent<T extends K8sObject = K8sObject> {
  type: WatchEventType;
  object: T;
}

export interface Condition {
  type: string;
  status: "True" | "False" | "Unknown";
  reason?: string;
  message?: string;
  lastTransitionTime?: string;
}

/* ----------------------------- Core workloads ----------------------------- */

export interface PodSpec {
  nodeName?: string;
  containers?: { name: string; image?: string }[];
}

export interface ContainerStatus {
  name: string;
  ready: boolean;
  restartCount: number;
  image?: string;
  state?: Record<string, unknown>;
}

export interface PodStatus {
  phase?: string;
  podIP?: string;
  hostIP?: string;
  startTime?: string;
  reason?: string;
  conditions?: Condition[];
  containerStatuses?: ContainerStatus[];
}

export type Pod = K8sObject<PodSpec, PodStatus>;

export interface DeploymentSpec {
  replicas?: number;
  selector?: { matchLabels?: Record<string, string> };
  template?: { spec?: PodSpec };
}

export interface DeploymentStatus {
  replicas?: number;
  readyReplicas?: number;
  availableReplicas?: number;
  updatedReplicas?: number;
  unavailableReplicas?: number;
  conditions?: Condition[];
}

export type Deployment = K8sObject<DeploymentSpec, DeploymentStatus>;

export interface ServicePort {
  name?: string;
  port: number;
  targetPort?: number | string;
  protocol?: string;
  nodePort?: number;
}

export interface ServiceSpec {
  type?: string;
  clusterIP?: string;
  clusterIPs?: string[];
  ports?: ServicePort[];
  selector?: Record<string, string>;
}

export interface ServiceStatus {
  loadBalancer?: { ingress?: { ip?: string; hostname?: string }[] };
}

export type Service = K8sObject<ServiceSpec, ServiceStatus>;

/* ------------------------------ Networking ------------------------------ */

export interface IngressSpec {
  ingressClassName?: string;
  rules?: {
    host?: string;
    http?: {
      paths?: {
        path?: string;
        pathType?: string;
        backend?: { service?: { name?: string; port?: { number?: number } } };
      }[];
    };
  }[];
  tls?: { hosts?: string[]; secretName?: string }[];
}
export interface IngressStatus {
  loadBalancer?: { ingress?: { ip?: string; hostname?: string }[] };
}
export type Ingress = K8sObject<IngressSpec, IngressStatus>;

export interface NetworkPolicySpec {
  podSelector?: { matchLabels?: Record<string, string> };
  policyTypes?: string[];
  ingress?: unknown[];
  egress?: unknown[];
}
export type NetworkPolicy = K8sObject<NetworkPolicySpec, unknown>;

export interface NodeSpec {
  podCIDR?: string;
  taints?: { key: string; value?: string; effect: string }[];
  unschedulable?: boolean;
}

export interface NodeStatus {
  capacity?: Record<string, string>;
  allocatable?: Record<string, string>;
  conditions?: Condition[];
  nodeInfo?: {
    kubeletVersion?: string;
    osImage?: string;
    architecture?: string;
    containerRuntimeVersion?: string;
    kernelVersion?: string;
  };
  addresses?: { type: string; address: string }[];
}

export type Node = K8sObject<NodeSpec, NodeStatus>;

export interface EventObj extends K8sObject {
  reason?: string;
  message?: string;
  type?: string; // Normal | Warning
  count?: number;
  lastTimestamp?: string;
  eventTime?: string;
  firstTimestamp?: string;
  involvedObject?: {
    kind?: string;
    name?: string;
    namespace?: string;
  };
  source?: { component?: string; host?: string };
  reportingComponent?: string;
}

/* ----------------------- open-infra Application CRD ------------------------ */

export interface ApplicationSpec {
  image: string;
  port: number;
  domain?: string;
  scaling?: {
    min?: number;
    max?: number;
    targetCPUPercent?: number;
  };
  database?: { engine?: string; name?: string; highAvailability?: boolean };
  storage?: { buckets?: string[] };
  queues?: string[];
  env?: { name: string; value: string }[];
  secrets?: string[];
  securityGroups?: string[];
}

export interface ApplicationStatus {
  url?: string;
  conditions?: Condition[];
}

export type Application = K8sObject<ApplicationSpec, ApplicationStatus>;

/** open-infra Application group/version/resource constants. */
export const OPENINFRA_GROUP = "openinfra.dev";
export const OPENINFRA_VERSION = "v1";
export const APPLICATIONS_PLURAL = "applications";

/* ------------------------ open-infra Function CRD ------------------------- */

export interface FunctionSpec {
  image: string;
  port?: number;
  gpu?: number;
  scaling?: { min?: number; max?: number; target?: number };
  queues?: string[];
  env?: { name: string; value: string }[];
  secrets?: string[];
  securityGroups?: string[];
  trigger?: { stream?: string; subject?: string }; // event-source mapping: CDC Stream -> this fn
}

/** Serverless (Knative) Function. Named OpenInfraFunction to avoid shadowing the global `Function`. */
export type OpenInfraFunction = K8sObject<FunctionSpec, ApplicationStatus>;
export const FUNCTIONS_PLURAL = "functions";
export const FUNCTIONS_CRD_NAME = "functions.openinfra.dev";

/* -------------------------- open-infra Model CRD -------------------------- */

export interface ModelSpec {
  model: string;
  gpu?: number;
  /** Run two replicas across nodes (load-balanced, survives a node loss). */
  highAvailability?: boolean;
  domain?: string;
  storageSize?: string;
}

export interface ModelStatus {
  endpoint?: string;
  model?: string;
  conditions?: Condition[];
}

export type Model = K8sObject<ModelSpec, ModelStatus>;
export const MODELS_PLURAL = "models";
export const MODELS_CRD_NAME = "models.openinfra.dev";

/* ---------------------- open-infra VirtualMachine CRD --------------------- */

export interface VirtualMachineSpec {
  os: string;
  cpu?: number;
  memory?: string;
  diskSize?: string;
  sshKey?: string;
  expose?: boolean;
  running?: boolean;
  ports?: { port: number; protocol?: string }[]; // extra TCP/UDP ports on the LAN IP
  securityGroups?: string[];
}

export interface VirtualMachineStatus {
  os?: string;
  ip?: string;
  ready?: boolean;
  conditions?: Condition[];
}

export type VirtualMachine = K8sObject<
  VirtualMachineSpec,
  VirtualMachineStatus
>;
export const VIRTUALMACHINES_PLURAL = "virtualmachines";
export const VIRTUALMACHINES_CRD_NAME = "virtualmachines.openinfra.dev";

// KubeVirt VirtualMachineInstance — the running guest. The console reads it
// (read-only) for live status: IP + phase. Backs the VM's connection + console.
export const KUBEVIRT_GROUP = "kubevirt.io";
export const KUBEVIRT_VERSION = "v1";
export interface VmiStatus {
  phase?: string;
  nodeName?: string;
  interfaces?: { ipAddress?: string; name?: string }[];
}
export type Vmi = K8sObject<unknown, VmiStatus>;

// KubeVirt VirtualMachine — read for the installer's printableStatus (the VM
// Images build progress: Provisioning/Running/Stopped).
export interface KubevirtVmStatus {
  printableStatus?: string;
  ready?: boolean;
}
export type KubevirtVm = K8sObject<unknown, KubevirtVmStatus>;

/* ---------------------- open-infra VmImage CRD (AMI builder) -------------- */

export interface VmImageSpec {
  os: string;
  sourceUrl?: string;
  diskSize?: string;
}
export interface VmImageStatus {
  phase?: string;
  ready?: boolean;
  conditions?: Condition[];
}
export type VmImage = K8sObject<VmImageSpec, VmImageStatus>;
export const VMIMAGES_PLURAL = "vmimages";
export const VMIMAGES_CRD_NAME = "vmimages.openinfra.dev";

/* ---------------------- open-infra Volume CRD (EBS-style) ----------------- */

export interface VolumeSpec {
  size?: string;
  source?: { snapshot?: string };
}
export interface VolumeStatus {
  phase?: string;
  size?: string;
}
export type Volume = K8sObject<VolumeSpec, VolumeStatus>;
export const VOLUMES_PLURAL = "volumes";

/* CSI VolumeSnapshot (snapshot.storage.k8s.io) — snapshots of a Volume's PVC. */
export interface VolumeSnapshotSpec {
  source?: { persistentVolumeClaimName?: string };
  volumeSnapshotClassName?: string;
}
export interface VolumeSnapshotStatus {
  readyToUse?: boolean;
  restoreSize?: string;
  creationTime?: string;
}
export type VolumeSnapshot = K8sObject<VolumeSnapshotSpec, VolumeSnapshotStatus>;

/* ---------------------- open-infra FileShare CRD (FSx-style SMB) ---------- */

export interface FileShareSpec {
  size?: string;
  expose?: boolean;
}
export interface FileShareStatus {
  share?: string;
  ready?: boolean;
}
export type FileShare = K8sObject<FileShareSpec, FileShareStatus>;
export const FILESHARES_PLURAL = "fileshares";

/* ------------- open-infra Directory CRD (Active Directory / Simple AD) ----- */

export interface DirectorySpec {
  domain?: string;
  size?: string;
  expose?: boolean;
}
export interface DirectoryStatus {
  domain?: string;
  ready?: boolean;
}
export type Directory = K8sObject<DirectorySpec, DirectoryStatus>;
export const DIRECTORIES_PLURAL = "directories";

/* --------------- open-infra Migration CRD (DMS — Airbyte-backed) ----------- */

export interface MigrationPasswordRef {
  name?: string;
  key?: string;
}
/** A source or target database endpoint. Source uses `schemas`; target uses `schema`. */
export interface MigrationEndpoint {
  engine?: string; // source: postgres|mysql|mariadb|sqlserver|mongodb · target: postgres
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  passwordSecretRef?: MigrationPasswordRef;
  schemas?: string[]; // source (postgres, sqlserver)
  schema?: string; // target
  ssl?: boolean;
}
export interface MigrationSpec {
  mode?: string; // full-load | cdc | full-load-and-cdc
  source?: MigrationEndpoint;
  target?: MigrationEndpoint;
  tables?: string[];
}
export interface MigrationStatus {
  connectionId?: string;
  phase?: string;
  ready?: boolean;
  conditions?: Condition[];
}
export type Migration = K8sObject<MigrationSpec, MigrationStatus>;
export const MIGRATIONS_PLURAL = "migrations";

/** A CDC Stream: source DB change log -> NATS JetStream (open-infra's "Kinesis"). */
export interface StreamSource {
  engine?: string; // postgres|mysql|mariadb|sqlserver|mongodb
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  passwordSecretRef?: MigrationPasswordRef;
  schemas?: string[];
  tables?: string[];
  ssl?: boolean;
}
export interface StreamSpec {
  source?: StreamSource;
}
export interface StreamStatus {
  stream?: string;
  subjects?: string;
  phase?: string;
  ready?: boolean;
  conditions?: Condition[];
}
export type Stream = K8sObject<StreamSpec, StreamStatus>;
export const STREAMS_PLURAL = "streams";

/* ------------- open-infra SecurityGroup CRD (AWS Security Group) ----------- */

/** One peer in a rule: exactly one of cidr / securityGroup / namespace. */
export interface SecurityGroupPeer {
  cidr?: string;
  securityGroup?: string;
  namespace?: string;
}
export interface SecurityGroupRule {
  protocol?: string; // TCP (default) | UDP
  ports?: number[]; // empty = all ports
  from?: SecurityGroupPeer[]; // ingress
  to?: SecurityGroupPeer[]; // egress
}
export interface SecurityGroupSpec {
  ingress?: SecurityGroupRule[];
  egress?: SecurityGroupRule[];
}
export interface SecurityGroupStatus {
  memberLabel?: string;
  conditions?: Condition[];
}
export type SecurityGroup = K8sObject<SecurityGroupSpec, SecurityGroupStatus>;
export const SECURITYGROUPS_PLURAL = "securitygroups";
export const SECURITYGROUPS_CRD_NAME = "securitygroups.openinfra.dev";

/* batch/v1 Job — read (only) to surface a Migration's live run status. */
export interface JobStatus {
  active?: number;
  succeeded?: number;
  failed?: number;
  startTime?: string;
  completionTime?: string;
  conditions?: Condition[];
}
export type Job = K8sObject<unknown, JobStatus>;

/* ---------------------- CloudNativePG managed Postgres -------------------- */

export interface CnpgClusterSpec {
  instances?: number;
  storage?: { size?: string; storageClass?: string };
}

export interface CnpgClusterStatus {
  phase?: string;
  readyInstances?: number;
  instances?: number;
}

export type CnpgCluster = K8sObject<CnpgClusterSpec, CnpgClusterStatus>;
export const CNPG_GROUP = "postgresql.cnpg.io";
export const CNPG_VERSION = "v1";
export const CNPG_CLUSTERS_PLURAL = "clusters";
export const APPLICATIONS_CRD_NAME = "applications.openinfra.dev";
