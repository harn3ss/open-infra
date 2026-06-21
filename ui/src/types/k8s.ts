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
