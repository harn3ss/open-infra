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
  database?: {
    engine?: string;
    name?: string;
    highAvailability?: boolean;
    stopped?: boolean;
  };
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

/* ------------------------ open-infra GraphQLApi CRD ----------------------- */

export interface GraphQLDataSource {
  name: string;
  type?: "memory" | "dynamodb" | "http" | "lambda";
  collection?: string;
  endpoint?: string;
}
export interface GraphQLResolverAuth {
  group?: string;
  resource?: string;
  verb?: string;
  namespace?: string;
  name?: string;
}
export interface GraphQLFunctionStep {
  dataSource: string;
  runtime?: string;
  request: string;
  response: string;
}
export interface GraphQLResolver {
  type: string; // Query | Mutation (root) or any object type (per-nested-field resolver)
  field: string;
  runtime?: string; // appsync-vtl (default) | appsync-js
  // Unit resolver:
  dataSource?: string;
  request?: string;
  response?: string;
  // Pipeline resolver:
  before?: string;
  after?: string;
  functions?: GraphQLFunctionStep[];
  auth?: GraphQLResolverAuth;
}
export interface GraphQLSubscription {
  field: string;
  subject?: string;
  runtime?: string;
  response: string;
  triggeredBy?: string[];
  auth?: GraphQLResolverAuth;
}
export interface GraphQLLimits {
  maxDepth?: number;
  maxCost?: number;
  persistedOnly?: boolean;
  persistedQueries?: string[];
  introspection?: "enabled" | "disabled" | "authenticated-only";
}
export interface GraphQLApiSpec {
  schema?: string; // GraphQL SDL (enables __schema/__type introspection)
  image?: string;
  replicas?: number;
  mongoURI?: string;
  mongoDB?: string;
  apiKeysSecret?: string; // Secret holding apikeys.json (key→identity) for @aws_api_key auth
  limits?: GraphQLLimits;
  dataSources?: GraphQLDataSource[];
  resolvers: GraphQLResolver[];
  subscriptions?: GraphQLSubscription[];
}
export interface GraphQLApiStatus {
  url?: string; // in-cluster GraphQL endpoint of the engine
  conditions?: Condition[];
}

/** open-appsync GraphQL API (resolver-first, VTL/JS-faithful AppSync engine). */
export type GraphQLApi = K8sObject<GraphQLApiSpec, GraphQLApiStatus>;
export const GRAPHQLAPIS_PLURAL = "graphqlapis";
export const GRAPHQLAPIS_CRD_NAME = "graphqlapis.openinfra.dev";

/* -------------------------- open-infra Model CRD -------------------------- */

export interface ModelServeSpec {
  image?: string;
  command?: string[];
  args?: string[];
  port?: number;
  artifact?: { bucket?: string; key?: string };
  gpu?: number;
  gpuTier?: "smallgpu" | "largegpu";
  cpu?: string;
  memory?: string;
  modelPackage?: string;
  env?: { name: string; value: string }[];
}

export interface ModelSpec {
  model?: string; // catalog model (OR serve)
  serve?: ModelServeSpec; // custom trained-artifact serving
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

/* ---------------------- open-infra ModelPackage CRD ----------------------- */
// The model registry: a versioned, approvable record of a trained artifact.
export interface ModelPackageSpec {
  modelName: string;
  version?: string;
  artifact: { bucket?: string; key?: string };
  image: string;
  port?: number;
  framework?: string;
  metrics?: string;
  description?: string;
  approvalStatus?: "PendingManualApproval" | "Approved" | "Rejected";
}
export interface ModelPackageStatus {
  approvalStatus?: string;
  conditions?: Condition[];
}
export type ModelPackage = K8sObject<ModelPackageSpec, ModelPackageStatus>;
export const MODELPACKAGES_PLURAL = "modelpackages";
export const MODELPACKAGES_CRD_NAME = "modelpackages.openinfra.dev";

/* ---------------------- open-infra VirtualMachine CRD --------------------- */

export interface VirtualMachineSpec {
  os: string;
  cpu?: number;
  memory?: string;
  diskSize?: string;
  sshKey?: string;
  expose?: boolean;
  running?: boolean;
  highAvailability?: boolean; // root disk on Longhorn (migratable) — enables live migration + snapshots
  cpuModel?: string;
  network?: string;
  existingRootClaim?: string; // boot from a pre-existing root PVC (migration / snapshot restore)
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

// CDI DataVolume — the root disk being imported (Linux) or cloned from a golden
// (Windows). Read-only, to surface clone/import progress and failures on the VM
// status (a doomed clone otherwise looks like an endless "Provisioning").
export const CDI_GROUP = "cdi.kubevirt.io";
export const CDI_VERSION = "v1beta1";
export interface DataVolumeStatus {
  // Pending | (Import|Clone)Scheduled | (Import|Clone)InProgress | Succeeded | Failed …
  phase?: string;
  progress?: string; // e.g. "45.0%" or "N/A"
  conditions?: Condition[];
}
export type DataVolume = K8sObject<unknown, DataVolumeStatus>;

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
  migratable?: boolean;
}
export interface VolumeStatus {
  phase?: string;
  size?: string;
}
export type Volume = K8sObject<VolumeSpec, VolumeStatus>;
export const VOLUMES_PLURAL = "volumes";

/* ---------------------- open-infra Query CRD (Athena) --------------------- */

export interface QuerySpec {
  sql: string;
  engine?: "duckdb" | "trino";
  outputBucket?: string;
}
export type Query = K8sObject<QuerySpec, { phase?: string }>;
export const QUERIES_PLURAL = "queries";

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

// kind: FaultInjection — chaos engineering ("Fault Injection Simulator").
export type FaultInjectionType =
  | "pod-kill"
  | "pod-failure"
  | "network-latency"
  | "network-loss"
  | "network-partition"
  | "stress-cpu"
  | "stress-memory"
  | "clock-skew"
  | "io-latency";
export interface FaultInjectionSpec {
  type: FaultInjectionType;
  target: { namespace?: string; labelSelector: Record<string, string> };
  mode?: "one" | "all" | "fixed-percent";
  value?: string;
  duration?: string;
  latency?: string;
  loss?: string;
  direction?: "to" | "from" | "both";
  cpuWorkers?: number;
  cpuLoad?: number;
  memory?: string;
  timeOffset?: string;
  volumePath?: string;
}
export interface FaultInjectionStatus {
  phase?: string;
}
export type FaultInjection = K8sObject<FaultInjectionSpec, FaultInjectionStatus>;
export const FAULTINJECTIONS_PLURAL = "faultinjections";

/* ----- open-infra Migration CRD (DMS — Debezium + apply-sink engine) ------- */

export interface MigrationPasswordRef {
  name?: string;
  key?: string;
}
/** A source or target database endpoint. Source uses `schemas`; target uses `schema`. */
export interface MigrationEndpoint {
  engine?: string; // source: postgres|mysql|mariadb|sqlserver · target: postgres|mysql|sqlserver
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
  phase?: string;
  ready?: boolean;
  stream?: string;
  conditions?: Condition[];
}
export type Migration = K8sObject<MigrationSpec, MigrationStatus>;
export const MIGRATIONS_PLURAL = "migrations";

/* ----- open-infra Replication CRD (bidirectional / multi-master) ----------- */

export interface ReplicationEndpoint {
  name?: string; // origin-marker site id
  engine?: string; // postgres|mysql|mariadb|sqlserver
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  passwordSecretRef?: MigrationPasswordRef;
  schema?: string;
  ssl?: boolean;
}
export interface ReplicationSpec {
  siteA?: ReplicationEndpoint;
  siteB?: ReplicationEndpoint;
  tables?: string[];
  versionColumn?: string;
  originColumn?: string;
}
export interface ReplicationStatus {
  phase?: string;
  ready?: boolean;
  conditions?: Condition[];
}
export type Replication = K8sObject<ReplicationSpec, ReplicationStatus>;
export const REPLICATIONS_PLURAL = "replications";

/* ----- open-infra DataFlow CRD (canvas topology: replication + migration) --- */

export interface DataFlowNode {
  name?: string;
  engine?: string; // postgres|mysql|mariadb|sqlserver
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  passwordSecretRef?: MigrationPasswordRef;
  schema?: string;
  ssl?: boolean;
  x?: number; // canvas position
  y?: number;
}
export interface DataFlowEdge {
  from?: string;
  to?: string;
  type?: string; // replication | migration
  mode?: string; // migration only: full-load | cdc | full-load-and-cdc
  tables?: string[];
}
export interface DataFlowSpec {
  nodes?: DataFlowNode[];
  edges?: DataFlowEdge[];
  tables?: string[];
  versionColumn?: string;
  originColumn?: string;
}
export interface DataFlowStatus {
  phase?: string;
  ready?: boolean;
  conditions?: Condition[];
}
export type DataFlow = K8sObject<DataFlowSpec, DataFlowStatus>;
export const DATAFLOWS_PLURAL = "dataflows";

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
  description?: string; // optional "why" note (AWS-style)
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

/* ---------------------- open-infra StateMachine CRD ----------------------- */
// open-infra's Step Functions: an ASL workflow. spec.definition is the ASL JSON
// string (like aws_sfn_state_machine.definition); runs are kind: Execution.
export interface StateMachineSpec {
  definition: string;
  type?: "Standard";
}
export interface StateMachineStatus {
  definitionConfigMap?: string;
  conditions?: Condition[];
}
export type StateMachine = K8sObject<StateMachineSpec, StateMachineStatus>;
export const STATEMACHINES_PLURAL = "statemachines";
export const STATEMACHINES_CRD_NAME = "statemachines.openinfra.dev";

/* ------------------------ open-infra Execution CRD ------------------------ */
// One run of a StateMachine. Creating one is StartExecution; the controller
// checkpoints progress into status.
export interface ExecutionSpec {
  stateMachineRef: { name: string };
  input?: string;
}
export interface ExecutionStatus {
  phase?: string; // Running | Succeeded | Failed | TimedOut
  output?: string;
  error?: string;
  cause?: string;
  currentState?: string;
  startedAt?: string;
  stoppedAt?: string;
  waitUntil?: string;
  history?: Record<string, unknown>[];
}
export type Execution = K8sObject<ExecutionSpec, ExecutionStatus>;
export const EXECUTIONS_PLURAL = "executions";
export const EXECUTIONS_CRD_NAME = "executions.openinfra.dev";

/* ---------------------- open-infra TrainingJob CRD ------------------------ */
// A run-once, GPU-capable model-training Job (SageMaker Training Jobs). Runs the
// user's container to completion; run status is the underlying batch Job's.
export interface TrainingJobSpec {
  image: string;
  command?: string[];
  args?: string[];
  env?: { name: string; value: string }[];
  gpu?: number;
  gpuTier?: "smallgpu" | "largegpu";
  cpu?: string;
  memory?: string;
  dataset?: { bucket?: string; prefix?: string };
  output?: { bucket?: string; prefix?: string };
  secrets?: string[];
  backoffLimit?: number;
  maxRuntimeSeconds?: number;
}
export interface TrainingJobStatus {
  jobName?: string;
  conditions?: Condition[];
}
export type TrainingJob = K8sObject<TrainingJobSpec, TrainingJobStatus>;
export const TRAININGJOBS_PLURAL = "trainingjobs";
export const TRAININGJOBS_CRD_NAME = "trainingjobs.openinfra.dev";

/* ---------------------- open-infra BatchTransform CRD --------------------- */
// A run-once, offline batch-inference Job (SageMaker Batch Transform).
export interface BatchTransformSpec {
  image: string;
  command?: string[];
  args?: string[];
  artifact?: { bucket?: string; key?: string };
  input: { bucket?: string; prefix?: string };
  output: { bucket?: string; prefix?: string };
  modelPackage?: string;
  gpu?: number;
  gpuTier?: "smallgpu" | "largegpu";
  cpu?: string;
  memory?: string;
  env?: { name: string; value: string }[];
  secrets?: string[];
  backoffLimit?: number;
  maxRuntimeSeconds?: number;
}
export interface BatchTransformStatus {
  jobName?: string;
  conditions?: Condition[];
}
export type BatchTransform = K8sObject<BatchTransformSpec, BatchTransformStatus>;
export const BATCHTRANSFORMS_PLURAL = "batchtransforms";
export const BATCHTRANSFORMS_CRD_NAME = "batchtransforms.openinfra.dev";

/* ------------------------ open-infra TuningJob CRD ------------------------ */
// Hyperparameter tuning (SageMaker Automatic Model Tuning): a grid-search sweep that
// runs a TrainingJob per hyperparameter combination and records the best.
export interface TuningTrial {
  name: string;
  parameters?: Record<string, string>;
  status?: string; // Pending | Running | Succeeded | Failed
  metric?: string;
}
export interface TuningJobSpec {
  training: {
    image: string;
    command?: string[];
    args?: string[];
    gpu?: number;
    gpuTier?: "smallgpu" | "largegpu";
    cpu?: string;
    memory?: string;
    dataset?: { bucket?: string; prefix?: string };
    output?: { bucket?: string; prefix?: string };
    env?: { name: string; value: string }[];
    secrets?: string[];
    maxRuntimeSeconds?: number;
  };
  parameters: { name: string; values: string[] }[];
  objective?: { metric?: string; goal?: "Minimize" | "Maximize" };
  metricRegex?: string;
  maxParallel?: number;
  maxTrials?: number;
}
export interface TuningJobStatus {
  phase?: string;
  bestTrial?: string;
  bestValue?: string;
  bestParameters?: string;
  trialsTotal?: number;
  trialsComplete?: number;
  trials?: TuningTrial[];
  conditions?: Condition[];
}
export type TuningJob = K8sObject<TuningJobSpec, TuningJobStatus>;
export const TUNINGJOBS_PLURAL = "tuningjobs";
export const TUNINGJOBS_CRD_NAME = "tuningjobs.openinfra.dev";

/* ---------------------- open-infra ProcessingJob CRD ---------------------- */
// A run-once data-processing Job (SageMaker Processing) with N named inputs/outputs.
export interface ProcessingChannel {
  name: string;
  bucket?: string;
  prefix?: string;
}
export interface ProcessingJobSpec {
  image: string;
  command?: string[];
  args?: string[];
  inputs?: ProcessingChannel[];
  outputs?: ProcessingChannel[];
  gpu?: number;
  gpuTier?: "smallgpu" | "largegpu";
  cpu?: string;
  memory?: string;
  env?: { name: string; value: string }[];
  secrets?: string[];
  backoffLimit?: number;
  maxRuntimeSeconds?: number;
}
export interface ProcessingJobStatus {
  jobName?: string;
  conditions?: Condition[];
}
export type ProcessingJob = K8sObject<ProcessingJobSpec, ProcessingJobStatus>;
export const PROCESSINGJOBS_PLURAL = "processingjobs";
export const PROCESSINGJOBS_CRD_NAME = "processingjobs.openinfra.dev";

/* ---------------------- open-infra ModelMonitor CRD ----------------------- */
// Scheduled data-drift monitoring (SageMaker Model Monitor).
export interface ModelMonitorSpec {
  schedule?: string;
  baseline: { bucket?: string; key?: string };
  current: { bucket?: string; prefix?: string };
  output: { bucket?: string; prefix?: string };
  features?: string[];
  threshold?: number;
  modelRef?: string;
}
export interface ModelMonitorStatus {
  cronJob?: string;
  conditions?: Condition[];
}
export type ModelMonitor = K8sObject<ModelMonitorSpec, ModelMonitorStatus>;
export const MODELMONITORS_PLURAL = "modelmonitors";
export const MODELMONITORS_CRD_NAME = "modelmonitors.openinfra.dev";

/* batch/v1 CronJob — read-only, to surface a ModelMonitor's schedule status. */
export interface CronJobStatus {
  lastScheduleTime?: string;
  lastSuccessfulTime?: string;
  active?: { name?: string }[];
}
export type CronJob = K8sObject<{ schedule?: string; suspend?: boolean }, CronJobStatus>;

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
