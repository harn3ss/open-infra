/**
 * Same-origin BFF client. The console NEVER talks to the Kubernetes API
 * directly — every request goes to the Go BFF under /api, which authenticates
 * and proxies. In dev, vite proxies /api to the BFF (see vite.config.ts).
 */

import type { K8sList, K8sObject } from "@/types/k8s";

/** Runtime config served by the BFF; fetched once before the app renders. */
export interface AppConfig {
  clusterName: string;
  grafanaBaseUrl: string;
  version: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  /** k8s Status `reason`, when the BFF forwards a k8s error object. */
  readonly reason?: string;

  constructor(message: string, status: number, body: unknown, reason?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.reason = reason;
  }
}

const API_BASE = "/api";

interface K8sStatusLike {
  kind?: string;
  message?: string;
  reason?: string;
  code?: number;
}

function isK8sStatus(v: unknown): v is K8sStatusLike {
  return (
    typeof v === "object" &&
    v !== null &&
    ("message" in v || "reason" in v || "kind" in v)
  );
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return undefined;
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json") || text.startsWith("{")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

async function request<T>(
  path: string,
  init?: RequestInit & { rawBody?: boolean },
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
  } catch (cause) {
    throw new ApiError(
      "Network error reaching the BFF. Is the open-infra BFF running?",
      0,
      cause,
    );
  }

  const body = await parseBody(res);

  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    let reason: string | undefined;
    if (isK8sStatus(body)) {
      message = body.message ?? message;
      reason = body.reason;
    } else if (typeof body === "string" && body) {
      message = body;
    }
    throw new ApiError(message, res.status, body, reason);
  }

  return body as T;
}

/* ------------------------------ Config ------------------------------ */

export function getConfig(): Promise<AppConfig> {
  return request<AppConfig>("/config");
}

/* ------------------------------ k8s REST ------------------------------ */

/**
 * Pass a k8s REST path (without the /api/k8s prefix), e.g.
 *   /api/v1/pods
 *   /apis/openinfra.dev/v1/applications
 */
function k8sPath(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return `/k8s${normalized}`;
}

export function k8sGet<T = K8sObject>(path: string): Promise<T> {
  return request<T>(k8sPath(path));
}

export function k8sList<T extends K8sObject = K8sObject>(
  path: string,
): Promise<K8sList<T>> {
  return request<K8sList<T>>(k8sPath(path));
}

export function k8sCreate<T = K8sObject>(
  path: string,
  obj: unknown,
): Promise<T> {
  return request<T>(k8sPath(path), {
    method: "POST",
    body: JSON.stringify(obj),
  });
}

export function k8sReplace<T = K8sObject>(
  path: string,
  obj: unknown,
  headers?: Record<string, string>,
): Promise<T> {
  return request<T>(k8sPath(path), {
    method: "PUT",
    body: JSON.stringify(obj),
    headers,
  });
}

export function k8sDelete<T = unknown>(path: string): Promise<T> {
  return request<T>(k8sPath(path), { method: "DELETE" });
}

/* ------------------------------ CRD schema ------------------------------ */

/**
 * The BFF returns a JSON Schema (draft-07-ish) normalized for rjsf.
 * `name` is the CRD name, e.g. "applications.openinfra.dev".
 */
export function getCrdSchema(name: string): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(
    `/crd-schema?name=${encodeURIComponent(name)}`,
  );
}

/** Build the SSE watch URL the BFF exposes for a given k8s list path. */
export function watchUrl(path: string, resourceVersion?: string): string {
  const params = new URLSearchParams({ path });
  if (resourceVersion) params.set("resourceVersion", resourceVersion);
  return `${API_BASE}/watch?${params.toString()}`;
}

/* ------------------------- Object storage (MinIO/S3) ------------------------- */

export interface BucketInfo {
  name: string;
  createdAt: string;
}
export interface ObjectInfo {
  key: string;
  size: number;
  lastModified: string;
  isPrefix: boolean;
}

export function listBuckets(): Promise<BucketInfo[]> {
  return request<BucketInfo[]>("/buckets");
}
export function listBucketObjects(
  bucket: string,
  prefix?: string,
): Promise<ObjectInfo[]> {
  const q = prefix ? `?prefix=${encodeURIComponent(prefix)}` : "";
  return request<ObjectInfo[]>(
    `/buckets/${encodeURIComponent(bucket)}/objects${q}`,
  );
}

export function createBucket(name: string): Promise<{ name: string }> {
  return request("/buckets", { method: "POST", body: JSON.stringify({ name }) });
}
export function deleteBucket(bucket: string): Promise<void> {
  return request(`/buckets/${encodeURIComponent(bucket)}`, { method: "DELETE" });
}
export function uploadObject(
  bucket: string,
  key: string,
  file: File,
): Promise<{ key: string }> {
  return request(
    `/buckets/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}`,
    {
      method: "PUT",
      body: file,
      headers: { "Content-Type": file.type || "application/octet-stream" },
    },
  );
}
export function objectDownloadUrl(bucket: string, key: string): string {
  return `${API_BASE}/buckets/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}`;
}
export function deleteObject(bucket: string, key: string): Promise<void> {
  return request(
    `/buckets/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}`,
    { method: "DELETE" },
  );
}

/* ---------------------- Messaging (NATS JetStream/SQS) ---------------------- */

export interface StreamInfo {
  name: string;
  account: string;
  subjects: string[];
  messages: number;
  bytes: number;
  consumers: number;
}

export function listQueues(): Promise<StreamInfo[]> {
  return request<StreamInfo[]>("/queues");
}

export function publishToQueue(
  subject: string,
  data: string,
): Promise<{ status: string }> {
  return request("/queues/publish", {
    method: "POST",
    body: JSON.stringify({ subject, data }),
  });
}
export function purgeQueue(stream: string): Promise<{ status: string }> {
  return request(`/queues/${encodeURIComponent(stream)}/purge`, {
    method: "POST",
  });
}

/* --------------------------- DMS (table discovery) ------------------------ */

export interface DiscoverSource {
  engine: string;
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  schemas?: string[];
  ssl?: boolean;
}
/** Discover a source database's tables (the wizard's table picker). */
export function discoverTables(
  src: DiscoverSource,
): Promise<{ tables: string[] }> {
  return request<{ tables: string[] }>("/migrations/discover", {
    method: "POST",
    body: JSON.stringify(src),
  });
}

/* ----------------------- DMS observability (live status) -------------------- */

export interface TableStat {
  subject: string;
  table: string;
  count: number;
}
/** Live apply-pipeline status for a Migration/Replication direction (from JetStream). */
export interface PipelineStatus {
  stream: string;
  found: boolean; // has the engine been provisioned yet?
  captured: number; // events captured into the stream
  bytes: number;
  lag: number; // events captured but not yet applied to the target
  ackPending: number; // currently being applied
  redelivered: number; // retries
  tables: TableStat[] | null; // per-table captured counts
  deadLetter: number; // rows that failed to apply
  dlqSubjects: TableStat[] | null;
}
export function getMigrationStatus(
  namespace: string,
  name: string,
): Promise<PipelineStatus> {
  return request<PipelineStatus>(
    `/migrations/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/status`,
  );
}

/** One directed leg of a DataFlow topology with its live pipeline status. */
export interface DataFlowDirection extends PipelineStatus {
  from: string;
  to: string;
  type: string; // replication | migration
}
export function getDataFlowStatus(
  namespace: string,
  name: string,
  edges: { from: string; to: string; type: string }[],
): Promise<{ directions: DataFlowDirection[] | null }> {
  return request<{ directions: DataFlowDirection[] | null }>(
    `/dataflows/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/status`,
    { method: "POST", body: JSON.stringify({ edges }) },
  );
}

/** Live database-engine internals for a DataFlow database node (issue #56). */
export interface DbStats {
  engine: string;
  connections: { active: number; idle: number; idleInTx: number; total: number; max: number };
  topQueries: { query: string; calls: number; meanMs: number; totalMs: number }[] | null;
  replication: { slot: string; active: boolean; lagBytes: number }[] | null;
  note?: string;
}
// Resolved server-side from the named DataFlow node (host + secret come from the
// resource, namespace-scoped) — the client passes only a reference, never a host
// or secret.
export function getDbStats(namespace: string, name: string, node: string): Promise<DbStats> {
  return request<DbStats>("/db-stats", {
    method: "POST",
    body: JSON.stringify({ namespace, name, node }),
  });
}
/** Live engine internals for a managed database (the /databases pages). The BFF resolves
 *  host + credentials from the DB's generated Secret (CNPG `<name>-app` / managed
 *  `<name>-mysql-app`), namespace-scoped — the client passes only the resource reference. */
export function getManagedDbStats(namespace: string, name: string): Promise<DbStats> {
  return request<DbStats>(
    `/databases/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/stats`,
    { method: "POST" },
  );
}
/** Per-site (per-direction) pipeline status for a bidirectional Replication. */
export function getReplicationStatus(
  namespace: string,
  name: string,
  siteA: string,
  siteB: string,
): Promise<Record<string, PipelineStatus>> {
  const q = new URLSearchParams({ siteA, siteB }).toString();
  return request<Record<string, PipelineStatus>>(
    `/replications/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/status?${q}`,
  );
}

/* ----------------------- Model playground (chat proxy) ---------------------- */

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}
export interface ChatCompletion {
  choices?: { message?: ChatMessage }[];
  error?: { message?: string } | string;
}

export function modelChat(
  namespace: string,
  name: string,
  messages: ChatMessage[],
): Promise<ChatCompletion> {
  return request<ChatCompletion>(
    `/models/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/chat`,
    {
      method: "POST",
      body: JSON.stringify({ messages, stream: false }),
    },
  );
}

export interface FunctionInvokeRequest {
  method: string;
  path: string;
  body?: string;
  headers?: Record<string, string>;
}
export interface FunctionInvokeResponse {
  status: number;
  durationMs: number;
  headers: Record<string, string>;
  body: string;
}

/** Send a test request to a Function via the BFF (which reaches the in-cluster
 *  Service the browser can't). Wakes a scaled-to-zero function. */
export function invokeFunction(
  namespace: string,
  name: string,
  req: FunctionInvokeRequest,
): Promise<FunctionInvokeResponse> {
  return request<FunctionInvokeResponse>(
    `/functions/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/invoke`,
    { method: "POST", body: JSON.stringify(req) },
  );
}

/** Read-only AD Explorer (kind: Directory). The BFF binds to the DC with the
 *  directory's own admin creds (server-side) and runs an LDAP search. */
export interface LdapEntry {
  dn: string;
  attributes: Record<string, string[]>;
}
export interface LdapSearchResult {
  baseDN: string;
  domain: string;
  entries: LdapEntry[];
}
export interface LdapSearchReq {
  baseDN?: string;
  filter?: string;
  scope?: "base" | "one" | "sub";
  attributes?: string[];
  sizeLimit?: number;
}
export function directoryLdap(
  namespace: string,
  name: string,
  req: LdapSearchReq,
): Promise<LdapSearchResult> {
  return request<LdapSearchResult>(
    `/directories/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/ldap`,
    { method: "POST", body: JSON.stringify(req) },
  );
}

export interface FunctionRoute {
  path: string;
  methods: string[];
}
export interface FunctionRoutes {
  /** "openapi" if a spec was discovered, else "none" (free-form fallback). */
  source: "openapi" | "none";
  specPath: string;
  routes: FunctionRoute[];
}

/** Discover a function's routes + allowed methods from its OpenAPI spec (if any). */
export function getFunctionRoutes(
  namespace: string,
  name: string,
): Promise<FunctionRoutes> {
  return request<FunctionRoutes>(
    `/functions/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/routes`,
  );
}

/* ------------------------------ Query (Athena) --------------------------- */

export interface QueryResult {
  state: "RUNNING" | "SUCCEEDED" | "FAILED";
  rowCount: number;
  executionTimeMs: number;
  error?: string;
  resultLocation?: string;
  columns?: string[];
  rows?: string[][];
  truncated?: boolean;
}

/** Read a kind: Query's state + result rows (from MinIO, via the BFF). */
export function queryResult(
  namespace: string,
  name: string,
  bucket?: string,
): Promise<QueryResult> {
  const q = bucket ? `?bucket=${encodeURIComponent(bucket)}` : "";
  return request<QueryResult>(
    `/queries/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/result${q}`,
  );
}

export interface CatalogSchema {
  schema: string;
  tables: string[];
}

/** The Iceberg catalog (schemas → tables) for the Trino-engine Data tree. */
export function listCatalogTables(): Promise<CatalogSchema[]> {
  return request<CatalogSchema[]>("/catalog/tables");
}

// --- Cost Explorer ----------------------------------------------------------

export interface CostCategory {
  category: string;
  monthly: number;
  detail: string;
}
export interface CostByNamespace {
  namespace: string;
  vcpu: number;
  memoryGiB: number;
  monthly: number;
}
export interface CostResponse {
  currency: string;
  youPay: number;
  monthlyAWS: number;
  yearlyAWS: number;
  categories: CostCategory[];
  byNamespace: CostByNamespace[];
  totals: {
    nodes: number;
    vcpu: number;
    memoryGiB: number;
    gpu: number;
    storageGiB: number;
    loadBalancers: number;
  };
  prices: {
    vcpuHour: number;
    gbHour: number;
    gpuHour: number;
    ebsGbMonth: number;
    lbMonth: number;
  };
}

export function getCost(): Promise<CostResponse> {
  return request<CostResponse>("/cost");
}

// --- Database snapshots (final-snapshot-before-delete + restore) -------------

export interface DbSnapshot {
  id: string;
  namespace: string;
  sourceName: string;
  engine: string;
  dbName: string;
  createdAt: string;
  status: "creating" | "ready" | "failed";
  sizeBytes: number;
}

export function createDbSnapshot(namespace: string, name: string): Promise<DbSnapshot> {
  return request<DbSnapshot>(
    `/databases/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/snapshot`,
    { method: "POST" },
  );
}

export function listDbSnapshots(): Promise<DbSnapshot[]> {
  return request<DbSnapshot[]>("/snapshots");
}

export function restoreDbSnapshot(id: string, namespace: string, target: string): Promise<unknown> {
  return request("/snapshots/restore", {
    method: "POST",
    body: JSON.stringify({ id, namespace, target }),
  });
}

export function deleteDbSnapshot(namespace: string, name: string, id: string): Promise<unknown> {
  const q = new URLSearchParams({ namespace, name, id });
  return request(`/snapshots?${q.toString()}`, { method: "DELETE" });
}
