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
): Promise<T> {
  return request<T>(k8sPath(path), {
    method: "PUT",
    body: JSON.stringify(obj),
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
