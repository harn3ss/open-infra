import {
  APPLICATIONS_PLURAL,
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
} from "@/types/k8s";

/**
 * Centralized k8s REST list-path builders. `namespace === undefined` means
 * "all namespaces"; a concrete namespace scopes the list.
 */

function nsSegment(namespace?: string): string {
  return namespace ? `/namespaces/${namespace}` : "";
}

export const corePaths = {
  pods: (ns?: string) => `/api/v1${nsSegment(ns)}/pods`,
  services: (ns?: string) => `/api/v1${nsSegment(ns)}/services`,
  events: (ns?: string) => `/api/v1${nsSegment(ns)}/events`,
  nodes: () => `/api/v1/nodes`,
  namespaces: () => `/api/v1/namespaces`,
};

export const appsPaths = {
  deployments: (ns?: string) => `/apis/apps/v1${nsSegment(ns)}/deployments`,
};

export const openinfraPaths = {
  applications: (ns?: string) =>
    `/apis/${OPENINFRA_GROUP}/${OPENINFRA_VERSION}${nsSegment(ns)}/${APPLICATIONS_PLURAL}`,
  application: (ns: string, name: string) =>
    `/apis/${OPENINFRA_GROUP}/${OPENINFRA_VERSION}/namespaces/${ns}/${APPLICATIONS_PLURAL}/${name}`,
};

/** Single-resource path helpers for GET/DELETE on a named object. */
export const resourcePaths = {
  pod: (ns: string, name: string) => `/api/v1/namespaces/${ns}/pods/${name}`,
  service: (ns: string, name: string) =>
    `/api/v1/namespaces/${ns}/services/${name}`,
  deployment: (ns: string, name: string) =>
    `/apis/apps/v1/namespaces/${ns}/deployments/${name}`,
  node: (name: string) => `/api/v1/nodes/${name}`,
};
