import {
  APPLICATIONS_PLURAL,
  CNPG_CLUSTERS_PLURAL,
  CNPG_GROUP,
  CNPG_VERSION,
  FUNCTIONS_PLURAL,
  KUBEVIRT_GROUP,
  KUBEVIRT_VERSION,
  MODELS_PLURAL,
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  VIRTUALMACHINES_PLURAL,
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

export const networkingPaths = {
  ingresses: (ns?: string) =>
    `/apis/networking.k8s.io/v1${nsSegment(ns)}/ingresses`,
  networkPolicies: (ns?: string) =>
    `/apis/networking.k8s.io/v1${nsSegment(ns)}/networkpolicies`,
};

const oiGV = `/apis/${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`;

export const openinfraPaths = {
  applications: (ns?: string) => `${oiGV}${nsSegment(ns)}/${APPLICATIONS_PLURAL}`,
  application: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${APPLICATIONS_PLURAL}/${name}`,
  functions: (ns?: string) => `${oiGV}${nsSegment(ns)}/${FUNCTIONS_PLURAL}`,
  function: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${FUNCTIONS_PLURAL}/${name}`,
  models: (ns?: string) => `${oiGV}${nsSegment(ns)}/${MODELS_PLURAL}`,
  model: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${MODELS_PLURAL}/${name}`,
  virtualmachines: (ns?: string) =>
    `${oiGV}${nsSegment(ns)}/${VIRTUALMACHINES_PLURAL}`,
  virtualmachine: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${VIRTUALMACHINES_PLURAL}/${name}`,
};

const kvGV = `/apis/${KUBEVIRT_GROUP}/${KUBEVIRT_VERSION}`;

// KubeVirt VirtualMachineInstance — read-only live guest status (IP, phase).
export const kubevirtPaths = {
  vmis: (ns?: string) => `${kvGV}${nsSegment(ns)}/virtualmachineinstances`,
  vmi: (ns: string, name: string) =>
    `${kvGV}/namespaces/${ns}/virtualmachineinstances/${name}`,
};

export const cnpgPaths = {
  clusters: (ns?: string) =>
    `/apis/${CNPG_GROUP}/${CNPG_VERSION}${nsSegment(ns)}/${CNPG_CLUSTERS_PLURAL}`,
  cluster: (ns: string, name: string) =>
    `/apis/${CNPG_GROUP}/${CNPG_VERSION}/namespaces/${ns}/${CNPG_CLUSTERS_PLURAL}/${name}`,
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
