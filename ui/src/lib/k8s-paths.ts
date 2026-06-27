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
  VMIMAGES_PLURAL,
  VOLUMES_PLURAL,
  FILESHARES_PLURAL,
  DIRECTORIES_PLURAL,
  MIGRATIONS_PLURAL,
  REPLICATIONS_PLURAL,
  DATAFLOWS_PLURAL,
  STREAMS_PLURAL,
  SECURITYGROUPS_PLURAL,
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
  pvcs: (ns?: string) => `/api/v1${nsSegment(ns)}/persistentvolumeclaims`,
  secrets: (ns?: string) => `/api/v1${nsSegment(ns)}/secrets`,
};

export const appsPaths = {
  deployments: (ns?: string) => `/apis/apps/v1${nsSegment(ns)}/deployments`,
};

// batch/v1 Jobs — read-only, to surface a Migration's live run status.
export const batchPaths = {
  jobs: (ns?: string) => `/apis/batch/v1${nsSegment(ns)}/jobs`,
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
  vmimages: (ns?: string) => `${oiGV}${nsSegment(ns)}/${VMIMAGES_PLURAL}`,
  vmimage: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${VMIMAGES_PLURAL}/${name}`,
  volumes: (ns?: string) => `${oiGV}${nsSegment(ns)}/${VOLUMES_PLURAL}`,
  volume: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${VOLUMES_PLURAL}/${name}`,
  fileshares: (ns?: string) => `${oiGV}${nsSegment(ns)}/${FILESHARES_PLURAL}`,
  fileshare: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${FILESHARES_PLURAL}/${name}`,
  directories: (ns?: string) => `${oiGV}${nsSegment(ns)}/${DIRECTORIES_PLURAL}`,
  directory: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${DIRECTORIES_PLURAL}/${name}`,
  migrations: (ns?: string) => `${oiGV}${nsSegment(ns)}/${MIGRATIONS_PLURAL}`,
  migration: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${MIGRATIONS_PLURAL}/${name}`,
  replications: (ns?: string) => `${oiGV}${nsSegment(ns)}/${REPLICATIONS_PLURAL}`,
  replication: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${REPLICATIONS_PLURAL}/${name}`,
  dataflows: (ns?: string) => `${oiGV}${nsSegment(ns)}/${DATAFLOWS_PLURAL}`,
  dataflow: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${DATAFLOWS_PLURAL}/${name}`,
  streams: (ns?: string) => `${oiGV}${nsSegment(ns)}/${STREAMS_PLURAL}`,
  stream: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${STREAMS_PLURAL}/${name}`,
  securitygroups: (ns?: string) =>
    `${oiGV}${nsSegment(ns)}/${SECURITYGROUPS_PLURAL}`,
  securitygroup: (ns: string, name: string) =>
    `${oiGV}/namespaces/${ns}/${SECURITYGROUPS_PLURAL}/${name}`,
};

const kvGV = `/apis/${KUBEVIRT_GROUP}/${KUBEVIRT_VERSION}`;

// KubeVirt VirtualMachineInstance (live guest IP/phase) + VirtualMachine
// (installer printableStatus for image builds).
export const kubevirtPaths = {
  vmis: (ns?: string) => `${kvGV}${nsSegment(ns)}/virtualmachineinstances`,
  vmi: (ns: string, name: string) =>
    `${kvGV}/namespaces/${ns}/virtualmachineinstances/${name}`,
  vms: (ns?: string) => `${kvGV}${nsSegment(ns)}/virtualmachines`,
  // VNC websocket subresource (served by virt-api). Relative to /api/k8s — the UI
  // builds a same-origin wss URL that the BFF reverse-proxies (with the SA token).
  vnc: (ns: string, name: string) =>
    `/apis/subresources.kubevirt.io/v1/namespaces/${ns}/virtualmachineinstances/${name}/vnc`,
  // Hotplug attach/detach of a volume to a running VM (PUT AddVolumeOptions /
  // RemoveVolumeOptions). --persist semantics: also updates the VM spec.
  addVolume: (ns: string, vm: string) =>
    `/apis/subresources.kubevirt.io/v1/namespaces/${ns}/virtualmachines/${vm}/addvolume`,
  removeVolume: (ns: string, vm: string) =>
    `/apis/subresources.kubevirt.io/v1/namespaces/${ns}/virtualmachines/${vm}/removevolume`,
};

// CSI VolumeSnapshots (snapshot.storage.k8s.io) — snapshot/restore Volumes.
export const snapshotPaths = {
  volumeSnapshots: (ns?: string) =>
    `/apis/snapshot.storage.k8s.io/v1${nsSegment(ns)}/volumesnapshots`,
  volumeSnapshot: (ns: string, name: string) =>
    `/apis/snapshot.storage.k8s.io/v1/namespaces/${ns}/volumesnapshots/${name}`,
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
  secret: (ns: string, name: string) =>
    `/api/v1/namespaces/${ns}/secrets/${name}`,
  deployment: (ns: string, name: string) =>
    `/apis/apps/v1/namespaces/${ns}/deployments/${name}`,
  node: (name: string) => `/api/v1/nodes/${name}`,
};
