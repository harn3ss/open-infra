import type { UiSchema } from "@rjsf/utils";

/**
 * Per-kind create configuration — the data that steers the unified schema-driven create page
 * (issue #96). Fields, defaults, enums, help text and validation all come from the CRD schema; this
 * supplies the editorial layer the schema can't encode: how to GROUP fields into named sections and
 * which sections are advanced (collapsed). Per the AWS/Cloudscape research, the advanced area is not
 * one flat blob — it's several titled, separately-collapsible sub-sections ("Network settings",
 * "Storage", …), each holding a few related fields.
 */
export interface SectionSpec {
  /** Section heading. */
  title: string;
  /** Spec property names in this section, in display order. */
  fields: string[];
  /** Advanced sections render collapsed (progressive disclosure); primary sections are always shown. */
  advanced?: boolean;
}

export interface CredentialSpec {
  /** Top-level spec property that is an endpoint object carrying a passwordSecretRef. */
  path: string;
  /** Password field label, e.g. "Source database password". */
  label: string;
}

export interface CreateKindSpec {
  kind: string;
  crdName: string;
  description: string;
  /** Ordered sections. The first (non-advanced) is the primary/essential group. */
  sections: SectionSpec[];
  /** Endpoint objects whose password is collected + stored as a Secret (the ref is filled on create). */
  credentials?: CredentialSpec[];
  uiSchema?: UiSchema;
}

export const VIRTUALMACHINE_CREATE: CreateKindSpec = {
  kind: "VirtualMachine",
  crdName: "virtualmachines.openinfra.dev",
  description:
    "A full virtual machine — pick an OS image and a size; open-infra clones the golden image, wires networking, and boots it.",
  sections: [
    { title: "Machine", fields: ["os", "cpu", "memory", "diskSize"] },
    { title: "Networking", fields: ["network", "expose", "ports", "securityGroups"], advanced: true },
    { title: "Access", fields: ["sshKey"], advanced: true },
    {
      title: "Placement & lifecycle",
      fields: ["running", "highAvailability", "cpuModel", "existingRootClaim"],
      advanced: true,
    },
  ],
  uiSchema: {
    memory: { "ui:placeholder": "2Gi" },
    diskSize: { "ui:placeholder": "20Gi" },
    sshKey: { "ui:placeholder": "ssh-ed25519 AAAA… (injected via cloud-init on Linux)" },
    cpuModel: { "ui:placeholder": "host-passthrough (or e.g. Broadwell-noTSX for live migration)" },
  },
};

export const STREAM_CREATE: CreateKindSpec = {
  kind: "Stream",
  crdName: "streams.openinfra.dev",
  description: "Tap a database's change log (CDC) and publish every row change to the event bus.",
  sections: [{ title: "Source database", fields: ["source"] }],
  credentials: [{ path: "source", label: "Source database password" }],
  uiSchema: { source: { "ui:title": "", host: { "ui:placeholder": "db.internal" } } },
};

export const MIGRATION_CREATE: CreateKindSpec = {
  kind: "Migration",
  crdName: "migrations.openinfra.dev",
  description: "Load and/or continuously replicate data from a source database into a target (AWS DMS-style).",
  sections: [
    { title: "Source database", fields: ["source"] },
    { title: "Target database", fields: ["target"] },
    { title: "What to migrate", fields: ["mode", "tables"] },
  ],
  credentials: [
    { path: "source", label: "Source database password" },
    { path: "target", label: "Target database password" },
  ],
  uiSchema: { source: { "ui:title": "" }, target: { "ui:title": "" } },
};

export const REPLICATION_CREATE: CreateKindSpec = {
  kind: "Replication",
  crdName: "replications.openinfra.dev",
  description: "Keep two database sites in sync both ways (multi-master), with conflict handling.",
  sections: [
    { title: "Site A", fields: ["siteA"] },
    { title: "Site B", fields: ["siteB"] },
    { title: "Tables", fields: ["tables"] },
    { title: "Advanced", fields: ["versionColumn", "originColumn", "scheduling"], advanced: true },
  ],
  credentials: [
    { path: "siteA", label: "Site A database password" },
    { path: "siteB", label: "Site B database password" },
  ],
  uiSchema: { siteA: { "ui:title": "" }, siteB: { "ui:title": "" }, scheduling: { "ui:title": "" } },
};

export const FUNCTION_CREATE: CreateKindSpec = {
  kind: "Function",
  crdName: "functions.openinfra.dev",
  description: "A scale-to-zero function from a container image — with optional GPU, HTTP exposure, and event triggers.",
  sections: [
    { title: "Function", fields: ["image", "port", "memory"] },
    { title: "Compute", fields: ["gpu", "timeout", "scaling"], advanced: true },
    { title: "Networking", fields: ["expose", "securityGroups"], advanced: true },
    { title: "Environment", fields: ["env", "secrets", "queues"], advanced: true },
    { title: "Trigger", fields: ["trigger"], advanced: true },
  ],
  uiSchema: { image: { "ui:placeholder": "ghcr.io/me/my-fn:latest" } },
};

export const MODEL_CREATE: CreateKindSpec = {
  kind: "Model",
  crdName: "models.openinfra.dev",
  description: "A served model endpoint (Bedrock-style) — pick a catalog model, OR serve a custom trained artifact via `serve` (usually promoted from a Model Package).",
  sections: [
    { title: "Model", fields: ["model", "storageSize"] },
    { title: "Serving", fields: ["highAvailability", "expose", "domain"], advanced: true },
    { title: "Custom serving (train→serve)", fields: ["serve"], advanced: true },
  ],
};

export const MODELPACKAGE_CREATE: CreateKindSpec = {
  kind: "ModelPackage",
  crdName: "modelpackages.openinfra.dev",
  description: "Register a trained model in the registry — a versioned, approvable record pointing at the artifact and the container that serves it. Promote an Approved package to a served Model.",
  sections: [
    { title: "Model package", fields: ["modelName", "version", "framework"] },
    { title: "Artifact & serving", fields: ["artifact", "image", "port"] },
    { title: "Metadata & approval", fields: ["metrics", "description", "approvalStatus"], advanced: true },
  ],
};

export const TRAININGJOB_CREATE: CreateKindSpec = {
  kind: "TrainingJob",
  crdName: "trainingjobs.openinfra.dev",
  description:
    "A run-once model-training job on a GPU (SageMaker-style) — your training container runs to completion; read a dataset and write model artifacts to the object store.",
  sections: [
    { title: "Training job", fields: ["image", "gpu", "gpuTier"] },
    { title: "Command", fields: ["command", "args"], advanced: true },
    { title: "Hyperparameters & config", fields: ["env", "secrets"], advanced: true },
    { title: "Data (object store)", fields: ["dataset", "output"], advanced: true },
    { title: "Resources & run", fields: ["cpu", "memory", "backoffLimit", "maxRuntimeSeconds"], advanced: true },
  ],
  uiSchema: { image: { "ui:placeholder": "pytorch/pytorch:2.4.1-cuda12.1-cudnn9-runtime" } },
};

export const TUNINGJOB_CREATE: CreateKindSpec = {
  kind: "TuningJob",
  crdName: "tuningjobs.openinfra.dev",
  description:
    "Hyperparameter tuning (SageMaker-style) — grid-search a training job over a parameter space and keep the best. Each trial runs as a Training Job.",
  sections: [
    { title: "Training template", fields: ["training"] },
    { title: "Search space", fields: ["parameters"] },
    { title: "Objective & limits", fields: ["objective", "maxParallel", "maxTrials", "metricRegex"], advanced: true },
  ],
};

export const BATCHTRANSFORM_CREATE: CreateKindSpec = {
  kind: "BatchTransform",
  crdName: "batchtransforms.openinfra.dev",
  description:
    "Offline batch inference (SageMaker-style) — a run-once job that loads a model, scores an input dataset, and writes predictions to the object store.",
  sections: [
    { title: "Batch transform", fields: ["image", "gpu", "gpuTier"] },
    { title: "Data", fields: ["input", "output", "artifact"] },
    { title: "Command", fields: ["command", "args"], advanced: true },
    { title: "Config", fields: ["env", "secrets", "cpu", "memory", "backoffLimit", "maxRuntimeSeconds"], advanced: true },
  ],
};

export const GRAPHQLAPI_CREATE: CreateKindSpec = {
  kind: "GraphQLApi",
  crdName: "graphqlapis.openinfra.dev",
  description: "A managed GraphQL API (AppSync-style) — an SDL schema wired to data sources by resolvers.",
  sections: [
    { title: "API", fields: ["schema", "image", "replicas"] },
    { title: "Data sources", fields: ["dataSources", "mongoURI", "mongoDB", "apiKeysSecret"], advanced: true },
    { title: "Resolvers", fields: ["resolvers"], advanced: true },
    { title: "Subscriptions", fields: ["subscriptions"], advanced: true },
    { title: "Limits", fields: ["limits"], advanced: true },
  ],
};

export const VOLUME_CREATE: CreateKindSpec = {
  kind: "Volume",
  crdName: "volumes.openinfra.dev",
  description: "A persistent block volume (EBS-style) you can attach to a VM or workload.",
  sections: [
    { title: "Volume", fields: ["size", "migratable"] },
    { title: "Restore from snapshot", fields: ["source"], advanced: true },
  ],
  uiSchema: { size: { "ui:placeholder": "20Gi" } },
};

export const FILESHARE_CREATE: CreateKindSpec = {
  kind: "FileShare",
  crdName: "fileshares.openinfra.dev",
  description: "A shared filesystem (EFS-style, SMB/NFS) mountable by many workloads or VMs.",
  sections: [
    { title: "File share", fields: ["size"] },
    { title: "Access", fields: ["expose", "nodeIP"], advanced: true },
  ],
  uiSchema: { size: { "ui:placeholder": "50Gi" } },
};

export const DIRECTORY_CREATE: CreateKindSpec = {
  kind: "Directory",
  crdName: "directories.openinfra.dev",
  description: "A managed Active Directory domain (Samba AD DC) machines and users can join.",
  sections: [
    { title: "Directory", fields: ["domain", "size"] },
    { title: "Access", fields: ["expose"], advanced: true },
  ],
  uiSchema: { domain: { "ui:placeholder": "corp.example.com" }, size: { "ui:placeholder": "5Gi" } },
};

export const CERTIFICATEAUTHORITY_CREATE: CreateKindSpec = {
  kind: "CertificateAuthority",
  crdName: "certificateauthorities.openinfra.dev",
  description:
    "A managed private certificate authority (AWS Private CA-style) — Vault-backed. Issue and revoke leaf certificates from it; the CA key never leaves Vault.",
  sections: [
    { title: "Authority", fields: ["commonName", "hierarchy", "parent"] },
    { title: "Key & validity", fields: ["keyType", "maxTtl", "allowedDomains"], advanced: true },
    { title: "Availability", fields: ["highAvailability"], advanced: true },
  ],
  uiSchema: {
    commonName: { "ui:placeholder": "My Root CA" },
    parent: { "ui:placeholder": "parent-ca-name (intermediate only)" },
    maxTtl: { "ui:placeholder": "8760h" },
  },
};

export const APPLICATION_CREATE: CreateKindSpec = {
  kind: "Application",
  crdName: "applications.openinfra.dev",
  description:
    "Declare intent — open-infra provisions hosting, scaling, and any attached database, buckets, or queues from this spec.",
  sections: [
    { title: "Container", fields: ["image", "port", "expose", "domain"] },
    { title: "Autoscaling", fields: ["scaling"], advanced: true },
    { title: "Database", fields: ["database"], advanced: true },
    { title: "Storage & queues", fields: ["storage", "queues"], advanced: true },
    { title: "Environment", fields: ["env", "secrets"], advanced: true },
    { title: "Network security", fields: ["securityGroups"], advanced: true },
  ],
  uiSchema: {
    image: { "ui:placeholder": "ghcr.io/me/my-api:latest" },
    domain: { "ui:placeholder": "my-api.example.com" },
  },
};
