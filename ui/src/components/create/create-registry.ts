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

export const PROCESSINGJOB_CREATE: CreateKindSpec = {
  kind: "ProcessingJob",
  crdName: "processingjobs.openinfra.dev",
  description:
    "Data processing (SageMaker-style) — a run-once job with named inputs and outputs for preprocessing, feature engineering, validation, or model evaluation.",
  sections: [
    { title: "Processing job", fields: ["image", "gpu", "gpuTier"] },
    { title: "Channels", fields: ["inputs", "outputs"] },
    { title: "Command", fields: ["command", "args"], advanced: true },
    { title: "Config", fields: ["env", "secrets", "cpu", "memory", "backoffLimit", "maxRuntimeSeconds"], advanced: true },
  ],
};

export const MODELMONITOR_CREATE: CreateKindSpec = {
  kind: "ModelMonitor",
  crdName: "modelmonitors.openinfra.dev",
  description:
    "Scheduled drift monitoring (SageMaker-style) — on a cron schedule, compare recent data to a baseline, flag features that drift, and write a report. The drift check is built in.",
  sections: [
    { title: "Monitor", fields: ["schedule", "modelRef", "threshold"] },
    { title: "Data", fields: ["baseline", "current", "output"] },
    { title: "Features", fields: ["features"], advanced: true },
  ],
};

export const FEATUREGROUP_CREATE: CreateKindSpec = {
  kind: "FeatureGroup",
  crdName: "featuregroups.openinfra.dev",
  description:
    "An online feature store (SageMaker-style) — low-latency PutRecord/GetRecord for real-time inference. Give it the record identifier and (optionally) a feature schema.",
  sections: [
    { title: "Feature group", fields: ["recordIdentifier", "eventTime"] },
    { title: "Schema", fields: ["features"] },
    { title: "Online store", fields: ["ttlSeconds"], advanced: true },
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

export const TABLE_CREATE: CreateKindSpec = {
  kind: "Table",
  crdName: "tables.openinfra.dev",
  description:
    "A managed key/value table (DynamoDB-compatible), served by the aws-shim DynamoDB front door. Pick a partition key and (optionally) a sort key — the key schema is immutable once created.",
  sections: [
    { title: "Table details", fields: ["tableName", "hashKey", "rangeKey"] },
    {
      title: "Settings",
      fields: ["billingMode", "ttlAttribute", "globalSecondaryIndexes"],
      advanced: true,
    },
  ],
  uiSchema: {
    tableName: { "ui:placeholder": "defaults to the resource name" },
    hashKey: { name: { "ui:placeholder": "e.g. pk" } },
    rangeKey: { name: { "ui:placeholder": "e.g. sk (optional)" } },
    ttlAttribute: { "ui:placeholder": "epoch-seconds attribute, e.g. expiresAt" },
    globalSecondaryIndexes: {
      items: {
        name: { "ui:placeholder": "index name (the Query IndexName)" },
        hashKey: { name: { "ui:placeholder": "index partition key" } },
        rangeKey: { name: { "ui:placeholder": "index sort key (optional)" } },
      },
    },
  },
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

export const NATGATEWAY_CREATE: CreateKindSpec = {
  kind: "NatGateway",
  crdName: "natgateways.openinfra.dev",
  description:
    "The border device for a private VPC (kube-ovn VpcNatGateway) — the AWS NAT Gateway (SNAT egress) and, on a flat network, the Internet-Gateway role. Requires the kube-ovn CNI.",
  sections: [
    { title: "Gateway", fields: ["vpc", "subnet", "internalIp"] },
    { title: "Egress", fields: ["egress"], advanced: true },
    { title: "Placement", fields: ["externalNetwork", "nodeSelector"], advanced: true },
  ],
  uiSchema: { internalIp: { "ui:placeholder": "10.0.0.254" } },
};

export const ELASTICIP_CREATE: CreateKindSpec = {
  kind: "ElasticIp",
  crdName: "elasticips.openinfra.dev",
  description:
    "A static public IP on a NAT gateway (kube-ovn IptablesEIP) — the AWS Elastic IP, optionally associated with a private workload (1:1 fip or per-port dnat).",
  sections: [
    { title: "Allocation", fields: ["natGateway", "address"] },
    { title: "Association", fields: ["target", "mode", "ports"], advanced: true },
    { title: "Network", fields: ["externalNetwork"], advanced: true },
  ],
  uiSchema: { address: { "ui:placeholder": "auto-assigned when empty" } },
};

export const TRANSITGATEWAY_CREATE: CreateKindSpec = {
  kind: "TransitGateway",
  crdName: "transitgateways.openinfra.dev",
  description:
    "A hub with transitive spoke-to-spoke routing (AWS Transit Gateway) — attach VPCs so they can route between each other through one hub.",
  sections: [{ title: "Attachments", fields: ["attachments"] }],
  uiSchema: {
    attachments: {
      items: {
        vpc: { "ui:placeholder": "spoke-vpc" },
        cidr: { "ui:placeholder": "10.1.0.0/16" },
        hubConnectIP: { "ui:placeholder": "169.254.100.1" },
        spokeConnectIP: { "ui:placeholder": "169.254.100.2" },
      },
    },
  },
};

export const USERPOOL_CREATE: CreateKindSpec = {
  kind: "UserPool",
  crdName: "userpools.openinfra.dev",
  description:
    "A customer-facing OIDC identity provider (AWS Cognito analog) — a Keycloak realm that issues tokens your applications sign in against. Expose an issuer + one app client; pair it with an HttpApi/GraphQLApi JWT authorizer.",
  sections: [
    { title: "Pool", fields: ["realm", "hostname"] },
    { title: "App client & sign-up", fields: ["clientId", "registrationAllowed"], advanced: true },
    { title: "Storage", fields: ["size", "storageClass"], advanced: true },
  ],
  uiSchema: {
    realm: { "ui:placeholder": "defaults to the resource name" },
    hostname: { "ui:placeholder": "login.example.com (external hosted login/admin; in-cluster only if omitted)" },
    clientId: { "ui:placeholder": "openinfra" },
    size: { "ui:placeholder": "2Gi" },
  },
};

export const FLOWLOG_CREATE: CreateKindSpec = {
  kind: "FlowLog",
  crdName: "flowlogs.openinfra.dev",
  description:
    "VPC flow logging (OVS sFlow → collector → Loki) — sample node traffic and ship flow records to Loki; scope to a VPC or subnet by CIDR at view time.",
  sections: [
    { title: "Sampling", fields: ["samplingRate"] },
    { title: "Collector", fields: ["namespace", "nodeSelector"], advanced: true },
  ],
  uiSchema: {
    samplingRate: { "ui:placeholder": "64" },
    namespace: { "ui:placeholder": "kube-system" },
  },
};

export const HTTPAPI_CREATE: CreateKindSpec = {
  kind: "HttpApi",
  crdName: "httpapis.openinfra.dev",
  description:
    "A managed HTTP API (API Gateway-style) — map path routes onto backends behind one hostname, with optional JWT authorization, CORS, throttling, TLS and WAF.",
  sections: [
    { title: "API", fields: ["domain", "routes"] },
    { title: "Authorization", fields: ["authorizer"], advanced: true },
    { title: "CORS", fields: ["cors"], advanced: true },
    { title: "Throttling", fields: ["rateLimit"], advanced: true },
    { title: "TLS & WAF", fields: ["tls", "waf"], advanced: true },
  ],
  uiSchema: {
    domain: { "ui:placeholder": "api.example.com" },
  },
};

export const STATICSITE_CREATE: CreateKindSpec = {
  kind: "StaticSite",
  crdName: "staticsites.openinfra.dev",
  description:
    "Static frontend hosting (S3 + CloudFront-style) — serve a built SPA (a dist/ tree) from an object-store bucket behind one hostname, with SPA routing, TLS, and periodic sync.",
  sections: [
    { title: "Site", fields: ["domain"] },
    {
      title: "Bucket & routing",
      fields: ["bucket", "spa", "indexDocument", "errorDocument"],
      advanced: true,
    },
    { title: "TLS & sync", fields: ["tls", "syncIntervalSeconds"], advanced: true },
  ],
  uiSchema: {
    domain: { "ui:placeholder": "app.example.com" },
    indexDocument: { "ui:placeholder": "index.html" },
    errorDocument: { "ui:placeholder": "index.html (SPA fallback)" },
  },
};

export const EMAILSENDER_CREATE: CreateKindSpec = {
  kind: "EmailSender",
  crdName: "emailsenders.openinfra.dev",
  description:
    "Transactional email sending (AWS SES-shaped) — a verified sending identity that emits an SMTP connection secret your applications send through.",
  sections: [
    { title: "Sending identity", fields: ["fromAddress"] },
    { title: "Display name", fields: ["fromName"], advanced: true },
  ],
  uiSchema: {
    fromAddress: { "ui:placeholder": "no-reply@example.com" },
    fromName: { "ui:placeholder": "Example App" },
  },
};
