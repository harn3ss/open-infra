// Cedar authoring vocabulary for the visual IAM policy editor (data-only, no UI).
//
// The visual editor renders an AWS-like Service → Access level → Action picker that emits Cedar
// `actions` (e.g. "s3:GetObject") into a Policy's spec.dataPlane statements. This module catalogs the
// vocabulary that editor needs: the data-plane services the platform governs, their actions grouped
// by AWS-style access level, the typed resource each service scopes to, and the request-condition
// keys the platform actually evaluates.
//
// GROUNDING (what the platform actually enforces, not the full AWS catalog):
//   - Governed services = the aws-shim front doors the Cedar engine covers: s3, dynamodb, lambda.
//     Confirmed in console-api/cmd/server/iam_simulate.go (`dataServices`), the enforcement path
//     console-api/internal/dataplaneauthz/authz.go, and policyengine/importaws.go (`SupportedServices`).
//   - The action strings are exactly those the shim derives before the data-plane check runs:
//       * S3     — console-api/cmd/aws-shim/policycheck.go `s3Action` (get/head→GetObject, put→PutObject,
//                  delete→DeleteObject, list-objects/head-bucket→ListBucket, list-buckets→ListAllMyBuckets).
//       * DynamoDB — console-api/cmd/aws-shim/dynamo.go: action is "dynamodb:"+<op> for every op
//                  `verbForOp` recognizes; the check runs when a TableName is present.
//       * Lambda — console-api/cmd/aws-shim/lambda.go: the only enforced action is "lambda:InvokeFunction".
//   - The typed resources are those policyengine/importaws.go maps ARNs to: Bucket::, Table::, Function::.
//   - The condition keys are those the shim puts in the Cedar context (policycheck.go `requestContext`):
//     `authenticated` (bool) and `sourceIp` (string).
// Where a value is an approximation of AWS's own classification (e.g. an access level for an action the
// shim recognizes but does not yet fully implement at the data layer), it is called out in a comment.

/** AWS-style access levels the editor groups data-plane actions under, in AWS render order. */
export type AccessLevel = "List" | "Read" | "Write" | "Permissions management" | "Tagging";

/** All access levels in AWS order. The editor may render every group header; those with no enforced
 *  action on a given service simply carry an empty list. */
export const ACCESS_LEVELS: readonly AccessLevel[] = [
  "List",
  "Read",
  "Write",
  "Permissions management",
  "Tagging",
] as const;

/** One data-plane action the platform can enforce, e.g. "s3:GetObject". */
export interface CedarAction {
  /** The Cedar action string emitted into a statement's `actions[]`, e.g. "s3:GetObject". */
  action: string;
  /** The operation half only, e.g. "GetObject" — for the picker label. */
  name: string;
  /** AWS-style access level this action belongs to. */
  level: AccessLevel;
  /** One-line description for the picker. */
  description: string;
  /**
   * When true, the action string is recognized/enforceable by policy but the underlying data
   * operation is not yet implemented by the shim (or is resource-agnostic, so resource scoping and
   * data-plane policy never apply to it). Surface it, but the editor may want to mark it.
   */
  approximate?: boolean;
}

/** A data-plane service the platform governs (an aws-shim front door + the Cedar engine). */
export interface CedarService {
  /** The action prefix, e.g. "s3" — also what dataplaneauthz uses to decide governance per service. */
  service: string;
  /** Display label, e.g. "S3". */
  label: string;
  /** Short description of the service front door. */
  description: string;
  /** The Cedar resource TYPE an action of this service scopes to, e.g. "Bucket". */
  resourceType: string;
  /** How the console labels one such resource in prose, e.g. "bucket". */
  resourceLabel: string;
  /** An example typed resource string, e.g. "Bucket::assets". */
  resourceExample: string;
  /** The enforceable actions, each tagged with its access level. */
  actions: CedarAction[];
}

/** The data-plane services the platform governs. Matches the BFF `dataServices` / `SupportedServices`. */
export const DATA_SERVICES = ["s3", "dynamodb", "lambda"] as const;
export type DataService = (typeof DATA_SERVICES)[number];

/**
 * The full authoring catalog. Each service's `actions` are exactly what the aws-shim derives and the
 * Cedar engine enforces (see GROUNDING above) — not the full AWS action list. Access levels follow
 * AWS's own classification.
 */
export const CEDAR_SERVICES: CedarService[] = [
  {
    service: "s3",
    label: "S3",
    description: "Object storage over MinIO (the aws-shim S3 front door).",
    resourceType: "Bucket",
    resourceLabel: "bucket",
    resourceExample: "Bucket::assets",
    actions: [
      // List
      {
        action: "s3:ListAllMyBuckets",
        name: "ListAllMyBuckets",
        level: "List",
        description: "List all buckets. Account-scoped, so per-resource scoping does not apply.",
        approximate: true,
      },
      {
        action: "s3:ListBucket",
        name: "ListBucket",
        level: "List",
        description: "List the objects in a bucket (and HEAD the bucket).",
      },
      // Read
      {
        action: "s3:GetObject",
        name: "GetObject",
        level: "Read",
        description: "Read (GET/HEAD) an object from a bucket.",
      },
      // Write
      {
        action: "s3:PutObject",
        name: "PutObject",
        level: "Write",
        description: "Write (PUT) an object into a bucket.",
      },
      {
        action: "s3:DeleteObject",
        name: "DeleteObject",
        // AWS classifies object deletion under the "Write" access level (S3 has no "Delete" level).
        level: "Write",
        description: "Delete an object from a bucket.",
      },
    ],
  },
  {
    service: "dynamodb",
    label: "DynamoDB",
    description: "NoSQL tables (the aws-shim DynamoDB front door).",
    resourceType: "Table",
    resourceLabel: "table",
    resourceExample: "Table::orders",
    actions: [
      // List
      {
        action: "dynamodb:ListTables",
        name: "ListTables",
        level: "List",
        description: "List table names. Table-agnostic, so per-resource scoping does not apply.",
        approximate: true,
      },
      // Read
      {
        action: "dynamodb:GetItem",
        name: "GetItem",
        level: "Read",
        description: "Read a single item by key.",
      },
      {
        action: "dynamodb:BatchGetItem",
        name: "BatchGetItem",
        level: "Read",
        description: "Read multiple items by key in one request.",
      },
      {
        action: "dynamodb:Query",
        name: "Query",
        level: "Read",
        description: "Query items by partition key (and optional sort-key condition).",
      },
      {
        action: "dynamodb:Scan",
        name: "Scan",
        level: "Read",
        description: "Scan a table (or index) for items.",
      },
      {
        action: "dynamodb:TransactGetItems",
        name: "TransactGetItems",
        level: "Read",
        description: "Read multiple items in a single transaction.",
      },
      {
        action: "dynamodb:DescribeTable",
        name: "DescribeTable",
        level: "Read",
        description: "Describe a table's schema and metadata.",
      },
      {
        action: "dynamodb:DescribeTimeToLive",
        name: "DescribeTimeToLive",
        level: "Read",
        description: "Read a table's TTL configuration.",
      },
      // Write
      {
        action: "dynamodb:PutItem",
        name: "PutItem",
        level: "Write",
        description: "Create or replace an item.",
      },
      {
        action: "dynamodb:UpdateItem",
        name: "UpdateItem",
        level: "Write",
        description: "Update attributes of an item.",
      },
      {
        action: "dynamodb:DeleteItem",
        name: "DeleteItem",
        // AWS classifies item deletion under "Write".
        level: "Write",
        description: "Delete an item by key.",
      },
      {
        action: "dynamodb:BatchWriteItem",
        name: "BatchWriteItem",
        level: "Write",
        description: "Put or delete multiple items in one request.",
      },
      {
        action: "dynamodb:TransactWriteItems",
        name: "TransactWriteItems",
        level: "Write",
        description: "Put/update/delete multiple items in a single transaction.",
      },
      {
        action: "dynamodb:CreateTable",
        name: "CreateTable",
        level: "Write",
        description: "Create a table.",
      },
      {
        action: "dynamodb:UpdateTimeToLive",
        name: "UpdateTimeToLive",
        level: "Write",
        description: "Enable or disable a table's TTL.",
      },
      {
        action: "dynamodb:DeleteTable",
        name: "DeleteTable",
        level: "Write",
        description: "Delete a table. Recognized for authorization; not yet implemented at the data layer.",
        approximate: true,
      },
    ],
  },
  {
    service: "lambda",
    label: "Lambda",
    description: "Function invocation (the aws-shim Lambda front door).",
    resourceType: "Function",
    resourceLabel: "function",
    resourceExample: "Function::worker",
    actions: [
      // Write (AWS classifies lambda:InvokeFunction under "Write").
      {
        action: "lambda:InvokeFunction",
        name: "InvokeFunction",
        level: "Write",
        description: "Invoke a function.",
      },
    ],
  },
];

/**
 * The Cedar resource TYPE per governed service (also the second half of a typed resource string,
 * "<Type>::<id>"). Mirrors the ARN → typed-resource mapping in policyengine/importaws.go.
 */
export const RESOURCE_TYPE_BY_SERVICE: Record<DataService, string> = {
  s3: "Bucket",
  dynamodb: "Table",
  lambda: "Function",
};

/**
 * Principal-type prefixes a Cedar block's `appliesTo` (and the simulator's `principal`) accept.
 * Grounded in dataplaneauthz `appliesTo` (User/Group/*) plus the simulator's Role principal.
 */
export const PRINCIPAL_TYPES = ["User", "Group", "Role"] as const;
export type PrincipalType = (typeof PRINCIPAL_TYPES)[number];

/** One request-condition key the platform's Cedar context actually carries. */
export interface CedarConditionKey {
  key: string;
  /** The value shape: "boolean" values are the strings "true"/"false"; "string" is free text. */
  type: "boolean" | "string";
  description: string;
}

/**
 * The request-condition keys the aws-shim populates and the Cedar engine can match on
 * (policycheck.go `requestContext`). A condition map value is a string (mirrors CedarStatement.condition:
 * Record<string,string>); boolean keys use "true"/"false".
 */
export const CEDAR_CONDITION_KEYS: CedarConditionKey[] = [
  {
    key: "authenticated",
    type: "boolean",
    description: 'Whether the request passed SigV4 auth. The shim sets it "true"; match to require it.',
  },
  {
    key: "sourceIp",
    type: "string",
    description: "The client IP the shim observed (from X-Forwarded-For or the peer address).",
  },
];

// ── Small pure lookups (no UI) ──────────────────────────────────────────────────

/** The service catalog entry for a service prefix, or undefined. */
export function serviceByName(service: string): CedarService | undefined {
  return CEDAR_SERVICES.find((s) => s.service === service);
}

/** Group a service's actions by access level, in AWS order. Levels with no action are omitted. */
export function actionsByLevel(service: CedarService): Array<{ level: AccessLevel; actions: CedarAction[] }> {
  return ACCESS_LEVELS.map((level) => ({
    level,
    actions: service.actions.filter((a) => a.level === level),
  })).filter((g) => g.actions.length > 0);
}

/** True when a string is one of the governed data-plane services (s3/dynamodb/lambda). */
export function isDataService(service: string): service is DataService {
  return (DATA_SERVICES as readonly string[]).includes(service);
}
