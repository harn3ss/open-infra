// Maps each resource kind to its documentation, so the console can offer "Learn more" links into the
// docs corpus (the console → docs bridge that didn't exist before). Until the docs site ships
// (Track B), these point at the rendered markdown on GitHub; the base URL is the single thing to
// repoint once the site is up.
const DOCS_BASE = "https://github.com/harn3ss/open-infra/blob/main/docs";

export function docsUrl(file: string): string {
  return `${DOCS_BASE}/${file}`;
}

/** kind → docs file (under docs/). Kinds without a dedicated doc are simply omitted (no link shown). */
const KIND_DOC_FILE: Record<string, string> = {
  Application: "quickstart.md",
  VirtualMachine: "virtual-machines.md",
  Function: "serverless.md",
  Model: "gpu.md",
  GraphQLApi: "aws-shim.md",
  Query: "query.md",
  Stream: "streaming.md",
  Migration: "migrations.md",
  Replication: "replication.md",
  DataFlow: "dataflow.md",
  SecurityGroup: "security-groups.md",
  Directory: "auth.md",
  EncryptionKey: "encryption.md",
  DataClassification: "data-classification.md",
  Destruction: "destruction.md",
  Grant: "iam.md",
  Policy: "iam.md",
  Role: "iam.md",
  User: "iam.md",
  Group: "iam.md",
};

/** The docs URL for a kind, or undefined if it has no dedicated doc yet. */
export function kindDocsUrl(kind: string): string | undefined {
  const file = KIND_DOC_FILE[kind];
  return file ? docsUrl(file) : undefined;
}
