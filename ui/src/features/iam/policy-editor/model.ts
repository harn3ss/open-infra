// The policy authoring model — the single in-memory shape both the Visual editor and the JSON editor
// bind to, plus the lossless mapping to/from the Policy CR document the BFF round-trips.
//
// WHY a shared model: AWS's editor has a Visual|JSON toggle that can silently "restructure" a policy.
// We avoid that by making BOTH views project the SAME model. `modelToDoc`/`docToModel` are inverses, so
// switching Visual↔JSON never loses or reshapes what the user authored.
//
// The two planes (see aws-iam-console-reference.md §2, §8.3):
//   - Control plane → `spec.statements[]` (Kubernetes RBAC). Allow-only, actions are "<resource>:<verb>"
//     over the openinfra.dev boundary, resources are effectively ["*"]. This is the existing coarse
//     resource×verb grid (reused verbatim from permission-editor.tsx).
//   - Data plane   → `spec.dataPlane` (Cedar, enforced at the aws-shim for S3/DynamoDB/Lambda). This is
//     what RBAC cannot express: an explicit Deny (which overrides), typed resource scoping, and request
//     conditions. Authored as AWS-style permission blocks.

import type { CedarBlock, CedarStatement, PolicyStatement } from "@/lib/api";
import {
  rowsToActions,
  actionsToRows,
  type PermRow,
} from "../permission-editor";
import {
  CEDAR_SERVICES,
  RESOURCE_TYPE_BY_SERVICE,
  serviceByName,
  type DataService,
} from "@/lib/iam-cedar-vocab";

/** The Policy document the BFF accepts on create/update (the authored artifact, minus metadata.name). */
export interface PolicyDoc {
  description: string;
  statements: PolicyStatement[];
  dataPlane?: CedarBlock;
  controlPlane?: CedarBlock;
}

/** One AWS-style data-plane permission block: one service, an effect, its actions, resources, conditions. */
export interface DataBlock {
  /** Stable local id for React keys and edits (not persisted). */
  id: string;
  /** Governed service prefix: "s3" | "dynamodb" | "lambda". */
  service: string;
  /** Allow or Deny. Deny overrides — the whole point of the Cedar plane; RBAC has no Deny. */
  effect: "Allow" | "Deny";
  /** When true the block grants every action of the service ("<service>:*"). */
  allActions: boolean;
  /** Specific action strings when !allActions, e.g. ["s3:GetObject"]. */
  actions: string[];
  /** When true the block applies to any resource of the service (no scope). */
  anyResource: boolean;
  /** Typed resources when !anyResource, e.g. ["Bucket::assets", "Bucket::log-*"]. */
  resources: string[];
  /** Request conditions (data plane only), e.g. [{ key: "authenticated", value: "true" }]. */
  conditions: Array<{ key: string; value: string }>;
}

/** The full authoring model. */
export interface PolicyModel {
  description: string;
  /** Control-plane grid rows (reused permission-editor shape) → spec.statements. */
  controlRows: PermRow[];
  /** Data-plane permission blocks → spec.dataPlane.statements. */
  dataBlocks: DataBlock[];
  /** Principals the data-plane block applies to → spec.dataPlane.appliesTo. Default ["*"]. */
  appliesTo: string[];
  /**
   * The Cedar control-plane block (Phase-2 shadow webhook). The Visual editor does not author it; it is
   * carried through untouched and editable only on the JSON tab, so a hand-authored controlPlane survives
   * a round-trip through the Visual editor.
   */
  controlPlane?: CedarBlock;
}

/** The default governed service (CEDAR_SERVICES is non-empty; guarded for noUncheckedIndexedAccess). */
const DEFAULT_SERVICE = CEDAR_SERVICES[0]?.service ?? "s3";

let seq = 0;
function newId(): string {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  } catch {
    /* ignore */
  }
  seq += 1;
  return `blk-${seq}-${Date.now()}`;
}

/** A fresh, empty model for the create flow. */
export function emptyModel(): PolicyModel {
  return { description: "", controlRows: [], dataBlocks: [], appliesTo: ["*"] };
}

/** A new data block seeded for a service (defaults to the first governed service). */
export function newDataBlock(service: string = DEFAULT_SERVICE): DataBlock {
  return {
    id: newId(),
    service,
    effect: "Allow",
    allActions: false,
    actions: [],
    anyResource: true,
    resources: [],
    conditions: [],
  };
}

/** Infer the governed service for a loaded Cedar statement from its actions (or typed resource). */
function inferService(st: CedarStatement): string {
  for (const a of st.actions ?? []) {
    const i = a.indexOf(":");
    if (i > 0) {
      const svc = a.slice(0, i);
      if (serviceByName(svc)) return svc;
    }
  }
  for (const r of st.resources ?? []) {
    const i = r.indexOf("::");
    if (i > 0) {
      const type = r.slice(0, i);
      const svc = (Object.keys(RESOURCE_TYPE_BY_SERVICE) as DataService[]).find(
        (s) => RESOURCE_TYPE_BY_SERVICE[s] === type,
      );
      if (svc) return svc;
    }
  }
  return DEFAULT_SERVICE;
}

/** Build the editor model from a Policy document (BFF read shape). Inverse of {@link modelToDoc}. */
export function docToModel(doc: PolicyDoc): PolicyModel {
  const controlActions = (doc.statements ?? []).flatMap((s) => s.actions ?? []);
  const controlRows = actionsToRows(controlActions);

  const dataStmts = doc.dataPlane?.statements ?? [];
  const dataBlocks: DataBlock[] = dataStmts.map((st) => {
    const service = inferService(st);
    const actions = st.actions ?? [];
    const allActions = actions.includes("*") || actions.includes(`${service}:*`);
    const resources = (st.resources ?? []).filter((r) => r && r !== "*");
    const anyResource = resources.length === 0;
    return {
      id: newId(),
      service,
      effect: st.effect === "Deny" ? "Deny" : "Allow",
      allActions,
      actions: allActions ? [] : actions,
      anyResource,
      resources,
      conditions: Object.entries(st.condition ?? {}).map(([key, value]) => ({ key, value })),
    };
  });

  const appliesTo = doc.dataPlane?.appliesTo?.length ? doc.dataPlane.appliesTo : ["*"];

  return {
    description: doc.description ?? "",
    controlRows,
    dataBlocks,
    appliesTo,
    controlPlane: doc.controlPlane,
  };
}

/**
 * Serialize one data block to a Cedar statement, or null when it would be unsafe/empty.
 *
 * SAFETY: an empty `actions` list means "any action" to the Cedar engine (matchAny with no values is a
 * wildcard). A block the user left with no actions selected must therefore NOT be emitted — dropping it
 * is fail-closed. `allActions` is the explicit way to say "every action of this service" ("<service>:*").
 */
function blockToStatement(b: DataBlock): CedarStatement | null {
  const actions = b.allActions ? [`${b.service}:*`] : b.actions.filter(Boolean);
  if (actions.length === 0) return null;
  const st: CedarStatement = { effect: b.effect, actions };
  if (!b.anyResource) {
    const resources = b.resources.map((r) => r.trim()).filter(Boolean);
    if (resources.length > 0) st.resources = resources;
  }
  const condition: Record<string, string> = {};
  for (const c of b.conditions) {
    if (c.key.trim()) condition[c.key.trim()] = c.value;
  }
  if (Object.keys(condition).length > 0) st.condition = condition;
  return st;
}

/** Build the Policy document from the editor model. Inverse of {@link docToModel}. */
export function modelToDoc(model: PolicyModel): PolicyDoc {
  const controlActions = rowsToActions(model.controlRows);
  const statements: PolicyStatement[] =
    controlActions.length > 0
      ? [{ effect: "Allow", actions: controlActions, resources: ["*"] }]
      : [];

  const dataStatements = model.dataBlocks
    .map(blockToStatement)
    .filter((s): s is CedarStatement => s !== null);

  const appliesTo = model.appliesTo.map((p) => p.trim()).filter(Boolean);

  // Always emit concrete blocks (empty when none). On UPDATE the BFF treats an omitted block as
  // "leave untouched" and an empty block as "clear it", so emitting an empty block is how a removed
  // plane is actually cleared (see updateIamPolicy in api.ts).
  const dataPlane: CedarBlock = {
    appliesTo: appliesTo.length ? appliesTo : ["*"],
    statements: dataStatements,
  };
  const controlPlane: CedarBlock = model.controlPlane ?? { appliesTo: [], statements: [] };

  return {
    description: model.description,
    statements,
    dataPlane,
    controlPlane,
  };
}

/** Pretty JSON of the document a model projects — the JSON tab's text. */
export function modelToJson(model: PolicyModel): string {
  return JSON.stringify(modelToDoc(model), null, 2);
}

/** True when the policy authors no permission on either plane (would grant nothing). */
export function isEmptyModel(model: PolicyModel): boolean {
  const doc = modelToDoc(model);
  const hasControl = doc.statements.some((s) => (s.actions ?? []).length > 0);
  const hasData = (doc.dataPlane?.statements ?? []).length > 0;
  return !hasControl && !hasData;
}

// ── Validation (three AWS severities: errors block, warnings caution, suggestions nudge) ─────────────

export interface Validation {
  errors: string[];
  warnings: string[];
  suggestions: string[];
}

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const TYPED_RESOURCE = /^[A-Za-z][A-Za-z0-9]*::.+$/;

/**
 * Live validation over the model (and the name on create). Mirrors AWS's in-editor Access-Analyzer
 * severities. Only `errors` block save; the primary button still follows the "never disabled for
 * validity" rule and is checked on submit.
 */
export function validateModel(
  model: PolicyModel,
  opts: { name?: string; isCreate: boolean },
): Validation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const suggestions: string[] = [];

  if (opts.isCreate) {
    if (!opts.name || !opts.name.trim()) errors.push("A policy name is required.");
    else if (!RFC1123.test(opts.name))
      errors.push("Name must be lowercase letters, digits and dashes only.");
  }

  if (isEmptyModel(model)) {
    suggestions.push("This policy grants nothing yet — add a platform permission or a data-service block.");
  }

  // Control plane
  for (const row of model.controlRows) {
    if (row.resource && row.verbs.length === 0)
      suggestions.push(`"${row.resource}" has no verbs selected — it grants nothing.`);
    if (row.resource === "*")
      warnings.push("A platform rule targets all resources (*) — grant the narrowest resource you can.");
  }

  // Data plane
  for (const b of model.dataBlocks) {
    const svc = serviceByName(b.service);
    const label = svc?.label ?? b.service;
    if (!b.allActions && b.actions.length === 0)
      suggestions.push(`The ${label} block selects no actions — it will be dropped (empty actions would match everything).`);
    if (b.allActions)
      warnings.push(`The ${label} block grants ALL ${label} actions (${b.service}:*).`);
    if (b.anyResource && !(svc && svc.actions.every((a) => a.approximate)))
      warnings.push(`The ${label} block applies to ANY ${svc?.resourceLabel ?? "resource"} — scope it to specific ones where you can.`);
    if (b.effect === "Deny")
      suggestions.push(`The ${label} block is a Deny — it overrides any Allow, including from other policies.`);
    for (const r of b.resources) {
      if (r.trim() && r !== "*" && !TYPED_RESOURCE.test(r.trim()))
        errors.push(`Resource "${r}" must be Type::id (e.g. ${svc?.resourceExample ?? "Bucket::assets"}) or a wildcard like ${svc?.resourceType ?? "Bucket"}::*.`);
    }
  }

  if (model.appliesTo.some((p) => p === "*") && model.dataBlocks.length > 0)
    warnings.push("Data-plane statements apply to all principals (*). Narrow appliesTo to specific Users/Groups where possible.");

  return { errors, warnings, suggestions };
}

/** Parse JSON-tab text into a document, throwing a readable error on malformed input. */
export function parseDoc(text: string): PolicyDoc {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("The policy document must be a JSON object.");
  const o = parsed as Record<string, unknown>;
  if (o.statements !== undefined && !Array.isArray(o.statements))
    throw new Error('"statements" must be an array.');
  if (o.dataPlane !== undefined && (typeof o.dataPlane !== "object" || o.dataPlane === null))
    throw new Error('"dataPlane" must be an object with a statements array.');
  return {
    description: typeof o.description === "string" ? o.description : "",
    statements: (o.statements as PolicyStatement[]) ?? [],
    dataPlane: o.dataPlane as CedarBlock | undefined,
    controlPlane: o.controlPlane as CedarBlock | undefined,
  };
}
