// AWS IAM policy documents and account ids in the console: pure helpers (no React), so node's test
// runner checks them directly.

/** A starting point for a new policy document: AWS's own minimal shape. */
export const EMPTY_POLICY_DOCUMENT = JSON.stringify(
  { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: [], Resource: "*" }] },
  null,
  2,
);

/**
 * Client-side check of an AWS JSON policy document, the way IAM's editor checks before saving: it must
 * parse, carry Version 2012-10-17 (or 2008-10-17) when it names one, and hold at least one statement
 * with an Effect of Allow or Deny and an Action or NotAction. The BFF validates again (and reports what
 * the evaluator narrows), so this only spares a round-trip. null when valid.
 */
export function checkPolicyDocument(text: string): string | null {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return `Not valid JSON: ${(e as Error).message}`;
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return "A policy document is a JSON object.";
  const d = doc as { Version?: unknown; Statement?: unknown };
  if (d.Version !== undefined && d.Version !== "2012-10-17" && d.Version !== "2008-10-17") {
    return 'Version must be "2012-10-17".';
  }
  const stmts = Array.isArray(d.Statement) ? d.Statement : d.Statement ? [d.Statement] : [];
  if (stmts.length === 0) return "A policy document needs at least one Statement.";
  for (const [i, s] of stmts.entries()) {
    const st = (s ?? {}) as { Effect?: unknown; Action?: unknown; NotAction?: unknown };
    if (st.Effect !== "Allow" && st.Effect !== "Deny") return `Statement ${i + 1}: Effect must be Allow or Deny.`;
    if (st.Action === undefined && st.NotAction === undefined) return `Statement ${i + 1}: needs an Action or NotAction.`;
  }
  return null;
}

/** How many statements a document holds, 0 when it doesn't parse. */
export function statementCount(text: string): number {
  try {
    const d = JSON.parse(text) as { Statement?: unknown };
    return Array.isArray(d.Statement) ? d.Statement.length : d.Statement ? 1 : 0;
  } catch {
    return 0;
  }
}

/** The 12-digit account id grouped as the AWS console shows it: 0000-0000-0000. */
export function formatAccountId(id: string): string {
  return /^\d{12}$/.test(id) ? `${id.slice(0, 4)}-${id.slice(4, 8)}-${id.slice(8)}` : id;
}
