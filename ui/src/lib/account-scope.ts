/**
 * The console's lists are the account's, as on AWS: "every bucket in this account", never "in this
 * namespace". A list asks for that with scope=account on an all-namespaces path; the server answers it
 * over the account's namespaces (console-api/cmd/server/account_scope.go). Namespaces are the platform's
 * own placement: user views do not show them — only the operator's views and a resource's YAML do.
 *
 * Kept free of runtime imports so `npm test` (node --test with type stripping) can load it directly.
 */

export const SCOPE_PARAM = "scope";
export const SCOPE_ACCOUNT = "account";

/** path with scope=account added (to its query, when it has one); unchanged when it already has it. */
export function withAccountScope(path: string): string {
  const [base, query = ""] = path.split("?", 2);
  const params = new URLSearchParams(query);
  params.set(SCOPE_PARAM, SCOPE_ACCOUNT);
  return `${base}?${params.toString()}`;
}

/** Whether path asks for the caller's account. */
export function isAccountScoped(path: string): boolean {
  const query = path.split("?", 2)[1] ?? "";
  return new URLSearchParams(query).get(SCOPE_PARAM) === SCOPE_ACCOUNT;
}

/** Whether a table column (TanStack's ColumnDef, read loosely) shows the resource's namespace, by its id,
 * accessor or header. */
export function isNamespaceColumn(col: object): boolean {
  const c = col as { id?: unknown; accessorKey?: unknown; header?: unknown };
  if (c.id === "namespace" || c.accessorKey === "metadata.namespace") return true;
  return typeof c.header === "string" && /^namespaces?$/i.test(c.header.trim());
}

/** columns without the namespace column(s): a user view's columns. */
export function withoutNamespaceColumns<C extends object>(columns: C[]): C[] {
  return columns.filter((c) => !isNamespaceColumn(c));
}

/**
 * The namespace a new resource lands in: the one asked for when it is the account's, else the account's
 * home, else (an older server that reports no account context) the fallback.
 */
export function createNamespace(
  account: { homeNamespace?: string; namespaces?: string[] } | null | undefined,
  asked: string | undefined,
  fallback = "default",
): string {
  const names = account?.namespaces ?? [];
  if (asked && (names.length === 0 || names.includes(asked))) return asked;
  return account?.homeNamespace || names[0] || asked || fallback;
}
