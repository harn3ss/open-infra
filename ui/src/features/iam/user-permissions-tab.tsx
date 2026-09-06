import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Boxes, FileText, ShieldCheck, ShieldAlert } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { InfoLink } from "@/components/help/info-link";
import { Spinner } from "@/components/common/states";
import {
  getIamConfig,
  listIamGroups,
  listIamPolicies,
  listIamRoles,
  type IamPolicy,
  type IamUser,
} from "@/lib/api";
import { serviceByName } from "@/lib/iam-cedar-vocab";

/**
 * The user's effective permissions — the one permissions table with an "Attached via" column
 * (house convention #3). RBAC has no user-direct policy attachment: a user's authority is exactly
 * the union of its groups' ClusterRoles, so this resolves each group → its ClusterRole → the Role or
 * Policy that compiled it → the actions those grant. Everything is computed client-side from the
 * existing list endpoints (no new BFF surface); a group outside the impersonation ceiling grants
 * nothing and is flagged, and the always-on structural platform boundary is surfaced honestly.
 */

/** AWS-style access levels for a control-plane verb, in render order. */
const ACCESS_ORDER = ["List", "Read", "Write", "Delete", "Permissions management"] as const;
type AccessLevel = (typeof ACCESS_ORDER)[number];

function levelForVerb(verb: string): AccessLevel {
  const v = verb.toLowerCase();
  if (v === "list" || v === "watch") return "List";
  if (v === "get") return "Read";
  if (v === "create" || v === "update" || v === "patch") return "Write";
  if (v === "delete" || v === "deletecollection") return "Delete";
  if (v === "bind" || v === "escalate" || v === "impersonate") return "Permissions management";
  return "Write";
}

/** What one group confers, resolved to a granting source. */
interface Resolved {
  group: string;
  /** false ⇒ the group is outside the impersonation ceiling and grants nothing. */
  bound: boolean;
  kind: "role" | "policy" | "builtin" | "unknown";
  /** The Role or Policy name (or the built-in ClusterRole). */
  sourceName: string;
  /** For a role, the policies it aggregates. */
  rolePolicies?: string[];
}

export function UserPermissionsTab({ user }: { user: IamUser }) {
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const groupsQ = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const rolesQ = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const policiesQ = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });

  const builtins = cfg.data?.builtinGroups ?? [];
  const groups = groupsQ.data ?? [];
  const roles = rolesQ.data ?? [];
  const policies = policiesQ.data ?? [];

  const userGroups = user.groups ?? [];
  const unbound = new Set(user.unboundGroups ?? []);

  // Resolve each group → its granting source (Role / Policy / built-in ClusterRole).
  const resolved = useMemo<Resolved[]>(() => {
    return userGroups.map((g) => {
      const bound = !unbound.has(g);
      const grp = groups.find((x) => x.name === g);
      const clusterRole = grp?.clusterRole;
      if (clusterRole) {
        const role = roles.find((r) => (r.clusterRole || `openinfra-role-${r.name}`) === clusterRole);
        if (role)
          return { group: g, bound, kind: "role", sourceName: role.name, rolePolicies: role.policies };
        const pol = policies.find((p) => p.clusterRole === clusterRole);
        if (pol) return { group: g, bound, kind: "policy", sourceName: pol.name };
        return { group: g, bound, kind: "builtin", sourceName: clusterRole };
      }
      // No Group object: a built-in name (admins/powerusers/readers) maps to a shipped ClusterRole.
      if (builtins.includes(g)) return { group: g, bound, kind: "builtin", sourceName: `console:${g}` };
      return { group: g, bound, kind: "unknown", sourceName: "—" };
    });
  }, [userGroups, unbound, groups, roles, policies, builtins]);

  // The Policy objects effective for the user (from bound groups only), with provenance.
  const effective = useMemo(() => {
    const byPolicy = new Map<string, { policy: IamPolicy; via: string[] }>();
    const add = (name: string, via: string) => {
      const policy = policies.find((p) => p.name === name);
      if (!policy) return;
      const cur = byPolicy.get(name);
      if (cur) cur.via.push(via);
      else byPolicy.set(name, { policy, via: [via] });
    };
    for (const r of resolved) {
      if (!r.bound) continue;
      if (r.kind === "policy") add(r.sourceName, `Group: ${r.group}`);
      if (r.kind === "role")
        for (const p of r.rolePolicies ?? []) add(p, `Group: ${r.group} → Role: ${r.sourceName}`);
    }
    return [...byPolicy.values()];
  }, [resolved, policies]);

  // Roll the effective policies' control-plane actions up by access level (AWS's summary table).
  const summary = useMemo(() => {
    const byLevel = new Map<AccessLevel, Set<string>>();
    const dataPlane = new Set<string>();
    for (const { policy } of effective) {
      for (const stmt of policy.statements ?? []) {
        for (const action of stmt.actions ?? []) {
          const [resource, verb = "*"] = action.split(":");
          if (verb === "*") {
            for (const lvl of ACCESS_ORDER) addTo(byLevel, lvl, `${resource}:*`);
          } else {
            addTo(byLevel, levelForVerb(verb), action);
          }
        }
      }
      for (const stmt of policy.dataPlane?.statements ?? []) {
        for (const action of stmt.actions ?? []) dataPlane.add(action);
      }
    }
    return { byLevel, dataPlane };
  }, [effective]);

  const loading = cfg.isLoading || groupsQ.isLoading || rolesQ.isLoading || policiesQ.isLoading;

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
        <Spinner /> Resolving effective permissions…
      </div>
    );
  }

  const hasBound = resolved.some((r) => r.bound);

  return (
    <div className="space-y-4">
      {/* No effective permissions is a fail-closed footgun worth surfacing loudly. */}
      {!hasBound ? (
        <Card className="border-amber-500/40">
          <CardContent className="flex items-start gap-2 p-4 text-sm text-amber-600 dark:text-amber-400">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>
              <b>{user.name}</b> is authorized for nothing. On this platform a user's access is exactly
              the union of its groups' ClusterRoles — with no effective group membership, they can sign
              in but do nothing. Add a group on the <b>Groups</b> tab.
            </span>
          </CardContent>
        </Card>
      ) : null}

      {/* Attached-via table: what grants this user, and how. */}
      <Card>
        <CardContent className="space-y-3 p-5">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">Permissions policies</h3>
            <InfoLink
              title="How a user gets permissions"
              body={
                <div className="space-y-2 text-sm">
                  <p>
                    Kubernetes RBAC is the enforcement plane, and it is purely additive with no
                    user-direct attachment. A user's authority is the union of its groups' ClusterRoles.
                  </p>
                  <p>
                    Each group points at a ClusterRole compiled from a Role (a bundle of policies) or a
                    single Policy. This table resolves that chain and shows the provenance in the
                    <b> Attached via</b> column.
                  </p>
                </div>
              }
            />
          </div>

          {resolved.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No groups. This user is authorized for nothing.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="py-2 pr-3 font-medium">Source</th>
                    <th className="py-2 pr-3 font-medium">Type</th>
                    <th className="py-2 pr-3 font-medium">Attached via</th>
                  </tr>
                </thead>
                <tbody>
                  {resolved.map((r) => (
                    <tr key={r.group} className="border-b last:border-0">
                      <td className="py-2 pr-3">
                        {!r.bound ? (
                          <span className="flex items-center gap-1 text-amber-600 dark:text-amber-400">
                            <AlertTriangle className="size-3.5" /> grants nothing
                          </span>
                        ) : r.kind === "role" ? (
                          <Link
                            to="/roles/$name"
                            params={{ name: r.sourceName }}
                            className="inline-flex items-center gap-1 font-medium text-primary hover:underline"
                          >
                            <Boxes className="size-3.5" /> {r.sourceName}
                          </Link>
                        ) : r.kind === "policy" ? (
                          <Link
                            to="/policies/$name"
                            params={{ name: r.sourceName }}
                            className="inline-flex items-center gap-1 font-medium text-primary hover:underline"
                          >
                            <FileText className="size-3.5" /> {r.sourceName}
                          </Link>
                        ) : (
                          <code className="text-xs text-muted-foreground">{r.sourceName}</code>
                        )}
                      </td>
                      <td className="py-2 pr-3">
                        <Badge variant={r.kind === "builtin" ? "muted" : "secondary"}>
                          {r.kind === "role"
                            ? "Role"
                            : r.kind === "policy"
                              ? "Policy"
                              : r.kind === "builtin"
                                ? "Built-in"
                                : "Unknown"}
                        </Badge>
                        {r.kind === "role" && (r.rolePolicies?.length ?? 0) > 0 ? (
                          <span className="ml-2 text-xs text-muted-foreground">
                            {r.rolePolicies?.length} {r.rolePolicies?.length === 1 ? "policy" : "policies"}
                          </span>
                        ) : null}
                      </td>
                      <td className="py-2 pr-3">
                        <span className="text-muted-foreground">Group: {r.group}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Access-level summary — the union of effective control-plane actions, AWS-style. */}
      {effective.length > 0 ? (
        <Card>
          <CardContent className="space-y-3 p-5">
            <h3 className="text-sm font-semibold">Effective actions by access level</h3>
            <div className="space-y-3">
              {ACCESS_ORDER.map((lvl) => {
                const actions = [...(summary.byLevel.get(lvl) ?? [])].sort();
                if (actions.length === 0) return null;
                const danger = lvl === "Permissions management";
                return (
                  <div key={lvl} className="space-y-1.5">
                    <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide">
                      {danger ? (
                        <ShieldAlert className="size-3.5 text-destructive" />
                      ) : (
                        <ShieldCheck className="size-3.5 text-muted-foreground" />
                      )}
                      <span className={danger ? "text-destructive" : "text-muted-foreground"}>{lvl}</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {actions.map((a) => (
                        <Badge key={a} variant={danger ? "destructive" : "outline"}>
                          {a}
                        </Badge>
                      ))}
                    </div>
                  </div>
                );
              })}
              {[...summary.byLevel.values()].every((s) => s.size === 0) ? (
                <p className="text-sm text-muted-foreground">
                  No control-plane actions — the effective policies grant only data-plane access (below)
                  or nothing.
                </p>
              ) : null}
            </div>

            {summary.dataPlane.size > 0 ? (
              <div className="space-y-1.5 border-t border-border pt-3">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Data plane (S3 / DynamoDB / Lambda)
                </div>
                <div className="flex flex-wrap gap-1">
                  {[...summary.dataPlane].sort().map((a) => {
                    const svc = serviceByName(a.split(":")[0] ?? "");
                    return (
                      <Badge key={a} variant="accent" title={svc?.label}>
                        {a}
                      </Badge>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {/* The structural boundary — always on, honest, not an AWS-style per-user boundary. */}
      <Card>
        <CardContent className="flex items-start gap-2 p-4 text-xs text-muted-foreground">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <span>
            <b className="text-foreground">Platform boundary (always).</b> A Policy can only ever grant
            on the ~{cfg.data?.policyResources?.length ?? 33} openinfra.dev product resources — identity
            kinds, Secrets and RBAC are excluded structurally, so no policy can escalate a user beyond
            the product surface. There is no per-user permissions boundary to set; the cap is built in.
          </span>
        </CardContent>
      </Card>
    </div>
  );
}

function addTo(m: Map<AccessLevel, Set<string>>, level: AccessLevel, value: string) {
  const s = m.get(level) ?? new Set<string>();
  s.add(value);
  m.set(level, s);
}
