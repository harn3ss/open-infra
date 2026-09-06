import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ClipboardCheck,
  Clock,
  Download,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  UserX,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { SplitPanel } from "@/components/common/split-panel";
import {
  PropertyFilter,
  applyFilterTokens,
  type FilterPropertyDef,
  type FilterToken,
} from "@/components/common/property-filter";
import { InfoLink } from "@/components/help/info-link";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { docsUrl } from "@/lib/kind-docs";
import { getAccessReview, type AccessPrincipal } from "@/lib/api";

// Human-readable label + badge tone for each review flag the assembler emits.
const FLAG_META: Record<string, { label: string; variant: "destructive" | "warning" | "muted" | "accent" }> = {
  privileged: { label: "Privileged", variant: "accent" },
  "retains-access-disabled": { label: "Disabled but retains access", variant: "destructive" },
  "no-recent-activity": { label: "No recent activity", variant: "warning" },
  dormant: { label: "Dormant", variant: "warning" },
  "no-sign-in-credential": { label: "No sign-in credential", variant: "muted" },
  "inert-group-membership": { label: "Inert group membership", variant: "muted" },
  "active-temporal-grant": { label: "Active grant", variant: "accent" },
};

function FlagBadge({ flag }: { flag: string }) {
  const meta = FLAG_META[flag] ?? { label: flag, variant: "muted" as const };
  return <Badge variant={meta.variant}>{meta.label}</Badge>;
}

function lastSeenLabel(p: AccessPrincipal): string {
  if (!p.lastSeen) return "—";
  const d = new Date(p.lastSeen);
  const days = Math.floor((Date.now() - d.getTime()) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  return `${days}d ago`;
}

function StatCard({ icon, value, label }: { icon: React.ReactNode; value: number; label: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="text-muted-foreground">{icon}</div>
        <div>
          <div className="text-2xl font-semibold tabular-nums">{value}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

// Filterable properties (the AWS Access-Advisor-style property filter tokens).
const FILTER_PROPERTIES: FilterPropertyDef<AccessPrincipal>[] = [
  { key: "name", label: "Principal", getValue: (p) => p.name },
  {
    key: "source",
    label: "Source",
    options: [
      { value: "local" },
      { value: "ldap" },
      { value: "oidc" },
    ],
    getValue: (p) => p.source,
  },
  {
    key: "status",
    label: "Status",
    options: [
      { value: "enabled" },
      { value: "disabled" },
    ],
    getValue: (p) => (p.disabled ? "disabled" : "enabled"),
  },
  {
    key: "admin",
    label: "Console admin",
    options: [
      { value: "yes" },
      { value: "no" },
    ],
    getValue: (p) => (p.admin ? "yes" : "no"),
  },
  {
    key: "grant",
    label: "Active grant",
    options: [
      { value: "yes", label: "has active grant" },
      { value: "no", label: "none" },
    ],
    getValue: (p) => ((p.grants ?? []).length > 0 ? "yes" : "no"),
  },
  { key: "role", label: "Standing role", getValue: (p) => p.standingRoles ?? [] },
  {
    key: "flag",
    label: "Review flag",
    options: Object.entries(FLAG_META).map(([value, m]) => ({ value, label: m.label })),
    getValue: (p) => p.flags ?? [],
  },
];

function csvEscape(v: string): string {
  return `"${v.replace(/"/g, '""')}"`;
}

function toCsv(principals: AccessPrincipal[]): string {
  const header = [
    "name",
    "displayName",
    "source",
    "status",
    "consoleAdmin",
    "groups",
    "inertGroups",
    "standingRoles",
    "activeGrants",
    "lastSeen",
    "reviewFlags",
  ];
  const rows = principals.map((p) =>
    [
      p.name,
      p.displayName ?? "",
      p.source,
      p.disabled ? "disabled" : "enabled",
      p.admin ? "yes" : "no",
      (p.groups ?? []).join("; "),
      (p.inertGroups ?? []).join("; "),
      (p.standingRoles ?? []).join("; "),
      (p.grants ?? [])
        .map((g) => `${g.clusterRole}${g.viaGroup ? ` via ${g.viaGroup}` : ""}${g.expiresAt ? ` (exp ${g.expiresAt})` : ""}`)
        .join("; "),
      p.lastSeen ?? "",
      (p.flags ?? []).map((f) => FLAG_META[f]?.label ?? f).join("; "),
    ]
      .map((x) => csvEscape(String(x)))
      .join(","),
  );
  return [header.map(csvEscape).join(","), ...rows].join("\r\n");
}

function credentialLabel(p: AccessPrincipal): string {
  if (p.source !== "local") return `External (${p.source})`;
  return p.hasPassword ? "Password set" : "No password — cannot sign in";
}

/** The per-principal drill-down shown in the split panel (Access Advisor detail). */
function PrincipalDetail({ p }: { p: AccessPrincipal }) {
  return (
    <KeyValuePairs
      columns={3}
      items={[
        {
          label: "Principal",
          value: (
            <span className="inline-flex items-center gap-2">
              {p.name}
              {p.disabled ? <Badge variant="muted">disabled</Badge> : null}
              {p.admin ? <Badge variant="accent">console admin</Badge> : null}
            </span>
          ),
        },
        { label: "Display name", value: p.displayName || "—" },
        { label: "Source", value: p.source },
        { label: "Sign-in credential", value: credentialLabel(p) },
        { label: "Last seen", value: lastSeenLabel(p) },
        {
          label: "Groups",
          value:
            (p.groups ?? []).length === 0 ? (
              <span className="text-muted-foreground">none</span>
            ) : (
              <div className="flex flex-wrap gap-1">
                {(p.groups ?? []).map((g) => (
                  <Badge key={g} variant={(p.inertGroups ?? []).includes(g) ? "muted" : "secondary"}>
                    {g}
                    {(p.inertGroups ?? []).includes(g) ? " (inert)" : ""}
                  </Badge>
                ))}
              </div>
            ),
        },
        {
          label: "Standing roles",
          value:
            (p.standingRoles ?? []).length === 0 ? (
              <span className="text-muted-foreground">no effective role</span>
            ) : (
              <div className="flex flex-wrap gap-1">
                {(p.standingRoles ?? []).map((r) => (
                  <code key={r} className="rounded bg-muted px-1 py-0.5 text-xs">
                    {r}
                  </code>
                ))}
              </div>
            ),
        },
        {
          label: "Active grants",
          value:
            (p.grants ?? []).length === 0 ? (
              <span className="text-muted-foreground">none</span>
            ) : (
              <div className="space-y-1">
                {(p.grants ?? []).map((g) => (
                  <div key={g.name} className="text-xs">
                    <code className="rounded bg-muted px-1 py-0.5">{g.clusterRole}</code>
                    {g.viaGroup ? <span className="text-muted-foreground"> via {g.viaGroup}</span> : null}
                    {g.expiresAt ? (
                      <span className="text-muted-foreground"> · expires {new Date(g.expiresAt).toLocaleString()}</span>
                    ) : null}
                  </div>
                ))}
              </div>
            ),
        },
        {
          label: "Review flags",
          value:
            (p.flags ?? []).length === 0 ? (
              <span className="text-muted-foreground">—</span>
            ) : (
              <div className="flex flex-wrap gap-1">
                {(p.flags ?? []).map((f) => (
                  <FlagBadge key={f} flag={f} />
                ))}
              </div>
            ),
        },
      ]}
    />
  );
}

export function AccessReviewPage() {
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["access-review"],
    queryFn: getAccessReview,
    refetchInterval: 120000,
  });

  const [tokens, setTokens] = useState<FilterToken[]>([]);
  const [selected, setSelected] = useState<string | null>(null);

  const principals = data?.principals ?? [];
  const filtered = useMemo(
    () => applyFilterTokens(principals, tokens, FILTER_PROPERTIES),
    [principals, tokens],
  );
  const selectedPrincipal = filtered.find((p) => p.name === selected) ?? null;

  const exportCsv = () => {
    const blob = new Blob([toCsv(filtered)], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `access-review-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ClipboardCheck />}
        title="Access Recertification"
        description="The standing access each account holds — group memberships, the roles they confer, and any active temporal grants — mapped to observed activity and flagged for review. The periodic 'does this person still need this access?' review (NIST AC-2(3)/AC-6(7)). Read-only: certify or revoke in Users, Groups & Grants."
        actions={
          <>
            <InfoLink
              title="Access recertification"
              body={
                <div className="space-y-2 text-sm">
                  <p>
                    This is the fleet view of standing access for AC-2/AC-6 recertification — the open-infra answer to
                    AWS's credential report plus Access Analyzer's unused-access findings.
                  </p>
                  <p>
                    "Last seen" is derived from the audit trail (Loki: k3s-audit + console <code>iam:</code> lines). A
                    blank last-seen means <em>unknown</em>, not inactive — if the audit source is unreachable the
                    dormant / no-activity flags are suppressed.
                  </p>
                  <p>
                    The page is read-only. Right-size access in Users and Groups; approve or revoke temporal elevation in
                    Grants.
                  </p>
                </div>
              }
              docsHref={docsUrl("iam.md")}
            />
            <Button variant="outline" onClick={exportCsv} disabled={!data || filtered.length === 0}>
              <Download className="size-4" /> Export CSV
            </Button>
            <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
            </Button>
          </>
        }
      />

      {isLoading ? (
        <LoadingState label="Assembling access review…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data ? null : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <StatCard icon={<ClipboardCheck className="size-5" />} value={data.summary.principals} label="Principals" />
            <StatCard icon={<ShieldAlert className="size-5" />} value={data.summary.needsReview} label="Need review" />
            <StatCard icon={<KeyRound className="size-5" />} value={data.summary.privileged} label="Privileged" />
            <StatCard icon={<UserX className="size-5" />} value={data.summary.disabledRetaining} label="Disabled, retaining access" />
            <StatCard icon={<Clock className="size-5" />} value={data.summary.dormant + data.summary.noRecentActivity} label="Dormant / inactive" />
          </div>

          {!data.activitySourceReachable ? (
            <Card className="border-warning/40 bg-warning/10">
              <CardContent className="flex items-start gap-2 p-4 text-sm">
                <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
                <span>
                  <span className="font-medium text-foreground">Activity data unavailable.</span> The audit source
                  (Loki) was unreachable this run, so “last seen” is missing for every account and the dormant /
                  no-recent-activity flags are suppressed — a blank last-seen means <em>unknown</em>, not inactive.
                </span>
              </CardContent>
            </Card>
          ) : null}

          <Card>
            <CardContent className="p-4 text-sm text-muted-foreground">
              Generated <span className="font-medium text-foreground">{new Date(data.generatedAt).toLocaleString()}</span>{" "}
              · activity over the last <span className="font-medium text-foreground">{data.lookbackDays}</span> day(s)
              · dormancy threshold <span className="font-medium text-foreground">{data.dormancyDays}</span> day(s)
              · {data.summary.withActiveGrants} account(s) with an active temporal grant
            </CardContent>
          </Card>

          <PropertyFilter
            properties={FILTER_PROPERTIES}
            tokens={tokens}
            onChange={setTokens}
            placeholder="Filter principals"
          />

          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              {filtered.length} of {principals.length} principal{principals.length === 1 ? "" : "s"}
            </span>
          </div>

          {filtered.length === 0 ? (
            <Card>
              <CardContent className="p-0">
                <EmptyState
                  icon={<ClipboardCheck />}
                  title={tokens.length > 0 ? "No principals match the current filter" : "No principals to review"}
                  description={
                    tokens.length > 0
                      ? "Adjust or clear the filter to see more."
                      : "Once Users exist, their standing access is assembled here."
                  }
                  action={
                    tokens.length > 0 ? (
                      <Button variant="outline" size="sm" onClick={() => setTokens([])}>
                        Clear filters
                      </Button>
                    ) : undefined
                  }
                />
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="p-3 font-medium">Principal</th>
                      <th className="p-3 font-medium">Standing access</th>
                      <th className="p-3 font-medium">Grants</th>
                      <th className="p-3 font-medium">Last seen</th>
                      <th className="p-3 font-medium">Review flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((p) => (
                      <tr
                        key={p.name}
                        onClick={() => setSelected(p.name)}
                        aria-selected={selected === p.name}
                        className={`cursor-pointer border-b align-top last:border-0 hover:bg-muted/40 ${
                          selected === p.name ? "bg-muted/60" : ""
                        }`}
                      >
                        <td className="p-3">
                          <div className="flex items-center gap-2 font-medium">
                            {p.name}
                            {p.disabled ? <Badge variant="muted">disabled</Badge> : null}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {p.displayName ? `${p.displayName} · ` : ""}
                            {p.source}
                            {p.source === "local" && !p.hasPassword ? " · no password" : ""}
                          </div>
                        </td>
                        <td className="p-3">
                          {p.admin ? <Badge variant="accent">console admin</Badge> : null}
                          <div className="flex flex-wrap gap-1 pt-1">
                            {(p.standingRoles ?? []).map((r) => (
                              <code key={r} className="rounded bg-muted px-1 py-0.5 text-xs">{r}</code>
                            ))}
                            {(p.standingRoles ?? []).length === 0 && !p.admin ? (
                              <span className="text-xs text-muted-foreground">no effective role</span>
                            ) : null}
                          </div>
                          {(p.inertGroups ?? []).length > 0 ? (
                            <div className="pt-1 text-xs text-muted-foreground">
                              inert: {(p.inertGroups ?? []).join(", ")}
                            </div>
                          ) : null}
                        </td>
                        <td className="p-3 text-xs">
                          {(p.grants ?? []).length === 0 ? (
                            <span className="text-muted-foreground">—</span>
                          ) : (
                            <div className="space-y-1">
                              {(p.grants ?? []).map((g) => (
                                <div key={g.name} className="whitespace-nowrap">
                                  <code className="rounded bg-muted px-1 py-0.5">{g.clusterRole}</code>
                                  {g.viaGroup ? <span className="text-muted-foreground"> via {g.viaGroup}</span> : null}
                                  {g.expiresAt ? (
                                    <span className="text-muted-foreground"> · exp {new Date(g.expiresAt).toLocaleDateString()}</span>
                                  ) : null}
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="p-3 whitespace-nowrap text-muted-foreground">{lastSeenLabel(p)}</td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {(p.flags ?? []).length === 0 ? (
                              <span className="text-xs text-muted-foreground">—</span>
                            ) : (
                              (p.flags ?? []).map((f) => <FlagBadge key={f} flag={f} />)
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          )}

          {selectedPrincipal ? (
            <SplitPanel
              open
              onOpenChange={(o) => !o && setSelected(null)}
              header={`Access detail · ${selectedPrincipal.name}`}
            >
              <PrincipalDetail p={selectedPrincipal} />
            </SplitPanel>
          ) : null}

          <p className="text-xs text-muted-foreground">{data.note}</p>
        </>
      )}
    </div>
  );
}
