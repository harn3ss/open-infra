import { useQuery } from "@tanstack/react-query";
import { ClipboardCheck, RefreshCw, ShieldAlert, UserX, Clock, KeyRound, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/common/states";
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

export function AccessReviewPage() {
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["access-review"],
    queryFn: getAccessReview,
    refetchInterval: 120000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ClipboardCheck />}
        title="Access Recertification"
        description="The standing access each account holds — group memberships, the roles they confer, and any active temporal grants — mapped to observed activity and flagged for review. The periodic 'does this person still need this access?' review (NIST AC-2(3)/AC-6(7)). Read-only: certify or revoke in Users, Groups & Grants."
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
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
                  {data.principals.map((p) => (
                    <tr key={p.name} className="border-b last:border-0 align-top">
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

          <p className="text-xs text-muted-foreground">{data.note}</p>
        </>
      )}
    </div>
  );
}
