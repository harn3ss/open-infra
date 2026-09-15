import { useQuery } from "@tanstack/react-query";
import { Info, AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingState, ErrorState } from "@/components/common/states";
import { getAccessAdvisor, type AccessAdvisorService } from "@/lib/api";

/**
 * Access Advisor — the AWS "services last accessed" least-privilege surface, shared by the
 * User / Group / Role / Policy detail pages (drop-in replacement for the old PendingTab).
 *
 * HONESTY is the whole point of this tab, so it is rendered in the UI, not just carried in the type:
 *  - The `coverage` line (from the BFF) is always shown — the audit trail records mutations + auth
 *    decisions, NOT reads, so "last accessed" means "last write observed" and an absent service means
 *    "no writes seen", never "proven unused".
 *  - When the audit source was unreachable, the tab says UNKNOWN, not "no access".
 *  - For a group/role/policy the view is aggregated across the users who effectively hold the
 *    principal, and it says so (with the resolved actor count).
 */
function whenLabel(ts?: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  const days = Math.floor((Date.now() - d.getTime()) / 86_400_000);
  const rel = days <= 0 ? "today" : days === 1 ? "yesterday" : `${days}d ago`;
  return `${d.toLocaleDateString()} · ${rel}`;
}

export function AccessAdvisorTab({
  kind,
  name,
}: {
  kind: "user" | "group" | "role" | "policy";
  name: string;
}) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["iam", "access-advisor", kind, name],
    queryFn: () => getAccessAdvisor(kind, name),
    refetchInterval: 30_000,
  });

  if (isLoading) return <LoadingState label="Loading access advisor…" />;
  if (isError) return <ErrorState error={error} />;
  if (!data) return null;

  const services = data.services ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="space-y-1 p-5">
          <h3 className="text-sm font-semibold">Access Advisor — services last accessed</h3>
          <p className="text-sm text-muted-foreground">
            Open-infra services (resource types) this {kind} has written to, most-recently-used first,
            over the last {data.lookbackDays} days. Use it to spot access that is granted but unused.
          </p>
          {data.aggregated ? (
            <p className="text-xs text-muted-foreground">
              Aggregated across {data.actors.length} actor{data.actors.length === 1 ? "" : "s"} who
              effectively hold this {kind}
              {data.actors.length > 0 ? `: ${data.actors.join(", ")}` : ""}.
            </p>
          ) : null}
        </CardContent>
      </Card>

      {/* The honesty boundary — always shown, verbatim from the BFF. */}
      <Card>
        <CardContent className="flex items-start gap-3 p-4">
          <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
          <p className="text-xs text-muted-foreground">{data.coverage}</p>
        </CardContent>
      </Card>

      {!data.activitySourceReachable ? (
        <Card>
          <CardContent className="flex items-start gap-3 p-4">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">Activity source unavailable</h4>
              <p className="text-sm text-muted-foreground">{data.note}</p>
            </div>
          </CardContent>
        </Card>
      ) : services.length === 0 ? (
        <Card>
          <CardContent className="flex items-start gap-3 p-5">
            <Info className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">No write activity observed</h4>
              <p className="text-sm text-muted-foreground">{data.note}</p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Service</th>
                  <th className="px-4 py-2 font-medium">Last accessed (write)</th>
                  <th className="px-4 py-2 font-medium">Actions observed</th>
                  {data.aggregated ? <th className="px-4 py-2 font-medium">By</th> : null}
                </tr>
              </thead>
              <tbody>
                {services.map((s: AccessAdvisorService) => (
                  <tr key={s.service} className="border-b border-border/60 last:border-0">
                    <td className="px-4 py-2 font-medium">{s.service}</td>
                    <td className="px-4 py-2 text-muted-foreground">{whenLabel(s.lastAccessed)}</td>
                    <td className="px-4 py-2">
                      <div className="flex flex-wrap gap-1">
                        {(s.actions ?? []).map((a) => (
                          <Badge key={a} variant="secondary" className="text-xs">
                            {a}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    {data.aggregated ? (
                      <td className="px-4 py-2 text-xs text-muted-foreground">
                        {(s.actors ?? []).join(", ")}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
