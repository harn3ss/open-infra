import { useQuery } from "@tanstack/react-query";
import { Waypoints, RefreshCw, ArrowRight } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { getLineage, type LineageFlow } from "@/lib/api";

function kindTone(kind: string): string {
  switch (kind) {
    case "Migration":
      return "bg-primary/15 text-primary";
    case "Replication":
      return "bg-amber-500/15 text-amber-600 dark:text-amber-400";
    case "Stream":
      return "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function FlowCard({ flow }: { flow: LineageFlow }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <span className={`rounded px-2 py-0.5 text-xs font-medium ${kindTone(flow.kind)}`}>{flow.kind}</span>
          <span className="font-medium">{flow.name}</span>
          <span className="text-xs text-muted-foreground">· {flow.namespace}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {!flow.edges || flow.edges.length === 0 ? (
          <div className="text-xs text-muted-foreground">no movements declared</div>
        ) : (
          flow.edges.map((e, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2 text-sm">
              <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{e.from}</code>
              <ArrowRight className="size-4 text-muted-foreground" />
              <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{e.to}</code>
              <Badge variant="outline" className="font-normal text-muted-foreground">
                {e.type}
              </Badge>
            </div>
          ))
        )}
        {flow.nodes && flow.nodes.length > 0 ? (
          <div className="pt-1 text-xs text-muted-foreground">
            nodes:{" "}
            {flow.nodes.map((n, i) => (
              <span key={i}>
                {i > 0 ? ", " : ""}
                <span className="font-medium">{n.name}</span>
                {n.engine ? ` (${n.engine})` : n.role ? ` (${n.role})` : ""}
              </span>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function LineagePage() {
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["lineage"],
    queryFn: getLineage,
    refetchInterval: 60000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Waypoints />}
        title="Data Lineage"
        description="Provenance of data movement across the platform — where data comes from and where it goes, derived from your DataFlow, Migration, Replication, and Stream topology. Read-only; answers 'where does this data flow?' for audit and CUI handling."
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Assembling lineage…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          icon={<Waypoints />}
          title="No data movements"
          description="No DataFlow, Migration, Replication, or Stream is configured yet. Once data moves between stores, its lineage appears here."
        />
      ) : (
        <div className="grid gap-4">
          {data.map((flow: LineageFlow) => (
            <FlowCard key={flow.origin} flow={flow} />
          ))}
        </div>
      )}
    </div>
  );
}
