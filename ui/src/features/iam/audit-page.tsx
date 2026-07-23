import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ScrollText, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { formatTimestamp, age } from "@/lib/format";
import { listAuditEvents, type AuditEvent } from "@/lib/api";

const WINDOWS = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "168h", label: "Last 7 days" },
  { value: "720h", label: "Last 30 days" },
];

function verbTone(verb: string): string {
  if (verb.startsWith("delete") || verb === "deleted") return "bg-destructive/15 text-destructive";
  if (verb.startsWith("create") || verb === "created") return "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400";
  return "bg-primary/15 text-primary";
}

export function AuditPage() {
  const [since, setSince] = useState("24h");
  const [actor, setActor] = useState("");
  const [resource, setResource] = useState("");
  // Debounce-free: filters apply on Enter / refetch; keeps the query key stable.
  const [applied, setApplied] = useState({ actor: "", resource: "" });

  const { data = [], isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["audit", since, applied.actor, applied.resource],
    queryFn: () =>
      listAuditEvents({ since, actor: applied.actor, resource: applied.resource, limit: 300 }),
    refetchInterval: 30000,
  });

  const apply = () => setApplied({ actor: actor.trim(), resource: resource.trim() });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ScrollText />}
        title="Audit"
        description="Who did what — the CloudTrail of open-infra. Every mutation and authorization decision, attributed to a person: console, kubectl, Terraform and Argo alike. Reads are omitted; the full record stays on the control-plane node."
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
        }
      />

      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 p-4">
          <label className="space-y-1 text-sm">
            <span className="text-muted-foreground">Window</span>
            <Select value={since} onValueChange={setSince}>
              <SelectTrigger className="h-9 w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {WINDOWS.map((w) => (
                  <SelectItem key={w.value} value={w.value}>
                    {w.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-muted-foreground">User</span>
            <Input
              className="h-9 w-44"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && apply()}
              placeholder="e.g. alice"
            />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-muted-foreground">Resource</span>
            <Input
              className="h-9 w-44"
              value={resource}
              onChange={(e) => setResource(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && apply()}
              placeholder="e.g. virtualmachines"
            />
          </label>
          <Button onClick={apply}>Filter</Button>
        </CardContent>
      </Card>

      {isLoading ? (
        <LoadingState label="Loading audit trail…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<ScrollText />}
          title="No activity in this window"
          description="Nothing recorded for the selected filters. Widen the window, or note that reads are not shown — only mutations and authorization decisions."
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">When</th>
                  <th className="p-3 font-medium">User</th>
                  <th className="p-3 font-medium">Action</th>
                  <th className="p-3 font-medium">Resource</th>
                  <th className="p-3 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {data.map((e: AuditEvent, i) => (
                  <tr key={i} className="border-b last:border-0 align-top">
                    <td className="p-3 text-muted-foreground whitespace-nowrap">
                      <span title={e.time}>{formatTimestamp(e.time)}</span>
                      <span className="ml-1 text-xs">· {age(e.time)}</span>
                    </td>
                    <td className="p-3 font-medium">{e.actor || "—"}</td>
                    <td className="p-3">
                      <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${verbTone(e.verb)}`}>
                        {e.verb}
                      </span>
                    </td>
                    <td className="p-3">
                      <code className="text-xs">{e.resource}</code>
                      {e.name ? <span className="text-muted-foreground"> / {e.name}</span> : null}
                      {e.namespace ? (
                        <span className="text-xs text-muted-foreground"> · {e.namespace}</span>
                      ) : null}
                    </td>
                    <td className="p-3">
                      {e.result ? (
                        <Badge
                          variant={e.result.startsWith("2") ? "secondary" : "outline"}
                          className={
                            e.result.startsWith("2")
                              ? ""
                              : "border-amber-500/40 text-amber-600 dark:text-amber-400"
                          }
                        >
                          {e.result}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          {e.source === "console" ? "console" : "—"}
                        </span>
                      )}
                    </td>
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
