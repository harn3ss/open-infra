import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2, Play, Search } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import { k8sCreate, queryResult } from "@/lib/api";
import type { StatusTone } from "@/lib/format";
import { age } from "@/lib/format";
import type { Query } from "@/types/k8s";

const DEFAULT_SQL =
  "SELECT * FROM read_parquet('s3://query-data/sales.parquet') LIMIT 100";

function toneFor(state?: string): StatusTone {
  if (state === "SUCCEEDED") return "success";
  if (state === "FAILED") return "destructive";
  return "warning";
}

/**
 * open-infra's Athena: write SQL, run it over the data lake (MinIO) with no
 * database to load into, and see results + query history. Submitting creates a
 * kind: Query (an execution); the page polls the result until it finishes.
 */
export function QueriesPage() {
  const { scoped } = useNamespace();
  const ns = scoped || "default";
  const [sql, setSql] = useState(DEFAULT_SQL);
  const [current, setCurrent] = useState<string | null>(null);

  const history = useK8sWatch<Query>(openinfraPaths.queries(scoped));
  const queries = useMemo(
    () =>
      [...history.items].sort((a, b) =>
        (b.metadata.creationTimestamp ?? "").localeCompare(
          a.metadata.creationTimestamp ?? "",
        ),
      ),
    [history.items],
  );

  const run = useMutation({
    mutationFn: async () => {
      const name = `q-${Date.now().toString(36)}`;
      await k8sCreate(openinfraPaths.queries(ns), {
        apiVersion: "openinfra.dev/v1",
        kind: "Query",
        metadata: { name, namespace: ns },
        spec: { sql },
      });
      return name;
    },
    onSuccess: (name) => setCurrent(name),
  });

  const result = useQuery({
    queryKey: ["query-result", ns, current],
    enabled: Boolean(current),
    queryFn: () => queryResult(ns, current as string),
    // poll while the execution is still running
    refetchInterval: (q) =>
      q.state.data && q.state.data.state !== "RUNNING" ? false : 1500,
  });
  const res = result.data;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Query"
        description="Serverless SQL over your data lake — no database to load into. open-infra's Athena."
        icon={<Search />}
      />

      <div className="grid gap-4 lg:grid-cols-[1fr_260px]">
        <div className="space-y-4">
          <Card>
            <CardContent className="space-y-3 p-4">
              <textarea
                value={sql}
                onChange={(e) => setSql(e.target.value)}
                spellCheck={false}
                rows={6}
                className="w-full resize-y rounded-md border bg-muted/30 p-3 font-mono text-sm outline-none focus:ring-1 focus:ring-ring"
                placeholder="SELECT * FROM read_parquet('s3://bucket/*.parquet')"
              />
              <div className="flex items-center gap-2">
                <Button
                  onClick={() => run.mutate()}
                  disabled={run.isPending || !sql.trim()}
                >
                  {run.isPending ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Play className="size-4" />
                  )}
                  Run
                </Button>
                <span className="text-xs text-muted-foreground">
                  Runs in namespace <code>{ns}</code>
                </span>
              </div>
            </CardContent>
          </Card>

          {current ? (
            <Card>
              <CardContent className="p-0">
                <div className="flex items-center gap-3 border-b p-3">
                  <StatusBadge
                    status={res?.state ?? "RUNNING"}
                    tone={toneFor(res?.state)}
                  />
                  {res?.state === "SUCCEEDED" ? (
                    <span className="text-xs text-muted-foreground">
                      {res.rowCount} rows · {res.executionTimeMs} ms
                      {res.truncated ? ` · showing first ${res.rows?.length}` : ""}
                    </span>
                  ) : res?.state === "RUNNING" || !res ? (
                    <span className="text-xs text-muted-foreground">running…</span>
                  ) : null}
                </div>
                {res?.state === "FAILED" ? (
                  <pre className="whitespace-pre-wrap p-3 text-xs text-destructive">
                    {res.error}
                  </pre>
                ) : res?.columns?.length ? (
                  <ScrollArea className="max-h-[440px]">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 bg-background">
                        <tr className="border-b text-left">
                          {res.columns.map((c) => (
                            <th key={c} className="p-2 font-medium">
                              {c}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {(res.rows ?? []).map((row, i) => (
                          <tr key={i} className="border-b last:border-0">
                            {row.map((cell, j) => (
                              <td key={j} className="p-2 font-mono text-xs">
                                {cell}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </ScrollArea>
                ) : (
                  <div className="p-3 text-xs text-muted-foreground">
                    No results.
                  </div>
                )}
              </CardContent>
            </Card>
          ) : null}
        </div>

        <Card>
          <CardContent className="p-2">
            <div className="px-2 py-1 text-xs font-medium text-muted-foreground">
              Recent queries
            </div>
            <div className="space-y-1">
              {queries.length === 0 ? (
                <div className="p-2 text-xs text-muted-foreground">
                  No queries yet.
                </div>
              ) : (
                queries.map((q) => (
                  <button
                    key={q.metadata.name}
                    onClick={() => {
                      setSql(q.spec?.sql ?? "");
                      setCurrent(q.metadata.name ?? null);
                    }}
                    title={q.spec?.sql}
                    className={`w-full rounded px-2 py-1.5 text-left hover:bg-muted ${
                      current === q.metadata.name ? "bg-muted" : ""
                    }`}
                  >
                    <div className="truncate font-mono text-xs">
                      {q.spec?.sql}
                    </div>
                    <div className="text-[10px] text-muted-foreground">
                      {age(q.metadata.creationTimestamp)}
                    </div>
                  </button>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
