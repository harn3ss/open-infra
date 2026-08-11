import { useQuery } from "@tanstack/react-query";
import { Tags, RefreshCw, CheckCircle2, XCircle, HelpCircle } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { getClassificationCompliance, type ClassRuleCheck } from "@/lib/api";

function levelTone(level: string): string {
  switch (level) {
    case "restricted":
      return "bg-destructive/15 text-destructive";
    case "confidential":
      return "bg-amber-500/15 text-amber-600 dark:text-amber-400";
    case "internal":
      return "bg-primary/15 text-primary";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function CheckIcon({ status }: { status: ClassRuleCheck["status"] }) {
  if (status === "pass") return <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />;
  if (status === "fail") return <XCircle className="size-4 text-destructive" />;
  return <HelpCircle className="size-4 text-muted-foreground" />;
}

export function DataClassificationPage() {
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["classification-compliance"],
    queryFn: getClassificationCompliance,
    refetchInterval: 60000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Tags />}
        title="Data Classification"
        description="Sensitivity levels and the handling requirements data at each level must meet (NIST RA-2). Tag a workload with the label openinfra.dev/classification=<name>; this page reports whether it meets its class's requirements. Classes are defined as kind: DataClassification (GitOps/kubectl)."
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Evaluating classification compliance…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : (
        <>
          {/* Defined classes */}
          <Card>
            <CardContent className="flex flex-wrap items-center gap-2 p-4">
              <span className="text-sm text-muted-foreground">Defined classes:</span>
              {data?.classes && data.classes.length > 0 ? (
                data.classes.map((c) => (
                  <span key={c.name} className={`rounded px-2 py-0.5 text-xs font-medium ${levelTone(c.level)}`}>
                    {c.name} · {c.level}
                  </span>
                ))
              ) : (
                <span className="text-sm text-muted-foreground">
                  none yet — create a <code className="text-xs">kind: DataClassification</code>.
                </span>
              )}
            </CardContent>
          </Card>

          {/* Compliance table */}
          {!data?.resources || data.resources.length === 0 ? (
            <EmptyState
              icon={<Tags />}
              title="No classified workloads"
              description="Nothing is tagged with openinfra.dev/classification yet. Label a Deployment or StatefulSet to bring it under a classification's handling requirements."
            />
          ) : (
            <Card>
              <CardContent className="p-0">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="p-3 font-medium">Workload</th>
                      <th className="p-3 font-medium">Class</th>
                      <th className="p-3 font-medium">Status</th>
                      <th className="p-3 font-medium">Checks</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.resources.map((res, i) => (
                      <tr key={i} className="border-b last:border-0 align-top">
                        <td className="p-3">
                          <div className="font-medium">{res.name}</div>
                          <div className="text-xs text-muted-foreground">
                            {res.kind} · {res.namespace}
                          </div>
                        </td>
                        <td className="p-3">
                          <span className={`rounded px-2 py-0.5 text-xs font-medium ${levelTone(res.level)}`}>
                            {res.class || "—"}
                            {res.level ? ` · ${res.level}` : ""}
                          </span>
                        </td>
                        <td className="p-3">
                          {res.compliant ? (
                            <Badge variant="secondary">compliant</Badge>
                          ) : (
                            <Badge variant="outline" className="border-destructive/40 text-destructive">
                              non-compliant
                            </Badge>
                          )}
                        </td>
                        <td className="p-3">
                          <ul className="space-y-1">
                            {(res.checks ?? []).map((c, j) => (
                              <li key={j} className="flex items-center gap-2">
                                <CheckIcon status={c.status} />
                                <span className="font-medium">{c.rule}</span>
                                <span className="text-xs text-muted-foreground">— {c.detail}</span>
                              </li>
                            ))}
                          </ul>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
