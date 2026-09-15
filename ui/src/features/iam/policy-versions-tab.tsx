import { useQuery } from "@tanstack/react-query";
import { Info, GitBranch } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { LoadingState, ErrorState } from "@/components/common/states";
import { getPolicyRevision } from "@/lib/api";

/**
 * The honest open-infra answer to AWS IAM's "Policy versions" tab.
 *
 * open-infra does NOT implement AWS's model of up-to-5 immutable, rollback-able policy versions. A
 * Policy is a Kubernetes custom resource: `metadata.generation` increments on each spec change, and the
 * real version HISTORY (prior contents, who changed them, rollback) lives in the DECLARATIVE SOURCE —
 * git / ArgoCD — when the policy is GitOps-managed. Rather than fabricate a version list the platform
 * doesn't keep, this tab shows the genuine current-revision metadata and states plainly where real
 * history does and does not exist (the BFF supplies the `note`).
 */
export function PolicyVersionsTab({ name }: { name: string }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["iam", "policy", name, "revision"],
    queryFn: () => getPolicyRevision(name),
  });

  if (isLoading) return <LoadingState label="Loading revision…" />;
  if (isError) return <ErrorState error={error} />;
  if (!data) return null;

  const created = data.createdAt ? new Date(data.createdAt).toLocaleString() : "—";

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="space-y-3 p-5">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">Current revision</h3>
            <Badge variant="secondary">generation {data.generation}</Badge>
            {data.gitOpsManaged ? (
              <Badge variant="outline" className="gap-1">
                <GitBranch className="size-3" /> GitOps-managed
              </Badge>
            ) : null}
          </div>
          <KeyValuePairs
            columns={2}
            items={[
              { label: "Generation (current revision)", value: String(data.generation) },
              { label: "Created", value: created },
              ...(data.resourceVersion
                ? [{ label: "Resource version", value: data.resourceVersion }]
                : []),
              ...(data.gitOpsTrackingId
                ? [{ label: "GitOps source", value: data.gitOpsTrackingId }]
                : []),
            ]}
          />
        </CardContent>
      </Card>

      {/* The honest note about how versioning actually works here — always shown. */}
      <Card>
        <CardContent className="flex items-start gap-3 p-4">
          <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
          <p className="text-xs text-muted-foreground">{data.note}</p>
        </CardContent>
      </Card>
    </div>
  );
}
