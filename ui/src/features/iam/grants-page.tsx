import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Clock, Plus } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { listIamGrants, type IamGrant } from "@/lib/api";

export function phaseBadge(phase: string): { variant: "default" | "secondary" | "destructive" | "outline"; label: string } {
  switch (phase) {
    case "Active":
      return { variant: "default", label: "Active" };
    case "AwaitingApproval":
      return { variant: "secondary", label: "Awaiting approval" };
    case "Approved":
      return { variant: "secondary", label: "Approved" };
    case "Expired":
      return { variant: "outline", label: "Expired" };
    case "NotGrantable":
      return { variant: "destructive", label: "Not grantable" };
    default:
      return { variant: "outline", label: phase || "Unknown" };
  }
}

export function GrantsPage() {
  const navigate = useNavigate();
  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "grants"],
    queryFn: listIamGrants,
    refetchInterval: 10000,
  });

  const awaiting = data.filter((g: IamGrant) => g.phase === "AwaitingApproval").length;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Clock />}
        title="Grants"
        description="Temporary access: policies attached to a user or group for a while, at most 24 hours. A grant is a request: it attaches nothing until someone other than the requester approves it (separation of duties, AC-2(2)/AC-5), and its policies are detached on their own when it ends."
        actions={
          <Button onClick={() => navigate({ to: "/grants/new" })}>
            <Plus className="size-4" /> Request access
          </Button>
        }
      />

      {awaiting > 0 ? (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm">
          {awaiting} grant{awaiting === 1 ? "" : "s"} awaiting approval — open one to approve or deny.
        </div>
      ) : null}

      {isLoading ? (
        <LoadingState label="Loading grants…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<Clock />}
          title="No grants"
          description="Request temporary access; someone other than you approves it before its policies are attached."
          action={
            <Button onClick={() => navigate({ to: "/grants/new" })}>
              <Plus className="size-4" /> Request access
            </Button>
          }
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Name</th>
                  <th className="p-3 font-medium">Subject</th>
                  <th className="p-3 font-medium">Policies</th>
                  <th className="p-3 font-medium">Duration</th>
                  <th className="p-3 font-medium">Phase</th>
                </tr>
              </thead>
              <tbody>
                {data.map((g) => {
                  const b = phaseBadge(g.phase);
                  return (
                    <tr
                      key={g.name}
                      className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                      onClick={() => navigate({ to: "/grants/$name", params: { name: g.name } })}
                    >
                      <td className="p-3 font-medium text-primary">{g.name}</td>
                      <td className="p-3 text-muted-foreground">
                        {g.subjectKind}/{g.subjectName}
                      </td>
                      <td className="p-3 text-muted-foreground">
                        <code className="text-xs">{(g.policies ?? []).join(", ")}</code>
                      </td>
                      <td className="p-3 tabular-nums text-muted-foreground">{g.duration}</td>
                      <td className="p-3">
                        <Badge variant={b.variant}>{b.label}</Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

    </div>
  );
}
