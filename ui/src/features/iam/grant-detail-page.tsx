import { useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock, ShieldCheck } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState, Spinner } from "@/components/common/states";
import { approveIamGrant, getIamGrant, revokeIamGrant } from "@/lib/api";
import { phaseBadge } from "./grants-page";

export function GrantDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [note, setNote] = useState("");

  const { data: grant, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "grant", name],
    queryFn: () => getIamGrant(name),
    refetchInterval: 5000,
  });

  const approve = useMutation({
    mutationFn: () => approveIamGrant(name, note),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "grants"] });
      void qc.invalidateQueries({ queryKey: ["iam", "grant", name] });
      void refetch();
    },
  });

  const del = useMutation({
    mutationFn: () => revokeIamGrant(name),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "grants"] });
      navigate({ to: "/grants" });
    },
  });

  if (isLoading) return <LoadingState label="Loading grant…" />;
  if (isError || !grant) return <ErrorState error={error} onRetry={refetch} />;

  const b = phaseBadge(grant.phase);
  const approved = grant.approvedBy !== "";

  return (
    <DetailShell
      backTo="/grants"
      backLabel="Grants"
      icon={<Clock className="size-5" />}
      title={grant.name}
      subtitle={`${grant.subjectKind}/${grant.subjectName} → ${grant.clusterRole}`}
      actions={<Badge variant={b.variant}>{b.label}</Badge>}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="approve">Approve</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Subject">
                {grant.subjectKind}/{grant.subjectName}
              </DetailRow>
              <DetailRow label="ClusterRole">
                <code className="text-xs">{grant.clusterRole}</code>
              </DetailRow>
              <DetailRow label="Duration">{grant.duration}</DetailRow>
              <DetailRow label="Reason">{grant.reason || "—"}</DetailRow>
              <DetailRow label="Requested by">{grant.requestedBy || "—"}</DetailRow>
              <DetailRow label="Phase">
                <Badge variant={b.variant}>{b.label}</Badge>
              </DetailRow>
              <DetailRow label="Bound to">
                {grant.boundTo ? <code className="text-xs">{grant.boundTo}</code> : "— (no binding)"}
              </DetailRow>
              {grant.message ? <DetailRow label="Status">{grant.message}</DetailRow> : null}
            </CardContent>
          </Card>
          {approved ? (
            <Card>
              <CardContent className="divide-y divide-border p-0">
                <DetailRow label="Approved by">{grant.approvedBy}</DetailRow>
                <DetailRow label="Approved at">{grant.approvedAt || "—"}</DetailRow>
                {grant.approvalNote ? (
                  <DetailRow label="Approver note">{grant.approvalNote}</DetailRow>
                ) : null}
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>

        <TabsContent value="approve" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-4 p-4">
              {approved ? (
                <p className="text-sm text-muted-foreground">
                  Already approved by{" "}
                  <span className="font-medium text-foreground">{grant.approvedBy}</span>
                  {grant.approvedAt ? ` at ${grant.approvedAt}` : ""}.
                </p>
              ) : grant.phase === "NotGrantable" ? (
                <p className="text-sm text-destructive">{grant.message}</p>
              ) : (
                <>
                  <p className="text-sm text-muted-foreground">
                    Approving grants{" "}
                    <span className="font-medium text-foreground">{grant.subjectKind}/{grant.subjectName}</span>{" "}
                    the role <code className="text-xs">{grant.clusterRole}</code> for {grant.duration}.
                    You must be a <strong>different</strong> person from the requester
                    {grant.requestedBy ? ` (${grant.requestedBy})` : ""} — separation of duties (AC-5).
                  </p>
                  <div className="space-y-1.5">
                    <Label htmlFor="approve-note">Approval note (optional)</Label>
                    <Input
                      id="approve-note"
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder="verified with the requester over the incident bridge"
                    />
                  </div>
                  {approve.isError ? (
                    <p className="text-sm text-destructive">{(approve.error as Error).message}</p>
                  ) : null}
                  <Button disabled={approve.isPending} onClick={() => approve.mutate()}>
                    {approve.isPending ? <Spinner className="size-4" /> : <ShieldCheck className="size-4" />}
                    Approve grant
                  </Button>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Grant"
            resourceName={grant.name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Revoke grant <span className="font-medium text-foreground">{grant.name}</span>. This
                deletes the grant and tears down its ClusterRoleBinding immediately, ending any access
                it conferred.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
