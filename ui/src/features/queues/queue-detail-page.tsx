import { useState } from "react";
import { useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Send, Trash2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import { listQueues, publishToQueue, purgeQueue } from "@/lib/api";
import { formatBytes } from "@/lib/format";

export function QueueDetailPage() {
  const { stream } = useParams({ strict: false }) as { stream: string };
  const qc = useQueryClient();
  const [subject, setSubject] = useState("");
  const [data, setData] = useState("");
  const [confirmPurge, setConfirmPurge] = useState(false);

  const { data: streams, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["queues"],
    queryFn: listQueues,
    refetchInterval: 5_000,
  });
  const s = streams?.find((x) => x.name === stream);
  const defaultSubject =
    subject || (s?.subjects?.[0] ?? "").replace(/[>*]$/, "msg");

  const publishMut = useMutation({
    mutationFn: () => publishToQueue(defaultSubject, data),
    onSuccess: () => {
      setData("");
      qc.invalidateQueries({ queryKey: ["queues"] });
    },
  });
  const purgeMut = useMutation({
    mutationFn: () => purgeQueue(stream),
    onSuccess: () => {
      setConfirmPurge(false);
      qc.invalidateQueries({ queryKey: ["queues"] });
    },
  });

  if (isLoading) return <LoadingState label="Loading stream…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (!s)
    return (
      <DetailShell
        backTo="/queues"
        backLabel="Queues"
        icon={<Send className="size-5" />}
        title={stream}
      >
        <EmptyState
          title="Stream not found"
          description="This JetStream stream no longer exists."
        />
      </DetailShell>
    );

  return (
    <DetailShell
      backTo="/queues"
      backLabel="Queues"
      icon={<Send className="size-5" />}
      title={stream}
      subtitle={`JetStream stream · account ${s.account}`}
      actions={
        <Button variant="destructive" onClick={() => setConfirmPurge(true)}>
          <Trash2 className="size-4" />
          Purge
        </Button>
      }
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="publish">Publish</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="queue" name={stream} />
              <DetailRow label="Messages">
                {s.messages.toLocaleString()}
              </DetailRow>
              <DetailRow label="Size">{formatBytes(s.bytes)}</DetailRow>
              <DetailRow label="Consumers">{s.consumers}</DetailRow>
              <DetailRow label="Subjects">
                <span className="flex flex-wrap gap-1">
                  {(s.subjects ?? []).map((sub) => (
                    <Badge key={sub} variant="secondary">
                      {sub}
                    </Badge>
                  ))}
                </span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="publish" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <p className="text-sm text-muted-foreground">
                Publish a test message to this stream.
              </p>
              <div className="space-y-1.5">
                <Label htmlFor="subject">Subject</Label>
                <Input
                  id="subject"
                  value={defaultSubject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="data">Message</Label>
                <Input
                  id="data"
                  value={data}
                  placeholder="hello from the console"
                  onChange={(e) => setData(e.target.value)}
                />
              </div>
              {publishMut.isError ? (
                <p className="text-sm text-destructive">Failed to publish.</p>
              ) : null}
              <Button
                onClick={() => publishMut.mutate()}
                disabled={!defaultSubject || publishMut.isPending}
              >
                <Send className="size-4" />
                {publishMut.isPending ? "Publishing…" : "Publish"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={confirmPurge}
        onOpenChange={setConfirmPurge}
        title="Purge stream?"
        description={
          <>
            Delete all messages in{" "}
            <span className="font-medium text-foreground">{stream}</span>. This
            cannot be undone.
          </>
        }
        confirmLabel="Purge"
        loading={purgeMut.isPending}
        onConfirm={() => purgeMut.mutate()}
      />
    </DetailShell>
  );
}
