import { useState } from "react";
import { useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Inbox, RefreshCw, Send, Trash2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import { listQueues, peekQueue, publishToQueue, purgeQueue } from "@/lib/api";
import { formatBytes, formatTimestamp } from "@/lib/format";

export function QueueDetailPage() {
  const { stream } = useParams({ strict: false }) as { stream: string };
  const qc = useQueryClient();
  const [subject, setSubject] = useState("");
  const [data, setData] = useState("");
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [tab, setTab] = useState("overview");

  const { data: streams, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["queues"],
    queryFn: listQueues,
    refetchInterval: 5_000,
  });
  const s = streams?.find((x) => x.name === stream);
  const defaultSubject =
    subject || (s?.subjects?.[0] ?? "").replace(/[>*]$/, "msg");

  // Non-destructive peek — only fetched while the Receive tab is open. A manual
  // "Poll again" (the SQS-poll analog) refetches; it consumes nothing.
  const peekQ = useQuery({
    queryKey: ["queue-peek", stream],
    queryFn: () => peekQueue(stream, 25),
    enabled: tab === "receive",
    refetchInterval: false,
    retry: false,
  });

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
      qc.invalidateQueries({ queryKey: ["queue-peek", stream] });
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
      subtitle={`NATS JetStream stream · account ${s.account}`}
      actions={
        <Button variant="destructive" onClick={() => setConfirmPurge(true)}>
          <Trash2 className="size-4" />
          Purge
        </Button>
      }
    >
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="receive">Receive</TabsTrigger>
          <TabsTrigger value="publish">Publish</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="queue" name={stream} />
              <DetailRow label="Backend">
                NATS JetStream (open-infra's SQS/SNS-style messaging)
              </DetailRow>
              <DetailRow label="Messages">
                {s.messages.toLocaleString()}
              </DetailRow>
              <DetailRow label="Size">{formatBytes(s.bytes)}</DetailRow>
              <DetailRow label="Consumers">
                {s.consumers}
                <span className="ml-2 text-xs text-muted-foreground">
                  durable subscribers (apps / Functions / sinks)
                </span>
              </DetailRow>
              <DetailRow label="Subjects">
                <span className="flex flex-wrap gap-1">
                  {(s.subjects ?? []).length ? (
                    (s.subjects ?? []).map((sub) => (
                      <Badge key={sub} variant="secondary">
                        {sub}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="receive" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <p className="text-sm font-medium">Peek at stored messages</p>
                  <p className="max-w-2xl text-sm text-muted-foreground">
                    A non-destructive look at the {" "}
                    <span className="font-medium text-foreground">most recent</span>{" "}
                    messages this stream currently holds (newest first). This{" "}
                    <span className="font-medium text-foreground">does not consume</span>{" "}
                    them: no consumer is created, no cursor advances, and delivery to
                    the stream's durable consumers is untouched. Unlike SQS, JetStream
                    has no per-message visibility timeout here — real receipt happens
                    on the app's own durable consumer.
                  </p>
                </div>
                <Button
                  variant="outline"
                  onClick={() => peekQ.refetch()}
                  disabled={peekQ.isFetching}
                >
                  <RefreshCw className="size-4" />
                  {peekQ.isFetching ? "Polling…" : "Poll again"}
                </Button>
              </div>

              {peekQ.isError ? (
                <ErrorState
                  error={peekQ.error}
                  onRetry={() => peekQ.refetch()}
                />
              ) : peekQ.isLoading ? (
                <LoadingState label="Reading recent messages…" />
              ) : (peekQ.data?.messages.length ?? 0) === 0 ? (
                <EmptyState
                  icon={<Inbox className="size-6" />}
                  title="No messages"
                  description="This stream currently holds no messages to peek at."
                />
              ) : (
                <ul className="divide-y divide-border overflow-hidden rounded-md border">
                  {peekQ.data?.messages.map((m) => (
                    <li key={m.seq} className="space-y-1 p-3">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <span className="rounded bg-secondary px-1.5 py-0.5 font-mono">
                          #{m.seq}
                        </span>
                        <code className="text-foreground">{m.subject}</code>
                        <span className="ml-auto">{formatTimestamp(m.time)}</span>
                        <CopyButton value={m.data} />
                      </div>
                      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-muted/50 p-2 text-xs">
                        {m.data || "(empty payload)"}
                        {m.truncated ? "\n… (truncated)" : ""}
                      </pre>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="publish" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <p className="text-sm text-muted-foreground">
                Publish a test message to a subject on this stream.
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
