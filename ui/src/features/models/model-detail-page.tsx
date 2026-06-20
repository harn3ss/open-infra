import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot, BrainCircuit, Eye, EyeOff, Send, Trash2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState } from "@/components/common/states";
import { modelHealth, modelDesiredReplicas } from "@/lib/resource-health";
import { ApiError, k8sDelete, k8sGet, modelChat, type ChatMessage } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { useNodeHealth } from "@/hooks/use-node-health";
import { usePodNodeIndex } from "@/hooks/use-pod-node-index";
import { cn } from "@/lib/utils";
import { AlertTriangle } from "lucide-react";
import type { K8sObject, Model } from "@/types/k8s";

function decode(v?: string): string {
  if (!v) return "";
  try {
    return atob(v);
  } catch {
    return "";
  }
}

function Playground({ namespace, name }: { namespace: string; name: string }) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");

  const chat = useMutation({
    mutationFn: (msgs: ChatMessage[]) => modelChat(namespace, name, msgs),
    onSuccess: (res) => {
      if (res.error) {
        const m = typeof res.error === "string" ? res.error : res.error.message;
        setMessages((cur) => [
          ...cur,
          { role: "assistant", content: "⚠ " + (m || "error") },
        ]);
        return;
      }
      const reply = res.choices?.[0]?.message;
      if (reply) setMessages((cur) => [...cur, reply]);
    },
    onError: (e) =>
      setMessages((cur) => [
        ...cur,
        {
          role: "assistant",
          content: "⚠ " + (e instanceof ApiError ? e.message : "request failed"),
        },
      ]),
  });

  const send = () => {
    const text = input.trim();
    if (!text || chat.isPending) return;
    const next: ChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages(next);
    setInput("");
    chat.mutate(next);
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="min-h-[320px] space-y-3 rounded-md border border-border p-4">
        {messages.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Send a message to test the model — this calls the gated endpoint
            through the console (your key never leaves the cluster).
          </p>
        ) : (
          messages.map((m, i) => (
            <div
              key={i}
              className={cn("flex gap-2", m.role === "user" && "justify-end")}
            >
              {m.role !== "user" ? (
                <Bot className="mt-1 size-4 shrink-0 text-primary" />
              ) : null}
              <div
                className={cn(
                  "max-w-[80%] whitespace-pre-wrap rounded-lg px-3 py-2 text-sm",
                  m.role === "user"
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary",
                )}
              >
                {m.content}
              </div>
            </div>
          ))
        )}
        {chat.isPending ? (
          <p className="text-sm text-muted-foreground">…thinking</p>
        ) : null}
      </div>
      <div className="flex gap-2">
        <Input
          value={input}
          placeholder="Message the model…"
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        <Button onClick={send} disabled={chat.isPending || !input.trim()}>
          <Send className="size-4" />
          Send
        </Button>
      </div>
    </div>
  );
}

export function ModelDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const [showKey, setShowKey] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const navigate = useNavigate();
  const { offlineNodes } = useNodeHealth();
  const podIndex = usePodNodeIndex(namespace);
  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.model(namespace, name)),
    onSuccess: () => navigate({ to: "/models" }),
  });

  const { data: model, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["model", namespace, name],
    queryFn: () => k8sGet<Model>(openinfraPaths.model(namespace, name)),
  });
  const { data: secret } = useQuery({
    queryKey: ["model-secret", namespace, name],
    queryFn: () =>
      k8sGet<K8sObject<unknown, unknown> & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}-model`,
      ),
    retry: false,
  });

  if (isLoading) return <LoadingState label="Loading model…" />;
  if (isError || !model) return <ErrorState error={error} onRetry={refetch} />;

  const data = secret?.data ?? {};
  const endpoint = decode(data["OPENAI_BASE_URL"]);
  const apiKey = decode(data["OPENAI_API_KEY"]);
  const nodes = podIndex.nodesForApp(namespace, name);
  const desiredReplicas = modelDesiredReplicas(model.spec?.highAvailability);
  const readyReplicas = podIndex.statsForApp(namespace, name).ready;
  const health = modelHealth(model, {
    nodes,
    offlineNodes,
    ready: readyReplicas,
    desired: desiredReplicas,
  });

  return (
    <DetailShell
      backTo="/models"
      backLabel="Models"
      icon={<BrainCircuit className="size-5" />}
      title={name}
      subtitle={`Managed inference · ${model.spec?.model ?? ""}`}
      status={health}
      actions={
        <Button variant="destructive" onClick={() => setConfirmDelete(true)}>
          <Trash2 className="size-4" />
          Delete
        </Button>
      }
    >
      <Tabs defaultValue="playground">
        <TabsList>
          <TabsTrigger value="playground">Playground</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        <TabsContent value="playground" className="pt-4">
          <Playground namespace={namespace} name={name} />
        </TabsContent>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Model">{model.spec?.model ?? "—"}</DetailRow>
              <DetailRow label="High availability">
                {model.spec?.highAvailability ? (
                  <span
                    className={cn(
                      readyReplicas < desiredReplicas &&
                        "font-medium text-warning",
                    )}
                  >
                    On · {readyReplicas}/{desiredReplicas} replicas ready
                    {readyReplicas < desiredReplicas
                      ? " (degraded — GPU-limited?)"
                      : ""}
                  </span>
                ) : (
                  <span className="text-muted-foreground">
                    Off (single replica)
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Namespace">{namespace}</DetailRow>
              <DetailRow label="Node">
                {nodes.length === 0 ? (
                  <span className="text-muted-foreground">
                    No running pod (scaled to zero or unscheduled)
                  </span>
                ) : (
                  <span className="flex flex-wrap items-center gap-2">
                    {nodes.map((n) => {
                      const offline = offlineNodes.has(n);
                      return (
                        <span
                          key={n}
                          className={cn(
                            "flex items-center gap-1",
                            offline && "font-medium text-destructive",
                          )}
                          title={offline ? "Node is NotReady" : undefined}
                        >
                          {offline ? (
                            <AlertTriangle className="size-3.5" />
                          ) : null}
                          <code className="text-xs">{n}</code>
                          {offline ? " (offline)" : ""}
                        </span>
                      );
                    })}
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Endpoint (OpenAI-compatible)">
                <span className="flex items-center gap-1">
                  <code className="text-xs">{endpoint || "—"}</code>
                  {endpoint ? <CopyButton value={endpoint} /> : null}
                </span>
              </DetailRow>
              <DetailRow label="API key">
                <span className="flex items-center gap-1">
                  <code className="text-xs">
                    {apiKey ? (showKey ? apiKey : "•".repeat(12)) : "—"}
                  </code>
                  {apiKey ? (
                    <>
                      <button
                        onClick={() => setShowKey((s) => !s)}
                        className="text-muted-foreground hover:text-foreground"
                        aria-label={showKey ? "Hide key" : "Show key"}
                      >
                        {showKey ? (
                          <EyeOff className="size-4" />
                        ) : (
                          <Eye className="size-4" />
                        )}
                      </button>
                      <CopyButton value={apiKey} />
                    </>
                  ) : null}
                </span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          <GrafanaEmbed uid="openinfra-gpu-overview" />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={model} />
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete Model?"
        description={
          <>
            Permanently delete{" "}
            <span className="font-medium text-foreground">{name}</span> and its
            GPU-backed endpoint.
          </>
        }
        confirmLabel="Delete"
        loading={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
      />
    </DetailShell>
  );
}
