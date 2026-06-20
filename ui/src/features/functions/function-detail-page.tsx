import { useEffect, useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ExternalLink, Send, Trash2, Zap } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import {
  ApiError,
  getFunctionRoutes,
  invokeFunction,
  k8sDelete,
  k8sGet,
  type FunctionInvokeResponse,
} from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { OpenInfraFunction } from "@/types/k8s";

const ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"];

/** Send a test request to the function through the BFF and show the response.
 *  Routes + allowed methods are discovered from the function's OpenAPI spec
 *  (if it exposes one); otherwise we fall back to a free-form path + all
 *  methods. */
function FunctionTester({
  namespace,
  name,
}: {
  namespace: string;
  name: string;
}) {
  const { data: routesData } = useQuery({
    queryKey: ["function-routes", namespace, name],
    queryFn: () => getFunctionRoutes(namespace, name),
    staleTime: 60_000,
  });
  const routes = routesData?.routes ?? [];
  const discovered = routesData?.source === "openapi" && routes.length > 0;

  const [method, setMethod] = useState<string>("GET");
  const [path, setPath] = useState("/");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<FunctionInvokeResponse | null>(null);
  const [initialized, setInitialized] = useState(false);

  // Seed from the first discovered route once the spec loads.
  useEffect(() => {
    const first = routes[0];
    if (!initialized && discovered && first) {
      setPath(first.path);
      setMethod(first.methods[0] ?? "GET");
      setInitialized(true);
    }
  }, [initialized, discovered, routes]);

  // Methods offered = the matching route's methods (so unsupported verbs aren't
  // shown), or all methods when the path isn't a known route / no spec exists.
  const matched = routes.find((r) => r.path === path);
  const availableMethods = matched ? matched.methods : ALL_METHODS;

  const onPathChange = (next: string) => {
    setPath(next);
    const r = routes.find((rt) => rt.path === next);
    if (r && !r.methods.includes(method)) setMethod(r.methods[0] ?? "GET");
  };

  const invoke = useMutation({
    mutationFn: () =>
      invokeFunction(namespace, name, {
        method,
        path,
        body: body.trim() ? body : undefined,
      }),
    onSuccess: setResult,
  });
  const hasBody = method === "POST" || method === "PUT" || method === "PATCH";
  const listId = `routes-${namespace}-${name}`;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex gap-2">
        <select
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className="rounded-md border border-border bg-background px-2 text-sm"
          aria-label="HTTP method"
        >
          {availableMethods.map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <Input
          value={path}
          onChange={(e) => onPathChange(e.target.value)}
          placeholder="/"
          list={discovered ? listId : undefined}
          onKeyDown={(e) => {
            if (e.key === "Enter") invoke.mutate();
          }}
        />
        {discovered ? (
          <datalist id={listId}>
            {routes.map((r) => (
              <option key={r.path} value={r.path} />
            ))}
          </datalist>
        ) : null}
        <Button onClick={() => invoke.mutate()} disabled={invoke.isPending}>
          <Send className="size-4" />
          Send
        </Button>
      </div>
      {hasBody ? (
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="Request body (optional)"
          className="min-h-[80px] rounded-md border border-border bg-background p-2 font-mono text-xs"
        />
      ) : null}
      <p className="text-xs text-muted-foreground">
        {discovered
          ? `${routes.length} route${routes.length > 1 ? "s" : ""} discovered from the function's OpenAPI spec — pick one (methods filter to what each route allows).`
          : "No OpenAPI spec exposed by this function, so routes can't be auto-discovered — enter a path and method manually."}{" "}
        The first request may be slow — it wakes a scaled-to-zero function.
      </p>
      {invoke.isPending ? (
        <p className="text-sm text-muted-foreground">…invoking</p>
      ) : null}
      {invoke.isError ? (
        <p className="text-sm text-destructive">
          ⚠{" "}
          {invoke.error instanceof ApiError
            ? invoke.error.message
            : "request failed"}
        </p>
      ) : null}
      {result ? (
        <Card>
          <CardContent className="space-y-2 p-4">
            <div className="flex items-center gap-2 text-sm">
              <Badge variant={result.status < 400 ? "secondary" : "destructive"}>
                {result.status}
              </Badge>
              <span className="text-muted-foreground">{result.durationMs} ms</span>
            </div>
            <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 text-xs">
              {result.body || "(empty body)"}
            </pre>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export function FunctionDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const [confirmDelete, setConfirmDelete] = useState(false);

  const { data: fn, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["function", namespace, name],
    queryFn: () =>
      k8sGet<OpenInfraFunction>(openinfraPaths.function(namespace, name)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.function(namespace, name)),
    onSuccess: () => navigate({ to: "/functions" }),
  });

  if (isLoading) return <LoadingState label="Loading function…" />;
  if (isError || !fn) return <ErrorState error={error} onRetry={refetch} />;

  const s = fn.spec;
  const url = fn.status?.url;

  return (
    <DetailShell
      backTo="/functions"
      backLabel="Functions"
      icon={<Zap className="size-5" />}
      title={name}
      subtitle={`Serverless function · ${namespace}`}
      status={claimHealth(fn)}
      actions={
        <Button variant="destructive" onClick={() => setConfirmDelete(true)}>
          <Trash2 className="size-4" />
          Delete
        </Button>
      }
    >
      <Tabs defaultValue="test">
        <TabsList>
          <TabsTrigger value="test">Test</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        <TabsContent value="test" className="pt-4">
          <FunctionTester namespace={namespace} name={name} />
        </TabsContent>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Image">
                <code className="text-xs">{s?.image ?? "—"}</code>
              </DetailRow>
              <DetailRow label="Port">{s?.port ?? 8080}</DetailRow>
              <DetailRow label="Scaling">
                {s?.scaling?.min ?? 0}–{s?.scaling?.max ?? 10} pods · target{" "}
                {s?.scaling?.target ?? 100} concurrent
                {(s?.gpu ?? 0) > 0 ? ` · ${s?.gpu}×GPU` : ""}
              </DetailRow>
              {url ? (
                <DetailRow label="URL">
                  <a
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    <code className="text-xs">{url}</code>
                    <ExternalLink className="size-3" />
                  </a>
                </DetailRow>
              ) : null}
              {s?.queues?.length ? (
                <DetailRow label="Queues">
                  <span className="flex flex-wrap gap-1">
                    {s.queues.map((q) => (
                      <Badge key={q} variant="secondary">
                        {q}
                      </Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
              {s?.secrets?.length ? (
                <DetailRow label="Secrets">
                  <span className="flex flex-wrap gap-1">
                    {s.secrets.map((sec) => (
                      <Badge key={sec} variant="secondary">
                        {sec}
                      </Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{ "var-namespace": namespace }}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={fn} />
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete Function?"
        description={
          <>
            Permanently delete{" "}
            <span className="font-medium text-foreground">{name}</span>.
          </>
        }
        confirmLabel="Delete"
        loading={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
      />
    </DetailShell>
  );
}
