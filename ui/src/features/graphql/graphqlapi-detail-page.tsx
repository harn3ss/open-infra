import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ExternalLink, Play, Waypoints } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import {
  ApiError,
  k8sDelete,
  k8sGet,
  testResolver,
  type TestResolverResponse,
} from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { GraphQLApi, GraphQLResolver } from "@/types/k8s";

/** Render a resolver's request/response templates against a sample $ctx via the engine's
 *  POST /test-resolver (proxied by the BFF) — no data source is touched. Prefill from any of the API's
 *  declared resolvers, then edit freely. */
function ResolverTester({
  namespace,
  name,
  resolvers,
}: {
  namespace: string;
  name: string;
  resolvers: GraphQLResolver[];
}) {
  const [runtime, setRuntime] = useState("appsync-vtl");
  const [reqTemplate, setReqTemplate] = useState(
    '{\n  "version": "2018-05-29",\n  "operation": "GetItem",\n  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) }\n}',
  );
  const [respTemplate, setRespTemplate] = useState("$util.toJson($ctx.result)");
  const [contextJSON, setContextJSON] = useState('{\n  "args": { "id": "1" }\n}');
  const [resultJSON, setResultJSON] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [result, setResult] = useState<TestResolverResponse | null>(null);

  const prefill = (idx: number) => {
    const r = resolvers[idx];
    if (!r) return;
    const step = r.functions?.[0];
    setRuntime(r.runtime ?? step?.runtime ?? "appsync-vtl");
    setReqTemplate(r.request ?? step?.request ?? "");
    setRespTemplate(r.response ?? step?.response ?? "");
  };

  const run = useMutation({
    mutationFn: () => {
      setParseError(null);
      let context: unknown;
      let sampleResult: unknown;
      try {
        context = contextJSON.trim() ? JSON.parse(contextJSON) : {};
      } catch {
        throw new Error("Context is not valid JSON");
      }
      try {
        sampleResult = resultJSON.trim() ? JSON.parse(resultJSON) : undefined;
      } catch {
        throw new Error("Result is not valid JSON");
      }
      return testResolver(namespace, name, {
        runtime,
        request: reqTemplate,
        response: respTemplate,
        context,
        result: sampleResult,
      });
    },
    onSuccess: setResult,
    onError: (e) => setParseError(e instanceof Error ? e.message : "failed"),
  });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={runtime}
          onChange={(e) => setRuntime(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
          aria-label="Runtime"
        >
          <option value="appsync-vtl">appsync-vtl</option>
          <option value="appsync-js">appsync-js</option>
        </select>
        {resolvers.length > 0 ? (
          <select
            onChange={(e) => {
              const idx = Number(e.target.value);
              if (!Number.isNaN(idx)) prefill(idx);
            }}
            defaultValue=""
            className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            aria-label="Prefill from a resolver"
          >
            <option value="" disabled>
              Prefill from resolver…
            </option>
            {resolvers.map((r, i) => (
              <option key={`${r.type}.${r.field}`} value={i}>
                {r.type}.{r.field}
              </option>
            ))}
          </select>
        ) : null}
        <Button onClick={() => run.mutate()} disabled={run.isPending}>
          <Play className="size-4" />
          Test resolver
        </Button>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <TemplateBox label="Request mapping template" value={reqTemplate} onChange={setReqTemplate} />
        <TemplateBox label="Response mapping template" value={respTemplate} onChange={setRespTemplate} />
        <TemplateBox label="Context ($ctx) — JSON" value={contextJSON} onChange={setContextJSON} />
        <TemplateBox
          label="Sample data-source result — JSON (optional; runs the response phase)"
          value={resultJSON}
          onChange={setResultJSON}
        />
      </div>

      <p className="text-xs text-muted-foreground">
        Renders the templates against your sample <code>$ctx</code> on this API's engine — no data source
        is called. Supply a sample result to also run the response phase.
      </p>

      {parseError || run.isError ? (
        <p className="text-sm text-destructive">
          ⚠ {parseError ?? (run.error instanceof ApiError ? run.error.message : "request failed")}
        </p>
      ) : null}
      {run.isPending ? <p className="text-sm text-muted-foreground">…rendering</p> : null}

      {result ? (
        <Card>
          <CardContent className="space-y-3 p-4">
            {result.error ? (
              <div className="text-sm">
                <Badge variant="destructive">{result.errorType || "error"}</Badge>
                <pre className="mt-2 whitespace-pre-wrap rounded-md bg-secondary p-3 text-xs">
                  {result.error}
                </pre>
              </div>
            ) : null}
            {result.requestOp !== undefined ? (
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">
                  Request → data-source operation
                </p>
                <pre className="max-h-[240px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 text-xs">
                  {JSON.stringify(result.requestOp, null, 2)}
                </pre>
              </div>
            ) : null}
            {result.response !== undefined ? (
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">Response value</p>
                <pre className="max-h-[240px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 text-xs">
                  {JSON.stringify(result.response, null, 2)}
                </pre>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function TemplateBox({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="min-h-[120px] rounded-md border border-border bg-background p-2 font-mono text-xs"
        spellCheck={false}
      />
    </label>
  );
}

export function GraphQLApiDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();

  const { data: api, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["graphqlapi", namespace, name],
    queryFn: () =>
      k8sGet<GraphQLApi>(openinfraPaths.graphqlapi(namespace, name)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.graphqlapi(namespace, name)),
    onSuccess: () => navigate({ to: "/graphql" }),
  });

  if (isLoading) return <LoadingState label="Loading GraphQL API…" />;
  if (isError || !api) return <ErrorState error={error} onRetry={refetch} />;

  const s = api.spec;
  const url = api.status?.url;
  const resolvers = s?.resolvers ?? [];
  const dataSources = s?.dataSources ?? [];
  const subscriptions = s?.subscriptions ?? [];

  return (
    <DetailShell
      backTo="/graphql"
      backLabel="GraphQL APIs"
      icon={<Waypoints className="size-5" />}
      title={name}
      subtitle={`GraphQL API · ${namespace}`}
      status={claimHealth(api)}
    >
      <Tabs defaultValue="test">
        <TabsList>
          <TabsTrigger value="test">Test</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="schema">Schema</TabsTrigger>
          <TabsTrigger value="resolvers">Resolvers</TabsTrigger>
          <TabsTrigger value="datasources">Data sources</TabsTrigger>
          <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="test" className="pt-4">
          <ResolverTester namespace={namespace} name={name} resolvers={resolvers} />
        </TabsContent>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="graphqlapi" name={name} namespace={namespace} />
              <DetailRow label="Image">
                <code className="text-xs">{s?.image ?? "—"}</code>
              </DetailRow>
              <DetailRow label="Replicas">{s?.replicas ?? 1}</DetailRow>
              <DetailRow label="Resolvers">{resolvers.length}</DetailRow>
              <DetailRow label="Data sources">{dataSources.length}</DetailRow>
              <DetailRow label="Subscriptions">{subscriptions.length}</DetailRow>
              <DetailRow label="Introspection">
                {s?.schema
                  ? s?.limits?.introspection ?? "enabled"
                  : "unavailable (no schema)"}
              </DetailRow>
              <DetailRow label="API-key auth (@aws_api_key)">
                {s?.apiKeysSecret ? (
                  <span className="text-xs text-muted-foreground">
                    enforced · keys from Secret <code>{s.apiKeysSecret}</code>{" "}
                    <span>(each key impersonates its mapped identity)</span>
                  </span>
                ) : (
                  <span className="text-xs text-muted-foreground">
                    no API keys configured
                  </span>
                )}
              </DetailRow>
              {s?.limits ? (
                <DetailRow label="Hostile-load guards">
                  <span className="text-xs text-muted-foreground">
                    maxDepth {s.limits.maxDepth ?? "default"} · maxCost{" "}
                    {s.limits.maxCost ?? "default"}
                    {s.limits.persistedOnly ? " · persisted-only" : ""}
                  </span>
                </DetailRow>
              ) : null}
              {s?.mongoURI ? (
                <DetailRow label="FerretDB (Mongo)">
                  <code className="text-xs">
                    {s.mongoURI} / {s.mongoDB ?? "open_appsync"}
                  </code>
                </DetailRow>
              ) : null}
              {url ? (
                <DetailRow label="Endpoint">
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
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="schema" className="pt-4">
          {s?.schema ? (
            <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 font-mono text-xs">
              {s.schema}
            </pre>
          ) : (
            <p className="text-sm text-muted-foreground">
              No SDL schema set. Introspection is unavailable until <code>spec.schema</code> is provided;
              the engine still serves the declared resolvers.
            </p>
          )}
        </TabsContent>

        <TabsContent value="resolvers" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {resolvers.length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No resolvers.</p>
              ) : (
                resolvers.map((r) => (
                  <DetailRow key={`${r.type}.${r.field}`} label={`${r.type}.${r.field}`}>
                    <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                      <Badge variant="secondary">{r.runtime ?? "appsync-vtl"}</Badge>
                      <Badge variant="secondary">
                        {r.functions?.length ? `pipeline (${r.functions.length})` : "unit"}
                      </Badge>
                      {r.dataSource ? <span>→ {r.dataSource}</span> : null}
                      {r.auth?.verb ? <Badge variant="secondary">auth: {r.auth.verb}</Badge> : null}
                    </span>
                  </DetailRow>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="datasources" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {dataSources.length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No data sources.</p>
              ) : (
                dataSources.map((d) => (
                  <DetailRow key={d.name} label={d.name}>
                    <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                      <Badge variant="secondary">{d.type ?? "memory"}</Badge>
                      {d.collection ? <span>collection: {d.collection}</span> : null}
                      {d.endpoint ? <code className="text-xs">{d.endpoint}</code> : null}
                    </span>
                  </DetailRow>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="subscriptions" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {subscriptions.length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No subscriptions.</p>
              ) : (
                subscriptions.map((sub) => (
                  <DetailRow key={sub.field} label={sub.field}>
                    <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                      {sub.subject ? <code className="text-xs">{sub.subject}</code> : null}
                      {sub.triggeredBy?.length ? (
                        <span>triggered by: {sub.triggeredBy.join(", ")}</span>
                      ) : null}
                    </span>
                  </DetailRow>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={api} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="GraphQL API"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
