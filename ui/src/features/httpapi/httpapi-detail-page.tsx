import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Webhook, Info, ExternalLink } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { Condition, HttpApi, HttpApiRoute } from "@/types/k8s";

function apiStatus(a: HttpApi): { label: string; tone: StatusTone } {
  const ready = a.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

function OnOff({ on, onLabel = "Enabled", offLabel = "Disabled" }: { on?: boolean; onLabel?: string; offLabel?: string }) {
  return on ? (
    <Badge variant="secondary">{onLabel}</Badge>
  ) : (
    <span className="text-muted-foreground">{offLabel}</span>
  );
}

/** Backend cell → a link to the backing Function/Application. */
function BackendLink({ route, namespace }: { route: HttpApiRoute; namespace: string }) {
  const b = route.backend;
  const kind = b?.kind ?? "Function";
  const port = b?.port ?? 80;
  if (!b?.name) return <span className="text-muted-foreground">—</span>;
  const to = kind === "Application" ? "/applications/$namespace/$name" : "/functions/$namespace/$name";
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-muted-foreground">{kind}</span>
      <Link to={to} params={{ namespace, name: b.name }} className="text-primary hover:underline">
        {b.name}
      </Link>
      <code className="text-xs text-muted-foreground">:{port}</code>
    </span>
  );
}

function MethodPills({ methods }: { methods?: string[] }) {
  if (!methods || methods.length === 0) {
    return <Badge variant="outline">ANY</Badge>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {methods.map((m) => (
        <Badge key={m} variant="outline" className="font-mono text-[11px]">
          {m}
        </Badge>
      ))}
    </span>
  );
}

export function HttpApiDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.httpapi(namespace, name);

  const { data: api, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["httpapi", namespace, name],
    queryFn: () => k8sGet<HttpApi>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/http-apis" }),
  });

  if (isLoading) return <LoadingState label="Loading HTTP API…" />;
  if (isError || !api) return <ErrorState error={error} onRetry={refetch} />;

  const status = apiStatus(api);
  const spec = api.spec;
  const routes = spec?.routes ?? [];
  const url = api.status?.url ?? (spec?.domain ? `${spec?.tls === false ? "http" : "https"}://${spec.domain}` : undefined);
  const cors = spec?.cors;
  const jwt = spec?.authorizer?.jwt;
  const rateLimit = spec?.rateLimit;

  return (
    <DetailShell
      backTo="/http-apis"
      backLabel="HTTP APIs"
      icon={<Webhook className="size-5" />}
      title={name}
      subtitle={`HTTP API · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="routes">Routes ({routes.length})</TabsTrigger>
          <TabsTrigger value="authorization">Authorization</TabsTrigger>
          <TabsTrigger value="cors">CORS</TabsTrigger>
          <TabsTrigger value="throttling">Throttling</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        {/* ── Overview ── */}
        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Domain",
                    value: spec?.domain ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{spec.domain}</code>
                        <CopyButton value={spec.domain} />
                      </span>
                    ) : null,
                  },
                  {
                    label: "URL",
                    value: url ? (
                      <span className="inline-flex items-center gap-1">
                        <a href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                          <code className="text-xs">{url}</code>
                          <ExternalLink className="size-3" />
                        </a>
                        <CopyButton value={url} />
                      </span>
                    ) : null,
                  },
                  { label: "Routes", value: routes.length },
                  { label: "TLS", value: <OnOff on={spec?.tls !== false} onLabel="cert-manager TLS" offLabel="Off (plain HTTP)" /> },
                  { label: "WAF", value: <OnOff on={spec?.waf} onLabel="Coraza / OWASP CRS" offLabel="Off" /> },
                  { label: "JWT authorizer", value: <OnOff on={!!jwt} offLabel="None" /> },
                  { label: "CORS", value: <OnOff on={!!cors} onLabel="Configured" offLabel="Off" /> },
                  { label: "Throttling", value: <OnOff on={!!rateLimit} onLabel="Configured" offLabel="Off" /> },
                  { label: "Status", value: <StatusBadge status={status.label} tone={status.tone} /> },
                ]}
              />
            </CardContent>
          </Card>

          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              This is the AWS <span className="font-medium text-foreground">API Gateway HTTP API</span> analog: one hostname whose{" "}
              <span className="font-medium text-foreground">routes</span> (path + methods) forward to Function or Application backends.
              Routes are evaluated in order — put specific paths before catch-all prefixes.
            </span>
          </div>
        </TabsContent>

        {/* ── Routes ── the signature table (method + path → backend). */}
        <TabsContent value="routes" className="pt-4">
          <div className="overflow-hidden rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Path</th>
                  <th className="px-3 py-2 text-left font-medium">Match</th>
                  <th className="px-3 py-2 text-left font-medium">Methods</th>
                  <th className="px-3 py-2 text-left font-medium">Backend</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {routes.length ? (
                  routes.map((r, i) => (
                    <tr key={`${r.path}-${i}`}>
                      <td className="px-3 py-2">
                        <code className="text-xs">{r.path}</code>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">{r.pathType ?? "Prefix"}</td>
                      <td className="px-3 py-2">
                        <MethodPills methods={r.methods} />
                      </td>
                      <td className="px-3 py-2">
                        <BackendLink route={r} namespace={namespace} />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="px-3 py-3 text-xs text-muted-foreground">
                      No routes. Add at least one route (path → backend) on the API's spec.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </TabsContent>

        {/* ── Authorization (JWT) ── */}
        <TabsContent value="authorization" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">JWT authorizer</CardTitle>
            </CardHeader>
            <CardContent>
              {jwt ? (
                <KeyValuePairs
                  columns={2}
                  items={[
                    {
                      label: "Issuer (OIDC)",
                      value: (
                        <span className="inline-flex items-center gap-1">
                          <code className="break-all text-xs">{jwt.issuer}</code>
                          <CopyButton value={jwt.issuer} />
                        </span>
                      ),
                    },
                    {
                      label: "Audience",
                      value: jwt.audience?.length ? (
                        <span className="flex flex-wrap gap-1">
                          {jwt.audience.map((a) => (
                            <Badge key={a} variant="outline" className="text-xs">
                              {a}
                            </Badge>
                          ))}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">any</span>
                      ),
                    },
                    {
                      label: "Token required",
                      value: (
                        <OnOff
                          on={jwt.required !== false}
                          onLabel="Required — reject unauthenticated requests"
                          offLabel="Optional — validated when present"
                        />
                      ),
                    },
                  ]}
                />
              ) : (
                <p className="text-sm text-muted-foreground">
                  No authorizer. This API is open to anyone who can reach its domain. Add a JWT authorizer (issuer +
                  audience) to require a valid OIDC token — point the issuer at a User Pool's ISSUER_URL.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── CORS ── */}
        <TabsContent value="cors" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Cross-origin resource sharing (CORS)</CardTitle>
            </CardHeader>
            <CardContent>
              {cors ? (
                <KeyValuePairs
                  columns={2}
                  items={[
                    {
                      label: "Allow origins",
                      value: cors.allowOrigins?.length ? (
                        <code className="break-all text-xs">{cors.allowOrigins.join(", ")}</code>
                      ) : (
                        <code className="text-xs">*</code>
                      ),
                    },
                    {
                      label: "Allow methods",
                      value: cors.allowMethods?.length ? (
                        <span className="flex flex-wrap gap-1">
                          {cors.allowMethods.map((m) => (
                            <Badge key={m} variant="outline" className="font-mono text-[11px]">
                              {m}
                            </Badge>
                          ))}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">default set</span>
                      ),
                    },
                    {
                      label: "Allow headers",
                      value: cors.allowHeaders?.length ? (
                        <code className="break-all text-xs">{cors.allowHeaders.join(", ")}</code>
                      ) : (
                        <code className="text-xs">*</code>
                      ),
                    },
                    { label: "Allow credentials", value: <OnOff on={cors.allowCredentials} /> },
                    {
                      label: "Preflight max-age",
                      value: cors.maxAge != null ? `${cors.maxAge}s` : <span className="text-muted-foreground">600s (default)</span>,
                    },
                  ]}
                />
              ) : (
                <p className="text-sm text-muted-foreground">
                  CORS is not configured. Browsers on other origins will be blocked by the same-origin policy. Configure
                  CORS to allow specific origins, methods, and headers.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Throttling ── */}
        <TabsContent value="throttling" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Throttling</CardTitle>
            </CardHeader>
            <CardContent>
              {rateLimit ? (
                <KeyValuePairs
                  columns={2}
                  items={[
                    {
                      label: "Average rate",
                      value: rateLimit.average != null ? `${rateLimit.average} req/s` : <span className="text-muted-foreground">100 req/s (default)</span>,
                    },
                    {
                      label: "Burst",
                      value: rateLimit.burst != null ? `${rateLimit.burst} req` : <span className="text-muted-foreground">50 req (default)</span>,
                    },
                  ]}
                />
              ) : (
                <p className="text-sm text-muted-foreground">
                  Throttling is not configured — requests are not rate-limited. Set an average sustained rate and a burst
                  allowance to protect the backends.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── YAML ── */}
        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={api} />
        </TabsContent>

        {/* ── Danger Zone ── */}
        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="HTTP API"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete HTTP API <span className="font-medium text-foreground">{name}</span>. Its Ingress and
                TLS certificate are removed and the domain stops serving; the backing Functions and Applications are not
                deleted.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
