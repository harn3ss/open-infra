import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { IdCard, Info } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { userPoolStatus } from "@/features/userpool/userpools-page";
import type { UserPool } from "@/types/k8s";

/** A copyable read-only line: a muted label, a monospace value, and a CopyButton. */
function CopyLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-muted/40 px-3 py-2">
      <div className="min-w-0">
        <div className="text-xs font-medium text-muted-foreground">{label}</div>
        <code className="block truncate text-xs text-foreground">{value}</code>
      </div>
      <CopyButton value={value} />
    </div>
  );
}

export function UserPoolDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.userpool(namespace, name);

  const { data: pool, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["userpool", namespace, name],
    queryFn: () => k8sGet<UserPool>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/user-pools" }),
  });

  if (isLoading) return <LoadingState label="Loading user pool…" />;
  if (isError || !pool) return <ErrorState error={error} onRetry={refetch} />;

  const status = userPoolStatus(pool);
  const spec = pool.spec ?? {};
  const issuer = pool.status?.issuer;
  const realm = pool.status?.realm ?? spec.realm ?? name;
  const clientId = spec.clientId ?? "openinfra";
  // Well-known OIDC endpoints Keycloak derives from the realm issuer. Shown for muscle memory;
  // the discovery document at .../.well-known/openid-configuration is the authoritative source.
  const wellKnown = issuer ? `${issuer}/.well-known/openid-configuration` : undefined;
  const authEndpoint = issuer ? `${issuer}/protocol/openid-connect/auth` : undefined;
  const tokenEndpoint = issuer ? `${issuer}/protocol/openid-connect/token` : undefined;

  return (
    <DetailShell
      backTo="/user-pools"
      backLabel="User Pools"
      icon={<IdCard className="size-5" />}
      title={name}
      subtitle={`User pool · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="app">App integration</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Pool details</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={2}
                items={[
                  {
                    label: "OIDC issuer URL",
                    value: issuer ? (
                      <span className="inline-flex max-w-full items-center gap-1">
                        <code className="truncate text-xs">{issuer}</code>
                        <CopyButton value={issuer} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">pending — assigned once the realm is ready</span>
                    ),
                  },
                  { label: "Realm", value: <code className="text-xs">{realm}</code> },
                  { label: "App client ID", value: <code className="text-xs">{clientId}</code> },
                  {
                    label: "Hosted login / admin host",
                    value: spec.hostname ? (
                      <code className="text-xs">{spec.hostname}</code>
                    ) : (
                      <span className="text-muted-foreground">in-cluster only (no external host)</span>
                    ),
                  },
                  {
                    label: "Self-service sign-up",
                    value:
                      spec.registrationAllowed === false ? (
                        <StatusBadge status="Disabled" tone="muted" />
                      ) : (
                        <StatusBadge status="Allowed" tone="success" />
                      ),
                  },
                  {
                    label: "Ready",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                  {
                    label: "Storage class",
                    value: <code className="text-xs">{spec.storageClass ?? "longhorn"}</code>,
                  },
                  {
                    label: "Pool storage size",
                    value: <code className="text-xs">{spec.size ?? "2Gi"}</code>,
                  },
                ]}
              />
            </CardContent>
          </Card>

          {/* Honest scope note: a Keycloak realm behind an OIDC issuer — not the full Cognito surface. */}
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              A User Pool is a <span className="font-medium text-foreground">Keycloak realm</span> exposed as an{" "}
              <span className="font-medium text-foreground">OIDC issuer</span> with one app client — the customer-facing
              identity provider your applications authenticate against. It is the Cognito analog for the sign-in surface
              (issuer, client, hosted login, self-service sign-up), not a full re-implementation of Cognito: features like
              Lambda triggers, per-attribute schemas, adaptive-risk MFA and identity-pool credential vending are Keycloak
              realm settings, not modeled fields here. It is separate from the internal IAM Users who administer this
              console.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="app" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">OIDC endpoints</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {issuer ? (
                <>
                  <CopyLine label="Issuer" value={issuer} />
                  <CopyLine label="Client ID" value={clientId} />
                  {wellKnown ? <CopyLine label="Discovery document" value={wellKnown} /> : null}
                  {authEndpoint ? <CopyLine label="Authorization endpoint" value={authEndpoint} /> : null}
                  {tokenEndpoint ? <CopyLine label="Token endpoint" value={tokenEndpoint} /> : null}
                </>
              ) : (
                <p className="text-sm text-muted-foreground">
                  The issuer URL and endpoints appear here once the realm is ready.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Wire an application to this pool</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <p>
                Point any OIDC/OAuth2 client at the issuer above. The client discovers the authorization, token and JWKS
                endpoints from the discovery document, so the issuer + client ID are usually all you configure:
              </p>
              <div className="relative rounded-md border border-border bg-muted/40 p-3">
                <pre className="overflow-x-auto text-xs text-foreground">
                  <code>{`OIDC_ISSUER_URL=${issuer ?? "<pending>"}
OIDC_CLIENT_ID=${clientId}
# discovery: ${wellKnown ?? "<issuer>/.well-known/openid-configuration"}
# redirect/callback URL: register your app's callback in the realm's client settings`}</code>
                </pre>
                {issuer ? (
                  <div className="absolute right-2 top-2">
                    <CopyButton
                      value={`OIDC_ISSUER_URL=${issuer}\nOIDC_CLIENT_ID=${clientId}`}
                      label="Copy OIDC config"
                    />
                  </div>
                ) : null}
              </div>
              <p>
                The gateway kinds consume this directly: an{" "}
                <span className="font-medium text-foreground">HttpApi</span> or{" "}
                <span className="font-medium text-foreground">GraphQLApi</span> JWT authorizer takes this issuer as its{" "}
                <code className="text-xs">issuer</code> and the client ID as an allowed{" "}
                <code className="text-xs">audience</code>. Redirect/callback URLs and client credentials (for a
                confidential client) are managed in the realm's client settings on the hosted admin UI
                {spec.hostname ? (
                  <>
                    {" "}
                    at <code className="text-xs">{spec.hostname}</code>
                  </>
                ) : null}
                .
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={pool} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="User Pool"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete user pool <span className="font-medium text-foreground">{name}</span>. Every account
                registered in this realm and any application relying on its issuer will lose sign-in. Repoint or remove
                dependent HttpApi/GraphQLApi authorizers first.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
