import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Fingerprint, Info } from "lucide-react";
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
import { identityProviderStatus } from "@/features/identityprovider/identityproviders-page";
import type { IdentityProvider } from "@/types/k8s";

export function IdentityProviderDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();
  const path = openinfraPaths.identityprovider(namespace, name);

  const { data: idp, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["identityprovider", namespace, name],
    queryFn: () => k8sGet<IdentityProvider>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/identity-providers" }),
  });

  if (isLoading) return <LoadingState label="Loading identity provider…" />;
  if (isError || !idp) return <ErrorState error={error} onRetry={refetch} />;

  const status = identityProviderStatus(idp);
  const spec = idp.spec ?? {};
  const issuer = spec.issuerURL ?? idp.status?.issuer;
  const audiences = spec.audiences ?? [];
  const subjectClaim = spec.subjectClaim ?? "sub";
  const wellKnown = issuer ? `${issuer}/.well-known/openid-configuration` : undefined;
  const trustValue = `OIDC::${name}`;

  return (
    <DetailShell
      backTo="/identity-providers"
      backLabel="Identity Providers"
      icon={<Fingerprint className="size-5" />}
      title={name}
      subtitle={`Identity provider · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="use">Use with a Role</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Provider details</CardTitle>
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
                      <span className="text-muted-foreground">—</span>
                    ),
                  },
                  {
                    label: "Audiences",
                    value: audiences.length ? (
                      <code className="text-xs">{audiences.join(", ")}</code>
                    ) : (
                      <span className="text-muted-foreground">none</span>
                    ),
                  },
                  { label: "Subject claim", value: <code className="text-xs">{subjectClaim}</code> },
                  { label: "Ready", value: <StatusBadge status={status.label} tone={status.tone} /> },
                  {
                    label: "Discovery document",
                    value: wellKnown ? (
                      <span className="inline-flex max-w-full items-center gap-1">
                        <code className="truncate text-xs">{wellKnown}</code>
                        <CopyButton value={wellKnown} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    ),
                  },
                ]}
              />
            </CardContent>
          </Card>

          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              An Identity Provider registers an <span className="font-medium text-foreground">external OIDC issuer</span>{" "}
              the platform trusts for <code className="text-xs">AssumeRoleWithWebIdentity</code>. Tokens are verified by
              the aws-shim against this issuer's discovery document + JWKS (signature, issuer, audience and expiry). OIDC
              only — SAML is not modeled. This is separate from the internal IAM Users who administer this console.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="use" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Let a Role trust this provider</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <p>
                Add this principal to a Role's <span className="font-medium text-foreground">trust policy</span> (the
                Web-identity entity in the Role trust editor) so tokens from this provider may assume it:
              </p>
              <div className="relative rounded-md border border-border bg-muted/40 p-3">
                <pre className="overflow-x-auto text-xs text-foreground">
                  <code>{trustValue}</code>
                </pre>
                <div className="absolute right-2 top-2">
                  <CopyButton value={trustValue} label="Copy trust principal" />
                </div>
              </div>
              <p>
                A caller then presents an OIDC token from{" "}
                <code className="text-xs">{issuer ?? "<issuer>"}</code> (with an <code className="text-xs">aud</code> in{" "}
                {audiences.length ? <code className="text-xs">{audiences.join(", ")}</code> : "this provider's audiences"}
                ) as the <code className="text-xs">WebIdentityToken</code>; the assumed subject is the token's{" "}
                <code className="text-xs">{subjectClaim}</code> claim. A Role may also trust an exact subject rather than
                the whole provider.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={idp} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Identity Provider"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete identity provider <span className="font-medium text-foreground">{name}</span>. Any Role
                whose trust names <code className="text-xs">{trustValue}</code> will no longer be assumable by this
                issuer's tokens. Update or remove those Roles' trust policies first.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
