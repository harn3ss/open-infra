import { useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  ShieldCheck,
  Plus,
  RefreshCw,
  CheckCircle2,
  Clock,
  FileBadge,
  Ban,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { DangerZone } from "@/components/common/danger-zone";
import { EmptyState, ErrorState, LoadingState, Spinner } from "@/components/common/states";
import {
  getCertificateAuthorities,
  issueCertificate,
  revokeCertificate,
  k8sDelete,
  ApiError,
  type IssuedCertificate,
} from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";

/* ------------------------------ List ------------------------------ */

export function PkiPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["certificate-authorities"],
    queryFn: getCertificateAuthorities,
    refetchInterval: 30000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ShieldCheck />}
        title="Certificate Authorities"
        description="Managed private certificate authorities (AWS Private CA-style), backed by HashiCorp Vault's PKI engine. The CA key never leaves Vault; issue and revoke leaf certificates from a CA's detail page. Create one as kind: CertificateAuthority. Requires the encryption component (Vault)."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
            </Button>
            <Button onClick={() => navigate({ to: "/pki/new" })}>
              <Plus className="size-4" /> New Certificate Authority
            </Button>
          </div>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading certificate authorities…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck />}
          title="No certificate authorities"
          description="Create a kind: CertificateAuthority to provision a Vault-backed private CA. The encryption component (Vault) must be enabled first — see docs/pki.md."
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Name</th>
                  <th className="p-3 font-medium">Common name</th>
                  <th className="p-3 font-medium">Hierarchy</th>
                  <th className="p-3 font-medium">Key</th>
                  <th className="p-3 font-medium">State</th>
                </tr>
              </thead>
              <tbody>
                {data.map((ca) => (
                  <tr
                    key={`${ca.namespace}/${ca.name}`}
                    className="cursor-pointer border-b align-top last:border-0 hover:bg-muted/50"
                    onClick={() =>
                      navigate({
                        to: "/pki/$namespace/$name",
                        params: { namespace: ca.namespace, name: ca.name },
                      })
                    }
                  >
                    <td className="p-3">
                      <div className="font-medium">{ca.name}</div>
                      <div className="text-xs text-muted-foreground">{ca.namespace}</div>
                    </td>
                    <td className="p-3">
                      <code className="text-xs">{ca.commonName || "—"}</code>
                    </td>
                    <td className="p-3">
                      <Badge variant="outline">{ca.hierarchy || "root"}</Badge>
                      {ca.hierarchy === "intermediate" && ca.parent ? (
                        <div className="mt-1 text-xs text-muted-foreground">↳ {ca.parent}</div>
                      ) : null}
                    </td>
                    <td className="p-3">
                      <code className="text-xs">{ca.keyType || "—"}</code>
                    </td>
                    <td className="p-3">
                      {ca.ready ? (
                        <Badge variant="secondary" className="gap-1">
                          <CheckCircle2 className="size-3.5 text-emerald-600 dark:text-emerald-400" /> ready
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="gap-1 border-amber-500/40 text-amber-600 dark:text-amber-400">
                          <Clock className="size-3.5" /> provisioning
                        </Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ------------------------------ Detail ------------------------------ */

/** A certificate issued during this browser session (the private key is held only here, in memory). */
interface SessionIssued extends IssuedCertificate {
  commonName: string;
  issuedAt: string;
}

export function CertificateAuthorityDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["certificate-authorities"],
    queryFn: getCertificateAuthorities,
    refetchInterval: 30000,
  });
  const ca = useMemo(
    () => (data ?? []).find((c) => c.namespace === namespace && c.name === name),
    [data, namespace, name],
  );

  const del = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.certificateauthority(namespace, name)),
    onSuccess: () => navigate({ to: "/pki" }),
  });

  const [issued, setIssued] = useState<SessionIssued[]>([]);

  if (isLoading) return <LoadingState label="Loading certificate authority…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (!ca) {
    return (
      <ErrorState
        error={new Error(`Certificate authority ${namespace}/${name} not found.`)}
        onRetry={refetch}
      />
    );
  }

  return (
    <DetailShell
      backTo="/pki"
      backLabel="Certificate Authorities"
      icon={<ShieldCheck className="size-5" />}
      title={ca.name}
      subtitle={`CertificateAuthority · ${namespace}`}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="issue">Issue certificate</TabsTrigger>
          <TabsTrigger value="issued">Issued / Revoke</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Namespace">{namespace}</DetailRow>
              <DetailRow label="Common name">
                <code className="text-xs">{ca.commonName || "—"}</code>
              </DetailRow>
              <DetailRow label="Hierarchy">
                {ca.hierarchy || "root"}
                {ca.hierarchy === "intermediate" && ca.parent ? ` (parent: ${ca.parent})` : ""}
              </DetailRow>
              <DetailRow label="Key type">
                <code className="text-xs">{ca.keyType || "—"}</code>
              </DetailRow>
              <DetailRow label="Max TTL">
                <code className="text-xs">{ca.maxTtl || "—"}</code>
              </DetailRow>
              <DetailRow label="Allowed domains">
                {ca.allowedDomains && ca.allowedDomains.length > 0 ? (
                  <span className="flex flex-wrap gap-1">
                    {ca.allowedDomains.map((d) => (
                      <Badge key={d} variant="outline" className="text-xs">
                        {d}
                      </Badge>
                    ))}
                  </span>
                ) : (
                  <span className="text-muted-foreground">any</span>
                )}
              </DetailRow>
              <DetailRow label="Vault PKI mount">
                <code className="text-xs">{ca.pkiMount || "—"}</code>
              </DetailRow>
              <DetailRow label="State">
                {ca.ready ? "Ready" : "Provisioning"}
              </DetailRow>
              <DetailRow label="Serial">
                <code className="text-xs">{ca.serial || "—"}</code>
              </DetailRow>
              <DetailRow label="Not after">{ca.notAfter || "—"}</DetailRow>
              <DetailRow label="CA certificate">
                {ca.caCertPem ? (
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-1">
                      <CopyButton value={ca.caCertPem} />
                      <span className="text-xs text-muted-foreground">Copy PEM</span>
                    </div>
                    <pre className="max-h-48 overflow-auto rounded bg-muted p-2 text-[11px] leading-tight">
                      {ca.caCertPem}
                    </pre>
                  </div>
                ) : (
                  <span className="text-muted-foreground">pending…</span>
                )}
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="issue" className="pt-4">
          <IssueCertificateTab
            namespace={namespace}
            name={name}
            ready={ca.ready}
            onIssued={(c) => setIssued((prev) => [c, ...prev])}
          />
        </TabsContent>

        <TabsContent value="issued" className="pt-4">
          <IssuedRevokeTab namespace={namespace} name={name} issued={issued} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="CertificateAuthority"
            resourceName={name}
            deleting={del.isPending}
            description="Permanently delete this certificate authority and its Vault PKI mount. Certificates it issued can no longer be validated against a live CRL. This cannot be undone."
            onConfirm={() => del.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}

/* ------------------------------ Issue tab ------------------------------ */

function IssueCertificateTab({
  namespace,
  name,
  ready,
  onIssued,
}: {
  namespace: string;
  name: string;
  ready: boolean;
  onIssued: (c: SessionIssued) => void;
}) {
  const [commonName, setCommonName] = useState("");
  const [ttl, setTtl] = useState("");
  const [altNames, setAltNames] = useState("");
  const [result, setResult] = useState<SessionIssued | null>(null);

  const issue = useMutation({
    mutationFn: () =>
      issueCertificate(namespace, name, {
        commonName: commonName.trim(),
        ttl: ttl.trim() || undefined,
        altNames: altNames
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    onSuccess: (c) => {
      const rec: SessionIssued = { ...c, commonName: commonName.trim(), issuedAt: new Date().toISOString() };
      setResult(rec);
      onIssued(rec);
    },
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="space-y-4 p-5">
          {!ready ? (
            <p className="text-sm text-muted-foreground">
              The CA is still provisioning — issuing opens once it's Ready.
            </p>
          ) : null}
          <div className="space-y-1.5">
            <Label htmlFor="ca-cn">Common name</Label>
            <Input
              id="ca-cn"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
              placeholder="service.example.com"
            />
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="ca-ttl">TTL (optional)</Label>
              <Input
                id="ca-ttl"
                value={ttl}
                onChange={(e) => setTtl(e.target.value)}
                placeholder="720h"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ca-alt">Subject alt names (comma-separated)</Label>
              <Input
                id="ca-alt"
                value={altNames}
                onChange={(e) => setAltNames(e.target.value)}
                placeholder="www.example.com, api.example.com"
              />
            </div>
          </div>
          {issue.error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {issue.error instanceof ApiError ? issue.error.message : "Failed to issue the certificate."}
            </div>
          ) : null}
          <div className="flex justify-end">
            <Button
              onClick={() => issue.mutate()}
              disabled={!ready || issue.isPending || commonName.trim().length === 0}
            >
              {issue.isPending ? <Spinner className="text-current" /> : <FileBadge className="size-4" />}
              Issue certificate
            </Button>
          </div>
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardContent className="space-y-4 p-5">
            <div>
              <h3 className="text-sm font-semibold">Certificate issued</h3>
              <p className="text-xs text-muted-foreground">
                Serial <code>{result.serialNumber}</code>. The private key is shown once and is never
                stored by open-infra — copy it now.
              </p>
            </div>
            <PemBlock label="Private key (shown once)" value={result.privateKey} />
            <PemBlock label="Certificate" value={result.certificate} />
            <PemBlock label="Issuing CA" value={result.issuingCa} />
            {result.caChain && result.caChain.length > 0 ? (
              <PemBlock label="CA chain" value={result.caChain.join("\n")} />
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function PemBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 space-y-1">
      <div className="flex items-center gap-2">
        <Label className="text-xs text-muted-foreground">{label}</Label>
        <CopyButton value={value} />
      </div>
      <pre className="max-h-48 overflow-auto rounded bg-muted p-2 text-[11px] leading-tight">
        {value}
      </pre>
    </div>
  );
}

/* ------------------------------ Issued / Revoke tab ------------------------------ */

function IssuedRevokeTab({
  namespace,
  name,
  issued,
}: {
  namespace: string;
  name: string;
  issued: SessionIssued[];
}) {
  const [serial, setSerial] = useState("");
  const [revoked, setRevoked] = useState<Set<string>>(new Set());

  const revoke = useMutation({
    mutationFn: (sn: string) => revokeCertificate(namespace, name, sn),
    onSuccess: (_res, sn) => setRevoked((prev) => new Set(prev).add(sn)),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="space-y-3 p-5">
          <div>
            <h3 className="text-sm font-semibold">Revoke by serial number</h3>
            <p className="text-xs text-muted-foreground">
              Revoke any certificate this CA issued — it's added to the CA's CRL.
            </p>
          </div>
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="ca-serial">Serial number</Label>
              <Input
                id="ca-serial"
                value={serial}
                onChange={(e) => setSerial(e.target.value)}
                placeholder="12:34:56:…"
              />
            </div>
            <Button
              variant="outline"
              className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
              onClick={() => revoke.mutate(serial.trim())}
              disabled={revoke.isPending || serial.trim().length === 0}
            >
              {revoke.isPending ? <Spinner className="text-current" /> : <Ban className="size-4" />}
              Revoke
            </Button>
          </div>
          {revoke.error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {revoke.error instanceof ApiError ? revoke.error.message : "Failed to revoke the certificate."}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          <div className="border-b p-3">
            <h3 className="text-sm font-semibold">Issued this session</h3>
            <p className="text-xs text-muted-foreground">
              Certificates minted from this page in the current browser session.
            </p>
          </div>
          {issued.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">Nothing issued yet.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Common name</th>
                  <th className="p-3 font-medium">Serial</th>
                  <th className="p-3 font-medium">Issued</th>
                  <th className="p-3 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {issued.map((c) => {
                  const isRevoked = revoked.has(c.serialNumber);
                  return (
                    <tr key={c.serialNumber} className="border-b last:border-0 align-top">
                      <td className="p-3">
                        <code className="text-xs">{c.commonName}</code>
                      </td>
                      <td className="p-3">
                        <code className="text-xs">{c.serialNumber}</code>
                      </td>
                      <td className="p-3 text-muted-foreground">
                        {new Date(c.issuedAt).toLocaleString()}
                      </td>
                      <td className="p-3 text-right">
                        {isRevoked ? (
                          <Badge variant="outline" className="border-destructive/40 text-destructive">
                            revoked
                          </Badge>
                        ) : (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                            onClick={() => revoke.mutate(c.serialNumber)}
                            disabled={revoke.isPending}
                          >
                            <Ban className="size-4" /> Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
