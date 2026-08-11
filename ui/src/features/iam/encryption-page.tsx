import { useQuery } from "@tanstack/react-query";
import { KeyRound, RefreshCw, CheckCircle2, Clock } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { getEncryptionKeys } from "@/lib/api";

export function EncryptionPage() {
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["encryption-keys"],
    queryFn: getEncryptionKeys,
    refetchInterval: 60000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<KeyRound />}
        title="Encryption Keys"
        description="Customer-owned key-encryption keys, held in HashiCorp Vault's Transit engine (NIST SC-12/13/28). open-infra never sees the key material; storage layers wrap their data keys with these. Create one as kind: EncryptionKey (GitOps/kubectl). Destroying a key crypto-erases the data it protects."
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading encryption keys…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          icon={<KeyRound />}
          title="No encryption keys"
          description="Create a kind: EncryptionKey to provision a customer-owned Vault Transit key. The encryption component (Vault) must be enabled first — see docs/encryption.md."
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Key</th>
                  <th className="p-3 font-medium">Type</th>
                  <th className="p-3 font-medium">State</th>
                  <th className="p-3 font-medium">Version</th>
                  <th className="p-3 font-medium">Rotation</th>
                </tr>
              </thead>
              <tbody>
                {data.map((k) => (
                  <tr key={k.name} className="border-b last:border-0 align-top">
                    <td className="p-3">
                      <div className="font-medium">{k.name}</div>
                      {k.description ? (
                        <div className="text-xs text-muted-foreground">{k.description}</div>
                      ) : null}
                      <div className="text-xs text-muted-foreground">
                        <code>{k.vaultKeyPath}</code>
                      </div>
                    </td>
                    <td className="p-3">
                      <code className="text-xs">{k.keyType || "—"}</code>
                    </td>
                    <td className="p-3">
                      {k.provisioned ? (
                        <Badge variant="secondary" className="gap-1">
                          <CheckCircle2 className="size-3.5 text-emerald-600 dark:text-emerald-400" /> provisioned
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="gap-1 border-amber-500/40 text-amber-600 dark:text-amber-400">
                          <Clock className="size-3.5" /> pending
                        </Badge>
                      )}
                    </td>
                    <td className="p-3">{k.provisioned ? `v${k.latestVersion}` : "—"}</td>
                    <td className="p-3 text-muted-foreground">
                      {k.rotationDays > 0 ? `every ${k.rotationDays}d` : "manual"}
                      {k.lastRotated ? (
                        <div className="text-xs">last: {new Date(k.lastRotated).toLocaleDateString()}</div>
                      ) : null}
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
