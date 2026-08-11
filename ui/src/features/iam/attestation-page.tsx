import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, RefreshCw, CheckCircle2, MinusCircle } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/common/states";
import { getAttestation } from "@/lib/api";

export function AttestationPage() {
  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["attestation"],
    queryFn: getAttestation,
    refetchInterval: 60000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<BadgeCheck />}
        title="Compliance Attestation"
        description="Live NIST 800-53 control coverage with evidence gathered from this cluster right now — not a static claim. Daily immutable snapshots are written to the WORM audit store; sign one out-of-band with the release GPG key to produce a verifiable attestation (see docs/compliance-attestation.md)."
        actions={
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`size-4 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Assembling attestation…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data ? null : (
        <>
          <Card>
            <CardContent className="p-4 text-sm text-muted-foreground">
              Generated <span className="font-medium text-foreground">{new Date(data.generatedAt).toLocaleString()}</span>
              {data.auditHead ? (
                <>
                  {" "}· off-site audit head <code className="text-xs">{data.auditHead}</code>
                </>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="p-3 font-medium">Control</th>
                    <th className="p-3 font-medium">Mechanism</th>
                    <th className="p-3 font-medium">Present</th>
                    <th className="p-3 font-medium">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.controls.map((c, i) => (
                    <tr key={i} className="border-b last:border-0 align-top">
                      <td className="p-3 font-medium whitespace-nowrap">{c.control}</td>
                      <td className="p-3">{c.feature}</td>
                      <td className="p-3">
                        {c.present ? (
                          <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
                        ) : (
                          <MinusCircle className="size-4 text-muted-foreground" />
                        )}
                      </td>
                      <td className="p-3 text-muted-foreground">{c.evidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>

          <p className="text-xs text-muted-foreground">{data.note}</p>
        </>
      )}
    </div>
  );
}
