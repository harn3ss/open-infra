import { useQuery } from "@tanstack/react-query";
import {
  Cpu,
  DollarSign,
  HardDrive,
  MemoryStick,
  Network,
  Server,
  Zap,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { LiveIndicator } from "@/components/common/live-indicator";
import { ErrorState, LoadingState } from "@/components/common/states";
import { getCost, type CostResponse } from "@/lib/api";

const usd = (n: number) =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: n >= 100 ? 0 : 2,
  }).format(n);

function Stat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
      <span className="text-muted-foreground">{label}</span>
      <span className="ml-auto font-medium tabular-nums">{value}</span>
    </div>
  );
}

export function CostPage() {
  const { data, isLoading, isError, error, isFetching } = useQuery<CostResponse>(
    {
      queryKey: ["cost"],
      queryFn: getCost,
      refetchInterval: 30000,
    },
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<DollarSign />}
        title="Cost Explorer"
        description="What AWS would charge to run this cluster — priced against public on-demand rates."
        actions={<LiveIndicator live={isFetching} />}
      />

      {isLoading ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data ? (
        <>
          {/* Hero: the bill you're not paying */}
          <Card className="overflow-hidden border-primary/20">
            <CardContent className="grid gap-6 p-6 sm:grid-cols-3">
              <div>
                <div className="text-sm text-muted-foreground">
                  Estimated on AWS
                </div>
                <div className="pt-1 text-3xl font-semibold tracking-tight text-primary tabular-nums">
                  {usd(data.monthlyAWS)}
                  <span className="text-base font-normal text-muted-foreground">
                    {" "}
                    / mo
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  {usd(data.yearlyAWS)} / year
                </div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">
                  You pay on open-infra
                </div>
                <div className="pt-1 text-3xl font-semibold tracking-tight tabular-nums">
                  {usd(data.youPay)}
                  <span className="text-base font-normal text-muted-foreground">
                    {" "}
                    / mo
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  your own hardware
                </div>
              </div>
              <div className="sm:text-right">
                <div className="text-sm text-muted-foreground">
                  You're saving
                </div>
                <div className="pt-1 text-3xl font-semibold tracking-tight text-emerald-600 dark:text-emerald-400 tabular-nums">
                  {usd(data.yearlyAWS)}
                  <span className="text-base font-normal text-muted-foreground">
                    {" "}
                    / yr
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  vs. AWS on-demand
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Cost by category */}
            <Card>
              <CardContent className="space-y-4 p-5">
                <div className="text-sm font-semibold">By service</div>
                <div className="space-y-3">
                  {data.categories.map((c) => {
                    const pct =
                      data.monthlyAWS > 0
                        ? Math.round((c.monthly / data.monthlyAWS) * 100)
                        : 0;
                    return (
                      <div key={c.category} className="space-y-1">
                        <div className="flex items-baseline justify-between gap-2 text-sm">
                          <span className="font-medium">{c.category}</span>
                          <span className="tabular-nums">{usd(c.monthly)}</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {c.detail}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Provisioned totals */}
            <Card>
              <CardContent className="space-y-3 p-5">
                <div className="text-sm font-semibold">Provisioned</div>
                <Stat
                  icon={<Server />}
                  label="Nodes"
                  value={String(data.totals.nodes)}
                />
                <Stat
                  icon={<Cpu />}
                  label="vCPU"
                  value={String(data.totals.vcpu)}
                />
                <Stat
                  icon={<MemoryStick />}
                  label="Memory"
                  value={`${data.totals.memoryGiB} GiB`}
                />
                <Stat
                  icon={<Zap />}
                  label="GPUs"
                  value={String(data.totals.gpu)}
                />
                <Stat
                  icon={<HardDrive />}
                  label="Block storage"
                  value={`${data.totals.storageGiB} GiB`}
                />
                <Stat
                  icon={<Network />}
                  label="Load balancers"
                  value={String(data.totals.loadBalancers)}
                />
              </CardContent>
            </Card>
          </div>

          {/* By namespace */}
          {data.byNamespace.length > 0 && (
            <Card>
              <CardContent className="p-5">
                <div className="pb-3 text-sm font-semibold">
                  Compute by namespace
                  <span className="pl-2 font-normal text-muted-foreground">
                    (from running pod requests)
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="py-2 font-medium">Namespace</th>
                        <th className="py-2 text-right font-medium">vCPU</th>
                        <th className="py-2 text-right font-medium">Memory</th>
                        <th className="py-2 text-right font-medium">AWS / mo</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.byNamespace.map((n) => (
                        <tr key={n.namespace} className="border-b last:border-0">
                          <td className="py-2 font-medium">{n.namespace}</td>
                          <td className="py-2 text-right tabular-nums">
                            {n.vcpu}
                          </td>
                          <td className="py-2 text-right tabular-nums">
                            {n.memoryGiB} GiB
                          </td>
                          <td className="py-2 text-right tabular-nums">
                            {usd(n.monthly)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          <p className="text-xs text-muted-foreground">
            Estimate only. Compute priced at AWS Fargate rates (
            {usd(data.prices.vcpuHour)}/vCPU-hr, {usd(data.prices.gbHour)}/GB-hr),
            GPU at {usd(data.prices.gpuHour)}/hr (g4dn.xlarge class), EBS gp3 at{" "}
            {usd(data.prices.ebsGbMonth)}/GB-mo, ALB at {usd(data.prices.lbMonth)}
            /mo — us-east-1 on-demand list prices, overridable via{" "}
            <code>COST_*</code> env on the console. Excludes data transfer, S3
            object storage, and RDS/support premiums.
          </p>
        </>
      ) : null}
    </div>
  );
}
