import { useQuery } from "@tanstack/react-query";
import { DollarSign } from "lucide-react";
import { Widget } from "@/features/dashboard/widget";
import { ErrorState, LoadingState } from "@/components/common/states";
import { getCost, type CostResponse } from "@/lib/api";

const usd = (n: number) =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: n >= 100 ? 0 : 2,
  }).format(n);

/**
 * Cost and usage — AWS Console Home's Cost and Usage widget. A compact headline
 * (what this cluster would cost on AWS) plus the top services as mini bars, from
 * the same `/cost` estimate the Cost Explorer page uses. Deep-links to Cost
 * Explorer. Estimate only — no fabricated spend.
 */
export function CostWidget({ className }: { className?: string }) {
  const { data, isLoading, isError, error, refetch } = useQuery<CostResponse>({
    queryKey: ["cost"],
    queryFn: getCost,
    refetchInterval: 30000,
  });

  const top = data
    ? [...data.categories].sort((a, b) => b.monthly - a.monthly).slice(0, 4)
    : [];
  const max = top.reduce((m, c) => Math.max(m, c.monthly), 0);

  return (
    <Widget
      title="Cost and usage"
      icon={DollarSign}
      className={className}
      footerHref="/cost"
      footerLabel="Cost Explorer"
    >
      {isLoading ? (
        <LoadingState label="Estimating cost…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : data ? (
        <div className="flex flex-1 flex-col gap-4">
          <div className="flex items-end justify-between gap-4">
            <div>
              <div className="text-xs text-muted-foreground">
                Estimated on AWS
              </div>
              <div className="text-2xl font-semibold tracking-tight tabular-nums">
                {usd(data.monthlyAWS)}
                <span className="text-sm font-normal text-muted-foreground">
                  {" "}
                  / mo
                </span>
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-muted-foreground">You pay</div>
              <div className="text-lg font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
                {usd(data.youPay)}
              </div>
            </div>
          </div>

          <div className="space-y-2.5">
            {top.map((c) => (
              <div key={c.category} className="space-y-1">
                <div className="flex items-baseline justify-between gap-2 text-xs">
                  <span className="truncate font-medium">{c.category}</span>
                  <span className="shrink-0 tabular-nums text-muted-foreground">
                    {usd(c.monthly)}
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{ width: `${max > 0 ? (c.monthly / max) * 100 : 0}%` }}
                  />
                </div>
              </div>
            ))}
          </div>

          <p className="mt-auto text-xs text-muted-foreground">
            Estimate against AWS on-demand list prices — you run it on your own
            hardware.
          </p>
        </div>
      ) : null}
    </Widget>
  );
}
