import { useMemo } from "react";
import { AlertCircle, Info } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { LiveIndicator } from "@/components/common/live-indicator";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { corePaths } from "@/lib/k8s-paths";
import { age, eventTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { newestFirst } from "@/lib/watch-events";
import type { EventObj } from "@/types/k8s";

/**
 * Recent events, live: the account's own, as every Console Home widget is the account's (a namespace's
 * when one is given). The newest 100 are shown, each event's time read once per update.
 */
export function EventsFeed({ namespace }: { namespace?: string }) {
  const { items, isLoading, isError, error, live, refetch } =
    useK8sWatch<EventObj>(corePaths.events(namespace), { accountScope: !namespace });

  const sorted = useMemo(() => newestFirst(items, 100, eventTime), [items]);

  return (
    <Card className="flex h-full flex-col">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">Recent events</CardTitle>
        <LiveIndicator live={live} />
      </CardHeader>
      <CardContent className="flex-1 p-0">
        {isLoading ? (
          <LoadingState label="Loading events…" />
        ) : isError ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : sorted.length === 0 ? (
          <EmptyState
            icon={<Info className="size-6" />}
            title="No recent events"
            description="Cluster events will appear here as they happen."
          />
        ) : (
          <ScrollArea className="h-[22rem]">
            <ul className="divide-y divide-border">
              {sorted.map((e) => {
                const warning = e.type === "Warning";
                const obj = e.involvedObject;
                return (
                  <li
                    key={e.metadata.uid ?? `${e.metadata.name}-${eventTime(e)}`}
                    className="flex gap-3 px-5 py-2.5"
                  >
                    <div
                      className={cn(
                        "mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full",
                        warning
                          ? "bg-destructive/10 text-destructive"
                          : "bg-secondary text-muted-foreground",
                      )}
                    >
                      {warning ? (
                        <AlertCircle className="size-3.5" />
                      ) : (
                        <Info className="size-3.5" />
                      )}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-sm font-medium">
                          {e.reason ?? "Event"}
                        </span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {age(eventTime(e))}
                        </span>
                      </div>
                      <p className="line-clamp-2 text-xs text-muted-foreground">
                        {e.message}
                      </p>
                      {obj?.kind ? (
                        <p className="mt-0.5 text-[0.7rem] text-muted-foreground/70">
                          {obj.kind}
                          {obj.name ? `/${obj.name}` : ""}
                          {obj.namespace ? ` · ${obj.namespace}` : ""}
                        </p>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
