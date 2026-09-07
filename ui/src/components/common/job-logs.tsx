import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError, jobLogs } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * In-console log viewer for a SageMaker-style job's backing batch/v1 Job — the AWS CloudWatch
 * "log stream" equivalent that replaces the "run `kubectl logs`" dead-end. Tails the Job's pod
 * logs via the BFF, aggregated per pod. `jobName` MUST be the backing Job name (resolved from
 * the CR's status), not the CR name. Honest-empty when the Job has no pods yet.
 */

const TAIL_OPTIONS = [200, 1000, 5000] as const;

export function JobLogs({
  namespace,
  jobName,
  running = false,
  className,
}: {
  namespace: string;
  jobName: string;
  /** When the run is active, poll every 10s (in addition to the manual Refresh). */
  running?: boolean;
  className?: string;
}) {
  const [tailLines, setTailLines] = useState<number>(1000);
  const [selectedPod, setSelectedPod] = useState<string | null>(null);

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ["job-logs", namespace, jobName, tailLines],
    queryFn: () => jobLogs(namespace, jobName, { tailLines }),
    refetchInterval: running ? 10_000 : false,
  });

  const pods = data?.pods ?? [];
  const active = useMemo(
    () => pods.find((p) => p.pod === selectedPod) ?? pods[0],
    [pods, selectedPod],
  );

  return (
    <div className={cn("space-y-3", className)}>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <Terminal className="size-4 shrink-0 text-muted-foreground" />
          {pods.length > 1 ? (
            <Select
              value={active?.pod ?? ""}
              onValueChange={(v) => setSelectedPod(v)}
            >
              <SelectTrigger className="h-8 w-[22rem] max-w-full text-xs">
                <SelectValue placeholder="Select a pod" />
              </SelectTrigger>
              <SelectContent>
                {pods.map((p) => (
                  <SelectItem key={p.pod} value={p.pod} className="text-xs">
                    {p.pod}
                    {p.container ? ` · ${p.container}` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : active ? (
            <code className="truncate text-xs text-muted-foreground">
              {active.pod}
              {active.container ? ` · ${active.container}` : ""}
            </code>
          ) : (
            <span className="text-xs text-muted-foreground">Job: {jobName}</span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <Select value={String(tailLines)} onValueChange={(v) => setTailLines(Number(v))}>
            <SelectTrigger className="h-8 w-[8.5rem] text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TAIL_OPTIONS.map((n) => (
                <SelectItem key={n} value={String(n)} className="text-xs">
                  Last {n.toLocaleString()} lines
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn("size-4", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Scrollback */}
      <div className="overflow-hidden rounded-md border border-border bg-zinc-950">
        {isLoading ? (
          <div className="flex items-center justify-center gap-2 py-16 text-xs text-zinc-400">
            <RefreshCw className="size-4 animate-spin" />
            Loading logs…
          </div>
        ) : isError ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center text-xs text-zinc-300">
            <AlertTriangle className="size-5 text-amber-400" />
            <p className="max-w-md">
              {error instanceof ApiError ? error.message : "Couldn't load logs."}
            </p>
            <Button variant="outline" size="sm" onClick={() => refetch()} className="mt-1">
              <RefreshCw className="size-4" />
              Retry
            </Button>
          </div>
        ) : pods.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-1 py-16 text-center text-xs text-zinc-400">
            <Terminal className="size-5" />
            <p>No pods yet — the job may not have started.</p>
          </div>
        ) : !active?.logs?.trim() ? (
          <div className="flex flex-col items-center justify-center gap-1 py-16 text-center text-xs text-zinc-400">
            <Terminal className="size-5" />
            <p>No log output from this pod yet.</p>
          </div>
        ) : (
          <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-xs leading-relaxed text-zinc-100">
            {active.logs}
          </pre>
        )}
      </div>

      <p className="text-[11px] text-muted-foreground">
        Aggregated from the backing Job's pods
        {running ? " · auto-refreshes every 10s while Running" : ""}.
      </p>
    </div>
  );
}
