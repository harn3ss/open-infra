import { useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, RefreshCw } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/common/states";
import { getVmConsoleOutput, getVmConsoleScreenshot } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";

/*
 * The EC2 console's Actions → Monitor and troubleshoot → "Get system log" and "Get instance
 * screenshot": a read-only look at what the instance's console shows, for troubleshooting a guest that
 * can't be reached over the network. The system log is the last 64 KB of the serial console; the
 * screenshot is a still image of the display. Neither is a session; to work on the instance, connect
 * to it (SSH or Remote Desktop).
 */

type Props = {
  namespace: string;
  name: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
};

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function SystemLogDialog({ namespace, name, open, onOpenChange }: Props) {
  const q = useQuery({
    queryKey: ["vm-console-output", namespace, name],
    queryFn: () => getVmConsoleOutput(namespace, name),
    enabled: open,
    gcTime: 0,
  });
  const log = q.data?.output ?? "";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Get system log</DialogTitle>
          <DialogDescription>
            The most recent output of the instance&apos;s serial console (up to 64 KB)
            {q.data?.timestamp ? <>, as of {formatTimestamp(q.data.timestamp)}</> : null}.
          </DialogDescription>
        </DialogHeader>
        {q.isLoading ? (
          <LoadingState label="Getting the system log…" />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : log ? (
          <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
            {log}
          </pre>
        ) : (
          <p className="rounded-md border bg-muted/40 p-4 text-sm text-muted-foreground">
            {q.data?.note ?? "The instance has written nothing to its console yet."}
          </p>
        )}
        <DialogFooter className="gap-2">
          <Button
            variant="outline"
            onClick={() => download(new Blob([log], { type: "text/plain" }), `${name}-system-log.txt`)}
            disabled={!log}
          >
            <Download className="size-4" /> Download
          </Button>
          <Button variant="outline" onClick={() => q.refetch()} disabled={q.isFetching}>
            <RefreshCw className="size-4" /> Refresh
          </Button>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ScreenshotDialog({ namespace, name, open, onOpenChange }: Props) {
  const q = useQuery({
    queryKey: ["vm-console-screenshot", namespace, name],
    queryFn: () => getVmConsoleScreenshot(namespace, name),
    enabled: open,
    gcTime: 0,
    retry: false,
  });
  const src = useMemo(() => (q.data ? URL.createObjectURL(q.data) : ""), [q.data]);
  useEffect(() => () => {
    if (src) URL.revokeObjectURL(src);
  }, [src]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Get instance screenshot</DialogTitle>
          <DialogDescription>
            A still image of the instance&apos;s display, taken now. It is not a live session: to work
            on the instance, connect to it.
          </DialogDescription>
        </DialogHeader>
        {q.isLoading ? (
          <LoadingState label="Taking a screenshot…" />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : src ? (
          <img
            src={src}
            alt={`Screenshot of ${name}`}
            className="max-h-[60vh] w-full rounded-md border bg-black object-contain"
          />
        ) : null}
        <DialogFooter className="gap-2">
          <Button
            variant="outline"
            onClick={() => q.data && download(q.data, `${name}-screenshot.jpg`)}
            disabled={!q.data}
          >
            <Download className="size-4" /> Download
          </Button>
          <Button variant="outline" onClick={() => q.refetch()} disabled={q.isFetching}>
            <RefreshCw className="size-4" /> Refresh
          </Button>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
