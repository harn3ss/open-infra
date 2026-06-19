import { Loader2, ServerCrash } from "lucide-react";
import { BrandMark } from "@/components/layout/brand";
import { ApiError } from "@/lib/api";

/** Shown while /api/config is being fetched at startup. */
export function BootLoading() {
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-4 oi-aurora">
      <BrandMark className="size-10" />
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" />
        Connecting to open-infra…
      </div>
    </div>
  );
}

/** Shown when /api/config can't be loaded (BFF down or misconfigured). */
export function BootError({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry: () => void;
}) {
  const detail =
    error instanceof ApiError || error instanceof Error
      ? error.message
      : "Unknown error";
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-5 px-6 text-center oi-aurora">
      <div className="flex size-16 items-center justify-center rounded-2xl bg-destructive/10 text-destructive">
        <ServerCrash className="size-8" />
      </div>
      <div className="space-y-1.5">
        <h1 className="text-xl font-semibold">Can’t reach the open-infra BFF</h1>
        <p className="max-w-md text-sm text-muted-foreground">
          The console couldn’t load <code>/api/config</code>. Make sure the
          open-infra BFF is running and serving this app. In development, it
          should be reachable so Vite can proxy <code>/api</code> to it.
        </p>
        <p className="max-w-md break-words text-xs text-muted-foreground/80">
          {detail}
        </p>
      </div>
      <button
        type="button"
        onClick={onRetry}
        className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
      >
        Retry
      </button>
    </div>
  );
}
