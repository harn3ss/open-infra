import { AlertTriangle, Inbox, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Centered inline spinner. */
export function Spinner({ className }: { className?: string }) {
  return (
    <Loader2 className={cn("size-4 animate-spin text-muted-foreground", className)} />
  );
}

/** Full-panel loading state. */
export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
      <Loader2 className="size-6 animate-spin" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

/** Empty-result state with optional action. */
export function EmptyState({
  title,
  description,
  icon,
  action,
}: {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-secondary text-muted-foreground">
        {icon ?? <Inbox className="size-6" />}
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description ? (
          <p className="max-w-sm text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

function describeError(error: unknown): { title: string; detail?: string } {
  if (error instanceof ApiError) {
    if (error.status === 0) {
      return {
        title: "Can't reach the BFF",
        detail: error.message,
      };
    }
    if (error.status === 401 || error.status === 403) {
      return {
        title: "Not authorized",
        detail: error.message,
      };
    }
    if (error.status === 404) {
      return { title: "Not found", detail: error.message };
    }
    return { title: `Error ${error.status}`, detail: error.message };
  }
  if (error instanceof Error) return { title: "Something went wrong", detail: error.message };
  return { title: "Something went wrong" };
}

/** Full-panel error state with retry. */
export function ErrorState({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  const { title, detail } = describeError(error);
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <AlertTriangle className="size-6" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {detail ? (
          <p className="max-w-md text-sm text-muted-foreground">{detail}</p>
        ) : null}
      </div>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="size-4" />
          Retry
        </Button>
      ) : null}
    </div>
  );
}
