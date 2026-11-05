import { AlertTriangle, Inbox, Loader2, Lock, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { LearnMore } from "@/components/help/learn-more";
import { ApiError, accessDenied } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * The AWS console's access-denied panel: the action and the resource IAM refused, and what fixes it
 * (a policy that allows that action). Shown wherever a page's data comes back AccessDeniedException.
 */
export function AccessDeniedState({ error }: { error: unknown }) {
  const d = accessDenied(error);
  if (!d) return null;
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-amber-500/10 text-amber-600 dark:text-amber-400">
        <Lock className="size-6" />
      </div>
      <div className="max-w-xl space-y-2">
        <p className="text-sm font-medium text-foreground">You don&apos;t have permission</p>
        {d.action ? (
          <p className="text-sm text-muted-foreground">
            You are not authorized to perform <code className="text-xs text-foreground">{d.action}</code>
            {d.resource ? (
              <>
                {" "}on <code className="break-all text-xs text-foreground">{d.resource}</code>
              </>
            ) : null}
            .
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">{d.message}</p>
        )}
        <p className="text-xs text-muted-foreground">
          Ask an administrator to attach a policy that allows this action to you or to one of your
          groups.
        </p>
      </div>
    </div>
  );
}

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

/** Empty-result state with optional action and a "Learn more" doc link. */
export function EmptyState({
  title,
  description,
  icon,
  action,
  learnMore,
}: {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  /** Optional docs URL — renders a "Learn more" link under the action. */
  learnMore?: string;
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
      {learnMore ? <LearnMore href={learnMore} /> : null}
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
  if (accessDenied(error)) return <AccessDeniedState error={error} />;
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
