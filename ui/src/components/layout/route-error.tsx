import { useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Catches render/loader errors within a route and offers a recovery path. */
export function RouteErrorBoundary({ error }: ErrorComponentProps) {
  const router = useRouter();
  const message =
    error instanceof Error ? error.message : "An unexpected error occurred.";
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 text-center">
      <div className="flex size-14 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <AlertTriangle className="size-7" />
      </div>
      <div className="space-y-1">
        <h1 className="text-xl font-semibold">This view hit an error</h1>
        <p className="max-w-md text-sm text-muted-foreground">{message}</p>
      </div>
      <Button variant="outline" onClick={() => router.invalidate()}>
        Reload view
      </Button>
    </div>
  );
}
