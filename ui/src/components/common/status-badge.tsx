import { Badge } from "@/components/ui/badge";
import { statusTone, type StatusTone } from "@/lib/format";
import { cn } from "@/lib/utils";

const toneToVariant: Record<
  StatusTone,
  "success" | "warning" | "destructive" | "muted" | "default" | "accent"
> = {
  success: "success",
  warning: "warning",
  destructive: "destructive",
  muted: "muted",
  default: "default",
  accent: "accent",
};

const dotColor: Record<StatusTone, string> = {
  success: "bg-success",
  warning: "bg-warning",
  destructive: "bg-destructive",
  muted: "bg-muted-foreground",
  default: "bg-primary",
  accent: "bg-accent",
};

/**
 * A status pill with a leading dot. Pass an explicit `tone`, or let it be
 * inferred from the status text.
 */
export function StatusBadge({
  status,
  tone,
  className,
}: {
  status: string | undefined;
  tone?: StatusTone;
  className?: string;
}) {
  const resolved = tone ?? statusTone(status);
  const label = status ?? "Unknown";
  return (
    <Badge variant={toneToVariant[resolved]} className={cn("gap-1.5", className)}>
      <span
        className={cn(
          "size-1.5 rounded-full",
          dotColor[resolved],
          resolved === "warning" && "animate-pulse",
        )}
      />
      {label}
    </Badge>
  );
}
