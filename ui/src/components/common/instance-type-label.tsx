import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { matchInstanceType, type InstanceTypeGroup } from "@/lib/instance-types";

/**
 * Show a resource's sizing as its AWS-style instance-type name (matching the create picker), with the
 * raw vCPU/RAM/GPU as a caption. When the spec doesn't map to a catalog type (raw sizing, or a field
 * left at the XRD default), it falls back to the raw `detail` string alone — never a wrong type name.
 *
 * `compact` (list cells): just the type id, or the raw detail when unmatched (with the detail on hover).
 */
export function InstanceTypeLabel({
  groups,
  spec,
  detail,
  compact = false,
  className,
}: {
  groups: InstanceTypeGroup[];
  spec: Record<string, unknown> | undefined | null;
  /** Raw sizing summary, e.g. "2 vCPU · 4Gi". Shown as caption when matched, or alone when not. */
  detail: string;
  compact?: boolean;
  className?: string;
}) {
  const t = matchInstanceType(groups, spec);

  if (compact) {
    return (
      <span className={cn("font-mono text-xs text-muted-foreground", className)} title={detail}>
        {t ? t.id : detail}
      </span>
    );
  }

  if (!t) {
    return <span className={cn("font-mono text-xs text-muted-foreground", className)}>{detail}</span>;
  }
  return (
    <span className={cn("flex flex-wrap items-center gap-2", className)}>
      <Badge variant="secondary" className="font-mono">{t.id}</Badge>
      <span className="font-mono text-xs text-muted-foreground">{detail}</span>
    </span>
  );
}
