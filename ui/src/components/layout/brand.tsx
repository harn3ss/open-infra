import { cn } from "@/lib/utils";

/** The open-infra mark: a hexagonal node with an indigo→teal gradient. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      className={cn("size-7", className)}
      role="img"
      aria-label="open-infra"
    >
      <defs>
        <linearGradient id="oi-brand" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="hsl(243 75% 66%)" />
          <stop offset="1" stopColor="hsl(172 66% 50%)" />
        </linearGradient>
      </defs>
      <path
        d="M16 4 27 10.25v11.5L16 28 5 21.75v-11.5z"
        fill="none"
        stroke="url(#oi-brand)"
        strokeWidth="2.25"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="3.4" fill="url(#oi-brand)" />
    </svg>
  );
}

export function BrandWordmark({
  collapsed,
  className,
}: {
  collapsed?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <BrandMark />
      {!collapsed ? (
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-tight">
            open-infra
          </div>
          <div className="text-[0.65rem] uppercase tracking-[0.18em] text-muted-foreground">
            console
          </div>
        </div>
      ) : null}
    </div>
  );
}
