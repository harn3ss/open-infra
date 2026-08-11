import { type ReactNode } from "react";
import { ExternalLink } from "lucide-react";

/** A "Learn more" doc link (the "Meal" tier) — always opens the docs in a new tab so the console is
 *  never lost. Fed by the per-kind docs map. */
export function LearnMore({ href, children }: { href: string; children?: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
    >
      {children ?? "Learn more"} <ExternalLink className="size-3" />
    </a>
  );
}
