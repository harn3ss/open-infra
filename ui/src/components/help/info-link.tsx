import { type ReactNode } from "react";
import { useHelp } from "@/components/help/help-context";

/**
 * The "Info" link (AWS/Cloudscape) — a small affordance next to a label or section header that opens
 * the Help panel with contextual guidance. Deliberately understated so it doesn't compete with the
 * field; the panel carries the depth + a "Learn more" doc link.
 */
export function InfoLink({ title, body, docsHref }: { title: string; body: ReactNode; docsHref?: string }) {
  const { show } = useHelp();
  return (
    <button
      type="button"
      onClick={() => show({ title, body, docsHref })}
      className="text-xs font-normal text-primary hover:underline"
      aria-label={`Info about ${title}`}
    >
      Info
    </button>
  );
}
