import { forwardRef, type ReactNode } from "react";
import { Button, type ButtonProps } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useKindAvailability } from "@/hooks/use-capabilities";

export interface CreateButtonProps extends ButtonProps {
  /** The open-infra kind this button creates, e.g. "VirtualMachine". */
  kind: string;
  children: ReactNode;
}

/**
 * A "New <kind>" button that respects the kind's architecture capability (#41 Phase 3). When the kind
 * cannot run on this cluster it renders DISABLED with a tooltip stating why — never hidden, because a
 * greyed entry with a reason teaches the operator, while an absent one reads as "the platform can't do
 * that". `available` and `untested` kinds render a normal button (untested is permitted; its caveat is
 * surfaced on the create page). Fails open: unknown/loading/degraded → a normal button.
 */
export const CreateButton = forwardRef<HTMLButtonElement, CreateButtonProps>(
  function CreateButton({ kind, children, ...props }, ref) {
    const avail = useKindAvailability(kind);
    if (!avail.unavailable) {
      return (
        <Button ref={ref} {...props}>
          {children}
        </Button>
      );
    }
    // Disabled buttons don't emit pointer events, so the tooltip hangs off a wrapping span.
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex" tabIndex={0}>
            <Button ref={ref} {...props} disabled onClick={undefined}>
              {children}
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          {avail.reason || `${kind} can't run on this cluster.`}
        </TooltipContent>
      </Tooltip>
    );
  },
);
