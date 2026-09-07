import { type ReactNode } from "react";
import { Info } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

/**
 * An honest placeholder for an AWS-parity tab whose data the BFF does not yet
 * surface. It renders the tab *structure* (so the tab set lines up with AWS
 * side-by-side) with a plain "not available yet" explanation instead of a
 * fabricated widget. Use it wherever a tab is backend-blocked; say what would
 * fill it and what has to land first.
 */
export function PendingTab({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardContent className="flex items-start gap-3 p-5">
        <Info className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">{title}</h3>
          <div className="text-sm text-muted-foreground">{children}</div>
        </div>
      </CardContent>
    </Card>
  );
}
