import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { cn } from "@/lib/utils";

/**
 * The platform object behind a resource, for operators: collapsed by default under the detail page's
 * "Advanced" tab. An AWS user never needs it (the console's other tabs and the AWS API describe the
 * resource); a platform operator can open it to read the object as the platform stores it.
 */
export function AdvancedYaml({ value, className }: { value: unknown; className?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={cn("space-y-3", className)}>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground"
      >
        <ChevronRight className={cn("size-4 transition-transform", open && "rotate-90")} />
        Platform object (for operators)
      </button>
      {open ? (
        <YamlViewer value={value} />
      ) : (
        <p className="text-sm text-muted-foreground">
          The object the platform keeps for this resource. You don't need it to use the resource; it is here
          for platform operators.
        </p>
      )}
    </div>
  );
}
