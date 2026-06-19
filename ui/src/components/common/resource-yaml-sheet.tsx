import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { YamlViewer } from "@/components/common/yaml-viewer";
import type { K8sObject } from "@/types/k8s";

/** Read-only YAML drawer for any resource. */
export function ResourceYamlSheet({
  resource,
  open,
  onOpenChange,
}: {
  resource: K8sObject | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-2xl">
        {resource ? (
          <>
            <SheetHeader>
              <SheetTitle className="truncate pr-8">
                {resource.kind ?? "Resource"}: {resource.metadata.name}
              </SheetTitle>
              <SheetDescription>
                {resource.metadata.namespace
                  ? `Namespace ${resource.metadata.namespace}`
                  : "Cluster-scoped"}
              </SheetDescription>
            </SheetHeader>
            <div className="flex-1 overflow-auto p-5">
              <YamlViewer value={resource} maxHeightClassName="max-h-[78vh]" />
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
