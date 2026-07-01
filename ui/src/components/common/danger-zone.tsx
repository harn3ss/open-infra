import { type ReactNode, useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/common/confirm-dialog";

/**
 * A consistent "Danger Zone" block for resource detail pages: a destructive
 * card with a delete action gated behind a confirm dialog. Drop it at the
 * bottom of a detail page; pass the delete mutation via onConfirm.
 */
export function DangerZone({
  resourceLabel,
  resourceName,
  onConfirm,
  deleting,
  description,
  confirmDescription,
  inline,
}: {
  /** Human label, e.g. "Model", "Database". */
  resourceLabel: string;
  /** The resource's name, shown in the confirm dialog. */
  resourceName: string;
  onConfirm: () => void;
  deleting?: boolean;
  /** Optional override for the card's explanatory text. */
  description?: ReactNode;
  /** Optional override for the confirm dialog body. */
  confirmDescription?: ReactNode;
  /**
   * Compact form: just a destructive button (+ confirm dialog), no Card. For
   * placing the delete action in the detail page's tab-bar row instead of a
   * full-width block at the bottom of a tab.
   */
  inline?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const dialog = (
    <ConfirmDialog
      open={open}
      onOpenChange={setOpen}
      title={`Delete ${resourceLabel}?`}
      description={
        confirmDescription ?? (
          <>
            Permanently delete{" "}
            <span className="font-medium text-foreground">{resourceName}</span>.
            This cannot be undone.
          </>
        )
      }
      confirmLabel="Delete"
      loading={deleting}
      onConfirm={onConfirm}
    />
  );

  if (inline) {
    return (
      <>
        <Button
          variant="outline"
          size="sm"
          className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
          onClick={() => setOpen(true)}
        >
          <Trash2 className="size-4" />
          Delete {resourceLabel}
        </Button>
        {dialog}
      </>
    );
  }

  return (
    <Card className="border-destructive/40">
      <CardContent className="flex flex-wrap items-center justify-between gap-4 p-5">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-destructive">Danger Zone</h3>
          <p className="text-sm text-muted-foreground">
            {description ??
              `Permanently delete this ${resourceLabel.toLowerCase()}. This cannot be undone.`}
          </p>
        </div>
        <Button variant="destructive" onClick={() => setOpen(true)}>
          <Trash2 className="size-4" />
          Delete {resourceLabel}
        </Button>
      </CardContent>
      {dialog}
    </Card>
  );
}
