import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/common/states";
import { createIamPolicy, updateIamPolicy, type IamPolicy } from "@/lib/api";
import {
  PermissionEditor,
  actionsToRows,
  rowsToActions,
  type PermRow,
} from "./permission-editor";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Create or edit a Policy. A policy is a set of permissions over openinfra.dev resources —
 * the boundary — attached to Roles later. Pass `editing` to modify one in place.
 */
export function NewPolicyDialog({
  open,
  onOpenChange,
  resources,
  editing,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  resources: string[];
  editing?: IamPolicy | null;
}) {
  const qc = useQueryClient();
  const isEdit = Boolean(editing);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rows, setRows] = useState<PermRow[]>([{ resource: "", verbs: [] }]);

  useEffect(() => {
    if (!open) return;
    save.reset();
    if (editing) {
      setName(editing.name);
      setDescription(editing.description);
      const actions = editing.statements.flatMap((s) => s.actions ?? []);
      const r = actionsToRows(actions);
      setRows(r.length ? r : [{ resource: "", verbs: [] }]);
    } else {
      setName("");
      setDescription("");
      setRows([{ resource: "", verbs: [] }]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing]);

  const save = useMutation({
    mutationFn: () => {
      const actions = rowsToActions(rows);
      const statements = [{ effect: "Allow", actions, resources: ["*"] }];
      if (isEdit) return updateIamPolicy(name, { description, statements });
      return createIamPolicy({ name, description, statements });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "policies"] });
      if (isEdit) void qc.invalidateQueries({ queryKey: ["iam", "policy", name] });
      onOpenChange(false);
    },
  });

  const nameOk = RFC1123.test(name);
  const actionCount = rowsToActions(rows).length;
  const canSave = nameOk && actionCount > 0 && !save.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="size-5" /> {isEdit ? `Edit policy ${name}` : "New policy"}
          </DialogTitle>
          <DialogDescription>
            An attachable set of permissions over open-infra resources. It grants nothing until
            a Role includes it. Policies can only ever grant on openinfra.dev kinds — the
            permission boundary.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="p-name">Name</Label>
            <Input
              id="p-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="virtual-machine-operator"
              disabled={isEdit}
              autoFocus={!isEdit}
            />
            {name && !nameOk ? (
              <p className="text-xs text-destructive">
                Lowercase letters, digits and dashes only.
              </p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="p-desc">Description (optional)</Label>
            <Input
              id="p-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Full control of VMs and their disks"
            />
          </div>

          <div className="space-y-1.5">
            <Label>Permissions</Label>
            <PermissionEditor resources={resources} rows={rows} onChange={setRows} />
          </div>

          {save.isError ? (
            <p className="text-sm text-destructive">{(save.error as Error).message}</p>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!canSave} onClick={() => save.mutate()}>
            {save.isPending ? <Spinner className="size-4" /> : null}
            {isEdit ? "Save policy" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
