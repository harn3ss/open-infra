import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Check } from "lucide-react";
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
import { createIamRole, listIamPolicies, type IamRole } from "@/lib/api";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Create a Role: a name and the set of Policies it bundles. */
export function NewRoleDialog({
  open,
  onOpenChange,
  editing,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  editing?: IamRole | null;
}) {
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<string[]>([]);

  useEffect(() => {
    if (!open) return;
    save.reset();
    setName(editing?.name ?? "");
    setDescription(editing?.description ?? "");
    setSelected(editing?.policies ?? []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing]);

  const save = useMutation({
    mutationFn: () => createIamRole({ name, description, policies: selected }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
      onOpenChange(false);
    },
  });

  const toggle = (p: string) =>
    setSelected(selected.includes(p) ? selected.filter((x) => x !== p) : [...selected, p]);
  const nameOk = RFC1123.test(name);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Boxes className="size-5" /> New role
          </DialogTitle>
          <DialogDescription>
            A named bundle of policies. Point a Group at it (Grants → <code>openinfra-role-…</code>)
            to give its members the union of those policies.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="r-name">Name</Label>
            <Input
              id="r-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="vm-operator"
              autoFocus
            />
            {name && !nameOk ? (
              <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="r-desc">Description (optional)</Label>
            <Input
              id="r-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Operate VMs and their storage"
            />
          </div>

          <div className="space-y-1.5">
            <Label>Attached policies</Label>
            {policies.data && policies.data.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {policies.data.map((p) => {
                  const on = selected.includes(p.name);
                  return (
                    <button
                      key={p.name}
                      type="button"
                      onClick={() => toggle(p.name)}
                      className={[
                        "inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                        on
                          ? "border-primary/40 bg-primary/15 text-primary"
                          : "border-border text-muted-foreground hover:bg-muted",
                      ].join(" ")}
                    >
                      {on ? <Check className="size-3" /> : null}
                      {p.name}
                    </button>
                  );
                })}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">
                No policies yet — create a Policy first, then attach it here.
              </p>
            )}
          </div>

          {save.isError ? (
            <p className="text-sm text-destructive">{(save.error as Error).message}</p>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!nameOk || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? <Spinner className="size-4" /> : null}
            Create role
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
