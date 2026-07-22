import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, UsersRound } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/common/states";
import { createIamGroup, listIamRoles } from "@/lib/api";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

// The ClusterRoles the platform ships. spec.clusterRole is the ONLY field that grants
// anything, so these are offered explicitly rather than as free text.
const ROLE_OPTIONS = [
  { value: "open-infra-console", label: "Full access (open-infra-console)" },
  { value: "open-infra-poweruser", label: "Power user — manage resources, not secrets/RBAC" },
  { value: "open-infra-readonly", label: "Read-only" },
];

export function NewGroupDialog({
  open,
  onOpenChange,
  builtins,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  builtins: string[];
}) {
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [clusterRole, setClusterRole] = useState("open-infra-readonly");

  // Built-in tiers plus any custom Role's aggregated ClusterRole, so a group can grant a
  // policy-composed role (Roles page) as easily as a built-in tier.
  const roleOptions = [
    ...ROLE_OPTIONS,
    ...(roles.data ?? []).map((r) => ({
      value: r.clusterRole || `openinfra-role-${r.name}`,
      label: `Role: ${r.name}`,
    })),
  ];

  useEffect(() => {
    if (!open) return;
    setName("");
    setDescription("");
    setClusterRole("open-infra-readonly");
    create.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const create = useMutation({
    mutationFn: () => createIamGroup({ name, description, clusterRole }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
      onOpenChange(false);
    },
  });

  const nameOk = RFC1123.test(name);
  const isBuiltin = builtins.includes(name);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <UsersRound className="size-5" /> New group
          </DialogTitle>
          <DialogDescription>
            A <code>kind: Group</code> binds its members to a ClusterRole. That role is the only
            thing that grants access — choose it deliberately.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="g-name">Name</Label>
            <Input
              id="g-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="dba"
              autoFocus
            />
            {name && !nameOk ? (
              <p className="text-xs text-destructive">
                Lowercase letters, digits and dashes only (a DNS label).
              </p>
            ) : null}
            {nameOk && !isBuiltin ? (
              <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  This is not one of the built-in group names, so it won't take effect until an
                  operator adds <code>openinfra:{name}</code> to the impersonator ClusterRole.
                  The group is still created.
                </span>
              </p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="g-desc">Description (optional)</Label>
            <Input
              id="g-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Database administrators"
            />
          </div>

          <div className="space-y-1.5">
            <Label>Grants (ClusterRole)</Label>
            <Select value={clusterRole} onValueChange={setClusterRole}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {roleOptions.map((r) => (
                  <SelectItem key={r.value} value={r.value}>
                    {r.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {create.isError ? (
            <p className="text-sm text-destructive">{(create.error as Error).message}</p>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!nameOk || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? <Spinner className="size-4" /> : null}
            Create group
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
