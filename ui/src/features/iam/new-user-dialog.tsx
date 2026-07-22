import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
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
import { createIamUser, type IamGroup } from "@/lib/api";
import { GroupPicker } from "./group-picker";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Create a local User: a name, an optional display name, its groups, and a password. */
export function NewUserDialog({
  open,
  onOpenChange,
  builtins,
  groups,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  builtins: string[];
  groups: IamGroup[];
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (!open) return;
    setName("");
    setDisplayName("");
    setSelected([]);
    setPassword("");
    create.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      createIamUser({ name, displayName, groups: selected, password }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      onOpenChange(false);
    },
  });

  const nameOk = RFC1123.test(name);
  const pwOk = password.length >= 8;
  const canSave = nameOk && pwOk && !create.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <UserPlus className="size-5" /> New user
          </DialogTitle>
          <DialogDescription>
            A console sign-in stored as a <code>kind: User</code>. The password is saved as a
            bcrypt hash in a Secret — never in the User itself.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="u-name">Username</Label>
            <Input
              id="u-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="alice"
              autoFocus
            />
            {name && !nameOk ? (
              <p className="text-xs text-destructive">
                Lowercase letters, digits and dashes only (a DNS label).
              </p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="u-display">Display name (optional)</Label>
            <Input
              id="u-display"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Alice Example"
            />
          </div>

          <div className="space-y-1.5">
            <Label>Groups</Label>
            <p className="text-xs text-muted-foreground">
              Permissions come entirely from group membership. No groups = can sign in, but do
              nothing.
            </p>
            <GroupPicker
              builtins={builtins}
              known={groups.map((g) => g.name)}
              value={selected}
              onChange={setSelected}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="u-pw">Password</Label>
            <Input
              id="u-pw"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
            />
            {password && !pwOk ? (
              <p className="text-xs text-destructive">At least 8 characters.</p>
            ) : null}
          </div>

          {create.isError ? (
            <p className="text-sm text-destructive">{(create.error as Error).message}</p>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!canSave} onClick={() => create.mutate()}>
            {create.isPending ? <Spinner className="size-4" /> : null}
            Create user
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
