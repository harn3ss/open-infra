import { useState } from "react";
import { ArrowLeftRight, ChevronDown, Undo2, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CopyButton } from "@/components/common/copy-button";
import { ApiError, getCurrentUser, switchBack, switchRole } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { queryClient } from "@/lib/query-client";
import { formatAccountId } from "@/lib/policy-document";

/** The name an assumed-role session shows: the role, from arn:aws:sts::<acct>:assumed-role/<role>/<session>. */
function roleOf(arn?: string): string | undefined {
  const m = arn?.match(/:assumed-role\/([^/]+)\//);
  return m?.[1];
}

/**
 * The AWS console's account menu (top right): who you are to IAM (ARN), the account you are acting in,
 * and Switch role — assuming a role in another account (its OrganizationAccountAccessRole, typically) —
 * or Switch back to your own identity.
 */
export function AccountMenu() {
  const { user, setUser } = useAuth();
  const [open, setOpen] = useState(false);
  if (!user || user.authDisabled) return null;
  const account = user.account ?? "000000000000";
  const assumed = user.principalType === "Role" ? roleOf(user.arn) : undefined;

  async function back() {
    await switchBack();
    queryClient.clear();
    setUser(await getCurrentUser());
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="gap-1.5" title={user.arn}>
            <UserRound className="size-4" />
            <span className="max-w-[10rem] truncate">
              {assumed ? `${assumed} @ ${user.accountAlias || formatAccountId(account)}` : user.user}
            </span>
            <ChevronDown className="size-3.5 opacity-60" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-80">
          <DropdownMenuLabel className="space-y-1 font-normal">
            <div className="text-xs text-muted-foreground">Account ID</div>
            <div className="flex items-center gap-1 font-mono text-sm text-foreground">
              {formatAccountId(account)}
              <CopyButton value={account} />
            </div>
            {user.accountAlias ? (
              <div className="text-xs text-muted-foreground">
                Alias <span className="text-foreground">{user.accountAlias}</span>
              </div>
            ) : null}
          </DropdownMenuLabel>
          <DropdownMenuLabel className="space-y-1 font-normal">
            <div className="text-xs text-muted-foreground">{assumed ? "Role session" : "Signed in as"}</div>
            <div className="flex items-start gap-1 break-all font-mono text-xs text-foreground">
              {user.arn ?? user.user}
              {user.arn ? <CopyButton value={user.arn} /> : null}
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setOpen(true)}>
            <ArrowLeftRight className="size-4" />
            Switch role
          </DropdownMenuItem>
          {assumed ? (
            <DropdownMenuItem onClick={() => void back()}>
              <Undo2 className="size-4" />
              Switch back to {user.user}
            </DropdownMenuItem>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <SwitchRoleDialog open={open} onOpenChange={setOpen} />
    </>
  );
}

function SwitchRoleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const { setUser } = useAuth();
  const [account, setAccount] = useState("");
  const [role, setRole] = useState("OrganizationAccountAccessRole");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const acct = account.replace(/[-\s]/g, "");
  const valid = /^\d{12}$/.test(acct) && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(role.toLowerCase());

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await switchRole(acct, role.toLowerCase());
      queryClient.clear();
      setUser(await getCurrentUser());
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not switch role.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Switch role</DialogTitle>
          <DialogDescription>
            Act as a role in another account. The role&apos;s trust policy must name you or your account,
            and your policies must allow <code className="text-xs">sts:AssumeRole</code> on it.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="sr-account">Account ID</Label>
            <Input id="sr-account" placeholder="1234-5678-9012" value={account} onChange={(e) => setAccount(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="sr-role">IAM role name</Label>
            <Input id="sr-role" value={role} onChange={(e) => setRole(e.target.value)} />
          </div>
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={!valid || busy}>
            Switch role
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
