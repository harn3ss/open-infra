import { useState, type FormEvent } from "react";
import { KeyRound, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { BrandWordmark } from "@/components/layout/brand";
import { changeOwnPassword, getCurrentUser } from "@/lib/api";
import { useAuth } from "@/lib/auth";

/**
 * The forced password change, as the AWS console has it: an IAM user whose login profile requires a new
 * password (PasswordResetRequired, or a password past the account's maximum age) sets one, proving the
 * current one, before it reaches anything else.
 */
export function ChangePasswordPage() {
  const { user, setUser, signOut } = useAuth();
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (newPassword !== confirm) {
      setError("The new passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await changeOwnPassword(oldPassword, newPassword);
      setUser(await getCurrentUser());
    } catch (err) {
      setError((err as Error).message || "The password could not be changed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="oi-aurora flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex justify-center">
          <BrandWordmark />
        </div>

        <Card>
          <CardContent className="space-y-4 pt-6">
            <div className="space-y-1">
              <h1 className="text-lg font-semibold">Change your password</h1>
              <p className="text-sm text-muted-foreground">
                {user?.user ? <span className="font-medium">{user.user}</span> : "Your account"} must set a new
                password before continuing.
              </p>
            </div>
            <form onSubmit={onSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="old-password">Current password</Label>
                <Input
                  id="old-password"
                  type="password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  autoComplete="current-password"
                  autoFocus
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="new-password">New password</Label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm-password">Confirm new password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                  required
                />
              </div>

              {error ? (
                <p className="flex items-start gap-2 text-sm text-destructive">
                  <ShieldAlert className="mt-0.5 size-4 shrink-0" />
                  <span>{error}</span>
                </p>
              ) : null}

              <Button type="submit" className="w-full" disabled={busy}>
                <KeyRound className="size-4" />
                {busy ? "Changing…" : "Confirm password change"}
              </Button>
              <Button type="button" variant="ghost" className="w-full" onClick={() => void signOut()}>
                Sign out
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
