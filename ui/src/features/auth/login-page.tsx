import { useState, type FormEvent } from "react";
import { LogIn, ShieldAlert, Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { BrandWordmark } from "@/components/layout/brand";
import { getCurrentUser, login, loginMfa, type CurrentUser } from "@/lib/api";
import { useAuth } from "@/lib/auth";

/**
 * Full-screen sign-in. Rendered instead of the console shell when signed out. A user with an MFA device
 * signs in in two steps, as on the AWS console: the password, then the code the device shows.
 */
export function LoginPage() {
  const { setUser } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // The password step passed and the user's MFA code is needed next.
  const [mfaStep, setMfaStep] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function finish(u: CurrentUser) {
    // The session as /auth/me reports it (account, ARN, capabilities); the sign-in answer if that fails.
    setUser(await getCurrentUser().catch(() => u));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const u = await login(username.trim(), password);
      if (u.mfaRequired) {
        setPassword("");
        setMfaStep(true);
        return;
      }
      await finish(u);
    } catch (err) {
      setError((err as Error).message || "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  async function onSubmitCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await finish(await loginMfa(code.trim()));
    } catch (err) {
      const msg = (err as Error).message || "The MFA code was not accepted";
      // An expired or restarted step goes back to the password.
      if (/sign in again/i.test(msg)) {
        cancelMfa();
      }
      setError(msg);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  function cancelMfa() {
    setMfaStep(false);
    setCode("");
    setError(null);
  }

  return (
    <div className="oi-aurora flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex justify-center">
          <BrandWordmark />
        </div>

        <Card>
          <CardContent className="pt-6">
            {mfaStep ? (
              <form onSubmit={onSubmitCode} className="space-y-4">
                <div className="space-y-1">
                  <h2 className="flex items-center gap-2 text-base font-semibold">
                    <Smartphone className="size-4" /> Multi-factor authentication
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    Your account is secured using multi-factor authentication (MFA). To finish
                    signing in, open your authenticator app and enter the code it shows for{" "}
                    <span className="font-medium text-foreground">{username.trim()}</span>.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="mfa-code">MFA code</Label>
                  <Input
                    id="mfa-code"
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    autoFocus
                    required
                  />
                </div>

                {error ? (
                  <p className="flex items-start gap-2 text-sm text-destructive">
                    <ShieldAlert className="mt-0.5 size-4 shrink-0" />
                    <span>{error}</span>
                  </p>
                ) : null}

                <div className="flex gap-2">
                  <Button type="button" variant="outline" className="flex-1" onClick={cancelMfa} disabled={busy}>
                    Cancel
                  </Button>
                  <Button type="submit" className="flex-1" disabled={busy || code.length !== 6}>
                    {busy ? "Verifying…" : "Submit"}
                  </Button>
                </div>
              </form>
            ) : (
              <form onSubmit={onSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    autoFocus
                    required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
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
                  <LogIn className="size-4" />
                  {busy ? "Signing in…" : "Sign in"}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground">
          First time? The <span className="font-medium">root</span> password was printed
          once in the console-api logs on first start.
        </p>
      </div>
    </div>
  );
}
