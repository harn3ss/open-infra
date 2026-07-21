import { useState, type FormEvent } from "react";
import { LogIn, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { BrandWordmark } from "@/components/layout/brand";
import { login } from "@/lib/api";
import { useAuth } from "@/lib/auth";

/** Full-screen sign-in. Rendered instead of the console shell when signed out. */
export function LoginPage() {
  const { setUser } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const u = await login(username.trim(), password);
      setUser(u);
    } catch (err) {
      setError((err as Error).message || "Sign-in failed");
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
          <CardContent className="pt-6">
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
