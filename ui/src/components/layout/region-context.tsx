import { Globe } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { formatAccountId } from "@/lib/policy-document";

/** AWS's display names for the regions the console may report. */
const REGION_NAMES: Record<string, string> = { "us-east-1": "N. Virginia" };

/**
 * The top bar's scope: the account the session acts in and its region, as the AWS console shows them.
 * The account comes from the session (switch accounts with Switch role in the account menu); the
 * platform serves one region. Everything a page lists is in this account and region.
 */
export function RegionContext() {
  const { user } = useAuth();
  if (!user) return null;
  const region = user.region ?? "us-east-1";
  const account = user.accountAlias || formatAccountId(user.account ?? "000000000000");
  return (
    <div
      className="flex h-9 items-center gap-2 rounded-md border border-border px-2.5 text-sm"
      title={`Account ${user.account ?? ""} · Region ${region}`}
      aria-label={`Account ${account}, region ${region}`}
    >
      <Globe className="size-4 shrink-0 text-muted-foreground" />
      <span className="hidden max-w-[9rem] truncate font-mono text-xs text-muted-foreground xl:inline">{account}</span>
      <span className="font-medium">{REGION_NAMES[region] ?? region}</span>
      <span className="hidden text-xs text-muted-foreground sm:inline">{region}</span>
    </div>
  );
}
