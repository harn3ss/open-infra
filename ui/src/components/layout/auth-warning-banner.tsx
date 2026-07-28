import { ShieldAlert } from "lucide-react";
import { useConfig } from "@/lib/config-context";

/**
 * A persistent, non-dismissable banner shown across the whole console when the BFF
 * reports AUTH_MODE=none — i.e. the console API is UNAUTHENTICATED and anyone who can
 * reach it has full admin over the cluster. The startup log warns whoever runs the
 * server; this warns whoever is actually *using* the UI. It deliberately cannot be
 * dismissed: the risk lasts the whole session, so the warning should too.
 */
export function AuthWarningBanner() {
  const { authMode } = useConfig();
  if (authMode !== "none") return null;
  return (
    <div
      role="alert"
      className="flex items-center justify-center gap-2 bg-destructive px-4 py-1.5 text-center text-sm font-medium text-destructive-foreground"
    >
      <ShieldAlert className="size-4 shrink-0" aria-hidden />
      <span>
        Authentication is <strong>disabled</strong> (<code>AUTH_MODE=none</code>). Anyone who
        can reach this console has full admin over the cluster — do not expose it to untrusted
        networks.
      </span>
    </div>
  );
}
