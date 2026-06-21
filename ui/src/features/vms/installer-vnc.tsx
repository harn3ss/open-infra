import { useEffect, useRef, useState } from "react";
import RFB from "@novnc/novnc";
import { kubevirtPaths } from "@/lib/k8s-paths";

/**
 * Live (view-only) VNC of an installer VM, so VM Images can show a Windows build
 * as it installs. Connects noVNC to the KubeVirt VMI /vnc websocket via the BFF's
 * same-origin /api/k8s proxy (which injects the SA token). KubeVirt streams raw
 * RFB under the `plain.kubevirt.io` subprotocol.
 */
export function InstallerVnc({
  namespace,
  name,
}: {
  namespace: string;
  name: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "error">(
    "connecting",
  );

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/api/k8s${kubevirtPaths.vnc(
      namespace,
      name,
    )}`;
    let rfb: RFB | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let cancelled = false;

    // noVNC has no built-in reconnect, and an idle install screen gets its
    // websocket dropped (Traefik idle timeout). Reconnect with capped backoff so
    // the live view keeps streaming without a manual page refresh.
    const connect = () => {
      if (cancelled) return;
      setStatus("connecting");
      try {
        rfb = new RFB(el, url, { wsProtocols: ["plain.kubevirt.io"] });
        rfb.viewOnly = true; // watch-only; the install is unattended
        rfb.scaleViewport = true;
        rfb.background = "#000";
        rfb.addEventListener("connect", () => {
          attempt = 0;
          setStatus("connected");
        });
        rfb.addEventListener("disconnect", () => {
          rfb = null;
          if (cancelled) return;
          setStatus("connecting");
          const delay = Math.min(1000 * 2 ** attempt, 10000);
          attempt += 1;
          retry = setTimeout(connect, delay);
        });
      } catch {
        setStatus("error");
      }
    };
    connect();

    return () => {
      cancelled = true;
      if (retry) clearTimeout(retry);
      try {
        rfb?.disconnect();
      } catch {
        /* already gone */
      }
    };
  }, [namespace, name]);

  return (
    <div className="space-y-1">
      <div
        ref={ref}
        className="aspect-video w-full overflow-hidden rounded-md border border-border bg-black"
      />
      {status !== "connected" ? (
        <p className="text-xs text-muted-foreground">
          {status === "connecting"
            ? "Connecting to the install screen…"
            : "Console not available yet — the installer VM may still be starting."}
        </p>
      ) : null}
    </div>
  );
}
