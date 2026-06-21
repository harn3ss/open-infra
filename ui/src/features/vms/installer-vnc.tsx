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
    setStatus("connecting");
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/api/k8s${kubevirtPaths.vnc(
      namespace,
      name,
    )}`;
    let rfb: RFB | null = null;
    try {
      rfb = new RFB(el, url, { wsProtocols: ["plain.kubevirt.io"] });
      rfb.viewOnly = true; // watch-only; the install is unattended
      rfb.scaleViewport = true;
      rfb.background = "#000";
      rfb.addEventListener("connect", () => setStatus("connected"));
      rfb.addEventListener("disconnect", () => setStatus("error"));
    } catch {
      setStatus("error");
    }
    return () => {
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
