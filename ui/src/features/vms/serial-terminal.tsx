import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { serialConsoleUrl } from "@/lib/api";

/**
 * The EC2 serial console in the browser: a terminal on the instance's serial port (ttyS0), over the
 * console's websocket, which holds the instance's one serial console session while it is open. What you
 * type goes to the guest as it is typed; press Enter to see its login prompt.
 */
export function SerialTerminal({ namespace, name }: { namespace: string; name: string }) {
  const host = useRef<HTMLDivElement>(null);
  const [ended, setEnded] = useState(false);

  useEffect(() => {
    if (!host.current) return;
    const term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 13,
      scrollback: 5000,
      theme: { background: "#0b0f14" },
    });
    term.open(host.current);
    term.focus();
    const ws = new WebSocket(serialConsoleUrl(namespace, name));
    ws.binaryType = "arraybuffer";
    const enc = new TextEncoder();
    ws.onopen = () => term.write("\x1b[90mConnected to the serial console. Press Enter for the login prompt.\x1b[0m\r\n");
    ws.onmessage = (ev) => {
      term.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data as ArrayBuffer));
    };
    ws.onclose = () => {
      term.write("\r\n\x1b[90mThe serial console session ended.\x1b[0m\r\n");
      setEnded(true);
    };
    const input = term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d));
    });
    return () => {
      input.dispose();
      ws.close();
      term.dispose();
    };
  }, [namespace, name]);

  return (
    <div className="space-y-2">
      <div ref={host} className="h-[60vh] w-full overflow-hidden rounded-md border bg-[#0b0f14] p-2" />
      {ended ? (
        <p className="text-xs text-muted-foreground">
          The session has ended. Close this window and connect again to open a new one.
        </p>
      ) : null}
    </div>
  );
}
