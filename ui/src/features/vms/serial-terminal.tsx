import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { CopyButton } from "@/components/common/copy-button";
import { serialConsoleUrl } from "@/lib/api";

/**
 * The EC2 serial console in the browser: a terminal on the instance's serial port (ttyS0), over the
 * console's websocket, which holds the instance's one serial console session while it is open. What you
 * type goes to the guest as it is typed; press Enter to see its login prompt.
 *
 * The terminal fills its window and follows it as it is resized. A serial line carries no window size, so
 * the guest still assumes its own (80×24 by default) until told: full-screen programs such as htop or vi
 * need `stty rows R cols C` in the guest, which is shown, with the window's size, below the terminal.
 */
export function SerialTerminal({ namespace, name }: { namespace: string; name: string }) {
  const host = useRef<HTMLDivElement>(null);
  const [ended, setEnded] = useState(false);
  const [size, setSize] = useState<{ cols: number; rows: number } | null>(null);

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
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current);
    const refit = () => {
      try {
        fit.fit();
      } catch {
        // not laid out yet
      }
    };
    refit();
    setSize({ cols: term.cols, rows: term.rows });
    const resized = term.onResize(({ cols, rows }) => setSize({ cols, rows }));
    const observer = new ResizeObserver(() => refit());
    observer.observe(host.current);
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
      observer.disconnect();
      resized.dispose();
      input.dispose();
      ws.close();
      term.dispose();
    };
  }, [namespace, name]);

  const stty = size ? `stty rows ${size.rows} cols ${size.cols}` : "";
  return (
    <div className="space-y-2">
      <div ref={host} className="h-[65vh] w-full overflow-hidden rounded-md border bg-[#0b0f14] p-2" />
      {ended ? (
        <p className="text-xs text-muted-foreground">
          The session has ended. Close this window and connect again to open a new one.
        </p>
      ) : stty ? (
        <p className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
          A serial line doesn't carry the window size. For full-screen programs, run
          <code className="rounded bg-muted px-1 text-foreground">{stty}</code>
          <CopyButton value={stty} />
          in the guest after you sign in.
        </p>
      ) : null}
    </div>
  );
}
