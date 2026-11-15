import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ChevronDown, MonitorSmartphone } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { ErrorState, LoadingState } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { checkRemoteDesktop, remoteDesktopUrl } from "@/lib/api";
import {
  ClientState,
  loadGuacamole,
  remoteDesktopTunnel,
  statusMessage,
  type GuacClient,
} from "@/lib/guacamole";

/*
 * Fleet Manager → Connect with Remote Desktop: an RDP session to a Windows Server instance in the browser.
 * Sign in with a Windows account on the instance (User credentials); the connection lasts 60 minutes
 * (Renew session resets it) and ends after 10 minutes without input. Actions: Ctrl+Alt+Del, the display
 * resolution (Adapt Automatically follows the window), Renew session, Disconnect.
 */

const RESOLUTIONS = [
  { value: "auto", label: "Adapt Automatically" },
  { value: "1920x1080", label: "1920 x 1080" },
  { value: "1400x900", label: "1400 x 900" },
  { value: "1366x768", label: "1366 x 768" },
  { value: "800x600", label: "800 x 600" },
] as const;

// X11 keysyms: Control_L, Alt_L, Delete.
const CTRL_ALT_DEL = [0xffe3, 0xffe9, 0xffff];

type Phase = "signin" | "connecting" | "connected" | "ended";

function remaining(until: Date | null, now: number): string {
  if (!until) return "";
  const s = Math.max(0, Math.round((until.getTime() - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function RemoteDesktopPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const check = useQuery({
    queryKey: ["remote-desktop-check", namespace, name],
    queryFn: () => checkRemoteDesktop(namespace, name),
    retry: false,
  });

  const [phase, setPhase] = useState<Phase>("signin");
  const [username, setUsername] = useState("Administrator");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [expires, setExpires] = useState<Date | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [resolution, setResolution] = useState<string>("auto");

  const page = useRef<HTMLDivElement>(null);
  const frame = useRef<HTMLDivElement>(null);
  const holder = useRef<HTMLDivElement>(null);
  const client = useRef<GuacClient | null>(null);
  const renew = useRef<(() => void) | null>(null);
  const resolutionRef = useRef(resolution);
  resolutionRef.current = resolution;

  useEffect(() => {
    if (phase !== "connected") return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [phase]);

  // Fit the remote display into the frame: Adapt Automatically asks the instance for the frame's size;
  // a fixed resolution is scaled down to fit.
  const fit = useCallback(() => {
    const c = client.current;
    const f = frame.current;
    if (!c || !f) return;
    const d = c.getDisplay();
    const w = f.clientWidth;
    const h = f.clientHeight;
    if (resolutionRef.current === "auto") {
      if (w > 0 && h > 0 && (Math.abs(d.getWidth() - w) > 2 || Math.abs(d.getHeight() - h) > 2)) c.sendSize(w, h);
    }
    const dw = d.getWidth() || 1;
    const dh = d.getHeight() || 1;
    d.scale(Math.min(w / dw, h / dh, 1));
  }, []);

  const setRes = (value: string) => {
    setResolution(value);
    resolutionRef.current = value;
    const c = client.current;
    if (!c) return;
    if (value !== "auto") {
      const [w = 1366, h = 768] = value.split("x").map(Number);
      c.sendSize(w, h);
    }
    fit();
  };

  const disconnect = useCallback(() => {
    client.current?.disconnect();
  }, []);

  useEffect(() => () => client.current?.disconnect(), []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPhase("connecting");
    let G;
    try {
      G = await loadGuacamole();
    } catch (err) {
      setError((err as Error).message);
      setPhase("signin");
      return;
    }
    // The session starts at the size the page leaves it (Adapt Automatically then follows the frame).
    const p = page.current;
    const width = Math.max(640, (p?.clientWidth ?? 1368) - 2);
    const height = Math.max(480, (p?.clientHeight ?? 840) - 72);
    const tunnel = remoteDesktopTunnel(
      G,
      remoteDesktopUrl(namespace, name),
      {
        username: username.trim(),
        password,
        width,
        height,
        dpi: Math.round(96 * (window.devicePixelRatio || 1)),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
      (at) => setExpires(at),
    );
    setPassword("");
    renew.current = () => tunnel.renew();
    const c = new G.Client(tunnel);
    client.current = c;
    const display = c.getDisplay();
    const el = display.getElement();
    holder.current?.replaceChildren(el);
    display.onresize = () => fit();

    let failed = false;
    c.onerror = (status) => {
      failed = true;
      setError(statusMessage(status));
    };
    c.onstatechange = (state) => {
      if (state === ClientState.CONNECTED) {
        setPhase("connected");
        holder.current?.focus();
        fit();
      }
      if (state === ClientState.DISCONNECTED) {
        client.current = null;
        renew.current = null;
        keyboard.onkeydown = null;
        keyboard.onkeyup = null;
        setExpires(null);
        setPhase(failed ? "signin" : "ended");
      }
    };

    // Input: the mouse over the display, the keyboard while the session has focus.
    const mouse = new G.Mouse(el);
    mouse.onEach(["mousedown", "mousemove", "mouseup"], (ev) => c.sendMouseState(ev.state, true));
    const keyboard = new G.Keyboard(holder.current ?? document);
    keyboard.onkeydown = (keysym) => {
      c.sendKeyEvent(1, keysym);
      return false;
    };
    keyboard.onkeyup = (keysym) => c.sendKeyEvent(0, keysym);

    // Text copied in the session reaches this computer's clipboard; text copied here is sent to the
    // session when the pointer comes back over it.
    let lastClip = "";
    c.onclipboard = (stream, mimetype) => {
      if (!mimetype.startsWith("text/")) return;
      const reader = new G.StringReader(stream);
      let text = "";
      reader.ontext = (t) => (text += t);
      reader.onend = () => {
        lastClip = text;
        void navigator.clipboard?.writeText(text).catch(() => undefined);
      };
    };
    const pushClipboard = () => {
      void navigator.clipboard
        ?.readText()
        .then((text) => {
          if (!text || text === lastClip || !client.current) return;
          lastClip = text;
          const w = new G.StringWriter(c.createClipboardStream("text/plain"));
          w.sendText(text);
          w.sendEnd();
        })
        .catch(() => undefined);
    };
    el.addEventListener("mouseenter", pushClipboard);

    try {
      c.connect();
    } catch (err) {
      setError(statusMessage(err as { code: number; message?: string }));
      setPhase("signin");
    }
  }

  useEffect(() => {
    if (phase !== "connected" || !frame.current) return;
    const ro = new ResizeObserver(() => fit());
    ro.observe(frame.current);
    return () => ro.disconnect();
  }, [phase, fit]);

  const instanceId = check.data?.instanceId;
  const left = remaining(expires, now);
  const nearEnd = expires ? expires.getTime() - now < 5 * 60 * 1000 : false;

  return (
    <div ref={page} className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      <PageHeader
        icon={<MonitorSmartphone />}
        title="Remote Desktop"
        description={`Fleet Manager — ${instanceId ?? "…"} (${name})`}
        actions={
          phase === "connected" ? (
            <>
              <span className={`text-sm tabular-nums ${nearEnd ? "text-amber-600" : "text-muted-foreground"}`}>
                Session ends in {left}
              </span>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    Actions <ChevronDown className="size-3.5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem
                    onSelect={() => {
                      const c = client.current;
                      if (!c) return;
                      CTRL_ALT_DEL.forEach((k) => c.sendKeyEvent(1, k));
                      [...CTRL_ALT_DEL].reverse().forEach((k) => c.sendKeyEvent(0, k));
                    }}
                  >
                    Ctrl+Alt+Del
                  </DropdownMenuItem>
                  <DropdownMenuSub>
                    <DropdownMenuSubTrigger>Resolutions</DropdownMenuSubTrigger>
                    <DropdownMenuSubContent>
                      <DropdownMenuRadioGroup value={resolution} onValueChange={setRes}>
                        {RESOLUTIONS.map((r) => (
                          <DropdownMenuRadioItem key={r.value} value={r.value}>
                            {r.label}
                          </DropdownMenuRadioItem>
                        ))}
                      </DropdownMenuRadioGroup>
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                  <DropdownMenuItem onSelect={() => renew.current?.()}>Renew session</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem className="text-destructive" onSelect={disconnect}>
                    Disconnect
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          ) : (
            <Button variant="outline" size="sm" asChild>
              <Link to="/fleet-manager">Fleet Manager</Link>
            </Button>
          )
        }
      />

      {phase === "connected" && nearEnd ? (
        <div className="flex items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
          <AlertTriangle className="size-4 shrink-0 text-amber-600" />
          This session ends in {left}. Choose Actions → Renew session to keep it.
        </div>
      ) : null}

      {phase === "signin" || phase === "ended" ? (
        check.isLoading ? (
          <LoadingState label="Checking the instance…" />
        ) : check.isError ? (
          <ErrorState error={check.error} onRetry={() => check.refetch()} />
        ) : (
          <Card className="max-w-lg">
            <CardContent className="space-y-4 p-6">
              <div className="space-y-1">
                <h2 className="font-semibold">Connect with Remote Desktop</h2>
                <p className="text-sm text-muted-foreground">
                  The connection lasts {check.data?.maxDurationMinutes ?? 60} minutes (Renew session resets it) and ends
                  after {check.data?.idleTimeoutMinutes ?? 10} minutes without input.
                </p>
              </div>
              {phase === "ended" && !error ? (
                <p className="rounded-md border bg-muted/40 p-3 text-sm">The Remote Desktop session ended.</p>
              ) : null}
              {error ? (
                <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">{error}</p>
              ) : null}
              <form className="space-y-3" onSubmit={connect}>
                <div className="space-y-1">
                  <Label>Authentication type</Label>
                  <p className="text-sm">User credentials</p>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="rdp-user">User name</Label>
                  <Input
                    id="rdp-user"
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="rdp-pass">Password</Label>
                  <Input
                    id="rdp-pass"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
                <Button type="submit" disabled={!username.trim() || !password}>
                  Connect
                </Button>
              </form>
            </CardContent>
          </Card>
        )
      ) : null}

      {phase === "connecting" ? <LoadingState label="Connecting…" /> : null}

      <div
        ref={frame}
        className={`relative min-h-0 flex-1 overflow-hidden rounded-md border bg-black ${phase === "connected" ? "" : "hidden"}`}
      >
        <div
          ref={holder}
          tabIndex={0}
          className="absolute inset-0 flex items-center justify-center outline-none"
          onClick={() => holder.current?.focus()}
        />
      </div>
    </div>
  );
}
