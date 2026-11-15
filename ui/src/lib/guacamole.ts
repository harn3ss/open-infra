/*
 * Apache Guacamole's JavaScript client (guacamole-common-js 1.6.0), which draws a Fleet Manager Remote
 * Desktop session and sends its input. It is the Apache release's own code, unmodified, served from
 * /vendor (public/vendor/guacamole-common-1.6.0.js, whose header says where it came from) and loaded
 * as a classic script the first time a Remote Desktop session opens, so the console's other pages
 * never carry it.
 *
 * The types below are the part of its API the console uses.
 */

const SCRIPT = "/vendor/guacamole-common-1.6.0.js";

export interface GuacStatus {
  code: number;
  message?: string;
}

export interface GuacDisplay {
  getElement(): HTMLElement;
  getWidth(): number;
  getHeight(): number;
  scale(s: number): void;
  showCursor(shown: boolean): void;
  onresize: ((width: number, height: number) => void) | null;
}

export interface GuacInputStream {
  onblob: ((data: string) => void) | null;
  onend: (() => void) | null;
}

export interface GuacOutputStream {
  index: number;
}

export interface GuacClient {
  connect(data?: string): void;
  disconnect(): void;
  getDisplay(): GuacDisplay;
  sendSize(width: number, height: number): void;
  sendKeyEvent(pressed: 0 | 1 | boolean, keysym: number): void;
  sendMouseState(state: unknown, applyDisplayScale?: boolean): void;
  createClipboardStream(mimetype: string): GuacOutputStream;
  onstatechange: ((state: number) => void) | null;
  onerror: ((status: GuacStatus) => void) | null;
  onclipboard: ((stream: GuacInputStream, mimetype: string) => void) | null;
}

export interface GuacTunnel {
  state: number;
  uuid: string | null;
  receiveTimeout: number;
  unstableThreshold: number;
  connect(data?: string): void;
  disconnect(): void;
  sendMessage(...elements: unknown[]): void;
  setState(state: number): void;
  setUUID(uuid: string): void;
  isConnected(): boolean;
  oninstruction: ((opcode: string, args: string[]) => void) | null;
  onerror: ((status: GuacStatus) => void) | null;
  onstatechange: ((state: number) => void) | null;
}

export interface GuacMouseEvent {
  state: unknown;
}

export interface GuacamoleNS {
  Client: new (tunnel: GuacTunnel) => GuacClient;
  Tunnel: { new (): GuacTunnel; State: Record<"CONNECTING" | "OPEN" | "CLOSED" | "UNSTABLE", number>; INTERNAL_DATA_OPCODE: string };
  Parser: { new (): { receive(packet: string): void; oninstruction: ((opcode: string, args: string[]) => void) | null }; toInstruction(elements: ArrayLike<unknown>): string };
  Status: {
    new (code: number, message?: string): GuacStatus;
    Code: { SUCCESS: number; SERVER_ERROR: number; UPSTREAM_TIMEOUT: number; UPSTREAM_NOT_FOUND: number; fromWebSocketCode(code: number): number };
  };
  Mouse: new (element: HTMLElement) => { onEach(types: string[], listener: (e: GuacMouseEvent) => void): void };
  Keyboard: new (element: HTMLElement | Document) => {
    onkeydown: ((keysym: number) => boolean | void) | null;
    onkeyup: ((keysym: number) => void) | null;
    reset(): void;
  };
  StringWriter: new (stream: GuacOutputStream) => { sendText(text: string): void; sendEnd(): void };
  StringReader: new (stream: GuacInputStream) => { ontext: ((text: string) => void) | null; onend: (() => void) | null };
}

/** Guacamole.Client's states. */
export const ClientState = { IDLE: 0, CONNECTING: 1, WAITING: 2, CONNECTED: 3, DISCONNECTING: 4, DISCONNECTED: 5 } as const;

let loading: Promise<GuacamoleNS> | null = null;

/** Guacamole's client library, loaded once. */
export function loadGuacamole(): Promise<GuacamoleNS> {
  const w = window as unknown as { Guacamole?: GuacamoleNS };
  if (w.Guacamole) return Promise.resolve(w.Guacamole);
  if (!loading) {
    loading = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = SCRIPT;
      s.async = true;
      s.onload = () => (w.Guacamole ? resolve(w.Guacamole) : reject(new Error("The Remote Desktop client did not load.")));
      s.onerror = () => {
        loading = null;
        reject(new Error("The Remote Desktop client could not be loaded."));
      };
      document.head.appendChild(s);
    });
  }
  return loading;
}

/** What the console's Remote Desktop connection starts with: the Windows account and the display. */
export interface RemoteDesktopStart {
  username: string;
  password: string;
  domain?: string;
  width: number;
  height: number;
  dpi: number;
  timezone?: string;
}

/**
 * The console's Remote Desktop tunnel: Guacamole's WebSocket tunnel, except that the connection's
 * Windows credentials go in its first message (never the URL), and the console's own messages — when
 * the connection ends, renewed — reach onExpires. Renew session is renew().
 */
export function remoteDesktopTunnel(
  G: GuacamoleNS,
  url: string,
  start: RemoteDesktopStart,
  onExpires: (at: Date) => void,
): GuacTunnel & { renew(): void } {
  const tunnel = new G.Tunnel() as GuacTunnel & { renew(): void };
  const State = G.Tunnel.State;
  const INTERNAL = G.Tunnel.INTERNAL_DATA_OPCODE;
  let socket: WebSocket | null = null;
  let receiveTimer: number | undefined;
  let unstableTimer: number | undefined;
  let pingTimer: number | undefined;
  let lastPing = 0;
  const PING_FREQUENCY = 500;

  const close = (status: GuacStatus) => {
    window.clearTimeout(receiveTimer);
    window.clearTimeout(unstableTimer);
    window.clearTimeout(pingTimer);
    if (tunnel.state === State.CLOSED) return;
    if (status.code !== G.Status.Code.SUCCESS && tunnel.onerror) tunnel.onerror(status);
    tunnel.setState(State.CLOSED);
    socket?.close();
  };

  const ping = () => {
    lastPing = Date.now();
    tunnel.sendMessage(INTERNAL, "ping", lastPing);
  };

  const resetTimers = () => {
    window.clearTimeout(receiveTimer);
    window.clearTimeout(unstableTimer);
    window.clearTimeout(pingTimer);
    if (tunnel.state === State.UNSTABLE) tunnel.setState(State.OPEN);
    receiveTimer = window.setTimeout(
      () => close(new G.Status(G.Status.Code.UPSTREAM_TIMEOUT, "The connection stopped answering.")),
      tunnel.receiveTimeout,
    );
    unstableTimer = window.setTimeout(() => tunnel.setState(State.UNSTABLE), tunnel.unstableThreshold);
    const delay = Math.max(lastPing + PING_FREQUENCY - Date.now(), 0);
    if (delay > 0) pingTimer = window.setTimeout(ping, delay);
    else ping();
  };

  tunnel.sendMessage = (...elements: unknown[]) => {
    if (!tunnel.isConnected() || !elements.length || !socket) return;
    socket.send(G.Parser.toInstruction(elements));
  };

  tunnel.renew = () => tunnel.sendMessage(INTERNAL, "renew");

  tunnel.connect = () => {
    tunnel.setState(State.CONNECTING);
    const parser = new G.Parser();
    parser.oninstruction = (opcode, args) => {
      if (tunnel.uuid === null) {
        if (opcode === INTERNAL && args.length === 1 && args[0]) tunnel.setUUID(args[0]);
        tunnel.setState(State.OPEN);
      }
      if (opcode === INTERNAL) {
        if (args[0] === "expires" && args[1]) onExpires(new Date(Number(args[1])));
        return;
      }
      tunnel.oninstruction?.(opcode, args);
    };
    socket = new WebSocket(url, "guacamole");
    socket.onopen = () => {
      socket?.send(JSON.stringify(start));
      start.password = "";
      resetTimers();
    };
    socket.onclose = (e) => {
      if (e.reason) close(new G.Status(parseInt(e.reason, 10) || G.Status.Code.SERVER_ERROR, e.reason));
      else if (e.code) close(new G.Status(G.Status.Code.fromWebSocketCode(e.code)));
      else close(new G.Status(G.Status.Code.UPSTREAM_NOT_FOUND));
    };
    socket.onmessage = (e) => {
      resetTimers();
      try {
        parser.receive(String(e.data));
      } catch (err) {
        close(new G.Status(G.Status.Code.SERVER_ERROR, (err as Error).message));
      }
    };
  };

  tunnel.disconnect = () => close(new G.Status(G.Status.Code.SUCCESS, "Disconnected."));
  return tunnel;
}

/** What a Guacamole status code means to the person connecting. */
export function statusMessage(status: GuacStatus): string {
  switch (status.code) {
    case 0x0301: // guacd: the instance refused the sign-in
      return "The user name or password is incorrect, or this user isn't allowed to sign in with Remote Desktop.";
    case 0x0207:
    case 0x0208:
      return status.message || "The instance's Remote Desktop service couldn't be reached.";
    case 0x0202:
      return "The connection stopped answering.";
    default:
      return status.message && !/^\d+$/.test(status.message) ? status.message : `The connection ended (status ${status.code}).`;
  }
}
