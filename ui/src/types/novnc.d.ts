// Minimal type shim for noVNC's RFB client (the package ships no .d.ts).
// Used by the VM Images live build console to watch installer VMs.
declare module "@novnc/novnc" {
  export interface RFBOptions {
    shared?: boolean;
    credentials?: { username?: string; password?: string; target?: string };
    repeaterID?: string;
    wsProtocols?: string[];
  }
  export default class RFB extends EventTarget {
    constructor(
      target: HTMLElement,
      url: string | WebSocket,
      options?: RFBOptions,
    );
    viewOnly: boolean;
    scaleViewport: boolean;
    resizeSession: boolean;
    background: string;
    qualityLevel: number;
    compressionLevel: number;
    disconnect(): void;
    focus(): void;
    blur(): void;
  }
}
