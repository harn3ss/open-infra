import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Info,
  Loader2,
  X,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** Flash severity — mirrors Cloudscape `Flashbar` item types. */
export type FlashType = "success" | "error" | "warning" | "info" | "in-progress";

/** An optional inline action button rendered inside a flash. */
export interface FlashAction {
  label: string;
  onClick: () => void;
}

/** A single notification in the Flashbar stack. */
export interface Flash {
  id: string;
  type: FlashType;
  /** Bold leading line (optional). */
  header?: ReactNode;
  /** The message body. */
  content: ReactNode;
  /** Show the dismiss (✕) affordance. Default true (except `in-progress`). */
  dismissible?: boolean;
  /** Optional inline action button. */
  action?: FlashAction;
  /** Auto-dismiss after N ms. Omit to keep until dismissed. */
  autoDismiss?: number;
}

/** Fields the caller supplies to {@link FlashContextValue.push} (id is generated). */
export type FlashInput = Omit<Flash, "id"> & { id?: string };

export interface FlashContextValue {
  flashes: Flash[];
  /** Push a flash; returns its id (pass the same id again to replace it). */
  push: (flash: FlashInput) => string;
  dismiss: (id: string) => void;
  clear: () => void;
  /** Convenience: push a success flash. */
  success: (content: ReactNode, opts?: Partial<FlashInput>) => string;
  /** Convenience: push an error flash. */
  error: (content: ReactNode, opts?: Partial<FlashInput>) => string;
  /** Convenience: push a warning flash. */
  warning: (content: ReactNode, opts?: Partial<FlashInput>) => string;
  /** Convenience: push an info flash. */
  info: (content: ReactNode, opts?: Partial<FlashInput>) => string;
  /** Convenience: push an in-progress flash (not auto/dismissible by default). */
  inProgress: (content: ReactNode, opts?: Partial<FlashInput>) => string;
}

const FlashContext = createContext<FlashContextValue | null>(null);

let seq = 0;
function nextId(): string {
  seq += 1;
  return `flash-${Date.now()}-${seq}`;
}

/**
 * App-level provider for the notifications region (Cloudscape `Flashbar`). Mirrors
 * `HelpProvider`: wrap the tree once, render {@link Flashbar} where the pinned
 * region should live, and call {@link useFlash} anywhere to push operation
 * outcomes ("VPC prod-vpc created", "Failed to delete subnet").
 */
export function FlashProvider({ children }: { children: ReactNode }) {
  const [flashes, setFlashes] = useState<Flash[]>([]);
  const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setFlashes((f) => f.filter((x) => x.id !== id));
    const t = timers.current.get(id);
    if (t) {
      clearTimeout(t);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback(
    (flash: FlashInput) => {
      const id = flash.id ?? nextId();
      const entry: Flash = { ...flash, id };
      setFlashes((f) => [entry, ...f.filter((x) => x.id !== id)]);
      if (flash.autoDismiss && flash.autoDismiss > 0) {
        const t = setTimeout(() => dismiss(id), flash.autoDismiss);
        timers.current.set(id, t);
      }
      return id;
    },
    [dismiss],
  );

  const clear = useCallback(() => {
    timers.current.forEach((t) => clearTimeout(t));
    timers.current.clear();
    setFlashes([]);
  }, []);

  const value = useMemo<FlashContextValue>(
    () => ({
      flashes,
      push,
      dismiss,
      clear,
      success: (content, opts) =>
        push({ type: "success", content, autoDismiss: 6000, ...opts }),
      error: (content, opts) => push({ type: "error", content, ...opts }),
      warning: (content, opts) => push({ type: "warning", content, ...opts }),
      info: (content, opts) => push({ type: "info", content, ...opts }),
      inProgress: (content, opts) =>
        push({ type: "in-progress", content, dismissible: false, ...opts }),
    }),
    [flashes, push, dismiss, clear],
  );

  return <FlashContext.Provider value={value}>{children}</FlashContext.Provider>;
}

export function useFlash(): FlashContextValue {
  const ctx = useContext(FlashContext);
  if (!ctx) throw new Error("useFlash must be used within a FlashProvider");
  return ctx;
}

const TYPE_META: Record<
  FlashType,
  { icon: typeof Info; wrap: string; iconClass: string; label: string }
> = {
  success: {
    icon: CheckCircle2,
    wrap: "border-success/40 bg-success/10",
    iconClass: "text-success",
    label: "Success",
  },
  error: {
    icon: XCircle,
    wrap: "border-destructive/40 bg-destructive/10",
    iconClass: "text-destructive",
    label: "Error",
  },
  warning: {
    icon: AlertTriangle,
    wrap: "border-warning/40 bg-warning/10",
    iconClass: "text-warning",
    label: "Warning",
  },
  info: {
    icon: Info,
    wrap: "border-border bg-secondary",
    iconClass: "text-primary",
    label: "Info",
  },
  "in-progress": {
    icon: Loader2,
    wrap: "border-border bg-secondary",
    iconClass: "text-muted-foreground",
    label: "In progress",
  },
};

/** One rendered flash — exported for controlled/standalone use outside the provider. */
export function FlashItem({
  flash,
  onDismiss,
}: {
  flash: Flash;
  onDismiss?: (id: string) => void;
}) {
  const meta = TYPE_META[flash.type];
  const Icon = meta.icon;
  const dismissible = flash.dismissible ?? flash.type !== "in-progress";
  return (
    <div
      role="status"
      aria-live={flash.type === "error" ? "assertive" : "polite"}
      className={cn(
        "pointer-events-auto flex items-start gap-3 rounded-lg border p-3 text-sm shadow-sm",
        meta.wrap,
      )}
    >
      <Icon
        className={cn(
          "mt-0.5 size-4 shrink-0",
          meta.iconClass,
          flash.type === "in-progress" && "animate-spin",
        )}
        aria-hidden
      />
      <div className="min-w-0 flex-1 space-y-0.5">
        {flash.header ? (
          <div className="font-medium text-foreground">{flash.header}</div>
        ) : null}
        <div className="min-w-0 break-words text-foreground/90">
          <span className="sr-only">{meta.label}: </span>
          {flash.content}
        </div>
        {flash.action ? (
          <div className="pt-1">
            <Button variant="outline" size="sm" onClick={flash.action.onClick}>
              {flash.action.label}
            </Button>
          </div>
        ) : null}
      </div>
      {dismissible && onDismiss ? (
        <button
          type="button"
          onClick={() => onDismiss(flash.id)}
          aria-label="Dismiss notification"
          className="rounded-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <X className="size-4" />
        </button>
      ) : null}
    </div>
  );
}

/**
 * The pinned notifications region. Reads the {@link FlashProvider} context and
 * stacks flashes; collapses to a "show N more" toggle past `collapseAfter`.
 * Mount once (e.g. in `app.tsx` beside `HelpPanel`); position it via `className`.
 */
export function Flashbar({
  className,
  collapseAfter = 3,
}: {
  className?: string;
  /** Show at most this many, then a "N more" expander. Default 3. */
  collapseAfter?: number;
}) {
  const { flashes, dismiss } = useFlash();
  const [expanded, setExpanded] = useState(false);
  if (flashes.length === 0) return null;

  const collapsed = !expanded && flashes.length > collapseAfter;
  const shown = collapsed ? flashes.slice(0, collapseAfter) : flashes;
  const hidden = flashes.length - shown.length;

  return (
    <div className={cn("pointer-events-none space-y-2", className)}>
      {shown.map((flash) => (
        <FlashItem key={flash.id} flash={flash} onDismiss={dismiss} />
      ))}
      {collapsed ? (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="pointer-events-auto text-xs font-medium text-primary hover:underline"
        >
          Show {hidden} more notification{hidden === 1 ? "" : "s"}
        </button>
      ) : null}
    </div>
  );
}
