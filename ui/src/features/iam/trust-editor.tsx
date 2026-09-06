import { useState } from "react";
import {
  AlertTriangle,
  Braces,
  Globe,
  List,
  Plus,
  Server,
  UserRound,
  X,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/common/copy-button";
import { cn } from "@/lib/utils";

/**
 * The kinds of principal a `Role.spec.trust[]` entry can name, in the exact forms the
 * aws-shim STS AssumeRole / AssumeRoleWithWebIdentity path enforces
 * (`console-api/cmd/aws-shim/roleresolver.go`):
 *  - `wildcard`       — `"*"`, any authenticated principal.
 *  - `user`           — a bare `kind: User` name (e.g. `"alice"`), assumed via AssumeRole.
 *  - `serviceaccount` — `"system:serviceaccount:<ns>:<name>"`, a workload identity (the IRSA
 *                       analog) assumed via AssumeRoleWithWebIdentity with a projected SA token.
 *  - `custom`         — anything else (e.g. a future `OIDC::<provider>` federation value).
 */
export type PrincipalKind = "user" | "serviceaccount" | "wildcard" | "custom";

const SA_PREFIX = "system:serviceaccount:";
const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Classify a stored `spec.trust[]` entry by the form the shim recognizes. */
export function classifyPrincipal(p: string): PrincipalKind {
  if (p === "*") return "wildcard";
  if (p.startsWith(SA_PREFIX)) return "serviceaccount";
  if (RFC1123.test(p)) return "user";
  return "custom";
}

/** A human label for a trust principal (chips, tables, review). */
export function principalLabel(p: string): string {
  switch (classifyPrincipal(p)) {
    case "wildcard":
      return "Any authenticated principal";
    case "serviceaccount": {
      const [ns, name] = p.slice(SA_PREFIX.length).split(":");
      return name ? `ServiceAccount ${ns}/${name}` : p;
    }
    case "user":
      return `User ${p}`;
    default:
      return p;
  }
}

const KIND_ICON: Record<PrincipalKind, typeof UserRound> = {
  user: UserRound,
  serviceaccount: Server,
  wildcard: Globe,
  custom: Braces,
};

/**
 * Render the trust set as an AWS-shaped trust-policy document — a familiar view for a
 * migrating admin. This is a *rendering only*; the source of truth is `Role.spec.trust[]`.
 * A `"*"` entry subsumes named principals for the purposes of assumption, so it renders as
 * `Principal: { AWS: "*" }`.
 */
export function awsTrustDocument(trust: string[]): string {
  const named = trust.filter((t) => t !== "*");
  const principal = trust.includes("*") ? { AWS: "*" } : { OpenInfra: named };
  return JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: principal,
          Action: ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity"],
        },
      ],
    },
    null,
    2,
  );
}

interface EntityCard {
  kind: PrincipalKind;
  label: string;
  hint: string;
}

const CARDS: EntityCard[] = [
  { kind: "user", label: "User", hint: "A kind: User assumes the role (sts:AssumeRole)." },
  {
    kind: "serviceaccount",
    label: "Workload (service account)",
    hint: "A pod's ServiceAccount assumes it (web identity) — the IRSA analog.",
  },
  {
    kind: "wildcard",
    label: "Any authenticated",
    hint: "Any authenticated principal may assume the role. Broad — use with care.",
  },
  { kind: "custom", label: "Custom principal", hint: "Author a principal value directly." },
];

/**
 * The trust-relationship editor: the friendly surface over `Role.spec.trust[]` — who may
 * `sts:AssumeRole` this role. Mirrors AWS's "Trust relationships → Edit trust policy" with a
 * **Visual** mode (trusted-entity-type cards + principal chips) and a **JSON** mode (an
 * AWS-shaped document view for muscle memory, plus the source-of-truth `spec.trust[]` array,
 * editable). Fully controlled. A role with an empty trust set is assumable by no one
 * (fail closed) — surfaced as a warning, exactly as AWS requires a trust policy.
 */
export function TrustEditor({
  value,
  onChange,
  users = [],
  className,
}: {
  /** Current trust principals (source of truth = `Role.spec.trust[]`). */
  value: string[];
  onChange: (trust: string[]) => void;
  /** Existing kind: User names, offered as suggestions for the User card. */
  users?: string[];
  className?: string;
}) {
  const [view, setView] = useState<"visual" | "json">("visual");
  const [mode, setMode] = useState<PrincipalKind>("user");
  const [userVal, setUserVal] = useState("");
  const [saNs, setSaNs] = useState("");
  const [saName, setSaName] = useState("");
  const [customVal, setCustomVal] = useState("");
  const [jsonText, setJsonText] = useState("");
  const [jsonErr, setJsonErr] = useState<string | null>(null);

  const hasWildcard = value.includes("*");

  const add = (p: string) => {
    const v = p.trim();
    if (!v || value.includes(v)) return;
    onChange([...value, v]);
  };
  const remove = (p: string) => onChange(value.filter((x) => x !== p));

  const openJson = () => {
    setJsonText(JSON.stringify(value, null, 2));
    setJsonErr(null);
    setView("json");
  };
  const applyJson = (text: string) => {
    setJsonText(text);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setJsonErr("Not valid JSON.");
      return;
    }
    if (!Array.isArray(parsed) || parsed.some((x) => typeof x !== "string")) {
      setJsonErr("Trust must be a JSON array of principal strings (e.g. [\"alice\", \"*\"]).");
      return;
    }
    setJsonErr(null);
    onChange(Array.from(new Set(parsed as string[])).filter((s) => s.trim() !== ""));
  };

  return (
    <div className={cn("space-y-4", className)}>
      {/* Visual | JSON toggle */}
      <div className="inline-flex rounded-md border border-border p-0.5 text-xs">
        <button
          type="button"
          onClick={() => setView("visual")}
          className={cn(
            "flex items-center gap-1.5 rounded px-2.5 py-1 font-medium transition-colors",
            view === "visual" ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <List className="size-3.5" /> Visual
        </button>
        <button
          type="button"
          onClick={openJson}
          className={cn(
            "flex items-center gap-1.5 rounded px-2.5 py-1 font-medium transition-colors",
            view === "json" ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <Braces className="size-3.5" /> JSON
        </button>
      </div>

      {view === "visual" ? (
        <div className="space-y-4">
          {/* Current trusted principals */}
          <div className="space-y-2">
            <Label>Trusted principals</Label>
            {value.length === 0 ? (
              <p className="flex items-start gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-600 dark:text-amber-400">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  No trusted principals — this role can be assumed by <b>no one</b> (fail closed). Add a
                  principal below so it can be assumed.
                </span>
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {value.map((p) => {
                  const Icon = KIND_ICON[classifyPrincipal(p)];
                  const risky = p === "*";
                  return (
                    <span
                      key={p}
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium",
                        risky
                          ? "border-amber-500/50 bg-amber-500/15 text-amber-600 dark:text-amber-400"
                          : "border-primary/40 bg-primary/10 text-primary",
                      )}
                    >
                      <Icon className="size-3.5" />
                      {principalLabel(p)}
                      <button
                        type="button"
                        onClick={() => remove(p)}
                        aria-label={`Remove ${principalLabel(p)}`}
                        className="text-current/70 hover:text-current"
                      >
                        <X className="size-3" />
                      </button>
                    </span>
                  );
                })}
              </div>
            )}
            {hasWildcard ? (
              <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  <code>*</code> lets <b>any authenticated principal</b> assume this role. Narrow it to
                  specific users or service accounts unless this is intentional.
                </span>
              </p>
            ) : null}
          </div>

          {/* Add a principal — trusted-entity-type cards */}
          <div className="space-y-3 rounded-md border border-border p-3">
            <Label>Add a trusted entity</Label>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {CARDS.map((c) => {
                const Icon = KIND_ICON[c.kind];
                const on = mode === c.kind;
                return (
                  <button
                    key={c.kind}
                    type="button"
                    onClick={() => setMode(c.kind)}
                    aria-pressed={on}
                    className={cn(
                      "flex items-start gap-2 rounded-md border p-2.5 text-left transition-colors",
                      on ? "border-primary bg-primary/5 ring-1 ring-primary/30" : "border-border hover:bg-muted/50",
                    )}
                  >
                    <Icon className={cn("mt-0.5 size-4 shrink-0", on ? "text-primary" : "text-muted-foreground")} />
                    <span className="min-w-0">
                      <span className="block text-sm font-medium">{c.label}</span>
                      <span className="block text-xs text-muted-foreground">{c.hint}</span>
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Type-specific value entry */}
            {mode === "user" ? (
              <div className="flex flex-wrap items-end gap-2">
                <div className="min-w-48 flex-1 space-y-1.5">
                  <Label htmlFor="trust-user" className="text-xs">
                    User name
                  </Label>
                  <Input
                    id="trust-user"
                    list="trust-user-options"
                    value={userVal}
                    onChange={(e) => setUserVal(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        add(userVal);
                        setUserVal("");
                      }
                    }}
                    placeholder="alice"
                    className="h-8"
                  />
                  <datalist id="trust-user-options">
                    {users.map((u) => (
                      <option key={u} value={u} />
                    ))}
                  </datalist>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!userVal.trim()}
                  onClick={() => {
                    add(userVal);
                    setUserVal("");
                  }}
                >
                  <Plus className="size-4" /> Add
                </Button>
              </div>
            ) : null}

            {mode === "serviceaccount" ? (
              <div className="flex flex-wrap items-end gap-2">
                <div className="w-40 space-y-1.5">
                  <Label htmlFor="trust-sa-ns" className="text-xs">
                    Namespace
                  </Label>
                  <Input
                    id="trust-sa-ns"
                    value={saNs}
                    onChange={(e) => setSaNs(e.target.value)}
                    placeholder="apps"
                    className="h-8"
                  />
                </div>
                <div className="w-40 space-y-1.5">
                  <Label htmlFor="trust-sa-name" className="text-xs">
                    Service account
                  </Label>
                  <Input
                    id="trust-sa-name"
                    value={saName}
                    onChange={(e) => setSaName(e.target.value)}
                    placeholder="web-sa"
                    className="h-8"
                  />
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!saNs.trim() || !saName.trim()}
                  onClick={() => {
                    add(`${SA_PREFIX}${saNs.trim()}:${saName.trim()}`);
                    setSaNs("");
                    setSaName("");
                  }}
                >
                  <Plus className="size-4" /> Add
                </Button>
              </div>
            ) : null}

            {mode === "wildcard" ? (
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs text-muted-foreground">
                  Trust <code>*</code> — any authenticated principal may assume this role.
                </p>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={hasWildcard}
                  onClick={() => add("*")}
                >
                  <Plus className="size-4" /> {hasWildcard ? "Already trusted" : "Trust any authenticated"}
                </Button>
              </div>
            ) : null}

            {mode === "custom" ? (
              <div className="flex flex-wrap items-end gap-2">
                <div className="min-w-48 flex-1 space-y-1.5">
                  <Label htmlFor="trust-custom" className="text-xs">
                    Principal value
                  </Label>
                  <Input
                    id="trust-custom"
                    value={customVal}
                    onChange={(e) => setCustomVal(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        add(customVal);
                        setCustomVal("");
                      }
                    }}
                    placeholder="system:serviceaccount:team-a:runner"
                    className="h-8"
                  />
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!customVal.trim()}
                  onClick={() => {
                    add(customVal);
                    setCustomVal("");
                  }}
                >
                  <Plus className="size-4" /> Add
                </Button>
              </div>
            ) : null}
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="trust-json">Trust (source of truth — Role.spec.trust)</Label>
            <textarea
              id="trust-json"
              value={jsonText}
              onChange={(e) => applyJson(e.target.value)}
              spellCheck={false}
              rows={Math.min(10, Math.max(3, value.length + 2))}
              className="w-full rounded-md border border-border bg-background p-2.5 font-mono text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
              placeholder={'["alice", "system:serviceaccount:apps:web-sa"]'}
            />
            {jsonErr ? (
              <p className="text-xs text-destructive">{jsonErr}</p>
            ) : (
              <p className="text-xs text-muted-foreground">
                A JSON array of principal names (a User name, <code>system:serviceaccount:&lt;ns&gt;:&lt;name&gt;</code>,
                or <code>*</code>). Editing here writes back to <code>spec.trust</code>.
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <Label>AWS-shaped trust policy (view only)</Label>
            </div>
            <div className="relative rounded-md border border-border bg-muted/30">
              <div className="absolute right-2 top-2">
                <CopyButton value={awsTrustDocument(value)} label="Copy trust policy" />
              </div>
              <pre className="overflow-auto p-3 font-mono text-xs text-foreground/80">
                {awsTrustDocument(value)}
              </pre>
            </div>
            <p className="text-xs text-muted-foreground">
              Shown for familiarity. The stored form is <code>spec.trust[]</code> above; the shim implies{" "}
              <code>sts:AssumeRole</code> and does not need this document.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
