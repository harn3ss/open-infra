import { AlertTriangle, Check } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useState } from "react";

/**
 * Pick the groups a user belongs to. The built-in groups (admins/powerusers/readers)
 * are offered as toggle chips because they are guaranteed to take effect; any other
 * name can be typed, but is flagged, because a group only works if openinfra:<name> is
 * in the impersonator ClusterRole's resourceNames — otherwise the user signs in and can
 * do nothing. See docs/iam.md.
 */
export function GroupPicker({
  builtins,
  known,
  value,
  onChange,
}: {
  /** Group names guaranteed to take effect (from /api/iam/config). */
  builtins: string[];
  /** All existing Group names, so custom-but-real ones show up as chips too. */
  known: string[];
  value: string[];
  onChange: (groups: string[]) => void;
}) {
  const [custom, setCustom] = useState("");
  const toggle = (g: string) =>
    onChange(value.includes(g) ? value.filter((x) => x !== g) : [...value, g]);

  // Chips: builtins first, then any other known groups, then anything selected that
  // isn't in either list (a name typed here or set elsewhere).
  const chips = Array.from(
    new Set([...builtins, ...known.filter((g) => !builtins.includes(g)), ...value]),
  );
  const unbound = value.filter((g) => !builtins.includes(g));

  const addCustom = () => {
    const g = custom.trim();
    if (g && !value.includes(g)) onChange([...value, g]);
    setCustom("");
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        {chips.map((g) => {
          const on = value.includes(g);
          const risky = on && !builtins.includes(g);
          return (
            <button
              key={g}
              type="button"
              onClick={() => toggle(g)}
              className={[
                "inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                on
                  ? risky
                    ? "border-amber-500/50 bg-amber-500/15 text-amber-600 dark:text-amber-400"
                    : "border-primary/40 bg-primary/15 text-primary"
                  : "border-border text-muted-foreground hover:bg-muted",
              ].join(" ")}
            >
              {on ? <Check className="size-3" /> : null}
              {g}
            </button>
          );
        })}
      </div>

      <div className="flex gap-2">
        <Input
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addCustom();
            }
          }}
          placeholder="Add another group…"
          className="h-8 text-xs"
        />
      </div>

      {unbound.length > 0 ? (
        <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
          <span>
            {unbound.join(", ")} {unbound.length === 1 ? "is" : "are"} not a built-in group.
            {" "}Members won't gain access until an operator adds{" "}
            <code>openinfra:{unbound[0]}</code> to the impersonator ClusterRole.
          </span>
        </p>
      ) : null}
    </div>
  );
}
