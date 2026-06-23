import { Badge } from "@/components/ui/badge";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { SecurityGroup } from "@/types/k8s";

/**
 * Toggle the SecurityGroups attached to a resource. Lists the SGs that exist in
 * the given namespace and lets you click to attach/detach. Controlled — the
 * caller owns `value` (spec.securityGroups) and persists `onChange`.
 */
export function SecurityGroupPicker({
  namespace,
  value,
  onChange,
  disabled,
}: {
  namespace: string;
  value: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
}) {
  const { items } = useK8sWatch<SecurityGroup>(
    openinfraPaths.securitygroups(namespace),
  );
  const names = items
    .map((s) => s.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const toggle = (n: string) =>
    onChange(value.includes(n) ? value.filter((x) => x !== n) : [...value, n]);

  // Show any attached SG even if it no longer exists in the list (so it can be removed).
  const all = Array.from(new Set([...names, ...value])).sort((a, b) => a.localeCompare(b));

  if (!all.length) {
    return (
      <p className="text-xs text-muted-foreground">
        No security groups in <code>{namespace}</code> yet — create one on the{" "}
        <strong>Security Groups</strong> page, then attach it here.
      </p>
    );
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {all.map((n) => {
        const on = value.includes(n);
        return (
          <button
            key={n}
            type="button"
            disabled={disabled}
            onClick={() => toggle(n)}
            className="disabled:opacity-50"
          >
            <Badge
              variant={on ? "default" : "outline"}
              className="cursor-pointer font-mono text-xs"
            >
              {n}
            </Badge>
          </button>
        );
      })}
    </div>
  );
}
