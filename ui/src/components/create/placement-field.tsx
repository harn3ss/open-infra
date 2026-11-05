import type { ReactNode } from "react";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/lib/auth";
import { placementChoices } from "@/lib/account-scope";

/** The namespaces this session's create pages may offer (placementChoices): the operator's only (#360). */
export function usePlacementChoices(): string[] {
  const { user } = useAuth();
  return placementChoices(user);
}

/** The operator's placement choice on a create page, collapsed under Advanced; renders nothing otherwise. */
export function PlacementField({
  value,
  onChange,
  help,
}: {
  value: string;
  onChange: (namespace: string) => void;
  help?: ReactNode;
}) {
  const { user } = useAuth();
  const choices = placementChoices(user);
  if (choices.length === 0) return null;
  return (
    <details className="text-sm [&_summary]:cursor-pointer">
      <summary className="text-muted-foreground">Advanced</summary>
      <div className="mt-3 space-y-1.5">
        <Label htmlFor="oi-ns">Placement</Label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger id="oi-ns">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {choices.map((ns) => (
              <SelectItem key={ns} value={ns}>
                {ns}
                {ns === user?.homeNamespace ? " (default)" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          {help ?? <>Which of this account&apos;s namespaces holds the resource. The default is the account&apos;s home.</>}
        </p>
      </div>
    </details>
  );
}
