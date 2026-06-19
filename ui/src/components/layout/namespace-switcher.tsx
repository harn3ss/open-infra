import { Layers } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { corePaths } from "@/lib/k8s-paths";
import { ALL_NAMESPACES, useNamespace } from "@/lib/namespace-context";
import type { K8sObject } from "@/types/k8s";

/** Top-bar namespace scope selector, backed by a live namespace list. */
export function NamespaceSwitcher() {
  const { namespace, setNamespace } = useNamespace();
  const { items, isError } = useK8sWatch<K8sObject>(corePaths.namespaces());

  const names = items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  return (
    <Select value={namespace} onValueChange={setNamespace}>
      <SelectTrigger className="w-[200px]" aria-label="Namespace">
        <Layers className="size-4 shrink-0 text-muted-foreground" />
        <SelectValue placeholder="Namespace" />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          <SelectLabel>Scope</SelectLabel>
          <SelectItem value={ALL_NAMESPACES}>All namespaces</SelectItem>
        </SelectGroup>
        {names.length > 0 ? (
          <SelectGroup>
            <SelectLabel>Namespaces</SelectLabel>
            {names.map((name) => (
              <SelectItem key={name} value={name}>
                {name}
              </SelectItem>
            ))}
          </SelectGroup>
        ) : null}
        {isError ? (
          <SelectGroup>
            <SelectLabel>Namespaces unavailable</SelectLabel>
          </SelectGroup>
        ) : null}
      </SelectContent>
    </Select>
  );
}
