import { useMemo, useState } from "react";
import { Filter, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

/** Token comparison operators (Cloudscape `PropertyFilter` operator set). */
export type FilterOperator = "=" | "!=" | ":" | "!:";

const OPERATOR_LABEL: Record<FilterOperator, string> = {
  "=": "equals",
  "!=": "does not equal",
  ":": "contains",
  "!:": "does not contain",
};

const DEFAULT_OPERATORS: FilterOperator[] = ["=", "!=", ":", "!:"];
/** Sentinel Select value for the free-text "all properties" choice (Radix forbids ""). */
const ALL = "__all__";

/** A filterable property offered in the builder. */
export interface FilterProperty {
  /** Stable key stored on the token (and matched by {@link FilterPropertyDef.getValue}). */
  key: string;
  /** Human label shown in the property picker and on chips. */
  label: string;
  /** If set, the value control becomes a dropdown of these options. */
  options?: { value: string; label?: string }[];
  /** Operators offered for this property. Default: all four. */
  operators?: FilterOperator[];
}

/** A {@link FilterProperty} plus how to read its value off an item (for {@link applyFilterTokens}). */
export interface FilterPropertyDef<T> extends FilterProperty {
  getValue: (item: T) => string | string[] | null | undefined;
}

/** One active filter token. `property === ""` is a free-text-across-all token. */
export interface FilterToken {
  property: string;
  operator: FilterOperator;
  value: string;
}

/** How multiple tokens combine. */
export type FilterOperation = "and" | "or";

function normValues(raw: string | string[] | null | undefined): string[] {
  if (raw == null) return [];
  return (Array.isArray(raw) ? raw : [raw]).filter((v) => v !== "");
}

function tokenMatches<T>(
  item: T,
  token: FilterToken,
  defs: FilterPropertyDef<T>[],
): boolean {
  const values =
    token.property === ""
      ? defs.flatMap((d) => normValues(d.getValue(item)))
      : normValues(defs.find((d) => d.key === token.property)?.getValue(item));
  const needle = token.value.toLowerCase();
  const has = values.map((v) => v.toLowerCase());
  switch (token.operator) {
    case ":":
      return has.some((v) => v.includes(needle));
    case "!:":
      return !has.some((v) => v.includes(needle));
    case "=":
      return has.some((v) => v === needle);
    case "!=":
      return !has.some((v) => v === needle);
  }
}

/**
 * Pure predicate engine for {@link PropertyFilter} tokens. Filters `items` by all
 * tokens, combined with `operation` (default `"and"`). Wire it in a `useMemo`.
 */
export function applyFilterTokens<T>(
  items: T[],
  tokens: FilterToken[],
  defs: FilterPropertyDef<T>[],
  operation: FilterOperation = "and",
): T[] {
  if (tokens.length === 0) return items;
  return items.filter((item) => {
    const results = tokens.map((t) => tokenMatches(item, t, defs));
    return operation === "and" ? results.every(Boolean) : results.some(Boolean);
  });
}

function labelFor(properties: FilterProperty[], token: FilterToken): string {
  const prop =
    token.property === ""
      ? "Text"
      : (properties.find((p) => p.key === token.property)?.label ??
        token.property);
  const opts = properties.find((p) => p.key === token.property)?.options;
  const valLabel =
    opts?.find((o) => o.value === token.value)?.label ?? token.value;
  return `${prop} ${OPERATOR_LABEL[token.operator]} ${valLabel}`;
}

/**
 * Cloudscape-style tokenized property filter: pick a property → operator → value
 * and add a removable chip; chips combine with and/or. Falls back to a plain
 * free-text token when the "All properties" option is chosen. Fully controlled.
 *
 * @example
 * const [tokens, setTokens] = useState<FilterToken[]>([]);
 * <PropertyFilter
 *   properties={[{ key: "status", label: "Status", options: [{ value: "Available" }] }]}
 *   tokens={tokens} onChange={setTokens} />
 * const rows = applyFilterTokens(all, tokens, [
 *   { key: "status", label: "Status", getValue: (r) => r.status },
 * ]);
 */
export function PropertyFilter({
  properties,
  tokens,
  onChange,
  operation = "and",
  onOperationChange,
  placeholder = "Value",
  className,
}: {
  properties: FilterProperty[];
  tokens: FilterToken[];
  onChange: (tokens: FilterToken[]) => void;
  operation?: FilterOperation;
  onOperationChange?: (op: FilterOperation) => void;
  placeholder?: string;
  className?: string;
}) {
  const [propKey, setPropKey] = useState<string>(ALL);
  const [operator, setOperator] = useState<FilterOperator>(":");
  const [value, setValue] = useState("");

  const activeProp = useMemo(
    () => (propKey === ALL ? undefined : properties.find((p) => p.key === propKey)),
    [propKey, properties],
  );
  const operators = activeProp?.operators ?? (propKey === ALL ? [":", "!:"] : DEFAULT_OPERATORS);
  const options = activeProp?.options;

  const selectProp = (k: string) => {
    setPropKey(k);
    const next = k === ALL ? undefined : properties.find((p) => p.key === k);
    const ops = next?.operators ?? (k === ALL ? [":", "!:"] : DEFAULT_OPERATORS);
    if (!ops.includes(operator)) setOperator(ops[0] ?? ":");
    setValue("");
  };

  const add = () => {
    const v = value.trim();
    if (!v) return;
    onChange([
      ...tokens,
      { property: propKey === ALL ? "" : propKey, operator, value: v },
    ]);
    setValue("");
  };

  const remove = (i: number) => onChange(tokens.filter((_, idx) => idx !== i));

  return (
    <div
      className={cn(
        "rounded-lg border border-border bg-card p-2",
        className,
      )}
    >
      {/* Builder row */}
      <div className="flex flex-wrap items-center gap-2">
        <Filter className="ml-1 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <Select value={propKey} onValueChange={selectProp}>
          <SelectTrigger className="h-8 w-auto min-w-36" aria-label="Property">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All properties</SelectItem>
            {properties.map((p) => (
              <SelectItem key={p.key} value={p.key}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={operator}
          onValueChange={(v) => setOperator(v as FilterOperator)}
        >
          <SelectTrigger className="h-8 w-auto min-w-28" aria-label="Operator">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {operators.map((op) => (
              <SelectItem key={op} value={op}>
                {OPERATOR_LABEL[op]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {options ? (
          <Select value={value} onValueChange={setValue}>
            <SelectTrigger className="h-8 w-auto min-w-40" aria-label="Value">
              <SelectValue placeholder={placeholder} />
            </SelectTrigger>
            <SelectContent>
              {options.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label ?? o.value}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : (
          <Input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add();
              }
            }}
            placeholder={placeholder}
            className="h-8 w-44"
            aria-label="Value"
          />
        )}

        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={add}
          disabled={!value.trim()}
        >
          <Plus className="size-4" /> Add
        </Button>
      </div>

      {/* Chips */}
      {tokens.length > 0 ? (
        <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-border pt-2">
          {tokens.map((t, i) => (
            <span key={i} className="flex items-center gap-1">
              {i > 0 ? (
                <button
                  type="button"
                  onClick={() =>
                    onOperationChange?.(operation === "and" ? "or" : "and")
                  }
                  className={cn(
                    "rounded px-1 text-xs font-medium uppercase text-muted-foreground",
                    onOperationChange && "hover:bg-secondary hover:text-foreground",
                  )}
                  disabled={!onOperationChange}
                  aria-label="Toggle and/or"
                >
                  {operation}
                </button>
              ) : null}
              <span className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs">
                <span className="text-secondary-foreground">
                  {labelFor(properties, t)}
                </span>
                <button
                  type="button"
                  onClick={() => remove(i)}
                  aria-label={`Remove filter ${labelFor(properties, t)}`}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="size-3" />
                </button>
              </span>
            </span>
          ))}
          <button
            type="button"
            onClick={() => onChange([])}
            className="ml-1 text-xs font-medium text-primary hover:underline"
          >
            Clear filters
          </button>
        </div>
      ) : null}
    </div>
  );
}
