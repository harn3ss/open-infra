/**
 * Minimal, dependency-free YAML serializer for read-only display of Kubernetes
 * objects. It is NOT a general YAML library — it covers the JSON data model
 * (objects, arrays, strings, numbers, booleans, null) which is all the k8s API
 * returns. Output is stable and human-readable for the YAML viewer.
 */

type Json =
  | string
  | number
  | boolean
  | null
  | undefined
  | Json[]
  | { [key: string]: Json };

const SAFE_UNQUOTED = /^[A-Za-z0-9_./-]+$/;
const NEEDS_QUOTING =
  /^(true|false|null|yes|no|on|off|~|)$|^[-?:,[\]{}#&*!|>'"%@`]|:\s|\s#|^\s|\s$|^[\d.+-]+$/i;

function formatScalar(value: string | number | boolean | null): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null";

  const s = value;
  if (s === "") return '""';
  if (s.includes("\n")) {
    // Block scalar for multi-line strings.
    return s;
  }
  if (SAFE_UNQUOTED.test(s) && !NEEDS_QUOTING.test(s)) return s;
  // Quote and escape.
  return JSON.stringify(s);
}

function isObject(v: Json): v is { [key: string]: Json } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function serialize(value: Json, indent: number): string[] {
  const pad = "  ".repeat(indent);
  const lines: string[] = [];

  if (Array.isArray(value)) {
    if (value.length === 0) return [`${pad}[]`];
    for (const item of value) {
      if (isObject(item) || Array.isArray(item)) {
        const child = serialize(item, indent + 1);
        // Put the first child key on the same line as the dash.
        const first = child[0]?.trimStart() ?? "";
        lines.push(`${pad}- ${first}`);
        for (let i = 1; i < child.length; i++) lines.push(child[i] as string);
      } else {
        lines.push(`${pad}- ${formatScalar(item as string | number | boolean | null)}`);
      }
    }
    return lines;
  }

  if (isObject(value)) {
    const keys = Object.keys(value);
    if (keys.length === 0) return [`${pad}{}`];
    for (const key of keys) {
      const v = value[key];
      if (v === undefined) continue;
      if (Array.isArray(v)) {
        if (v.length === 0) {
          lines.push(`${pad}${key}: []`);
        } else {
          lines.push(`${pad}${key}:`);
          lines.push(...serialize(v, indent));
        }
      } else if (isObject(v)) {
        if (Object.keys(v).length === 0) {
          lines.push(`${pad}${key}: {}`);
        } else {
          lines.push(`${pad}${key}:`);
          lines.push(...serialize(v, indent + 1));
        }
      } else {
        const scalar = v as string | number | boolean | null;
        if (typeof scalar === "string" && scalar.includes("\n")) {
          lines.push(`${pad}${key}: |-`);
          for (const ln of scalar.split("\n")) {
            lines.push(`${"  ".repeat(indent + 1)}${ln}`);
          }
        } else {
          lines.push(`${pad}${key}: ${formatScalar(scalar)}`);
        }
      }
    }
    return lines;
  }

  return [`${pad}${formatScalar(value as string | number | boolean | null)}`];
}

/** Serialize a JSON-compatible value to YAML text. */
export function toYaml(value: unknown): string {
  try {
    return serialize(value as Json, 0).join("\n");
  } catch {
    // Fall back to pretty JSON if anything unexpected slips through.
    return JSON.stringify(value, null, 2);
  }
}
