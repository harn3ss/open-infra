import { useMemo } from "react";
import { CopyButton } from "@/components/common/copy-button";
import { toYaml } from "@/lib/yaml";
import { cn } from "@/lib/utils";

interface Token {
  text: string;
  className?: string;
}

/**
 * Tokenize a single YAML line into key / value / comment / punctuation spans.
 * Deliberately simple — good enough for read-only k8s manifests, no parser.
 */
function highlightLine(line: string): Token[] {
  const tokens: Token[] = [];
  const indentMatch = /^(\s*)/.exec(line);
  const indent = indentMatch ? indentMatch[1] ?? "" : "";
  let rest = line.slice(indent.length);
  if (indent) tokens.push({ text: indent });

  // List dash.
  if (rest.startsWith("- ")) {
    tokens.push({ text: "- ", className: "text-muted-foreground" });
    rest = rest.slice(2);
  } else if (rest === "-") {
    tokens.push({ text: "-", className: "text-muted-foreground" });
    rest = "";
  }

  // key: value
  const kv = /^([A-Za-z0-9_./-]+)(:)(\s*)(.*)$/.exec(rest);
  if (kv) {
    const [, key, colon, space, value] = kv;
    tokens.push({ text: key ?? "", className: "text-[hsl(var(--accent))]" });
    tokens.push({ text: colon ?? "", className: "text-muted-foreground" });
    if (space) tokens.push({ text: space });
    if (value) tokens.push(...highlightValue(value));
    return tokens;
  }

  // Bare value (array item scalar or block content).
  if (rest) tokens.push(...highlightValue(rest));
  return tokens;
}

function highlightValue(value: string): Token[] {
  const v = value.trim();
  if (v === "") return [{ text: value }];
  if (v === "{}" || v === "[]") {
    return [{ text: value, className: "text-muted-foreground" }];
  }
  if (/^(true|false|null)$/.test(v)) {
    return [{ text: value, className: "text-primary" }];
  }
  if (/^-?\d+(\.\d+)?$/.test(v)) {
    return [{ text: value, className: "text-[hsl(var(--warning))]" }];
  }
  if (/^["'].*["']$/.test(v)) {
    return [{ text: value, className: "text-success" }];
  }
  if (v === "|-" || v === "|" || v === ">-" || v === ">") {
    return [{ text: value, className: "text-muted-foreground" }];
  }
  return [{ text: value, className: "text-foreground" }];
}

/** Read-only, syntax-highlighted YAML view for any resource object. */
export function YamlViewer({
  value,
  className,
  maxHeightClassName = "max-h-[60vh]",
}: {
  /** A resource object, or a ready-made YAML string. */
  value: unknown;
  className?: string;
  maxHeightClassName?: string;
}) {
  const yaml = useMemo(
    () => (typeof value === "string" ? value : toYaml(value)),
    [value],
  );

  const lines = useMemo(() => yaml.split("\n"), [yaml]);

  return (
    <div
      className={cn(
        "relative rounded-lg border border-border bg-[hsl(var(--background))]",
        className,
      )}
    >
      <div className="absolute right-2 top-2 z-10">
        <CopyButton value={yaml} label="Copy YAML" />
      </div>
      <div className={cn("overflow-auto p-4", maxHeightClassName)}>
        <pre className="oi-yaml">
          <code>
            {lines.map((line, i) => (
              <div key={i} className="flex">
                <span className="mr-4 inline-block w-8 shrink-0 select-none text-right text-muted-foreground/40">
                  {i + 1}
                </span>
                <span className="whitespace-pre">
                  {highlightLine(line).map((t, j) => (
                    <span key={j} className={t.className}>
                      {t.text}
                    </span>
                  ))}
                </span>
              </div>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
}
