import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileCode, Package, Box, Download } from "lucide-react";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import type { Extension } from "@codemirror/state";
import { python } from "@codemirror/lang-python";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DetailRow } from "@/components/common/detail-row";
import { LoadingState, ErrorState } from "@/components/common/states";
import {
  getFunctionCode,
  objectDownloadUrl,
  type FunctionCodeFile,
} from "@/lib/api";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// Match the SQL/JSON editors' chrome so every code surface in the console feels identical.
const chrome = EditorView.theme({
  "&": { backgroundColor: "transparent", fontSize: "13px" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", lineHeight: "1.5" },
  ".cm-gutters": { backgroundColor: "transparent", border: "none" },
  "&.cm-focused": { outline: "none" },
  ".cm-content": { padding: "8px 0" },
});

/** CodeMirror language extension for a file, by extension — the runtimes we vouch for. */
function langFor(path: string): Extension[] {
  const ext = path.toLowerCase().split(".").pop() ?? "";
  switch (ext) {
    case "py":
      return [python()];
    case "js":
    case "mjs":
    case "cjs":
    case "jsx":
      return [javascript({ jsx: true })];
    case "ts":
    case "tsx":
      return [javascript({ jsx: true, typescript: true })];
    case "json":
      return [json()];
    default:
      return [];
  }
}

/** The file whose basename (sans extension) matches the handler's module/file,
 *  so we land on the entrypoint the way AWS opens the handler by default. */
function pickDefault(files: FunctionCodeFile[], handler?: string): string | undefined {
  if (files.length === 0) return undefined;
  const base = (handler ?? "").split(/[.:]/)[0]?.trim();
  if (base) {
    const match = files.find((f) => {
      const fname = f.path.split("/").pop() ?? f.path;
      const stem = fname.replace(/\.[^.]+$/, "");
      return stem === base;
    });
    if (match) return match.path;
  }
  const topText = files.find((f) => !f.path.includes("/") && !f.binary);
  return (topText ?? files[0])?.path;
}

export function FunctionCodeTab({
  namespace,
  name,
}: {
  namespace: string;
  name: string;
}) {
  const { theme } = useTheme();
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["function-code", namespace, name],
    queryFn: () => getFunctionCode(namespace, name),
    staleTime: 30_000,
  });

  const files = data?.files ?? [];
  const defaultPath = useMemo(
    () => pickDefault(files, data?.handler),
    [files, data?.handler],
  );
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const activePath = selected ?? defaultPath;
  const active = files.find((f) => f.path === activePath);
  const extensions = useMemo(
    () => [...langFor(active?.path ?? ""), chrome, EditorView.lineWrapping],
    [active?.path],
  );

  if (isLoading) return <LoadingState label="Loading source…" />;
  if (isError || !data) return <ErrorState error={error} onRetry={refetch} />;

  // Container image / nothing to show: honest notice, like AWS for image functions.
  if (data.mode === "image" || data.mode === "none" || files.length === 0) {
    return (
      <Card>
        <CardContent className="flex items-start gap-3 p-6">
          <Box className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
          <div className="space-y-2">
            <p className="text-sm">
              {data.note ?? "No source is available for this function."}
            </p>
            {data.image ? (
              <p className="text-xs text-muted-foreground">
                Image: <code className="text-xs">{data.image}</code>
              </p>
            ) : null}
          </div>
        </CardContent>
      </Card>
    );
  }

  const packageLabel = data.mode === "zip" ? "Deployment package (.zip)" : "Inline source";

  return (
    <div className="space-y-4">
      {/* ── Code source: toolbar + file tree + read-only editor (AWS "Code source"). ── */}
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/40 px-3 py-2">
          <span className="text-sm font-medium">Code source</span>
          {data.mode === "zip" ? (
            <Badge variant="secondary" className="gap-1">
              <Package className="size-3" /> {packageLabel}
            </Badge>
          ) : (
            <Badge variant="secondary" className="gap-1">
              <FileCode className="size-3" /> {packageLabel}
            </Badge>
          )}
          <span className="text-xs text-muted-foreground">
            {data.totalFiles} file{data.totalFiles === 1 ? "" : "s"}
            {data.packageSize ? ` · ${humanSize(data.packageSize)}` : ""}
          </span>
          {data.mode === "zip" && data.bucket && data.key ? (
            <a
              href={objectDownloadUrl(data.bucket, data.key)}
              className="ml-auto inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-secondary"
            >
              <Download className="size-3" /> Download .zip
            </a>
          ) : null}
        </div>

        {data.note && data.mode === "zip" ? (
          <p className="border-b border-border px-3 py-1.5 text-xs text-amber-600 dark:text-amber-500">
            {data.note}
          </p>
        ) : null}

        <CardContent className="flex flex-col p-0 md:flex-row">
          <ul className="max-h-[560px] shrink-0 overflow-auto border-b border-border md:w-64 md:border-b-0 md:border-r">
            {files.map((f) => {
              const fname = f.path.split("/").pop() ?? f.path;
              const isActive = f.path === activePath;
              return (
                <li key={f.path}>
                  <button
                    type="button"
                    onClick={() => setSelected(f.path)}
                    title={f.path}
                    className={cn(
                      "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-secondary",
                      isActive && "bg-secondary font-medium",
                    )}
                  >
                    <FileCode className="size-3.5 shrink-0 text-muted-foreground" />
                    <span className="truncate">{f.path.includes("/") ? f.path : fname}</span>
                    {f.binary ? (
                      <Badge variant="outline" className="ml-auto shrink-0 text-[10px]">
                        bin
                      </Badge>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>

          <div className="min-w-0 flex-1">
            {active ? (
              <div className="flex flex-col">
                <div className="flex items-center justify-between gap-2 border-b border-border bg-muted/40 px-3 py-1.5 text-xs">
                  <code className="truncate">{active.path}</code>
                  <span className="shrink-0 text-muted-foreground">
                    {humanSize(active.size)}
                    {active.truncated ? " · truncated" : ""}
                  </span>
                </div>
                {active.binary ? (
                  <p className="p-4 text-xs text-muted-foreground">
                    Binary file — {humanSize(active.size)}. Not shown.
                  </p>
                ) : active.tooLarge ? (
                  <p className="p-4 text-xs text-muted-foreground">
                    File is too large to preview in the console.
                  </p>
                ) : (
                  <CodeMirror
                    value={active.content ?? ""}
                    theme={theme === "dark" ? "dark" : "light"}
                    extensions={extensions}
                    editable={false}
                    readOnly
                    maxHeight="560px"
                    basicSetup={{
                      lineNumbers: true,
                      highlightActiveLine: false,
                      highlightActiveLineGutter: false,
                      foldGutter: false,
                      autocompletion: false,
                    }}
                  />
                )}
              </div>
            ) : (
              <p className="p-4 text-xs text-muted-foreground">
                Select a file to view its source.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ── Runtime settings (AWS shows this below Code source on the Code tab). ── */}
      <div>
        <h3 className="mb-2 text-sm font-medium">Runtime settings</h3>
        <Card>
          <CardContent className="divide-y divide-border p-0">
            <DetailRow label="Runtime">
              <code className="text-xs">{data.runtime ?? "—"}</code>
            </DetailRow>
            <DetailRow label="Handler">
              <code className="text-xs">{data.handler ?? "—"}</code>
            </DetailRow>
            <DetailRow label="Package type">
              {data.mode === "zip" ? "Zip" : "Inline (config)"}
            </DetailRow>
            {data.packageSize ? (
              <DetailRow label="Package size">{humanSize(data.packageSize)}</DetailRow>
            ) : null}
            {data.mode === "zip" && data.bucket ? (
              <DetailRow label="Package location">
                <code className="text-xs">
                  {data.bucket}/{data.key}
                </code>
              </DetailRow>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
