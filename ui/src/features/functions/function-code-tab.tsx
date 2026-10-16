import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileCode, Package, Box } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingState, ErrorState } from "@/components/common/states";
import { getFunctionCode, type FunctionCodeFile } from "@/lib/api";
import { cn } from "@/lib/utils";

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
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
  // Otherwise prefer a top-level (no slash) text file, else just the first.
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

  return (
    <div className="space-y-3">
      {/* Package header — runtime, handler, and where the code came from. */}
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {data.mode === "zip" ? (
          <Badge variant="secondary" className="gap-1">
            <Package className="size-3" /> Deployment package (.zip)
          </Badge>
        ) : (
          <Badge variant="secondary" className="gap-1">
            <FileCode className="size-3" /> Inline source
          </Badge>
        )}
        {data.runtime ? <span>Runtime: <code>{data.runtime}</code></span> : null}
        {data.handler ? <span>· Handler: <code>{data.handler}</code></span> : null}
        <span>· {data.totalFiles} file{data.totalFiles === 1 ? "" : "s"}</span>
        {data.mode === "zip" && data.bucket ? (
          <span className="truncate">· <code>{data.bucket}/{data.key}</code></span>
        ) : null}
      </div>

      {data.note && data.mode === "zip" ? (
        <p className="text-xs text-amber-600 dark:text-amber-500">{data.note}</p>
      ) : null}

      {/* AWS "Code source" layout: file tree on the left, viewer on the right. */}
      <Card className="overflow-hidden">
        <CardContent className="flex flex-col p-0 md:flex-row">
          <ul className="max-h-[520px] shrink-0 overflow-auto border-b border-border md:w-64 md:border-b-0 md:border-r">
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
                  <pre className="max-h-[520px] overflow-auto p-3 font-mono text-xs leading-relaxed">
                    {active.content || "(empty file)"}
                  </pre>
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
    </div>
  );
}
