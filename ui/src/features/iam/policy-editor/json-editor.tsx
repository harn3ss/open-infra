import { useRef } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import { useTheme } from "@/lib/theme";

/**
 * The JSON tab of the policy authoring surface — the AWS "JSON" view, except the document IS the
 * Policy CR (the single source of truth), not AWS IAM JSON. Reuses the CodeMirror dependency already in
 * the app (features/queries/sql-editor.tsx). No JSON language extension is bundled, so this is a plain
 * text surface with line numbers; validity is enforced by the caller via parseDoc().
 */

// Match the SQL editor's chrome so the two code surfaces feel identical.
const chrome = EditorView.theme({
  "&": { backgroundColor: "transparent", fontSize: "13px" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", lineHeight: "1.5" },
  ".cm-gutters": { backgroundColor: "transparent", border: "none" },
  "&.cm-focused": { outline: "none" },
  ".cm-content": { padding: "8px 0" },
});

export function JsonEditor({
  value,
  onChange,
  error,
  readOnly = false,
}: {
  value: string;
  onChange?: (v: string) => void;
  /** A parse/validation error to surface under the editor. */
  error?: string | null;
  readOnly?: boolean;
}) {
  const { theme } = useTheme();
  const viewRef = useRef<EditorView | null>(null);

  return (
    <div className="space-y-2">
      <div
        className={[
          "overflow-hidden rounded-lg border bg-[hsl(var(--background))]",
          error ? "border-destructive/60" : "border-border",
        ].join(" ")}
      >
        <CodeMirror
          value={value}
          onChange={onChange}
          theme={theme === "dark" ? "dark" : "light"}
          extensions={[chrome, EditorView.editable.of(!readOnly)]}
          height="420px"
          onCreateEditor={(view) => {
            viewRef.current = view;
          }}
          basicSetup={{
            lineNumbers: true,
            highlightActiveLine: !readOnly,
            highlightActiveLineGutter: !readOnly,
            foldGutter: false,
            autocompletion: false,
          }}
          editable={!readOnly}
        />
      </div>
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}
