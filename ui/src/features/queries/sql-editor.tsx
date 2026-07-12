import {
  forwardRef,
  useCallback,
  useImperativeHandle,
  useMemo,
  useRef,
} from "react";
import CodeMirror from "@uiw/react-codemirror";
import { sql } from "@codemirror/lang-sql";
import { EditorView, keymap } from "@codemirror/view";
import { useTheme } from "@/lib/theme";

export interface SqlEditorHandle {
  /** Run: the current selection if any, else the whole document (Athena semantics). */
  run: () => void;
  /** Insert text at the cursor (used by the data-tree "insert" action). */
  insert: (text: string) => void;
}

interface Props {
  value: string;
  onChange: (v: string) => void;
  onRun: (sqlToRun: string) => void;
}

// Blend CodeMirror into our panel: transparent surface (inherit the container bg),
// our mono font, no focus outline (the panel border carries focus). Syntax colors
// come from CodeMirror's built-in light/dark theme, which we switch with the app.
const chrome = EditorView.theme({
  "&": { backgroundColor: "transparent", fontSize: "13px" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", lineHeight: "1.5" },
  ".cm-gutters": { backgroundColor: "transparent", border: "none" },
  "&.cm-focused": { outline: "none" },
  ".cm-content": { padding: "8px 0" },
});

export const SqlEditor = forwardRef<SqlEditorHandle, Props>(function SqlEditor(
  { value, onChange, onRun },
  ref,
) {
  const { theme } = useTheme();
  const viewRef = useRef<EditorView | null>(null);

  const doRun = useCallback(() => {
    const view = viewRef.current;
    if (!view) {
      onRun(value);
      return;
    }
    const sel = view.state.selection.main;
    const text =
      sel.from !== sel.to
        ? view.state.sliceDoc(sel.from, sel.to)
        : view.state.doc.toString();
    onRun(text);
  }, [onRun, value]);

  useImperativeHandle(
    ref,
    () => ({
      run: doRun,
      insert: (text: string) => {
        const view = viewRef.current;
        if (view) view.dispatch(view.state.replaceSelection(text));
      },
    }),
    [doRun],
  );

  // Cmd/Ctrl+Enter runs (Mod = Cmd on macOS, Ctrl elsewhere) — one binding covers both.
  const runKeymap = useMemo(
    () =>
      keymap.of([
        {
          key: "Mod-Enter",
          preventDefault: true,
          run: () => {
            doRun();
            return true;
          },
        },
      ]),
    [doRun],
  );

  return (
    <CodeMirror
      value={value}
      onChange={onChange}
      theme={theme === "dark" ? "dark" : "light"}
      extensions={[sql(), chrome, runKeymap]}
      height="100%"
      onCreateEditor={(view) => {
        viewRef.current = view;
      }}
      basicSetup={{
        lineNumbers: true,
        highlightActiveLine: true,
        highlightActiveLineGutter: true,
        foldGutter: false,
        autocompletion: true,
      }}
    />
  );
});
