import { createContext, useContext, useState, type ReactNode } from "react";

/** One help topic: a title, a body (paragraphs/JSX), and an optional external "Learn more" doc. */
export interface HelpContent {
  title: string;
  body: ReactNode;
  docsHref?: string;
}

interface HelpContextValue {
  content: HelpContent | null;
  /** Open the Help panel with this content (AWS/Cloudscape "Info" → Help panel). */
  show: (c: HelpContent) => void;
  close: () => void;
}

const HelpContext = createContext<HelpContextValue | null>(null);

export function HelpProvider({ children }: { children: ReactNode }) {
  const [content, setContent] = useState<HelpContent | null>(null);
  return (
    <HelpContext.Provider value={{ content, show: setContent, close: () => setContent(null) }}>
      {children}
    </HelpContext.Provider>
  );
}

export function useHelp(): HelpContextValue {
  const ctx = useContext(HelpContext);
  if (!ctx) throw new Error("useHelp must be used within a HelpProvider");
  return ctx;
}
