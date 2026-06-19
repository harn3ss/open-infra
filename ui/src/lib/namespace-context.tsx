import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

/**
 * The currently-selected namespace scope. `ALL_NAMESPACES` is a sentinel for
 * "all namespaces" — list helpers treat an undefined namespace the same way.
 */
export const ALL_NAMESPACES = "__all__";

interface NamespaceContextValue {
  /** Selected namespace, or ALL_NAMESPACES. */
  namespace: string;
  /** Concrete namespace for path building, or undefined when "all". */
  scoped: string | undefined;
  setNamespace: (ns: string) => void;
}

const NamespaceContext = createContext<NamespaceContextValue | null>(null);

const STORAGE_KEY = "oi-namespace";

export function NamespaceProvider({ children }: { children: React.ReactNode }) {
  const [namespace, setNamespaceState] = useState<string>(() => {
    if (typeof window === "undefined") return ALL_NAMESPACES;
    return window.localStorage.getItem(STORAGE_KEY) ?? ALL_NAMESPACES;
  });

  const setNamespace = useCallback((ns: string) => {
    setNamespaceState(ns);
    try {
      window.localStorage.setItem(STORAGE_KEY, ns);
    } catch {
      /* ignore storage failures */
    }
  }, []);

  const value = useMemo<NamespaceContextValue>(
    () => ({
      namespace,
      scoped: namespace === ALL_NAMESPACES ? undefined : namespace,
      setNamespace,
    }),
    [namespace, setNamespace],
  );

  return (
    <NamespaceContext.Provider value={value}>
      {children}
    </NamespaceContext.Provider>
  );
}

export function useNamespace(): NamespaceContextValue {
  const ctx = useContext(NamespaceContext);
  if (!ctx) {
    throw new Error("useNamespace must be used within <NamespaceProvider>");
  }
  return ctx;
}
