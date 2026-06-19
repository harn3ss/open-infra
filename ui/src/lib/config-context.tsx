import { createContext, useContext } from "react";
import type { AppConfig } from "@/lib/api";

const ConfigContext = createContext<AppConfig | null>(null);

export function ConfigProvider({
  value,
  children,
}: {
  value: AppConfig;
  children: React.ReactNode;
}) {
  return (
    <ConfigContext.Provider value={value}>{children}</ConfigContext.Provider>
  );
}

/** Access the BFF runtime config. Guaranteed present once the app has mounted. */
export function useConfig(): AppConfig {
  const ctx = useContext(ConfigContext);
  if (!ctx) {
    throw new Error("useConfig must be used within <ConfigProvider>");
  }
  return ctx;
}
