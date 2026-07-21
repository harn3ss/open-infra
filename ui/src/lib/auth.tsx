import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  UNAUTHORIZED_EVENT,
  getCurrentUser,
  logout as apiLogout,
  type CurrentUser,
} from "@/lib/api";
import { queryClient } from "@/lib/query-client";

interface AuthState {
  user: CurrentUser | null;
  /** true until the initial /auth/me check resolves */
  loading: boolean;
  setUser: (u: CurrentUser | null) => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Initial session probe.
  useEffect(() => {
    let cancelled = false;
    getCurrentUser()
      .then((u) => !cancelled && setUser(u))
      .catch(() => !cancelled && setUser(null))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  // Any 401 from anywhere drops us back to the login screen.
  useEffect(() => {
    function onUnauthorized() {
      setUser(null);
      queryClient.clear();
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      /* signing out locally regardless */
    }
    setUser(null);
    queryClient.clear();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, setUser, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
