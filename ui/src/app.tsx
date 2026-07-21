import { useQuery } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { TooltipProvider } from "@/components/ui/tooltip";
import { BootError, BootLoading } from "@/components/layout/boot-screen";
import { LoginPage } from "@/features/auth/login-page";
import { getConfig } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { ConfigProvider } from "@/lib/config-context";
import { NamespaceProvider } from "@/lib/namespace-context";
import { SearchProvider } from "@/lib/search-context";
import { router } from "@/router";

/**
 * App root. Authentication resolves FIRST: every /api route (including
 * /api/config) now requires a session, so an unauthenticated visitor must land on
 * the login page rather than a confusing boot error. Once signed in, /api/config
 * is fetched once and provided to the whole tree.
 */
export function App() {
  const { user, loading } = useAuth();

  if (loading) return <BootLoading />;
  if (!user) return <LoginPage />;
  return <AuthenticatedApp />;
}

function AuthenticatedApp() {
  const configQuery = useQuery({
    queryKey: ["config"],
    queryFn: getConfig,
    staleTime: Infinity,
    retry: 1,
  });

  if (configQuery.isLoading) return <BootLoading />;
  if (configQuery.isError || !configQuery.data) {
    return (
      <BootError
        error={configQuery.error}
        onRetry={() => void configQuery.refetch()}
      />
    );
  }

  return (
    <ConfigProvider value={configQuery.data}>
      <NamespaceProvider>
        <SearchProvider>
          <TooltipProvider delayDuration={200}>
            <RouterProvider router={router} />
          </TooltipProvider>
        </SearchProvider>
      </NamespaceProvider>
    </ConfigProvider>
  );
}
