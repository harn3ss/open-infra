import { useQuery } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { TooltipProvider } from "@/components/ui/tooltip";
import { BootError, BootLoading } from "@/components/layout/boot-screen";
import { getConfig } from "@/lib/api";
import { ConfigProvider } from "@/lib/config-context";
import { NamespaceProvider } from "@/lib/namespace-context";
import { SearchProvider } from "@/lib/search-context";
import { router } from "@/router";

/**
 * App root. Per the contract, /api/config is fetched ONCE before the app
 * renders; the config is then provided to the whole tree. Routing, namespace
 * scope, and the global search box live above the router.
 */
export function App() {
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
