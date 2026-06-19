import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "@/lib/api";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Watch hooks keep lists fresh via SSE, so background refetch is rarely
      // needed; keep data fresh for a short window and refetch on focus.
      staleTime: 15_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        // Don't retry auth/permission/not-found; do retry transient errors.
        if (error instanceof ApiError) {
          if ([400, 401, 403, 404, 409, 422].includes(error.status)) {
            return false;
          }
        }
        return failureCount < 2;
      },
    },
    mutations: {
      retry: false,
    },
  },
});
