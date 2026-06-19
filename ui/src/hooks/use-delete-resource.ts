import { useMutation, useQueryClient } from "@tanstack/react-query";
import { k8sDelete } from "@/lib/api";
import { watchQueryKey } from "@/hooks/use-k8s-watch";

/**
 * Deletes a resource by its single-object k8s path. Optimistically removes it
 * from the watched list cache (the DELETE watch event will also arrive), and
 * invalidates the list on settle to stay correct.
 */
export function useDeleteResource(listPath: string) {
  const queryClient = useQueryClient();
  const listKey = watchQueryKey(listPath);

  return useMutation({
    mutationFn: (resourcePath: string) => k8sDelete(resourcePath),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: listKey });
    },
  });
}
