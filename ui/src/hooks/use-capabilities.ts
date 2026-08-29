import { useQuery } from "@tanstack/react-query";
import { getCapabilities, type ArchVerdict, type KindCapability } from "@/lib/api";

/**
 * Cluster architecture capability (#41 Phase 3): the declared per-kind registry
 * (kind-architectures.yaml) fused with the cluster's live node arches, served by GET /api/capabilities.
 * Architecture changes rarely, so cache generously.
 */
export function useCapabilities() {
  return useQuery({
    queryKey: ["capabilities"],
    queryFn: getCapabilities,
    staleTime: 5 * 60_000,
    gcTime: 30 * 60_000,
  });
}

export interface KindAvailability {
  verdict: ArchVerdict;
  /** Human-readable reason for a non-available verdict (empty when available). */
  reason: string;
  /** Convenience flags for the common branches. */
  unavailable: boolean;
  untested: boolean;
  /** True while capabilities are still loading — callers should not gate yet. */
  loading: boolean;
  /** The full record, when known. */
  capability?: KindCapability;
}

/**
 * Resolve one kind's availability. FAILS OPEN: while loading, when the backend marks the result
 * degraded, or when the kind is absent from the registry, it reports `available` so the console
 * never hides real capability on missing data. Only an explicit `unavailable`/`untested` verdict
 * from the fused registry gates the UI.
 */
export function useKindAvailability(kind: string): KindAvailability {
  const { data, isLoading } = useCapabilities();
  const cap = data?.kinds?.[kind];
  const verdict: ArchVerdict = cap?.verdict ?? "available";
  return {
    verdict,
    reason: cap?.reason ?? "",
    unavailable: verdict === "unavailable",
    untested: verdict === "untested",
    loading: isLoading,
    capability: cap,
  };
}
