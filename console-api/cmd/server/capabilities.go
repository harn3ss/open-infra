package main

import (
	"log/slog"
	"net/http"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// Architecture capability (#41 Phase 3). The console must not offer a kind it cannot run, nor
// silently hide it — it must show it disabled with an honest reason. This endpoint is the FIRST
// runtime consumer of the single source of truth, the declared per-kind architecture registry
// (platform/arch/kind-architectures.yaml -> ConfigMap openinfra-kind-architectures), fused with
// the cluster's live node architectures. It fails OPEN: if either input is unavailable it gates
// nothing (better a permitted-but-unverified create than a console that hides real capability).
const (
	archConfigMapNS   = "crossplane-system"
	archConfigMapName = "openinfra-kind-architectures"
	archConfigMapKey  = "kinds.yaml"
)

// archEntry mirrors one row of kinds.yaml: each arch is one of supported|unsupported|untested.
type archEntry struct {
	Amd64 string `json:"amd64"`
	Arm64 string `json:"arm64"`
	Image string `json:"image,omitempty"`
	Note  string `json:"note,omitempty"`
}

type kindCapability struct {
	Kind            string   `json:"kind"`
	Verdict         string   `json:"verdict"` // available | untested | unavailable
	SupportedArches []string `json:"supportedArches"`
	UntestedArches  []string `json:"untestedArches,omitempty"`
	Reason          string   `json:"reason,omitempty"` // human-readable, set for untested/unavailable
	Note            string   `json:"note,omitempty"`   // passthrough from the registry
}

type capabilitiesResponse struct {
	NodeArches []string                  `json:"nodeArches"`
	Kinds      map[string]kindCapability `json:"kinds"`
	// Degraded is true when arch data could not be fully determined, so the UI knows the
	// verdicts are permissive (nothing gated) rather than authoritative.
	Degraded bool   `json:"degraded"`
	Note     string `json:"note,omitempty"`
}

func handleCapabilities(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		resp := capabilitiesResponse{NodeArches: []string{}, Kinds: map[string]kindCapability{}}

		// 1. The cluster's node architectures — "what can actually run here".
		archSet := map[string]bool{}
		if nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err != nil {
			logger.Error("capabilities: list nodes", "err", err)
			resp.Degraded = true
			resp.Note = "could not list nodes; architecture gating disabled"
		} else {
			for _, n := range nodes.Items {
				if a := n.Status.NodeInfo.Architecture; a != "" {
					archSet[a] = true
				}
			}
		}
		for a := range archSet {
			resp.NodeArches = append(resp.NodeArches, a)
		}
		sort.Strings(resp.NodeArches)

		// 2. The declared per-kind architecture registry (the single source of truth).
		cm, err := cs.CoreV1().ConfigMaps(archConfigMapNS).Get(ctx, archConfigMapName, metav1.GetOptions{})
		if err != nil {
			logger.Error("capabilities: get arch registry ConfigMap", "err", err)
			resp.Degraded = true
			if resp.Note == "" {
				resp.Note = "architecture registry unavailable; nothing gated"
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		var registry map[string]archEntry
		if err := yaml.Unmarshal([]byte(cm.Data[archConfigMapKey]), &registry); err != nil {
			logger.Error("capabilities: parse kinds.yaml", "err", err)
			resp.Degraded = true
			resp.Note = "architecture registry malformed; nothing gated"
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// 3. Resolve each declared kind against the cluster's arch set. Fail OPEN: if we couldn't
		//    determine node arches, mark everything available rather than disabling the whole UI.
		gate := !resp.Degraded && len(resp.NodeArches) > 0
		for kind, e := range registry {
			resp.Kinds[kind] = resolveKind(kind, e, resp.NodeArches, gate)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// resolveKind computes one kind's availability verdict against the cluster's node arches. Pure +
// unit-tested (the arm64-only unavailable path can't be exercised against a cluster that has amd64
// nodes). `gate` is false when arch data was indeterminate — then everything is available (fail open).
func resolveKind(kind string, e archEntry, nodeArches []string, gate bool) kindCapability {
	supp := archesWithState(e, "supported")
	unt := archesWithState(e, "untested")
	kc := kindCapability{
		Kind:            kind,
		SupportedArches: supp,
		UntestedArches:  unt,
		Note:            e.Note,
	}
	switch {
	case !gate:
		kc.Verdict = "available"
	case intersects(nodeArches, supp):
		// At least one node arch supports this kind — the composition/admission places it.
		kc.Verdict = "available"
	case intersects(nodeArches, unt):
		kc.Verdict = "untested"
		kc.Reason = "untested on this cluster's architecture (" + joinOr(nodeArches) + ") — permitted, but not verified to run"
	default:
		kc.Verdict = "unavailable"
		if len(supp) > 0 {
			kc.Reason = "requires " + joinOr(supp) + "; this cluster has only " + joinOr(nodeArches) + " node(s)"
		} else {
			kc.Reason = "no supported architecture on this cluster (" + joinOr(nodeArches) + ")"
		}
	}
	return kc
}

// archesWithState returns the arch names whose declared state equals `state`.
func archesWithState(e archEntry, state string) []string {
	var out []string
	if e.Amd64 == state {
		out = append(out, "amd64")
	}
	if e.Arm64 == state {
		out = append(out, "arm64")
	}
	return out
}

func intersects(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

// joinOr renders a human list: "amd64", "amd64 or arm64", "a, b, or c".
func joinOr(xs []string) string {
	switch len(xs) {
	case 0:
		return "none"
	case 1:
		return xs[0]
	case 2:
		return xs[0] + " or " + xs[1]
	default:
		return strings.Join(xs[:len(xs)-1], ", ") + ", or " + xs[len(xs)-1]
	}
}
