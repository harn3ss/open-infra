//go:build convergence

package main

// Shared helpers for the per-plane oracle adapters. Each adapter drives/probes a real sandbox
// workload by shelling out to kubectl (the DRIVE half is domain-specific), but the VERDICT always
// goes through the singular engine — runOracle (recover) or runContinuous (tolerate/deny) — so no
// scenario forks the judge. The workload access is behind an interface in each adapter, so the
// verdict logic is unit-provable RED and GREEN with a fake, no cluster required.

import (
	"os"
	"os/exec"
	"strings"
)

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

// kubectl runs kubectl and returns trimmed stdout (stderr rides on the error).
func kubectl(args ...string) (string, error) {
	out, err := exec.Command("kubectl", args...).Output()
	return strings.TrimSpace(string(out)), err
}

// kubectlOK reports whether a kubectl command succeeded (exit 0) — used by boolean probes.
func kubectlOK(args ...string) bool {
	return exec.Command("kubectl", args...).Run() == nil
}
