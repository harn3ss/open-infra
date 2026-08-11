package main

import (
	"log/slog"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/harn3ss/open-infra/console-api/internal/attest"
)

// The compliance-attestation view — the live control-coverage report the console shows and the
// signing CronJob (cmd/attest) signs. Same assembler both places, so what you see is what gets
// signed. Admin-gated. This endpoint returns the report UNSIGNED (the console never holds the signing
// key); the signed, dated, immutable copies live in the WORM audit store under attestations/.
func handleAttestation(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		a := attest.Assemble(r.Context(), cs, auth.ns, getenv("AUDIT_ANCHOR_NAMESPACE", "monitoring"))
		a.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, a)
	}
}
