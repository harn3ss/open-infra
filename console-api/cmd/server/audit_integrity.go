package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7"
	"k8s.io/client-go/kubernetes"
)

// The audit-integrity view — the tamper-evidence half of the Audit page.
//
// audit-offsite (a CronJob) ships the API-server audit log to a WORM bucket as a hash chain and
// periodically re-verifies it, publishing the outcome to status/latest.json. This endpoint reads
// that outcome so the console can show whether the off-site audit record is intact, when it was
// last checked, and where the chain head is. It is a READ of the last automated verification: the
// authoritative, tamper-evident record is the locked segments themselves, which the CronJob (and
// anyone with read access) verifies from their contents alone — see docs/audit-offsite.md.
//
// Admin-gated with the same SubjectAccessReview as the rest of the Audit view.

type auditIntegrityResp struct {
	Available  bool            `json:"available"`            // false until audit-offsite has verified once
	Note       string          `json:"note,omitempty"`       // why it is unavailable, if so
	Report     json.RawMessage `json:"report,omitempty"`     // the verifier's statusReport, verbatim
	AgeSeconds *int64          `json:"ageSeconds,omitempty"` // how stale the verification is
}

func handleAuditIntegrity(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			logger.Warn("audit-integrity: minio client", slog.String("error", err.Error()))
			writeJSON(w, http.StatusOK, auditIntegrityResp{Available: false, Note: "object storage unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		bucket := getenv("AUDIT_BUCKET", "openinfra-audit")
		obj, err := cl.GetObject(ctx, bucket, "status/latest.json", minio.GetObjectOptions{})
		if err != nil {
			writeJSON(w, http.StatusOK, auditIntegrityResp{Available: false, Note: "no verification published yet"})
			return
		}
		defer func() { _ = obj.Close() }()
		data, err := io.ReadAll(obj)
		if err != nil {
			// A GetObject on a missing key surfaces the error only on read.
			writeJSON(w, http.StatusOK, auditIntegrityResp{Available: false, Note: "audit off-siting has not run yet"})
			return
		}

		resp := auditIntegrityResp{Available: true, Report: json.RawMessage(data)}
		var probe struct {
			VerifiedAt string `json:"verifiedAt"`
		}
		if json.Unmarshal(data, &probe) == nil && probe.VerifiedAt != "" {
			if t, err := time.Parse(time.RFC3339, probe.VerifiedAt); err == nil {
				age := int64(time.Since(t).Seconds())
				resp.AgeSeconds = &age
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
