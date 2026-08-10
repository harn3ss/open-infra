package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The audit-integrity view — the tamper-evidence half of the Audit page.
//
// audit-offsite (a CronJob) ships the API-server audit log to a WORM bucket as a hash chain,
// verifies it (reading each segment's LOCKED ORIGINAL version, so a shadowing overwrite can't fool
// it), and publishes the outcome to status/latest.json. It ALSO records the verified head (seq +
// hash) in a Kubernetes ConfigMap — a different trust domain than the object bucket.
//
// This endpoint does not trust status/latest.json on its own (a bucket-writer could forge it).
// It cross-checks the bucket's reported head against the ConfigMap anchor and requires the two to
// agree AND the verification to be fresh before it reports the trail intact. Forging the banner
// green would therefore require compromising BOTH the bucket and Kubernetes RBAC. See
// docs/audit-offsite.md.
//
// Admin-gated with the same SubjectAccessReview as the rest of the Audit view.

// maxIntegrityStale is how old the last verification may be before we stop trusting it (verify runs
// hourly; allow a few misses before flagging).
const maxIntegrityStale = 3 * time.Hour

type auditIntegrityResp struct {
	Available   bool            `json:"available"`             // false until audit-offsite has verified once
	Intact      bool            `json:"intact"`                // the trustworthy verdict: report intact AND anchor agrees AND fresh
	AnchorMatch *bool           `json:"anchorMatch,omitempty"` // did the bucket status agree with the k8s anchor?
	Note        string          `json:"note,omitempty"`        // why unavailable / not trusted, if so
	AgeSeconds  *int64          `json:"ageSeconds,omitempty"`  // how stale the verification is
	Report      json.RawMessage `json:"report,omitempty"`      // the verifier's statusReport, verbatim
}

// bucketStatus mirrors the fields audit-offsite writes to status/latest.json that we cross-check.
type bucketStatus struct {
	Intact     bool   `json:"intact"`
	HeadSeq    int    `json:"headSeq"`
	HeadHash   string `json:"headHash"`
	VerifiedAt string `json:"verifiedAt"`
}

// anchorState mirrors the audit-offsite-anchor ConfigMap.
type anchorState struct {
	HeadSeq  int    `json:"headSeq"`
	HeadHash string `json:"headHash"`
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
			writeJSON(w, http.StatusOK, auditIntegrityResp{Available: false, Note: "audit off-siting has not run yet"})
			return
		}

		var bs bucketStatus
		if json.Unmarshal(data, &bs) != nil {
			writeJSON(w, http.StatusOK, auditIntegrityResp{Available: false, Note: "unreadable verification status"})
			return
		}

		resp := auditIntegrityResp{Available: true, Report: json.RawMessage(data)}

		// Freshness.
		fresh := true
		if bs.VerifiedAt != "" {
			if t, perr := time.Parse(time.RFC3339, bs.VerifiedAt); perr == nil {
				age := int64(time.Since(t).Seconds())
				resp.AgeSeconds = &age
				fresh = time.Since(t) <= maxIntegrityStale
			}
		}

		// Cross-domain anchor: the bucket status must agree with the ConfigMap the CronJob writes in
		// the monitoring namespace (which a bucket-only attacker cannot reach).
		anchorNS := getenv("AUDIT_ANCHOR_NAMESPACE", "monitoring")
		match := false
		anchorNote := ""
		if cm, aerr := cs.CoreV1().ConfigMaps(anchorNS).Get(ctx, "audit-offsite-anchor", metav1.GetOptions{}); aerr == nil {
			var as anchorState
			if json.Unmarshal([]byte(cm.Data["anchor.json"]), &as) == nil {
				match = as.HeadHash != "" && as.HeadHash == bs.HeadHash && as.HeadSeq == bs.HeadSeq
				if !match {
					anchorNote = "bucket status disagrees with the cross-domain anchor — possible tampering"
				}
			}
		} else {
			anchorNote = "no cross-domain anchor recorded yet"
		}
		resp.AnchorMatch = &match

		resp.Intact = bs.Intact && match && fresh
		if !resp.Intact && anchorNote != "" {
			resp.Note = anchorNote
		} else if !resp.Intact && !fresh {
			resp.Note = "last verification is stale"
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
