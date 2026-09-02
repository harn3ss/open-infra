package main

// TrainingJob → ModelPackage registration (the one manual hop in the train→serve loop).
//
// A kind: TrainingJob runs a container to completion and writes a model artifact to a MinIO
// bucket. To serve it you register it as a kind: ModelPackage (the registry entry), have someone
// approve that package, then promote it to a kind: Model. Steps 2–4 already exist (the console's
// approve control and the ModelPackage "Deploy" bridge that creates a Model). Only step 1 —
// turning a finished TrainingJob into a ModelPackage — had no first-party path; users hand-wrote
// the ModelPackage and copied the artifact bucket/key across by eye.
//
// This endpoint closes that hop. The design question it answers (polyhedron #55) is an
// AUTHORIZATION one, not a plumbing one: the identity that can run a TrainingJob is NOT
// automatically the identity that may publish a servable model. So registration must not be done
// by a controller with ambient authority reacting to Job completion — that would let a
// train-capable, serve-incapable user promote by side effect. Instead it is a deliberate user
// action, authorized AS the signed-in user via a SubjectAccessReview (the same one-policy-world
// check every other BFF-native mutation uses):
//
//   - creating the ModelPackage is gated on `create modelpackages` for the signed-in user;
//   - the package is always born PendingManualApproval — never Approved — so serving still
//     requires a human approval AND a separate `create models` (the Deploy step) which is itself
//     SAR-gated. A user who can train but cannot create Models therefore cannot reach a served
//     endpoint through this path.
//
// No controller, no ambient authority, no owner-impersonation webhook: the promotion travels
// through the promoting user's own RBAC at every step.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// registerRequest is the body of POST /api/trainingjobs/{namespace}/{name}/register.
type registerRequest struct {
	ModelName   string `json:"modelName"`             // model group/family (required)
	Version     string `json:"version,omitempty"`     // version label; defaults to the timestamp
	Image       string `json:"image"`                 // SERVING image (required) — differs from the training image
	Port        int    `json:"port,omitempty"`        // serving port (must not be 8080)
	Framework   string `json:"framework,omitempty"`   // optional label (pytorch, sklearn, …)
	Description string `json:"description,omitempty"` // optional human description
}

func handleTrainingJobRegister(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")

		// Authorize AS the signed-in user: may they create a ModelPackage here? A user who can
		// run TrainingJobs but not publish registry entries is denied here, by construction —
		// the ServiceAccount's broader rights never leak into the decision.
		if !authorize(w, r, cs, auth, logger, "create", "openinfra.dev", "modelpackages", ns, "") {
			return
		}

		var in registerRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		in.ModelName, in.Image = strings.TrimSpace(in.ModelName), strings.TrimSpace(in.Image)
		if in.ModelName == "" || in.Image == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "modelName and image (the serving container) are required"})
			return
		}
		if in.Port == 8080 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "serving port must not be 8080 (reserved for the endpoint proxy)"})
			return
		}

		ctx := r.Context()

		// Read the finished TrainingJob for the artifact location it wrote to.
		raw, err := cs.CoreV1().RESTClient().Get().
			AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/trainingjobs/" + name).DoRaw(ctx)
		if err != nil {
			logger.Warn("register: read trainingjob", "err", err, "ns", ns, "name", name)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "training job not found: " + name})
			return
		}
		var tj struct {
			Spec struct {
				Output struct {
					Bucket string `json:"bucket"`
					Prefix string `json:"prefix"`
				} `json:"output"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &tj); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "parse training job"})
			return
		}
		if tj.Spec.Output.Bucket == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "training job has no spec.output.bucket to register from"})
			return
		}

		version := in.Version
		if version == "" {
			version = fmt.Sprintf("%d", time.Now().Unix())
		}
		mpName := modelPackageName(in.ModelName, version)

		// Construct the ModelPackage claim. approvalStatus is always PendingManualApproval — this
		// endpoint registers, it never approves. Serving is still two deliberate, separately
		// authorized steps away (approve, then Deploy→Model).
		spec := map[string]any{
			"modelName": in.ModelName,
			"version":   version,
			"artifact": map[string]any{
				"bucket": tj.Spec.Output.Bucket,
				"key":    tj.Spec.Output.Prefix,
			},
			"image":          in.Image,
			"approvalStatus": "PendingManualApproval",
			"description":    in.Description,
		}
		if in.Port != 0 {
			spec["port"] = in.Port
		}
		if in.Framework != "" {
			spec["framework"] = in.Framework
		}
		if in.Description == "" {
			spec["description"] = fmt.Sprintf("Registered from TrainingJob %s/%s", ns, name)
		}
		mp := map[string]any{
			"apiVersion": "openinfra.dev/v1",
			"kind":       "ModelPackage",
			"metadata": map[string]any{
				"name":      mpName,
				"namespace": ns,
				"annotations": map[string]any{
					"openinfra.dev/registered-from-trainingjob": name,
				},
			},
			"spec": spec,
		}
		body, _ := json.Marshal(mp)

		created, err := cs.CoreV1().RESTClient().Post().
			AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/modelpackages").
			Body(body).DoRaw(ctx)
		if err != nil {
			logger.Error("register: create modelpackage", "err", err, "ns", ns, "name", mpName)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create model package: " + err.Error()})
			return
		}
		logger.Info("registered training job as model package", "ns", ns, "trainingjob", name, "modelpackage", mpName)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(created)
	}
}

// modelPackageName builds a DNS-1123 name for the ModelPackage from the model group and version.
func modelPackageName(modelName, version string) string {
	safe := func(s string) string {
		s = strings.ToLower(s)
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				b.WriteRune(r)
			} else {
				b.WriteRune('-')
			}
		}
		return strings.Trim(b.String(), "-")
	}
	name := safe(modelName) + "-" + safe(version)
	if len(name) > 253 {
		name = name[:253]
	}
	return name
}
