package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// Managing kind: Grant (temporal access) from the console — request, approve, revoke.
//
// The security-meaningful part is the APPROVAL workflow (AC-2(2)/AC-5/AC-6(2)): a grant is a request,
// not an entitlement. Create stamps spec.requestedBy from the authenticated requester and NEVER writes
// approval, so a new grant is always AwaitingApproval and confers nothing (the composition renders no
// binding). Approve is a SEPARATE, SAR-gated action that records the approver from the session and
// REFUSES if the approver equals the requester — separation of duties enforced here, and again in the
// composition as a fail-safe (approvedBy == requestedBy → no binding). Like the rest of Security &
// Identity, every handler authorizes the signed-in user with a SubjectAccessReview against
// iam.openinfra.dev before acting, so it is admins-only, exactly as restricted as kubectl.

// grantResource is the shape read back from the apiserver (the fields the console needs).
type grantResource struct {
	Metadata struct {
		Name              string `json:"name"`
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
	Spec struct {
		Subject struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"subject"`
		ClusterRole string `json:"clusterRole"`
		Duration    string `json:"duration"`
		Reason      string `json:"reason"`
		RequestedBy string `json:"requestedBy"`
		Approval    struct {
			ApprovedBy string `json:"approvedBy"`
			ApprovedAt string `json:"approvedAt"`
			Note       string `json:"note"`
		} `json:"approval"`
	} `json:"spec"`
	Status struct {
		Ready   bool   `json:"ready"`
		Phase   string `json:"phase"`
		BoundTo string `json:"boundTo"`
		Message string `json:"message"`
	} `json:"status"`
}

// grantView is the console-facing projection.
type grantView struct {
	Name         string `json:"name"`
	SubjectKind  string `json:"subjectKind"`
	SubjectName  string `json:"subjectName"`
	ClusterRole  string `json:"clusterRole"`
	Duration     string `json:"duration"`
	Reason       string `json:"reason"`
	RequestedBy  string `json:"requestedBy"`
	ApprovedBy   string `json:"approvedBy"`
	ApprovedAt   string `json:"approvedAt"`
	ApprovalNote string `json:"approvalNote,omitempty"`
	Phase        string `json:"phase"`
	Ready        bool   `json:"ready"`
	BoundTo      string `json:"boundTo"`
	Message      string `json:"message"`
	CreatedAt    string `json:"createdAt"`
}

func grantViewOf(g grantResource) grantView {
	phase := g.Status.Phase
	if phase == "" {
		// Older objects (pre-approval-gate) or ones the composition has not reconciled yet.
		phase = "Unknown"
	}
	return grantView{
		Name: g.Metadata.Name, SubjectKind: g.Spec.Subject.Kind, SubjectName: g.Spec.Subject.Name,
		ClusterRole: g.Spec.ClusterRole, Duration: g.Spec.Duration, Reason: g.Spec.Reason,
		RequestedBy: g.Spec.RequestedBy, ApprovedBy: g.Spec.Approval.ApprovedBy,
		ApprovedAt: g.Spec.Approval.ApprovedAt, ApprovalNote: g.Spec.Approval.Note,
		Phase: phase, Ready: g.Status.Ready, BoundTo: g.Status.BoundTo, Message: g.Status.Message,
		CreatedAt: g.Metadata.CreationTimestamp,
	}
}

// getGrant reads a single kind: Grant claim by name.
func (a *authStore) getGrant(ctx context.Context, name string) (*grantResource, error) {
	rc := a.rawREST()
	if rc == nil {
		return nil, fmt.Errorf("no REST client")
	}
	raw, err := rc.Get().AbsPath(grantsAbsPath(a.ns) + "/" + name).DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	var g grantResource
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func handleIAMGrantsList(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "grants", auth.ns, "") {
			return
		}
		rc := auth.rawREST()
		out := []grantView{}
		if rc != nil {
			if raw, err := rc.Get().AbsPath(grantsAbsPath(auth.ns)).DoRaw(r.Context()); err == nil {
				var list struct {
					Items []grantResource `json:"items"`
				}
				if json.Unmarshal(raw, &list) == nil {
					for _, g := range list.Items {
						out = append(out, grantViewOf(g))
					}
				}
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		writeJSON(w, http.StatusOK, out)
	}
}

func handleIAMGrantGet(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "get", "iam.openinfra.dev", "grants", auth.ns, name) {
			return
		}
		g, err := auth.getGrant(r.Context(), name)
		if err != nil {
			writeIAMErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, grantViewOf(*g))
	}
}

type grantReq struct {
	Name        string `json:"name"`
	SubjectKind string `json:"subjectKind"`
	SubjectName string `json:"subjectName"`
	ClusterRole string `json:"clusterRole"`
	Duration    string `json:"duration"`
	Reason      string `json:"reason"`
}

func handleIAMGrantCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in grantReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		in.SubjectName = strings.TrimSpace(in.SubjectName)
		in.ClusterRole = strings.TrimSpace(in.ClusterRole)
		in.Duration = strings.TrimSpace(in.Duration)
		if !validName(in.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a lowercase DNS label (a-z, 0-9, -)"})
			return
		}
		if in.SubjectKind != "User" && in.SubjectKind != "Group" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subjectKind must be User or Group"})
			return
		}
		if in.SubjectName == "" || in.ClusterRole == "" || in.Duration == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subjectName, clusterRole and duration are required"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "grants", auth.ns, in.Name) {
			return
		}
		// requestedBy is the authenticated requester — never taken from the client. approval is NEVER set
		// here, so a new grant is always AwaitingApproval and confers nothing until a second party approves.
		requester := subjectOf(r)
		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Grant",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec": map[string]any{
				"subject":     map[string]any{"kind": in.SubjectKind, "name": in.SubjectName},
				"clusterRole": in.ClusterRole,
				"duration":    in.Duration,
				"reason":      in.Reason,
				"requestedBy": requester,
			},
		}
		if err := auth.postCR(r.Context(), grantsAbsPath(auth.ns), body); err != nil {
			logger.Error("iam: create grant", "grant", in.Name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: grant requested", "grant", in.Name, "subject", in.SubjectName,
			"clusterRole", in.ClusterRole, "by", requester)
		writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name, "phase": "AwaitingApproval"})
	}
}

type grantApproveReq struct {
	Note string `json:"note"`
}

// approvalDecision is the pure separation-of-duties gate for approving a grant (AC-5). It returns an
// empty msg when the approval may proceed; otherwise the HTTP status + a user-facing reason. Rules:
//   - approval must be attributable — an empty approver (auth off / no identity) cannot approve;
//   - the approver must differ from the requester (when the requester is known);
//   - a grant already approved is not re-approved.
//
// The composition enforces the same approvedBy != requestedBy invariant as a fail-safe, so a grant that
// somehow reached an approved-by-requester state still confers no binding.
func approvalDecision(approver, requestedBy, existingApprovedBy string) (status int, msg string) {
	if approver == "" {
		return http.StatusBadRequest, "approval requires an authenticated identity (AC-5); enable auth to approve grants"
	}
	if existingApprovedBy != "" {
		return http.StatusConflict, "grant is already approved by " + existingApprovedBy
	}
	if requestedBy != "" && approver == requestedBy {
		return http.StatusConflict, "the approver must differ from the requester (separation of duties, AC-5)"
	}
	return 0, ""
}

func handleIAMGrantApprove(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var in grantApproveReq
		_ = json.NewDecoder(r.Body).Decode(&in) // body optional (just a note)
		// Approval is an authorization act distinct from requesting; it must be attributable.
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "grants", auth.ns, name) {
			return
		}
		approver := subjectOf(r)
		g, err := auth.getGrant(r.Context(), name)
		if err != nil {
			writeIAMErr(w, err)
			return
		}
		if status, msg := approvalDecision(approver, g.Spec.RequestedBy, g.Spec.Approval.ApprovedBy); msg != "" {
			writeJSON(w, status, map[string]string{"error": msg})
			return
		}
		patch := map[string]any{"spec": map[string]any{"approval": map[string]any{
			"approvedBy": approver,
			"approvedAt": time.Now().UTC().Format(time.RFC3339),
			"note":       strings.TrimSpace(in.Note),
		}}}
		if err := auth.patchCR(r.Context(), grantsAbsPath(auth.ns)+"/"+name, patch); err != nil {
			logger.Error("iam: approve grant", "grant", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: grant approved", "grant", name, "requestedBy", g.Spec.RequestedBy, "approvedBy", approver)
		writeJSON(w, http.StatusOK, map[string]string{"name": name, "approvedBy": approver, "phase": "Active"})
	}
}

func handleIAMGrantDelete(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "delete", "iam.openinfra.dev", "grants", auth.ns, name) {
			return
		}
		if err := auth.deleteCR(r.Context(), grantsAbsPath(auth.ns)+"/"+name); err != nil {
			logger.Error("iam: revoke grant", "grant", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: grant revoked", "grant", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}
