package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

// Managing kind: Grant (temporary access) from the console — request, approve, revoke.
//
// A grant attaches IAM policies (AWS managed policies such as aws-readonlyaccess or aws-poweruseraccess,
// or customer policies) to a user, or to every member of a group, for a window of at most 24 hours from
// its approval. The one evaluator and the IAM compiler read every approved grant whose window is open as
// an attachment of its policies (iamauthz.GrantWindow), so this handler never binds anything: it writes
// the request, records the approval, and deletes the grant on revoke.
//
// The security-meaningful part is the APPROVAL workflow (AC-2(2)/AC-5/AC-6(2)): a grant is a request,
// not an entitlement. Create stamps spec.requestedBy from the signed-in requester and NEVER writes
// approval, so a new grant attaches nothing. Approve is a SEPARATE action that records the approver from
// the session and REFUSES if the approver is the requester — separation of duties enforced here, and
// again by the evaluator (approvedBy == requestedBy attaches nothing). Every handler is gated by its IAM
// action (routes.go: iam:Attach*Policy to request or approve, iam:DetachUserPolicy to revoke) and
// authorizes the signed-in user on iam.openinfra.dev grants before acting.

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
		Policies    []string `json:"policies"`
		Duration    string   `json:"duration"`
		Reason      string   `json:"reason"`
		RequestedBy string   `json:"requestedBy"`
		Approval    struct {
			ApprovedBy string `json:"approvedBy"`
			ApprovedAt string `json:"approvedAt"`
			Note       string `json:"note"`
		} `json:"approval"`
	} `json:"spec"`
	Status struct {
		Phase   string `json:"phase"`
		Message string `json:"message"`
	} `json:"status"`
}

// grantSpec is the grant as the evaluator decides it.
func (g grantResource) grantSpec() iamauthz.GrantSpec {
	return iamauthz.GrantSpec{
		SubjectKind: g.Spec.Subject.Kind, SubjectName: g.Spec.Subject.Name, Policies: g.Spec.Policies,
		Duration: g.Spec.Duration, RequestedBy: g.Spec.RequestedBy,
		ApprovedBy: g.Spec.Approval.ApprovedBy, ApprovedAt: g.Spec.Approval.ApprovedAt,
	}
}

// grantView is the console-facing projection.
type grantView struct {
	Name         string   `json:"name"`
	SubjectKind  string   `json:"subjectKind"`
	SubjectName  string   `json:"subjectName"`
	Policies     []string `json:"policies"`
	Duration     string   `json:"duration"`
	Reason       string   `json:"reason"`
	RequestedBy  string   `json:"requestedBy"`
	ApprovedBy   string   `json:"approvedBy"`
	ApprovedAt   string   `json:"approvedAt"`
	ApprovalNote string   `json:"approvalNote,omitempty"`
	// Phase is AwaitingApproval, Active (its policies are attached now), Expired (its window has passed;
	// the grant reconciler deletes it within a minute), NotGrantable (it attaches nothing: approved by
	// its requester, or a duration over 24h) or Approved (approved, its window not yet open).
	Phase string `json:"phase"`
	// Active is whether its policies are attached to the subject right now.
	Active bool `json:"active"`
	// AttachedTo is the subject's IAM ARN: the user or group the policies are attached to.
	AttachedTo string `json:"attachedTo"`
	// ExpiresAt is when the policies stop being attached (RFC 3339), once approved.
	ExpiresAt string `json:"expiresAt,omitempty"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
}

// Grant phases.
const (
	grantAwaitingApproval = "AwaitingApproval"
	grantNotGrantable     = "NotGrantable"
	grantApproved         = "Approved"
	grantActive           = "Active"
	grantExpired          = "Expired"
)

// grantPhase is where a grant stands at now, decided exactly as the evaluator decides it.
func grantPhase(g grantResource, now time.Time) (phase string, until time.Time, why string) {
	from, until, why := iamauthz.GrantWindow(g.grantSpec())
	switch {
	case g.Spec.Approval.ApprovedBy == "":
		return grantAwaitingApproval, time.Time{}, why
	case why != "":
		return grantNotGrantable, time.Time{}, why
	case now.Before(from):
		return grantApproved, until, ""
	case now.Before(until):
		return grantActive, until, ""
	}
	return grantExpired, until, ""
}

func grantViewOf(r *http.Request, g grantResource, now time.Time) grantView {
	phase, until, why := grantPhase(g, now)
	v := grantView{
		Name: g.Metadata.Name, SubjectKind: g.Spec.Subject.Kind, SubjectName: g.Spec.Subject.Name,
		Policies: nonNil(g.Spec.Policies), Duration: g.Spec.Duration, Reason: g.Spec.Reason,
		RequestedBy: g.Spec.RequestedBy, ApprovedBy: g.Spec.Approval.ApprovedBy,
		ApprovedAt: g.Spec.Approval.ApprovedAt, ApprovalNote: g.Spec.Approval.Note,
		Phase: phase, Active: phase == grantActive,
		AttachedTo: iamEntityARN(strings.ToLower(g.Spec.Subject.Kind), callerAccount(r), g.Spec.Subject.Name),
		CreatedAt:  g.Metadata.CreationTimestamp,
	}
	if !until.IsZero() {
		v.ExpiresAt = until.UTC().Format(time.RFC3339)
	}
	switch phase {
	case grantActive:
		v.Message = fmt.Sprintf("%s attached to %s until %s", strings.Join(v.Policies, ", "), v.AttachedTo, v.ExpiresAt)
	case grantExpired:
		v.Message = "expired at " + v.ExpiresAt + ": its policies are no longer attached"
	case grantApproved:
		v.Message = "approved; its policies are attached from " + g.Spec.Approval.ApprovedAt
	default:
		v.Message = why
	}
	return v
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
					now := time.Now()
					for _, g := range list.Items {
						out = append(out, grantViewOf(r, g, now))
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
		writeJSON(w, http.StatusOK, grantViewOf(r, *g, time.Now()))
	}
}

type grantReq struct {
	Name        string   `json:"name"`
	SubjectKind string   `json:"subjectKind"`
	SubjectName string   `json:"subjectName"`
	Policies    []string `json:"policies"`
	// ClusterRole is the old ClusterRole-elevation form, refused: a grant attaches IAM policies.
	ClusterRole string `json:"clusterRole"`
	Duration    string `json:"duration"`
	Reason      string `json:"reason"`
}

// maxGrantPolicies is how many policies one grant may attach (AWS's default managed policies per user).
const maxGrantPolicies = 10

// grantPolicyRef is a Policy name, or "<namespace>/<name>" for one outside the grant's namespace (the
// XRD's pattern).
var grantPolicyRef = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?/)?[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// validateGrantReq checks a grant request before anything is authorized or written: "" when it is
// well-formed, else the message (an AWS ValidationError).
func validateGrantReq(in *grantReq) string {
	in.Name = strings.TrimSpace(in.Name)
	in.SubjectName = strings.TrimSpace(in.SubjectName)
	in.Duration = strings.TrimSpace(in.Duration)
	in.Policies = cleanGroups(in.Policies)
	switch {
	case strings.TrimSpace(in.ClusterRole) != "":
		return "clusterRole is not supported: a grant attaches IAM policies to its subject for its window — name them in policies (for example aws-readonlyaccess or aws-poweruseraccess)"
	case !validName(in.Name):
		return "name must be a lowercase DNS label (a-z, 0-9, -)"
	case in.SubjectKind != "User" && in.SubjectKind != "Group":
		return "subjectKind must be User or Group"
	case in.SubjectName == "":
		return "subjectName is required"
	case strings.Contains(in.SubjectName, "/") || len(in.SubjectName) > 128:
		return "subjectName must be the name of a user or group in this account"
	case len(in.Policies) == 0:
		return "policies is required: name the policies the grant attaches (for example aws-readonlyaccess)"
	case len(in.Policies) > maxGrantPolicies:
		return fmt.Sprintf("a grant attaches at most %d policies", maxGrantPolicies)
	}
	for _, p := range in.Policies {
		if len(p) > 128 || !grantPolicyRef.MatchString(p) {
			return fmt.Sprintf("%q is not a policy name", p)
		}
	}
	if _, ok := iamauthz.ParseGrantDuration(in.Duration); !ok {
		return "duration must be whole hours, minutes or seconds (for example 30m, 4h or 1h30m), at most 24h"
	}
	return ""
}

// missingPolicy returns the first of the named policies that does not exist ("" when all do), or the
// error reading one. A bare name is a policy in the console's namespace (the IAM home, where the managed
// policies live); "<namespace>/<name>" one in that namespace.
func (a *authStore) missingPolicy(ctx context.Context, names []string) (string, error) {
	rc := a.rawREST()
	if rc == nil {
		return "", fmt.Errorf("no REST client")
	}
	for _, ref := range names {
		ns, name := a.ns, ref
		if i := strings.IndexByte(ref, '/'); i > 0 {
			ns, name = ref[:i], ref[i+1:]
		}
		_, err := rc.Get().AbsPath(policiesAbsPath(ns) + "/" + name).DoRaw(ctx)
		if apierrors.IsNotFound(err) {
			return ref, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", nil
}

func handleIAMGrantCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in grantReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if msg := validateGrantReq(&in); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg, "errorCode": "ValidationError"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "grants", auth.ns, in.Name) {
			return
		}
		// As AWS's AttachUserPolicy: a policy that does not exist cannot be attached.
		if missing, err := auth.missingPolicy(r.Context(), in.Policies); err != nil {
			writeIAMErr(w, err)
			return
		} else if missing != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy " + missing + " does not exist", "errorCode": "NoSuchEntity"})
			return
		}
		// requestedBy is the signed-in requester — never taken from the client. approval is NEVER set here,
		// so a new grant attaches nothing until a second person approves it.
		requester := subjectOf(r)
		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Grant",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec": map[string]any{
				"subject":     map[string]any{"kind": in.SubjectKind, "name": in.SubjectName},
				"policies":    in.Policies,
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
		logger.Info("iam: grant requested", "grant", in.Name, "subject", in.SubjectKind+"/"+in.SubjectName,
			"policies", strings.Join(in.Policies, ","), "duration", in.Duration, "by", requester)
		writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name, "phase": grantAwaitingApproval})
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
// The evaluator holds the same approvedBy != requestedBy invariant on its own, so a grant that somehow
// reached an approved-by-requester state still attaches nothing.
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
		approvedAt := time.Now().UTC()
		patch := map[string]any{"spec": map[string]any{"approval": map[string]any{
			"approvedBy": approver,
			"approvedAt": approvedAt.Format(time.RFC3339),
			"note":       strings.TrimSpace(in.Note),
		}}}
		if err := auth.patchCR(r.Context(), grantsAbsPath(auth.ns)+"/"+name, patch); err != nil {
			logger.Error("iam: approve grant", "grant", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		expires := ""
		if d, ok := iamauthz.ParseGrantDuration(g.Spec.Duration); ok {
			expires = approvedAt.Add(d).Format(time.RFC3339)
		}
		logger.Info("iam: grant approved", "grant", name, "subject", g.Spec.Subject.Kind+"/"+g.Spec.Subject.Name,
			"policies", strings.Join(g.Spec.Policies, ","), "requestedBy", g.Spec.RequestedBy, "approvedBy", approver,
			"expiresAt", expires)
		writeJSON(w, http.StatusOK, map[string]string{"name": name, "approvedBy": approver, "phase": grantActive, "expiresAt": expires})
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
