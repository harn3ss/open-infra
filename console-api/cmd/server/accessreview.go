package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/harn3ss/open-infra/console-api/internal/accessreview"
)

// The access-recertification report — the periodic "does this person still need this access?" review
// (NIST AC-2(3)/AC-2(j)/AC-6(7)). It composes what the console already holds — Users, Groups, Roles,
// Policies, temporal Grants, and the audit trail — into one per-principal view with review flags, so an
// admin can certify or revoke standing access. Read-only and admin-gated (same SubjectAccessReview as
// the IAM and Audit views: this is everyone's access, so it is exactly as sensitive).
//
// The pure composition lives in internal/accessreview; this handler only gathers the live inputs
// (including "last seen", derived from the same Loki audit streams the Audit view uses) and stamps the
// clock.

// grantForReview is the subset of a kind: Grant this report needs.
type grantForReview struct {
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
	} `json:"spec"`
	Status struct {
		Ready   bool   `json:"ready"`
		Message string `json:"message"`
	} `json:"status"`
}

func grantsAbsPath(ns string) string {
	return "/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/grants"
}

// listGrantsForReview best-effort lists temporal grants; a missing CRD (feature disabled) → none.
func (a *authStore) listGrantsForReview(ctx context.Context) []grantForReview {
	rc := a.rawREST()
	if rc == nil {
		return nil
	}
	raw, err := rc.Get().AbsPath(grantsAbsPath(a.ns)).DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []grantForReview `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list.Items
}

// lastSeenByActor queries the same two audit streams the Audit view merges (k8s-audit +
// console iam:), over `since`, and returns each actor's most-recent activity time. Best-effort: if Loki
// is down the map is empty and every account simply shows "no activity observed" (the report says so).
// Because queryLoki returns newest-first, the FIRST time we see an actor is its last-seen.
// It also reports whether the activity source was REACHABLE: reachable is true iff the authoritative
// k8s-audit query succeeded (empty-but-reachable still counts). When false the caller must NOT treat an
// absent last-seen as inactivity — a Loki outage would otherwise flag every account for review.
func lastSeenByActor(ctx context.Context, since time.Duration, logger *slog.Logger) (map[string]time.Time, bool) {
	seen := map[string]time.Time{}
	record := func(actor string, ts time.Time) {
		if actor == "" {
			return
		}
		if _, ok := seen[actor]; !ok {
			seen[actor] = ts
		}
	}
	// A generous cap: enough to reach real users behind the controller-dominated stream, bounded so the
	// report stays cheap. Users active only beyond this many events show as unseen — the note is explicit
	// that "last seen" is window/retention-limited.
	const fetch = 5000
	reachable := false
	if vals, err := queryLoki(ctx, `{job="k3s-audit"}`, since, fetch); err != nil {
		logger.Warn("access-review: k8s-audit query failed", "error", err.Error())
	} else {
		reachable = true // the authoritative activity source answered (even if empty)
		for _, v := range vals {
			if e, ok := auditFromK8s(v); ok {
				record(e.Actor, e.Time)
			}
		}
	}
	if vals, err := queryLoki(ctx, `{namespace="open-infra-console"} |= "iam:"`, since, fetch); err == nil {
		for _, v := range vals {
			if e, ok := auditFromConsole(v); ok {
				record(e.Actor, e.Time)
			}
		}
	}
	return seen, reachable
}

func handleAccessReview(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		ctx := r.Context()

		// Lookback window for "last seen" (also the honesty scope). Default 90d; bounded.
		lookbackDays := 90
		if s := r.URL.Query().Get("lookbackDays"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 365 {
				lookbackDays = n
			}
		}
		dormancyDays := 90
		if s := r.URL.Query().Get("dormancyDays"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 365 {
				dormancyDays = n
			}
		}
		lastSeen, activityReachable := lastSeenByActor(ctx, time.Duration(lookbackDays)*24*time.Hour, logger)

		// Users, with sign-in capability resolved from the password Secret.
		var users []accessreview.UserInput
		for _, u := range auth.listCRDUsers(ctx) {
			_, hasPw := auth.crdPasswordHash(ctx, u)
			users = append(users, accessreview.UserInput{
				Name: u.Metadata.Name, DisplayName: u.Spec.DisplayName, Source: u.Spec.Source,
				Disabled: u.Spec.Disabled, HasPassword: hasPw, Groups: u.Spec.Groups,
				LastSeen: lastSeen[u.Metadata.Name],
			})
		}

		var groups []accessreview.GroupInput
		for _, g := range auth.listCRDGroups(ctx) {
			groups = append(groups, accessreview.GroupInput{
				Name: g.Metadata.Name, ClusterRole: g.Spec.ClusterRole,
				BoundTo: g.Status.BoundTo, Ready: g.Status.Ready,
			})
		}

		var roles []accessreview.RoleInput
		for _, ro := range auth.listCRDRoles(ctx) {
			roles = append(roles, accessreview.RoleInput{
				Name: ro.Metadata.Name, Description: ro.Spec.Description,
				ClusterRole: ro.Status.ClusterRole, Policies: ro.Spec.Policies, Ready: ro.Status.Ready,
			})
		}

		var policies []accessreview.PolicyInput
		for _, po := range auth.listCRDPolicies(ctx) {
			n := 0
			for _, st := range po.Spec.Statements {
				n += len(st.Actions)
			}
			policies = append(policies, accessreview.PolicyInput{
				Name: po.Metadata.Name, Description: po.Spec.Description, ActionCount: n,
			})
		}

		var grants []accessreview.GrantInput
		for _, gr := range auth.listGrantsForReview(ctx) {
			created := time.Time{}
			if gr.Metadata.CreationTimestamp != "" {
				if t, err := time.Parse(time.RFC3339, gr.Metadata.CreationTimestamp); err == nil {
					created = t
				}
			}
			grants = append(grants, accessreview.GrantInput{
				Name: gr.Metadata.Name, SubjectKind: gr.Spec.Subject.Kind, SubjectName: gr.Spec.Subject.Name,
				ClusterRole: gr.Spec.ClusterRole, Reason: gr.Spec.Reason, Duration: gr.Spec.Duration,
				CreatedAt: created, Bound: gr.Status.Ready, Message: gr.Status.Message,
			})
		}

		report := accessreview.Build(accessreview.Inputs{
			ConsoleNS: auth.ns, LookbackDays: lookbackDays, DormancyDays: dormancyDays,
			ActivitySourceReachable: activityReachable,
			Users:                   users, Groups: groups, Roles: roles, Policies: policies, Grants: grants,
		}, time.Now())
		report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, report)
	}
}
