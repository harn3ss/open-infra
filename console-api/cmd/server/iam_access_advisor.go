package main

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/harn3ss/open-infra/console-api/internal/accessadvisor"
)

// Access Advisor — the AWS-IAM "last accessed / services this identity uses" surface, per principal.
//
// It answers "which open-infra services (resource types) has this principal actually written to, and
// when" — the least-privilege right-sizing view AWS puts on every user/group/role/policy detail page.
// The activity source is the SAME audit trail the Audit and Access-Review views use (k8s-audit +
// console iam:), so its HONESTY BOUNDARY is inherited and surfaced by the assembler's Coverage field:
// the trail records mutations and auth decisions, not reads, and not data-plane object access — so this
// finds unused-for-writes access, never "proven entirely unused". See internal/accessadvisor.
//
// Attribution: k8s-audit records the person (impersonatedUser), not an assumed role. So the User view is
// exact; the Group/Role/Policy views are AGGREGATED across the users who effectively hold the principal,
// and the report says so. Admin-gated identically to Access Review — this is everyone's activity.

// auditEventsForAdvisor queries the two audit streams over `since` and returns every mutation event as an
// accessadvisor.Event (actor + service=resource + verb + time), plus whether the authoritative k8s-audit
// source was reachable (so an outage reads as "unknown", never "no access"). Best-effort, like the
// access-review gather it mirrors.
func auditEventsForAdvisor(ctx context.Context, since time.Duration, logger *slog.Logger) ([]accessadvisor.Event, bool) {
	const fetch = 5000
	var events []accessadvisor.Event
	reachable := false
	if vals, err := queryLoki(ctx, `{job="k3s-audit"}`, since, fetch); err != nil {
		logger.Warn("access-advisor: k8s-audit query failed", "error", err.Error())
	} else {
		reachable = true
		for _, v := range vals {
			if e, ok := auditFromK8s(v); ok {
				events = append(events, accessadvisor.Event{Actor: e.Actor, Service: e.Resource, Verb: e.Verb, Time: e.Time})
			}
		}
	}
	if vals, err := queryLoki(ctx, `{namespace="open-infra-console"} |= "iam:"`, since, fetch); err == nil {
		for _, v := range vals {
			if e, ok := auditFromConsole(v); ok {
				events = append(events, accessadvisor.Event{Actor: e.Actor, Service: e.Resource, Verb: e.Verb, Time: e.Time})
			}
		}
	}
	return events, reachable
}

// resolveAdvisorActors returns the set of human actors whose audited activity should be attributed to a
// principal, plus whether the view is aggregated (true for group/role/policy). The resolution mirrors the
// access-review model: a Role is held by the users in the groups that bind its ClusterRole; a Policy is
// held by the users of the roles that include it, the users it is directly attached to, and the
// principals its dataPlane appliesTo names.
func (a *authStore) resolveAdvisorActors(ctx context.Context, kind, name string) (actors []string, aggregated bool) {
	switch kind {
	case "user":
		return []string{name}, false
	case "group":
		return a.usersInGroups(ctx, map[string]bool{name: true}), true
	case "role":
		roles := a.listCRDRoles(ctx)
		var cr string
		for _, ro := range roles {
			if ro.Metadata.Name == name {
				cr = ro.Status.ClusterRole
				break
			}
		}
		if cr == "" {
			return nil, true
		}
		return a.usersInGroups(ctx, a.groupsBindingClusterRole(ctx, cr)), true
	case "policy":
		groupSet := map[string]bool{}
		userSet := map[string]bool{}
		// Roles that include the policy → the groups binding them.
		for _, ro := range a.listCRDRoles(ctx) {
			if containsStr(ro.Spec.Policies, name) && ro.Status.ClusterRole != "" {
				for g := range a.groupsBindingClusterRole(ctx, ro.Status.ClusterRole) {
					groupSet[g] = true
				}
			}
		}
		// The policy's own dataPlane appliesTo principals (User::x / Group::x).
		for _, po := range a.listCRDPolicies(ctx) {
			if po.Metadata.Name != name || po.Spec.DataPlane == nil {
				continue
			}
			for _, p := range po.Spec.DataPlane.AppliesTo {
				if u, ok := strings.CutPrefix(p, "User::"); ok {
					userSet[u] = true
				} else if g, ok := strings.CutPrefix(p, "Group::"); ok {
					groupSet[g] = true
				}
			}
		}
		// Users the policy is directly attached to (spec.policies), plus users in the resolved groups.
		for _, u := range a.listCRDUsers(ctx) {
			if containsStr(u.Spec.Policies, name) {
				userSet[u.Metadata.Name] = true
			}
		}
		for _, u := range a.usersInGroups(ctx, groupSet) {
			userSet[u] = true
		}
		return keysOf(userSet), true
	}
	return nil, false
}

// usersInGroups returns the names of users whose declared spec.groups intersect the given set.
func (a *authStore) usersInGroups(ctx context.Context, groups map[string]bool) []string {
	if len(groups) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, u := range a.listCRDUsers(ctx) {
		for _, g := range u.Spec.Groups {
			if groups[strings.TrimSpace(g)] {
				set[u.Metadata.Name] = true
				break
			}
		}
	}
	return keysOf(set)
}

// groupsBindingClusterRole returns the custom Groups whose conferred ClusterRole is cr. A custom Group
// confers spec.clusterRole (or status.boundTo minus the openinfra: prefix).
func (a *authStore) groupsBindingClusterRole(ctx context.Context, cr string) map[string]bool {
	out := map[string]bool{}
	if cr == "" {
		return out
	}
	for _, g := range a.listCRDGroups(ctx) {
		conf := g.Spec.ClusterRole
		if conf == "" {
			conf = strings.TrimPrefix(g.Status.BoundTo, "openinfra:")
		}
		if conf == cr {
			out[g.Metadata.Name] = true
		}
	}
	return out
}

func handleIAMAccessAdvisor(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Same admin gate as Access Review / Audit — this exposes everyone's activity.
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		switch kind {
		case "user", "group", "role", "policy":
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be one of user|group|role|policy"})
			return
		}
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}
		lookbackDays := 90
		if s := r.URL.Query().Get("lookbackDays"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 365 {
				lookbackDays = n
			}
		}

		actors, aggregated := auth.resolveAdvisorActors(r.Context(), kind, name)
		events, reachable := auditEventsForAdvisor(r.Context(), time.Duration(lookbackDays)*24*time.Hour, logger)
		report := accessadvisor.Build(kind, name, actors, events, lookbackDays, reachable, aggregated, time.Now())
		report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, report)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
