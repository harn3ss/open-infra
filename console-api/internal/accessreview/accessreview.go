// Package accessreview assembles an access-recertification report: for every principal (a kind: User),
// the standing access it holds (group memberships and the ClusterRoles those confer), any active
// temporal kind: Grant reaching it, when it was last seen acting, and a set of review FLAGS that give a
// recertifier a worklist — dormant accounts, privileged accounts, disabled accounts that still retain
// access, sign-in-less accounts, inert (no-op) group memberships. It is the periodic
// "does this person still need this access?" review NIST AC-2(3)/AC-2(j)/AC-6(7) call for, composed
// from data the console already holds.
//
// Build is PURE — it takes already-fetched inputs plus a clock and returns the report, so it is fully
// deterministic and unit-tested. All Kubernetes / Loki / Secret gathering happens in the caller
// (cmd/server), which converts what it reads into the Input structs here. accessreview has no k8s or
// network dependency of its own.
package accessreview

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// defaultDormancyDays is how long without observed activity marks an ENABLED, signed-in-capable
// account "dormant" — a candidate for review. AC-2 wants stale accounts surfaced; 90 days is the
// common recertification cadence. The caller may override.
const defaultDormancyDays = 90

// builtinGroupRoles maps the built-in group names to the ClusterRole each confers. These are the group
// names that take effect out of the box (openinfra:<name> is in the impersonator ceiling); it MUST stay
// in step with builtinGroups in cmd/server/iam.go and the bindings in
// platform/console/manifests/rbac-roles.yaml. A custom kind: Group carries its own ClusterRole in its
// spec/status instead, so this map is only the built-ins.
var builtinGroupRoles = map[string]string{
	"admins":     "open-infra-console",
	"powerusers": "open-infra-poweruser",
	"readers":    "open-infra-readonly",
}

// adminClusterRole is the full-console-admin ClusterRole; a principal effectively bound to it is
// privileged and gets flagged for careful recertification.
const adminClusterRole = "open-infra-console"

// ── Inputs (what the caller gathers and hands in) ────────────────────────────────

type UserInput struct {
	Name        string
	DisplayName string
	Source      string // "local" | "directory" | …
	Disabled    bool
	HasPassword bool      // can this account actually sign in locally?
	Groups      []string  // declared group memberships
	LastSeen    time.Time // most recent observed activity; zero = none seen in the lookback window
}

type GroupInput struct {
	Name        string
	ClusterRole string // the ClusterRole a custom kind: Group confers (spec/status)
	BoundTo     string // status.boundTo, if bound
	Ready       bool   // a custom Group only takes effect once Ready
}

type RoleInput struct {
	Name        string
	Description string
	ClusterRole string
	Policies    []string
	Ready       bool
}

type PolicyInput struct {
	Name        string
	Description string
	ActionCount int
}

type GrantInput struct {
	Name        string
	SubjectKind string // "User" | "Group"
	SubjectName string
	ClusterRole string
	Reason      string
	Duration    string    // Go duration string, e.g. "4h"
	CreatedAt   time.Time // metadata.creationTimestamp
	Bound       bool      // status.ready — did it actually confer the binding?
	Message     string    // status.message when it conferred nothing
}

// Inputs is the whole gathered snapshot handed to Build.
type Inputs struct {
	ConsoleNS    string
	LookbackDays int // the audit window LastSeen was computed over (0 → unknown/unbounded)
	DormancyDays int // override defaultDormancyDays when > 0
	// ActivitySourceReachable is false when the audit store (Loki) could not be queried, so LastSeen is
	// unavailable for EVERY account. When false, Build suppresses the activity-based flags
	// (no-recent-activity, dormant): a blank LastSeen then means "unknown", not "inactive" — so a
	// monitoring outage cannot flag the whole directory for review.
	ActivitySourceReachable bool
	Users                   []UserInput
	Groups                  []GroupInput
	Roles                   []RoleInput
	Policies                []PolicyInput
	Grants                  []GrantInput
}

// ── Outputs (the report) ─────────────────────────────────────────────────────────

// GrantRef is one active temporal grant reaching a principal.
type GrantRef struct {
	Name        string `json:"name"`
	ClusterRole string `json:"clusterRole"`
	Reason      string `json:"reason,omitempty"`
	Duration    string `json:"duration,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"` // creation + duration, RFC3339; "" if not computable
	ViaGroup    string `json:"viaGroup,omitempty"`  // set when the grant reaches the user through a group
	Bound       bool   `json:"bound"`               // did it actually confer access?
}

// Principal is one account's recertification row.
type Principal struct {
	Name          string     `json:"name"`
	DisplayName   string     `json:"displayName,omitempty"`
	Source        string     `json:"source"`
	Disabled      bool       `json:"disabled"`
	HasPassword   bool       `json:"hasPassword"`
	Admin         bool       `json:"admin"` // effectively holds full console admin
	Groups        []string   `json:"groups"`
	InertGroups   []string   `json:"inertGroups,omitempty"`   // declared but not taking effect
	StandingRoles []string   `json:"standingRoles,omitempty"` // ClusterRoles conferred by effective groups
	Grants        []GrantRef `json:"grants,omitempty"`
	LastSeen      string     `json:"lastSeen,omitempty"` // RFC3339; "" = none seen in the window
	Flags         []string   `json:"flags,omitempty"`    // the recertifier's worklist for this account
}

// RoleRef is reference data: what a kind: Role confers, so the reviewer can judge a membership.
type RoleRef struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	ClusterRole string   `json:"clusterRole,omitempty"`
	Policies    []string `json:"policies,omitempty"`
	Ready       bool     `json:"ready"`
}

// Summary is the report's headline counts — the recertifier reads these first.
type Summary struct {
	Principals         int `json:"principals"`
	Enabled            int `json:"enabled"`
	Disabled           int `json:"disabled"`
	Privileged         int `json:"privileged"`         // effectively console-admin
	WithStandingAccess int `json:"withStandingAccess"` // in ≥1 effective group
	DisabledRetaining  int `json:"disabledRetaining"`  // disabled yet still holds access
	WithActiveGrants   int `json:"withActiveGrants"`   // ≥1 temporal grant reaching them
	NoRecentActivity   int `json:"noRecentActivity"`   // enabled, sign-in-capable, nothing seen
	Dormant            int `json:"dormant"`            // enabled, last seen beyond the dormancy window
	NeedsReview        int `json:"needsReview"`        // principals carrying ≥1 flag
	Policies           int `json:"policies"`
	Roles              int `json:"roles"`
}

// Report is the whole document.
type Report struct {
	GeneratedAt  string `json:"generatedAt"` // stamped by the caller (Build leaves it empty)
	ConsoleNS    string `json:"consoleNamespace"`
	LookbackDays int    `json:"lookbackDays"`
	DormancyDays int    `json:"dormancyDays"`
	// ActivitySourceReachable is false when the audit store was unreachable this run: "last seen" is
	// then unavailable for everyone and the dormant / no-recent-activity flags are suppressed. The UI
	// and any downstream check MUST read this before trusting an absent LastSeen as inactivity.
	ActivitySourceReachable bool        `json:"activitySourceReachable"`
	Principals              []Principal `json:"principals"`
	Roles                   []RoleRef   `json:"roles"`
	Summary                 Summary     `json:"summary"`
	Note                    string      `json:"note"`
}

// Review flag constants — a stable vocabulary the UI and any downstream check can key on.
const (
	FlagPrivileged        = "privileged"              // effectively full console admin
	FlagDisabledRetaining = "retains-access-disabled" // account disabled but still bound to access
	FlagNoRecentActivity  = "no-recent-activity"      // sign-in-capable but unseen in the window
	FlagDormant           = "dormant"                 // active account, last activity beyond dormancy
	FlagNoCredential      = "no-sign-in-credential"   // local account with no password — cannot sign in
	FlagInertGroups       = "inert-group-membership"  // member of group(s) that take no effect
	FlagActiveGrant       = "active-temporal-grant"   // has ≥1 live kind: Grant to re-justify
)

// Build composes the report from the gathered inputs and a clock. Pure and deterministic.
func Build(in Inputs, now time.Time) Report {
	dormancy := in.DormancyDays
	if dormancy <= 0 {
		dormancy = defaultDormancyDays
	}
	dormancyDur := time.Duration(dormancy) * 24 * time.Hour

	// Index the effective groups so membership can be resolved to a ClusterRole and an effect verdict.
	groupByName := make(map[string]GroupInput, len(in.Groups))
	for _, g := range in.Groups {
		groupByName[g.Name] = g
	}

	var principals []Principal
	var sum Summary
	sum.Policies = len(in.Policies)
	sum.Roles = len(in.Roles)

	for _, u := range in.Users {
		p := Principal{
			Name: u.Name, DisplayName: u.DisplayName, Source: u.Source,
			Disabled: u.Disabled, HasPassword: u.HasPassword, Groups: u.Groups,
		}
		if !u.LastSeen.IsZero() {
			p.LastSeen = u.LastSeen.UTC().Format(time.RFC3339)
		}

		// Resolve each declared group to effective/inert and to the ClusterRole it confers.
		roleSet := map[string]bool{}
		for _, gname := range u.Groups {
			gname = strings.TrimSpace(gname)
			if gname == "" {
				continue
			}
			cr, effective := resolveGroup(gname, groupByName)
			if !effective {
				p.InertGroups = append(p.InertGroups, gname)
				continue
			}
			if cr != "" {
				roleSet[cr] = true
			}
		}
		p.StandingRoles = sortedKeys(roleSet)
		p.Admin = roleSet[adminClusterRole]

		// Temporal grants reaching this user: directly (subject User) or through a group they are in.
		p.Grants = grantsFor(u, in.Grants)

		p.Flags = flagsFor(p, u, now, dormancyDur, in.ActivitySourceReachable)

		// Tally.
		sum.Principals++
		if u.Disabled {
			sum.Disabled++
		} else {
			sum.Enabled++
		}
		if p.Admin {
			sum.Privileged++
		}
		if len(p.StandingRoles) > 0 {
			sum.WithStandingAccess++
		}
		if len(p.Grants) > 0 {
			sum.WithActiveGrants++
		}
		if hasFlag(p.Flags, FlagDisabledRetaining) {
			sum.DisabledRetaining++
		}
		if hasFlag(p.Flags, FlagNoRecentActivity) {
			sum.NoRecentActivity++
		}
		if hasFlag(p.Flags, FlagDormant) {
			sum.Dormant++
		}
		if len(p.Flags) > 0 {
			sum.NeedsReview++
		}
		principals = append(principals, p)
	}

	// Deterministic ordering: accounts that need review first (most flags), then by name.
	sort.SliceStable(principals, func(i, j int) bool {
		if len(principals[i].Flags) != len(principals[j].Flags) {
			return len(principals[i].Flags) > len(principals[j].Flags)
		}
		return principals[i].Name < principals[j].Name
	})

	roles := make([]RoleRef, 0, len(in.Roles))
	for _, r := range in.Roles {
		roles = append(roles, RoleRef{
			Name: r.Name, Description: r.Description, ClusterRole: r.ClusterRole,
			Policies: r.Policies, Ready: r.Ready,
		})
	}
	sort.SliceStable(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })

	window := "the configured audit lookback window"
	if in.LookbackDays > 0 {
		window = fmt.Sprintf("the last %d day(s)", in.LookbackDays)
	}
	note := "Access-recertification report supporting NIST AC-2(3)/AC-2(j)/AC-6(7): the standing access " +
		"each account holds, mapped to activity and flagged for review. \"Last seen\" is drawn from the " +
		"audit store over " + window + " and is retention-limited, so an empty value means \"no activity " +
		"observed in that window\", not a proof the account has never been used. This report supports a " +
		"human recertification decision; it does not make one."
	if !in.ActivitySourceReachable {
		note += " NOTE: the activity source (audit store) was UNREACHABLE this run, so \"last seen\" is " +
			"unavailable for every account and the dormant / no-recent-activity flags are suppressed — a " +
			"blank last-seen here means unknown, not inactive."
	}

	return Report{
		ConsoleNS: in.ConsoleNS, LookbackDays: in.LookbackDays, DormancyDays: dormancy,
		ActivitySourceReachable: in.ActivitySourceReachable,
		Principals:              principals, Roles: roles, Summary: sum, Note: note,
	}
}

// resolveGroup returns the ClusterRole a group confers and whether it takes effect. Built-in groups are
// always effective (mapped role); a custom kind: Group is effective only once Ready, and confers the
// ClusterRole in its spec/status.
func resolveGroup(name string, byName map[string]GroupInput) (clusterRole string, effective bool) {
	if cr, ok := builtinGroupRoles[name]; ok {
		return cr, true
	}
	if name == "users" { // every signed-in identity; confers nothing on its own
		return "", true
	}
	if g, ok := byName[name]; ok && g.Ready {
		cr := g.ClusterRole
		if cr == "" {
			cr = strings.TrimPrefix(g.BoundTo, "openinfra:")
		}
		return cr, true
	}
	return "", false // named but not built-in and not a Ready Group → inert
}

// grantsFor returns the active temporal grants reaching a user: directly (subject User) or via a group
// the user belongs to (subject Group). Grants that still exist are active — the expiry reconciler
// deletes them when creation + duration passes.
func grantsFor(u UserInput, all []GrantInput) []GrantRef {
	inGroup := map[string]bool{}
	for _, g := range u.Groups {
		inGroup[strings.TrimSpace(g)] = true
	}
	var out []GrantRef
	for _, g := range all {
		via := ""
		switch g.SubjectKind {
		case "User":
			if g.SubjectName != u.Name {
				continue
			}
		case "Group":
			if !inGroup[g.SubjectName] {
				continue
			}
			via = g.SubjectName
		default:
			continue
		}
		ref := GrantRef{
			Name: g.Name, ClusterRole: g.ClusterRole, Reason: g.Reason,
			Duration: g.Duration, ViaGroup: via, Bound: g.Bound,
		}
		if !g.CreatedAt.IsZero() {
			if d, err := time.ParseDuration(g.Duration); err == nil {
				ref.ExpiresAt = g.CreatedAt.Add(d).UTC().Format(time.RFC3339)
			}
		}
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// flagsFor derives the recertification worklist flags for one principal. activityReachable is false when
// the audit source was down, in which case the activity-based flags are withheld (we cannot tell dormant
// from simply-unobserved) while the credential flag — which does not depend on activity — still fires.
func flagsFor(p Principal, u UserInput, now time.Time, dormancy time.Duration, activityReachable bool) []string {
	var flags []string
	holdsAccess := len(p.StandingRoles) > 0 || len(p.Grants) > 0

	if u.Disabled {
		// A disabled account should hold nothing; if it still does, that is the single most important
		// thing to surface, and we do not pile dormancy/activity flags onto it.
		if holdsAccess {
			flags = append(flags, FlagDisabledRetaining)
		}
		return flags
	}

	if p.Admin {
		flags = append(flags, FlagPrivileged)
	}
	if len(p.InertGroups) > 0 {
		flags = append(flags, FlagInertGroups)
	}
	if len(p.Grants) > 0 {
		flags = append(flags, FlagActiveGrant)
	}

	if u.Source == "local" && !u.HasPassword {
		// A local account with no password cannot sign in — likely an orphan or a never-completed setup.
		// This is independent of the activity source, so it stands even when that source is down.
		flags = append(flags, FlagNoCredential)
	} else if activityReachable {
		// Activity-based flags only when we actually have activity data — otherwise a Loki outage would
		// flag every account as inactive.
		switch {
		case u.LastSeen.IsZero():
			flags = append(flags, FlagNoRecentActivity)
		case now.Sub(u.LastSeen) > dormancy:
			flags = append(flags, FlagDormant)
		}
	}
	return flags
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
