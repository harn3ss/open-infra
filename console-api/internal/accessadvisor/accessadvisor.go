// Package accessadvisor assembles an AWS-IAM-"Access Advisor"-equivalent view: for a principal (a
// User, Group, Role, or Policy) it reports, per open-infra "service" (a resource type — the platform's
// analog of an AWS service, e.g. virtualmachines, buckets, functions), when that service was last
// touched and by which resolved actors. It is the least-privilege / right-sizing surface AWS puts on
// every identity detail page: "services this principal has access to, and when each was last used."
//
// HONESTY BOUNDARY (load-bearing — the caller MUST surface it, and Build stamps it into Coverage):
// the only activity source is the Kubernetes API-server audit trail (job=k3s-audit) plus the console's
// own iam: log. That trail records MUTATIONS (create/update/patch/delete) and authorization decisions —
// READS ARE DROPPED. So "last accessed" here means "last WRITE observed", and a service shown with no
// activity means "no writes seen in the window", NOT a proof the service was never read. This view finds
// unused-for-writes access; it must never be read as proof a permission is entirely unused. Data-plane
// object access through the aws-shim (S3/DynamoDB/Lambda) is not in the k8s-audit trail either, so it is
// out of this view's coverage. Stating this is the whole difference between an honest advisor and a
// fake one.
//
// Attribution: k8s-audit attributes to the human (impersonatedUser), not to an assumed role. So the
// per-User view is exact; the Group/Role/Policy views are AGGREGATED across the users who effectively
// hold that principal, and say so. An assumed-role session's own activity is not separately attributable
// from this trail — also stated.
//
// Build is PURE: it takes an already-resolved actor set + already-fetched audit events + a clock and
// returns the report deterministically, so it is fully unit-tested with no k8s/Loki dependency. All
// gathering happens in the caller (cmd/server).
package accessadvisor

import (
	"sort"
	"strings"
	"time"
)

// Event is the minimal audit fact the assembler needs (one mutation observed in the trail).
type Event struct {
	Actor   string    // the person (impersonatedUser / by), openinfra: prefix already stripped
	Service string    // the resource type touched, e.g. "virtualmachines", "buckets"
	Verb    string    // create / update / patch / delete / …
	Time    time.Time // when it happened
}

// ServiceAccess is one row: a service and the most-recent write activity across the resolved actors.
type ServiceAccess struct {
	Service      string   `json:"service"`                // resource type (open-infra's "service")
	LastAccessed string   `json:"lastAccessed,omitempty"` // RFC3339; "" = not observed in the window
	Actions      []string `json:"actions,omitempty"`      // distinct verbs observed (write verbs only)
	EventCount   int      `json:"eventCount"`             // how many events backed this row
	Actors       []string `json:"actors,omitempty"`       // which resolved actors touched it (aggregate kinds)
}

// Report is the whole document for one principal.
type Report struct {
	Kind                    string          `json:"kind"`         // user | group | role | policy
	Name                    string          `json:"name"`         // the principal's name
	Actors                  []string        `json:"actors"`       // the resolved actor set this aggregates over
	LookbackDays            int             `json:"lookbackDays"` // the audit window
	GeneratedAt             string          `json:"generatedAt"`  // stamped by the caller
	ActivitySourceReachable bool            `json:"activitySourceReachable"`
	Aggregated              bool            `json:"aggregated"` // true for group/role/policy (across members)
	Services                []ServiceAccess `json:"services"`
	Coverage                string          `json:"coverage"` // the writes-only / reads-dropped honesty label
	Note                    string          `json:"note"`
}

// coverageLabel is the fixed honesty statement about what this view can and cannot see. It is not
// optional decoration: it is the reason the view is honest rather than misleading.
const coverageLabel = "Derived from the audit trail, which records mutations (create/update/delete) " +
	"and authorization decisions — reads are not captured, and data-plane object access through the " +
	"aws-shim (S3/DynamoDB/Lambda) is not in this trail. \"Last accessed\" therefore means \"last write " +
	"observed\"; a service with no activity means no writes were seen in the window, not proof it was " +
	"never read. Use this to find unused-for-writes access, not to prove a permission is entirely unused."

// Build composes the report from a resolved actor set and the audit events, deterministically.
// `aggregated` should be true for group/role/policy (the actor set is the resolved membership) and false
// for a single user. When reachable is false the audit source was down: Services is empty and the note
// says the window is unknown rather than implying no access.
func Build(kind, name string, actors []string, events []Event, lookbackDays int, reachable, aggregated bool, now time.Time) Report {
	actorSet := map[string]bool{}
	for _, a := range actors {
		a = strings.TrimSpace(strings.TrimPrefix(a, "openinfra:"))
		if a != "" {
			actorSet[a] = true
		}
	}
	sortedActors := sortedKeys(actorSet)

	rep := Report{
		Kind: kind, Name: name, Actors: sortedActors, LookbackDays: lookbackDays,
		ActivitySourceReachable: reachable, Aggregated: aggregated, Services: []ServiceAccess{},
		Coverage: coverageLabel,
	}

	if !reachable {
		rep.Note = "The activity source (audit store) was UNREACHABLE this run, so service last-used is " +
			"unavailable. A blank result here means unknown, not \"no access\"."
		return rep
	}

	// Aggregate matching events by service.
	type agg struct {
		last   time.Time
		verbs  map[string]bool
		actors map[string]bool
		count  int
	}
	byService := map[string]*agg{}
	for _, e := range events {
		actor := strings.TrimPrefix(e.Actor, "openinfra:")
		if !actorSet[actor] || e.Service == "" {
			continue
		}
		a := byService[e.Service]
		if a == nil {
			a = &agg{verbs: map[string]bool{}, actors: map[string]bool{}}
			byService[e.Service] = a
		}
		if e.Time.After(a.last) {
			a.last = e.Time
		}
		if e.Verb != "" {
			a.verbs[e.Verb] = true
		}
		a.actors[actor] = true
		a.count++
	}

	for svc, a := range byService {
		row := ServiceAccess{Service: svc, Actions: sortedKeys(a.verbs), EventCount: a.count}
		if !a.last.IsZero() {
			row.LastAccessed = a.last.UTC().Format(time.RFC3339)
		}
		if aggregated {
			row.Actors = sortedKeys(a.actors)
		}
		rep.Services = append(rep.Services, row)
	}
	// Most-recently-used first; ties broken by service name for determinism.
	sort.SliceStable(rep.Services, func(i, j int) bool {
		if rep.Services[i].LastAccessed != rep.Services[j].LastAccessed {
			return rep.Services[i].LastAccessed > rep.Services[j].LastAccessed // RFC3339 sorts lexically
		}
		return rep.Services[i].Service < rep.Services[j].Service
	})

	window := "the audit lookback window"
	if lookbackDays > 0 {
		window = pluralDays(lookbackDays)
	}
	switch {
	case len(actorSet) == 0:
		rep.Note = "No actor resolved for this principal, so no activity could be attributed. " +
			"For a role or policy this can mean nobody effectively holds it yet."
	case aggregated:
		rep.Note = "Aggregated across the " + plural(len(actorSet), "actor") + " who effectively hold this " +
			kind + ", over " + window + ". The audit trail attributes activity to the person, not to an " +
			"assumed role, so this reflects those actors' own write activity — an assumed-role session's " +
			"activity is not separately attributable from this trail."
	default:
		rep.Note = "This user's own write activity over " + window + "."
	}
	return rep
}

func pluralDays(n int) string {
	if n == 1 {
		return "the last 1 day"
	}
	return "the last " + itoa(n) + " days"
}

func plural(n int, noun string) string {
	s := itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}

// itoa avoids importing strconv for two call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
