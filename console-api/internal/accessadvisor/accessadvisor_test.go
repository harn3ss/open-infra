package accessadvisor

import (
	"testing"
	"time"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestBuild_SingleUser_GroupsByServiceNewestFirst(t *testing.T) {
	now := mustTime("2026-09-15T00:00:00Z")
	events := []Event{
		{Actor: "alice", Service: "buckets", Verb: "create", Time: mustTime("2026-09-10T10:00:00Z")},
		{Actor: "alice", Service: "buckets", Verb: "delete", Time: mustTime("2026-09-12T10:00:00Z")},
		{Actor: "alice", Service: "virtualmachines", Verb: "update", Time: mustTime("2026-09-14T10:00:00Z")},
		{Actor: "bob", Service: "functions", Verb: "create", Time: mustTime("2026-09-14T11:00:00Z")}, // other actor, ignored
	}
	r := Build("user", "alice", []string{"alice"}, events, 90, true, false, now)

	if r.Aggregated {
		t.Fatal("single user must not be marked aggregated")
	}
	if len(r.Services) != 2 {
		t.Fatalf("want 2 services (buckets, virtualmachines), got %d: %+v", len(r.Services), r.Services)
	}
	// virtualmachines (last 09-14) must sort before buckets (last 09-12).
	if r.Services[0].Service != "virtualmachines" || r.Services[1].Service != "buckets" {
		t.Fatalf("wrong order: %s then %s", r.Services[0].Service, r.Services[1].Service)
	}
	// buckets aggregates two events with two distinct verbs and last = 09-12.
	b := r.Services[1]
	if b.EventCount != 2 || b.LastAccessed != "2026-09-12T10:00:00Z" {
		t.Fatalf("buckets: count=%d last=%s", b.EventCount, b.LastAccessed)
	}
	if len(b.Actions) != 2 || b.Actions[0] != "create" || b.Actions[1] != "delete" {
		t.Fatalf("buckets verbs not sorted-distinct: %v", b.Actions)
	}
	// A single-user report does not populate per-row Actors.
	if b.Actors != nil {
		t.Fatalf("single-user rows must not carry Actors, got %v", b.Actors)
	}
	if r.Coverage == "" {
		t.Fatal("coverage honesty label must always be set")
	}
}

func TestBuild_Aggregated_UnionsActors(t *testing.T) {
	now := mustTime("2026-09-15T00:00:00Z")
	events := []Event{
		{Actor: "alice", Service: "buckets", Verb: "create", Time: mustTime("2026-09-10T10:00:00Z")},
		{Actor: "carol", Service: "buckets", Verb: "update", Time: mustTime("2026-09-13T10:00:00Z")},
	}
	r := Build("group", "data-team", []string{"alice", "carol", "dave"}, events, 30, true, true, now)

	if !r.Aggregated {
		t.Fatal("group report must be aggregated")
	}
	if len(r.Services) != 1 || r.Services[0].Service != "buckets" {
		t.Fatalf("want single buckets row, got %+v", r.Services)
	}
	row := r.Services[0]
	if row.LastAccessed != "2026-09-13T10:00:00Z" { // max across actors
		t.Fatalf("aggregate last should be the newest across actors, got %s", row.LastAccessed)
	}
	if len(row.Actors) != 2 || row.Actors[0] != "alice" || row.Actors[1] != "carol" {
		t.Fatalf("aggregate row must list the actors who touched it, got %v", row.Actors)
	}
	// dave resolved into the actor set but touched nothing — still listed as a resolved actor.
	if len(r.Actors) != 3 {
		t.Fatalf("resolved actor set should carry all 3, got %v", r.Actors)
	}
}

func TestBuild_SourceUnreachable_IsUnknownNotEmpty(t *testing.T) {
	now := mustTime("2026-09-15T00:00:00Z")
	events := []Event{{Actor: "alice", Service: "buckets", Verb: "create", Time: now}}
	r := Build("user", "alice", []string{"alice"}, events, 90, false, false, now)

	if len(r.Services) != 0 {
		t.Fatal("when the source is unreachable, services must be empty (unknown), not computed")
	}
	if r.ActivitySourceReachable {
		t.Fatal("reachable flag must be false")
	}
	if r.Note == "" || !contains(r.Note, "unknown") {
		t.Fatalf("unreachable note must say the result is unknown, got %q", r.Note)
	}
}

func TestBuild_OpenInfraPrefixStripped(t *testing.T) {
	now := mustTime("2026-09-15T00:00:00Z")
	// The event actor still carries the openinfra: prefix; the resolved actor set is bare — they must match.
	events := []Event{{Actor: "openinfra:alice", Service: "users", Verb: "patch", Time: now}}
	r := Build("user", "alice", []string{"alice"}, events, 90, true, false, now)
	if len(r.Services) != 1 {
		t.Fatalf("prefix mismatch dropped the event: %+v", r.Services)
	}
}

func TestBuild_NoActors_HonestNote(t *testing.T) {
	now := mustTime("2026-09-15T00:00:00Z")
	r := Build("role", "orphan", nil, nil, 90, true, true, now)
	if len(r.Services) != 0 {
		t.Fatal("no actors → no services")
	}
	if !contains(r.Note, "nobody effectively holds") {
		t.Fatalf("empty-actor note should explain a role/policy nobody holds, got %q", r.Note)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
