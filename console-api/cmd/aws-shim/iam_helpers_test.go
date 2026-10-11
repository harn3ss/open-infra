package main

import (
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

// statementsToSpecAny renders translated statements into the kind: Policy spec.dataPlane shape that the
// dataplaneauthz loader reads back. The live time-condition probe (#266) found that likeConditions and
// timeConditions were silently dropped here (and in the XRD + loader) — a fail-open hole. This locks in
// that every condition kind the engine carries is emitted with the exact lowercase keys the loader and
// the XRD schema expect, so a round-trip through the CR preserves it.
func TestStatementsToSpecAny_EmitsAllConditionKinds(t *testing.T) {
	stmts := []policyengine.Statement{{
		Effect:    policyengine.Allow,
		Actions:   []string{"s3:GetObject"},
		Resources: []string{"Bucket::reports"},
		Condition: map[string]string{"authenticated": "true"},
		IPConditions: []policyengine.IPCondition{
			{Key: "sourceIp", CIDR: "10.0.0.0/8", Negate: false},
		},
		LikeConditions: []policyengine.LikeCondition{
			{Key: "username", Pattern: "admin-*", Negate: true},
		},
		TimeConditions: []policyengine.TimeCondition{
			{Key: "currentTime", Op: ">", Target: "2025-01-01T00:00:00Z"},
		},
	}}
	out := statementsToSpecAny(stmts)
	if len(out) != 1 {
		t.Fatalf("want 1 statement, got %d", len(out))
	}
	m := out[0].(map[string]any)

	// ipConditions (regression baseline)
	if _, ok := m["ipConditions"]; !ok {
		t.Error("ipConditions missing")
	}
	// likeConditions — the StringLike path that was dropped
	likes, ok := m["likeConditions"].([]any)
	if !ok || len(likes) != 1 {
		t.Fatalf("likeConditions missing/malformed: %#v", m["likeConditions"])
	}
	lk := likes[0].(map[string]any)
	if lk["key"] != "username" || lk["pattern"] != "admin-*" || lk["negate"] != true {
		t.Errorf("likeConditions keys wrong (must be key/pattern/negate): %#v", lk)
	}
	// timeConditions — the aws:CurrentTime path that was dropped
	times, ok := m["timeConditions"].([]any)
	if !ok || len(times) != 1 {
		t.Fatalf("timeConditions missing/malformed: %#v", m["timeConditions"])
	}
	tc := times[0].(map[string]any)
	if tc["key"] != "currentTime" || tc["op"] != ">" || tc["target"] != "2025-01-01T00:00:00Z" {
		t.Errorf("timeConditions keys wrong (must be key/op/target): %#v", tc)
	}
}
