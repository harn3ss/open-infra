package main

import (
	"testing"
	"time"
)

func TestAuditFromK8s(t *testing.T) {
	// A real-shaped impersonated mutation.
	line := `{"verb":"delete","stage":"ResponseComplete","requestReceivedTimestamp":"2026-07-23T14:00:00.5Z","user":{"username":"system:serviceaccount:open-infra-console:console"},"impersonatedUser":{"username":"openinfra:alice"},"objectRef":{"resource":"virtualmachines","namespace":"default","name":"web"},"responseStatus":{"code":200}}`
	e, ok := auditFromK8s(lokiValue{ts: time.Now(), line: line})
	if !ok {
		t.Fatal("expected a usable event")
	}
	if e.Actor != "alice" { // openinfra: prefix stripped, impersonated preferred over SA
		t.Errorf("actor = %q, want alice", e.Actor)
	}
	if e.Verb != "delete" || e.Resource != "virtualmachines" || e.Name != "web" || e.Result != "200" {
		t.Errorf("bad event: %+v", e)
	}
	if !e.Time.Equal(time.Date(2026, 7, 23, 14, 0, 0, 500000000, time.UTC)) {
		t.Errorf("time not parsed from requestReceivedTimestamp: %v", e.Time)
	}

	// No impersonation → falls back to user.username.
	e2, _ := auditFromK8s(lokiValue{line: `{"verb":"create","user":{"username":"kubernetes-admin"},"objectRef":{"resource":"volumes"},"responseStatus":{"code":201}}`})
	if e2.Actor != "kubernetes-admin" {
		t.Errorf("fallback actor = %q, want kubernetes-admin", e2.Actor)
	}

	// Lines without a verb or objectRef are not audit mutations.
	if _, ok := auditFromK8s(lokiValue{line: `{"kind":"Event","verb":""}`}); ok {
		t.Error("a line with no verb should be rejected")
	}
	if _, ok := auditFromK8s(lokiValue{line: `not json`}); ok {
		t.Error("non-JSON should be rejected")
	}
}

func TestAuditFromConsole(t *testing.T) {
	line := `{"time":"2026-07-23T14:01:02Z","level":"INFO","msg":"iam: user created","user":"bob","by":"root","request_id":"x"}`
	e, ok := auditFromConsole(lokiValue{line: line})
	if !ok {
		t.Fatal("expected a usable event")
	}
	if e.Actor != "root" || e.Resource != "user" || e.Verb != "created" || e.Name != "bob" {
		t.Errorf("bad console event: %+v", e)
	}
	if e.Source != "console" {
		t.Errorf("source = %q", e.Source)
	}

	// A group event logs the target under "group", not "user" — it must still be captured.
	g, ok := auditFromConsole(lokiValue{line: `{"msg":"iam: group deleted","group":"dba","by":"root"}`})
	if !ok || g.Resource != "group" || g.Verb != "deleted" || g.Name != "dba" {
		t.Errorf("group event: %+v", g)
	}

	// A non-iam log line, or one with no actor, is ignored.
	if _, ok := auditFromConsole(lokiValue{line: `{"msg":"http request","by":""}`}); ok {
		t.Error("non-iam line should be rejected")
	}
	if _, ok := auditFromConsole(lokiValue{line: `{"msg":"iam: user created","user":"bob"}`}); ok {
		t.Error("iam line without `by` should be rejected (can't attribute it)")
	}
}
