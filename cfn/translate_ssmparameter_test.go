package main

import (
	"strings"
	"testing"
)

// A String/SecureString SSM parameter maps faithfully: Name->path, Value, Type.
func TestTranslate_SSMParameter_Faithful(t *testing.T) {
	m, fs := translateSSMParameter("DbHost", map[string]any{
		"Name":        "/app/db/host",
		"Type":        "SecureString",
		"Value":       "db.internal:5432",
		"Description": "primary db endpoint",
		"Tier":        "Standard",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Parameter" || m.APIVersion != "openinfra.dev/v1" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	if m.Spec["path"] != "/app/db/host" || m.Spec["value"] != "db.internal:5432" || m.Spec["type"] != "SecureString" || m.Spec["tier"] != "Standard" {
		t.Fatalf("spec not faithful: %#v", m.Spec)
	}
	// Description has no equivalent — a declared caveat, not silently dropped.
	if !strings.Contains(strings.Join(m.Caveats, " | "), "Description") {
		t.Fatalf("Description should surface a caveat: %v", m.Caveats)
	}
}

// StringList stores a plain comma-separated string with a caveat (no list-typed parameter).
func TestTranslate_SSMParameter_StringListCaveat(t *testing.T) {
	m, fs := translateSSMParameter("Cidrs", map[string]any{
		"Name": "/net/cidrs", "Type": "StringList", "Value": "10.0.0.0/8,192.168.0.0/16",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Spec["type"] != "String" {
		t.Fatalf("StringList should store as String, got %v", m.Spec["type"])
	}
	if !strings.Contains(strings.Join(m.Caveats, " | "), "StringList") {
		t.Fatalf("StringList should surface a caveat: %v", m.Caveats)
	}
}

// A parameter with a lifecycle Policy (expiration) blocks — behavior-bearing, no equivalent.
func TestTranslate_SSMParameter_PolicyBlocks(t *testing.T) {
	_, fs := translateSSMParameter("Temp", map[string]any{
		"Name": "/tmp/token", "Value": "x",
		"Policies": `[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-12-31T00:00:00Z"}}]`,
	}, nil)
	if !strings.Contains(findingsText(fs), "Policies") {
		t.Fatalf("a lifecycle Policy must block, got: %s", findingsText(fs))
	}
}

// Missing Name or Value blocks (both required).
func TestTranslate_SSMParameter_RequiresNameAndValue(t *testing.T) {
	_, fs := translateSSMParameter("Bad", map[string]any{"Type": "String"}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "requires a Name") || !strings.Contains(txt, "requires a Value") {
		t.Fatalf("missing Name+Value must both block, got: %s", txt)
	}
}

// An unhandled property blocks (fail-closed).
func TestTranslate_SSMParameter_UnknownPropBlocks(t *testing.T) {
	_, fs := translateSSMParameter("P", map[string]any{
		"Name": "/a", "Value": "b", "AllowedValues": []any{"b"},
	}, nil)
	if !strings.Contains(findingsText(fs), "AllowedValues") {
		t.Fatalf("an unhandled property must block, got: %s", findingsText(fs))
	}
}
