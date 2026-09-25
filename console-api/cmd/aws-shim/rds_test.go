package main

import "testing"

func TestKnownInstanceClass(t *testing.T) {
	for _, ok := range []string{"db.t3.micro", "db.t3.medium", "db.m5.large", "db.m5.xlarge"} {
		if !knownInstanceClass(ok) {
			t.Errorf("%s should be known", ok)
		}
	}
	for _, bad := range []string{"db.r5.24xlarge", "db.t3.nano", "", "t3.micro"} {
		if knownInstanceClass(bad) {
			t.Errorf("%s should be unknown (refused)", bad)
		}
	}
}

func TestResourcesForHasRequestsAndLimits(t *testing.T) {
	r := resourcesFor("db.t3.medium")
	req, _ := r["requests"].(map[string]any)
	lim, _ := r["limits"].(map[string]any)
	if req["cpu"] == nil || req["memory"] == nil || lim["cpu"] == nil || lim["memory"] == nil {
		t.Errorf("resourcesFor missing fields: %v", r)
	}
}

func TestDBIdentifierRE(t *testing.T) {
	good := []string{"mydb", "app-db-1", "a", "prod-postgres-01"}
	bad := []string{"1db", "Db", "app_db", "-lead", "trail-", "with.dot", ""}
	for _, g := range good {
		if !dbIdentifierRE.MatchString(g) {
			t.Errorf("%q should be a valid identifier", g)
		}
	}
	for _, b := range bad {
		if dbIdentifierRE.MatchString(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}

func TestTagsEncodeDecodeRoundTrip(t *testing.T) {
	in := map[string]string{"env": "prod", "team": "data"}
	out := decodeTags(encodeTags(in))
	if out["env"] != "prod" || out["team"] != "data" {
		t.Errorf("tag round-trip failed: %v", out)
	}
	if encodeTags(map[string]string{}) != "" {
		t.Error("empty tags should encode to empty string")
	}
	if len(decodeTags("")) != 0 {
		t.Error("empty string should decode to empty map")
	}
}

func TestVerbForRDSOp(t *testing.T) {
	cases := map[string]string{
		"DescribeDBInstances":             "get",
		"CreateDBInstance":                "create",
		"RestoreDBInstanceFromDBSnapshot": "create",
		"DeleteDBInstance":                "delete",
		"DeleteDBSnapshot":                "delete",
	}
	for op, want := range cases {
		if got, ok := verbForRDSOp(op); !ok || got != want {
			t.Errorf("verbForRDSOp(%q)=%q,%v want %q", op, got, ok, want)
		}
	}
	if _, ok := verbForRDSOp("CreateGlobalCluster"); ok {
		t.Error("unimplemented op should be unknown")
	}
}
