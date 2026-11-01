package render

import (
	"path/filepath"
	"strings"
	"testing"
)

// The owner record names the claim INSTANCE (its composite's creation time). A claim deleted and created
// again under the same name is a new instance and never inherits the earlier one's data: an empty bucket
// is taken over, one that still holds data is refused. A record from before instances is upgraded.
func TestBucketOwnership_ClaimInstance(t *testing.T) {
	needJQ(t)
	const earlier = "2026-09-01T00:00:00Z"
	cases := []struct {
		name          string
		record        string
		objects       bool
		wantOK        bool
		wantInstance  string
		wantOutSubstr string
	}{
		{name: "the same instance uses its bucket", record: "team-a|Bucket/team-a/data|" + xrCreated,
			wantOK: true, wantInstance: xrCreated, wantOutSubstr: "belongs to Bucket/team-a/data"},
		{name: "a record with no instance is upgraded", record: "team-a|Bucket/team-a/data",
			wantOK: true, wantInstance: xrCreated},
		{name: "a re-created claim takes over its empty bucket", record: "team-a|Bucket/team-a/data|" + earlier,
			wantOK: true, wantInstance: xrCreated, wantOutSubstr: "is empty; taken over"},
		{name: "a re-created claim never inherits data", record: "team-a|Bucket/team-a/data|" + earlier, objects: true,
			wantInstance: earlier, wantOutSubstr: "still holds data from an earlier Bucket/team-a/data (created " + earlier + ")"},
	}
	for _, sh := range posixShells(t) {
		for _, c := range cases {
			t.Run(shellName(sh)+"/"+c.name, func(t *testing.T) {
				e := newBktEnv(t, map[string]string{"bucket-owner-data": c.record}, map[string]string{"data": "2026-09-01T00:00:00+00:00"})
				if c.objects {
					writeFile(t, filepath.Join(e.dir, "objects", "data"), "k")
				}
				out, err := e.run(t, sh, claimScript(t, "data"), ownerEnv...)
				if c.wantOK != (err == nil) || c.wantOK != strings.Contains(out, "CLAIMED") {
					t.Fatalf("ok=%v, want %v; output:\n%s", err == nil, c.wantOK, out)
				}
				if c.wantOutSubstr != "" && !strings.Contains(out, c.wantOutSubstr) {
					t.Errorf("output lacks %q:\n%s", c.wantOutSubstr, out)
				}
				if got := e.read("records/bucket-owner-data.instance"); got != c.wantInstance {
					t.Errorf("record instance = %q, want %q", got, c.wantInstance)
				}
			})
		}
	}
}

// A new record names the claim instance that created the bucket.
func TestBucketOwnership_NewRecordNamesTheInstance(t *testing.T) {
	needJQ(t)
	for _, sh := range posixShells(t) {
		e := newBktEnv(t, nil, nil)
		if out, err := e.run(t, sh, claimScript(t, "data"), ownerEnv...); err != nil {
			t.Fatalf("%s: %v\n%s", shellName(sh), err, out)
		}
		if got := e.read("records/bucket-owner-data.instance"); got != xrCreated {
			t.Errorf("%s: new record instance = %q, want %q", shellName(sh), got, xrCreated)
		}
	}
}
