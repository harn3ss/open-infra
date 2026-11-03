package policyengine

import "testing"

// S3 object operations are authorized on the object (Bucket::<bucket>/<key>). A whole-bucket entry keeps
// covering the bucket's objects on every axis — Allow, Deny, a NotResource exclusion and a permission
// boundary — so no existing grant changes meaning when objects are checked as objects.
func TestEngine_BucketEntryCoversItsObjects(t *testing.T) {
	alice := Principal{Type: "User", ID: "alice"}
	obj := func(id string) Resource { return Resource{Type: "Bucket", ID: id} }
	check := func(t *testing.T, eng *Engine, action string, res Resource, want bool) {
		t.Helper()
		if got := eng.Authorize(Request{alice, action, res, nil}); got.Allowed != want {
			t.Errorf("%s on %s: allowed=%v, want %v (%s)", action, res.ID, got.Allowed, want, got.Reason)
		}
	}

	t.Run("allow", func(t *testing.T) {
		eng, err := NewEngine([]Statement{{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}}})
		if err != nil {
			t.Fatal(err)
		}
		check(t, eng, "s3:GetObject", obj("assets"), true)
		check(t, eng, "s3:GetObject", obj("assets/logs/a.txt"), true)
		check(t, eng, "s3:GetObject", obj("assets-other/a.txt"), false) // a bucket whose name starts the same
		check(t, eng, "s3:GetObject", obj("other/a.txt"), false)
	})
	t.Run("deny", func(t *testing.T) {
		eng, err := NewEngine([]Statement{
			{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}},
			{Effect: Deny, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::secret"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		check(t, eng, "s3:GetObject", obj("secret/k"), false)
		check(t, eng, "s3:GetObject", obj("public/k"), true)
	})
	t.Run("notResource", func(t *testing.T) {
		eng, err := NewEngine([]Statement{{Effect: Allow, Actions: []string{"s3:*"}, NotResources: []string{"Bucket::secret"}}})
		if err != nil {
			t.Fatal(err)
		}
		check(t, eng, "s3:GetObject", obj("secret/k"), false) // excluded with its bucket, not widened
		check(t, eng, "s3:GetObject", obj("public/k"), true)
	})
	t.Run("boundary", func(t *testing.T) {
		eng, err := NewEngineWithBoundary(
			[]Statement{{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}}},
			[]Statement{{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"Bucket::assets"}}})
		if err != nil {
			t.Fatal(err)
		}
		check(t, eng, "s3:GetObject", obj("assets/k"), true)
		check(t, eng, "s3:GetObject", obj("other/k"), false)
	})
}

// An object-prefix entry grants the objects under the prefix and nothing else: not other keys in the
// bucket, and not the bucket itself (ListBucket is a bucket action, as on AWS).
func TestEngine_ObjectPrefixEntry(t *testing.T) {
	eng, err := NewEngine([]Statement{{Effect: Allow, Actions: []string{"s3:GetObject", "s3:ListBucket"}, Resources: []string{"Bucket::assets/public/*"}}})
	if err != nil {
		t.Fatal(err)
	}
	alice := Principal{Type: "User", ID: "alice"}
	for _, c := range []struct {
		action, id string
		want       bool
	}{
		{"s3:GetObject", "assets/public/a.png", true},
		{"s3:GetObject", "assets/private/a.png", false},
		{"s3:GetObject", "assets/publicity.png", false},
		{"s3:ListBucket", "assets", false},
	} {
		if got := eng.Authorize(Request{alice, c.action, Resource{Type: "Bucket", ID: c.id}, nil}); got.Allowed != c.want {
			t.Errorf("%s on %s: allowed=%v, want %v", c.action, c.id, got.Allowed, c.want)
		}
	}
}
