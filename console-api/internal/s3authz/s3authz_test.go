package s3authz

import (
	"context"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// sarAllowsEverything is a clientset whose SubjectAccessReviews allow every request (a coarse RBAC tier
// that reaches object storage).
func sarAllowsEverything() *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		sar.Status.Allowed = true
		return true, sar, nil
	})
	return cs
}

func gate(t *testing.T, mode iamauthz.Mode, w iamauthz.World) Gate {
	t.Helper()
	t.Setenv(iamauthz.EnvMode, string(mode))
	checker := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) { return w, nil }, time.Minute)
	return Gate{CS: sarAllowsEverything(), Authz: checker, NS: "default"}
}

var reqCtx = map[string]any{"authenticated": true}

func get(bucket, key string) Request {
	return Request{Action: "s3:GetObject", Verb: "get", Bucket: bucket, Key: key, Object: true}
}

// In enforce mode a User's object-storage access is its IAM policies alone: a User with no policy reads
// nothing, although its coarse RBAC tier would let it (the legacy decision, which shadow still returns).
func TestGate_EnforceIsThePoliciesAlone(t *testing.T) {
	w := iamauthz.World{
		Docs: []iamauthz.Policy{{Name: "reports-read", Statements: []policyengine.Statement{
			{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"}},
		}}},
		Attach: map[string][]string{"User::analyst": {"reports-read"}},
	}
	nobody := iam.Claims{Sub: "nobody", Groups: iam.GroupsFromSpec([]string{"readers"})}
	analyst := iam.Claims{Sub: "analyst", Groups: iam.GroupsFromSpec([]string{"readers"})}
	ctx := context.Background()

	legacy := gate(t, iamauthz.ModeLegacy, w)
	if ok, _ := legacy.Allow(ctx, nobody, get("anything", "k"), reqCtx); !ok {
		t.Fatal("expected the legacy decision to defer to the coarse tier for an ungoverned User")
	}
	shadow := gate(t, iamauthz.ModeShadow, w)
	if ok, _ := shadow.Allow(ctx, nobody, get("anything", "k"), reqCtx); !ok {
		t.Error("shadow must return the legacy decision")
	}
	enforce := gate(t, iamauthz.ModeEnforce, w)
	if ok, why := enforce.Allow(ctx, nobody, get("anything", "k"), reqCtx); ok {
		t.Errorf("enforce: a User with no policy read an object (%s)", why)
	}
	if ok, why := enforce.Allow(ctx, analyst, get("reports", "q3.csv"), reqCtx); !ok {
		t.Errorf("enforce: the analyst's own grant was refused (%s)", why)
	}
	if ok, _ := enforce.Allow(ctx, analyst, get("other", "k"), reqCtx); ok {
		t.Error("enforce: the analyst read outside its grant")
	}
	// The platform-bucket fence holds in every mode.
	w.Docs = append(w.Docs, iamauthz.Policy{Name: "all", Statements: []policyengine.Statement{
		{Effect: policyengine.Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}}}})
	w.Attach["User::analyst"] = []string{"all"}
	if ok, _ := gate(t, iamauthz.ModeEnforce, w).Allow(ctx, analyst, get("db-snapshots", "dump"), reqCtx); ok {
		t.Error("enforce: a non-admin reached a platform bucket")
	}
	root := iam.Claims{Sub: "root", Role: "root"}
	if ok, why := gate(t, iamauthz.ModeEnforce, iamauthz.World{}).Allow(ctx, root, get("db-snapshots", "dump"), reqCtx); !ok {
		t.Errorf("enforce: root was refused (%s)", why)
	}
}
