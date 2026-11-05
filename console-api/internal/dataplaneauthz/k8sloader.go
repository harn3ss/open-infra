package dataplaneauthz

import (
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// The IAM kinds the loader lists (it needs list on each).
var (
	policyGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}
	roleGVR   = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}
	userGVR   = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "users"}
	groupGVR  = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "groups"}
)

// K8sLoader reads the IAM policy world from the cluster (iamauthz.K8sLoader). It fails CLOSED on any list
// error, so the caller's ServiceAccount must be granted list on policies AND roles/users/groups in
// iam.openinfra.dev.
func K8sLoader(dc dynamic.Interface) Loader { return iamauthz.K8sLoader(dc) }

// K8sLoaderIn is K8sLoader with an explicit IAM home namespace (iamauthz.K8sLoaderIn).
func K8sLoaderIn(dc dynamic.Interface, home string) Loader { return iamauthz.K8sLoaderIn(dc, home) }

func toLikeConditions(v any) []policyengine.LikeCondition { return iamauthz.ToLikeConditions(v) }

func toTimeConditions(v any) []policyengine.TimeCondition { return iamauthz.ToTimeConditions(v) }
