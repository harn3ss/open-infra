package main

// Each account's ECS task definitions, clusters and services are its own: a member account's records are
// kept in its home namespace (the management account's in the ECS namespace, exactly where they always
// were), the same family or cluster name lives in both accounts independently, each account lists only
// its own, every ARN carries the caller's account, and a member account's service stacks are deployed in
// its home with a StackId in its account.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

const ecsTestNS = "open-infra-ecs"

func ecsAccountsDoorway(t *testing.T) (*ecsDoorway, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{configMapGVR: "ConfigMapList"})
	// The records are written with server-side apply (create or update), which the fake's tracker does
	// not do itself.
	dyn.PrependReactor("patch", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		act := a.(k8stesting.PatchAction)
		if act.GetPatchType() != types.ApplyPatchType {
			return false, nil, nil
		}
		obj := &unstructured.Unstructured{}
		if err := json.Unmarshal(act.GetPatch(), &obj.Object); err != nil {
			return true, nil, err
		}
		obj.SetNamespace(act.GetNamespace())
		tr := dyn.Tracker()
		if _, err := tr.Get(configMapGVR, act.GetNamespace(), act.GetName()); err != nil {
			return true, obj, tr.Create(configMapGVR, obj, act.GetNamespace())
		}
		return true, obj, tr.Update(configMapGVR, obj, act.GetNamespace())
	})
	return &ecsDoorway{
		cfg:     &rest.Config{Host: "http://127.0.0.1:1"},
		shimDyn: dyn,
		cs:      csWithSAR(true),
		authz:   doorAccountsAuthz(t),
		authzNS: "default",
		account: awsidentity.Current().AccountID,
		region:  "us-east-1",
		ns:      ecsTestNS,
		logger:  discardLogger(),
	}, dyn
}

func ecsCall(t *testing.T, h *ecsDoorway, c doorCaller, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return c.call(t, h.serve, ecsTargetPrefix+"."+op, body)
}

func ecsTaskDefBody(family, image string) map[string]any {
	return map[string]any{"family": family, "containerDefinitions": []any{
		map[string]any{"name": "app", "image": image, "memory": 256}}}
}

func ecsImage(out map[string]any) string {
	td, _ := out["taskDefinition"].(map[string]any)
	cs, _ := td["containerDefinitions"].([]any)
	if len(cs) == 0 {
		return ""
	}
	c, _ := cs[0].(map[string]any)
	s, _ := c["image"].(string)
	return s
}

func ecsTaskDefArnOf(out map[string]any) string {
	td, _ := out["taskDefinition"].(map[string]any)
	s, _ := td["taskDefinitionArn"].(string)
	return s
}

func TestECSAccounts_TaskDefinitionsAreEachAccountsOwn(t *testing.T) {
	h, dyn := ecsAccountsDoorway(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID

	if code, out := ecsCall(t, h, mgmt, "RegisterTaskDefinition", ecsTaskDefBody("web", "mgmt:1")); code != http.StatusOK ||
		ecsTaskDefArnOf(out) != "arn:aws:ecs:us-east-1:"+mgmtAcct+":task-definition/web:1" {
		t.Fatalf("management register: %d %v", code, out)
	}
	// The member account's first revision of the same family is its own revision 1, not the management
	// account's revision 2, and its ARN names the member account.
	code, out := ecsCall(t, h, member, "RegisterTaskDefinition", ecsTaskDefBody("web", "member:1"))
	if code != http.StatusOK || ecsTaskDefArnOf(out) != "arn:aws:ecs:us-east-1:"+testMember+":task-definition/web:1" {
		t.Fatalf("member register: %d %v", code, out)
	}
	ctx := context.Background()
	if _, err := dyn.Resource(configMapGVR).Namespace(memberHome).Get(ctx, "ecs-taskdef-web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("the member's record is kept in its home: %v", err)
	}
	if u, err := dyn.Resource(configMapGVR).Namespace(ecsTestNS).Get(ctx, "ecs-taskdef-web-1", metav1.GetOptions{}); err != nil ||
		!strings.Contains(cmData(u, "taskdef.json"), "mgmt:1") {
		t.Fatalf("the management account's record is untouched where it always was: %v", err)
	}

	if _, out := ecsCall(t, h, member, "DescribeTaskDefinition", map[string]any{"taskDefinition": "web:1"}); ecsImage(out) != "member:1" {
		t.Errorf("the member reads its own task definition: %v", out)
	}
	if _, out := ecsCall(t, h, mgmt, "DescribeTaskDefinition", map[string]any{"taskDefinition": "web"}); ecsImage(out) != "mgmt:1" {
		t.Errorf("the management account reads its own task definition: %v", out)
	}
	// By ARN: the member's own ARN is its task definition; the management account's ARN of the same family
	// and revision is not (it never resolves to the member's web:1, nor to the management account's).
	if _, out := ecsCall(t, h, member, "DescribeTaskDefinition", map[string]any{
		"taskDefinition": "arn:aws:ecs:us-east-1:" + testMember + ":task-definition/web:1"}); ecsImage(out) != "member:1" {
		t.Errorf("the member reads its own task definition by its ARN: %v", out)
	}
	if _, out := ecsCall(t, h, member, "DescribeTaskDefinition", map[string]any{
		"taskDefinition": "arn:aws:ecs:us-east-1:" + mgmtAcct + ":task-definition/web:1"}); jsonErrType(out) != "ClientException" {
		t.Errorf("another account's task-definition ARN must not resolve for a member: %v", out)
	}
	// A family only the management account has is not the member's.
	if _, out := ecsCall(t, h, mgmt, "RegisterTaskDefinition", ecsTaskDefBody("api", "mgmt:api")); jsonErrType(out) != "" {
		t.Fatal(out)
	}
	if code, out := ecsCall(t, h, member, "DescribeTaskDefinition", map[string]any{
		"taskDefinition": "arn:aws:ecs:us-east-1:" + mgmtAcct + ":task-definition/api:1"}); code == http.StatusOK || jsonErrType(out) != "ClientException" {
		t.Errorf("a member must not read the management account's task definition: %d %v", code, out)
	}
	// Deregistering the member's revision leaves the management account's.
	if code, out := ecsCall(t, h, member, "DeregisterTaskDefinition", map[string]any{"taskDefinition": "web:1"}); code != http.StatusOK {
		t.Fatalf("member deregister: %d %v", code, out)
	}
	if _, out := ecsCall(t, h, mgmt, "DescribeTaskDefinition", map[string]any{"taskDefinition": "web:1"}); ecsImage(out) != "mgmt:1" {
		t.Errorf("the management account's revision survives the member's deregister: %v", out)
	}
	if code, _ := ecsCall(t, h, member, "DescribeTaskDefinition", map[string]any{"taskDefinition": "web:1"}); code == http.StatusOK {
		t.Error("the member's deregistered revision is gone")
	}
}

func TestECSAccounts_ClustersAreEachAccountsOwn(t *testing.T) {
	h, _ := ecsAccountsDoorway(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID

	if code, out := ecsCall(t, h, mgmt, "CreateCluster", map[string]any{"clusterName": "shared"}); code != http.StatusOK {
		t.Fatalf("management create: %d %v", code, out)
	}
	code, out := ecsCall(t, h, member, "CreateCluster", map[string]any{"clusterName": "prod"})
	c, _ := out["cluster"].(map[string]any)
	if code != http.StatusOK || c["clusterArn"] != "arn:aws:ecs:us-east-1:"+testMember+":cluster/prod" {
		t.Fatalf("member create: %d %v", code, out)
	}
	arnsOf := func(out map[string]any) []string {
		var s []string
		for _, a := range out["clusterArns"].([]any) {
			s = append(s, a.(string))
		}
		return s
	}
	if _, out := ecsCall(t, h, member, "ListClusters", map[string]any{}); strings.Join(arnsOf(out), ",") != "arn:aws:ecs:us-east-1:"+testMember+":cluster/prod" {
		t.Errorf("the member lists its own clusters alone: %v", out)
	}
	if _, out := ecsCall(t, h, mgmt, "ListClusters", map[string]any{}); strings.Join(arnsOf(out), ",") != "arn:aws:ecs:us-east-1:"+mgmtAcct+":cluster/shared" {
		t.Errorf("the management account lists its own clusters alone: %v", out)
	}
	// The management account's cluster is missing for the member (its failure names the member's ARN) and
	// cannot be deleted by it.
	_, out = ecsCall(t, h, member, "DescribeClusters", map[string]any{"clusters": []any{"shared"}})
	if fs, _ := out["failures"].([]any); len(fs) != 1 || fs[0].(map[string]any)["arn"] != "arn:aws:ecs:us-east-1:"+testMember+":cluster/shared" {
		t.Errorf("the management account's cluster is missing in the member account: %v", out)
	}
	if _, out := ecsCall(t, h, member, "DeleteCluster", map[string]any{"cluster": "shared"}); jsonErrType(out) != "ClusterNotFoundException" {
		t.Errorf("a member must not delete the management account's cluster: %v", out)
	}
	if _, found, _ := h.getCluster(context.Background(), "shared"); !found {
		t.Error("the management account's cluster survives")
	}
}

// A service record (the last-applied request) is kept and listed in its account's namespace alone, and its
// ARN carries the account.
func TestECSAccounts_ServiceRecordsAreEachAccountsOwn(t *testing.T) {
	h, _ := ecsAccountsDoorway(t)
	mgmtCtx, memCtx := context.Background(), memberCtx()
	if err := h.putServiceRef(memCtx, &ecsServiceRef{ServiceName: "web", Cluster: "default", Body: map[string]any{"taskDefinition": "web:1"}}); err != nil {
		t.Fatal(err)
	}
	if refs := h.listServiceRefs(mgmtCtx); len(refs) != 0 {
		t.Errorf("the management account lists a member's service: %+v", refs)
	}
	if _, found, _ := h.getServiceRef(mgmtCtx, "web"); found {
		t.Error("the management account reads a member's service record")
	}
	if refs := h.listServiceRefs(memCtx); len(refs) != 1 || refs[0].ServiceName != "web" {
		t.Errorf("the member lists its own service: %+v", refs)
	}
	if got := h.serviceArn(memCtx, "default", "web"); got != "arn:aws:ecs:us-east-1:"+testMember+":service/default/web" {
		t.Errorf("member service ARN %q", got)
	}
	if got := h.serviceArn(mgmtCtx, "default", "web"); got != "arn:aws:ecs:us-east-1:"+h.account+":service/default/web" {
		t.Errorf("management service ARN %q", got)
	}
}

// A member account's service is provisioned in its home, its stack with a StackId in its account (so the
// engine resolves AWS::AccountId to it); the management account's is deployed exactly as before.
func TestECSAccounts_ServiceStacksActInTheCallersAccount(t *testing.T) {
	h, _ := ecsAccountsDoorway(t)
	mgmt := h.deployOpts(context.Background(), "web")
	if mgmt.Namespace != ecsTestNS || mgmt.StackID != "" {
		t.Errorf("the management account's stack options changed: %+v", mgmt)
	}
	mem := h.deployOpts(memberCtx(), "web")
	if mem.Namespace != memberHome || awsidentity.AccountOfARN(mem.StackID) != testMember {
		t.Errorf("member stack options: %+v", mem)
	}
	if name, ok := awsidentity.StackIDName(mem.StackID); !ok || name != "web" || mem.StackID != h.deployOpts(memberCtx(), "web").StackID {
		t.Errorf("the member's StackId names its stack and is stable: %q", mem.StackID)
	}
	ap, err := h.applierFor(memberCtx(), memberDoorCaller().claims)
	if err != nil || ap.ns != memberHome {
		t.Fatalf("the member's applier works in its home: %v %+v", err, ap)
	}
	if ap, err := h.applierFor(context.Background(), mgmtDoorCaller().claims); err != nil || ap.ns != ecsTestNS {
		t.Fatalf("the management account's applier works in the ECS namespace: %v", err)
	}
}

func TestECSAccounts_DoorIsAccountScoped(t *testing.T) {
	if !accountScopedServices["ecs"] {
		t.Fatal("ecs must be registered as account-scoped")
	}
}
