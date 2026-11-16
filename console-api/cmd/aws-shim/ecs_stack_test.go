package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
)

// A stack that made a cluster and a service in it, as an AWS user writes one (invented names).
const ecsStackTemplate = `
Resources:
  Cluster:
    Type: AWS::ECS::Cluster
    Properties: { ClusterName: web-cluster }
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: web
      ContainerDefinitions: [{ Name: web, Image: nginx }]
  Service:
    Type: AWS::ECS::Service
    Properties: { ServiceName: web, Cluster: !Ref Cluster, TaskDefinition: !Ref Task, LaunchType: FARGATE }
  Pending:
    Type: AWS::ECS::Service
    Properties: { ServiceName: not-yet, Cluster: !Ref Cluster, TaskDefinition: !Ref Task }
`

// ecsStackDoorway is an ECS front door whose account has the stack above: its service Service made (the
// record's Application), its service Pending not yet.
func ecsStackDoorway(t *testing.T) *ecsDoorway {
	t.Helper()
	h, _ := ecsAccountsDoorway(t)
	rec := &cfn.StackRecord{Name: "web-stack", Namespace: "open-infra-cfn", Status: "CREATE_COMPLETE",
		CreatedAt: "2026-01-02T03:04:05Z", Template: ecsStackTemplate,
		Resources: []cfn.StackResource{{LogicalID: "Service", APIVersion: ecsAppAPIVersion, Kind: "Application",
			Type: ecsServiceType, Name: "web-stack-service"}}}
	h.stacks = func(context.Context) ([]*cfn.StackRecord, error) { return []*cfn.StackRecord{rec}, nil }
	return h
}

// As on ECS, a service a stack made is a service of its cluster: ListServices lists it there and not in
// another cluster, and one the stack has not made yet is not listed.
func TestECSStack_ListServicesListsAStacksService(t *testing.T) {
	h := ecsStackDoorway(t)
	_, out := ecsCall(t, h, mgmtDoorCaller(), "ListServices", map[string]any{"cluster": "web-cluster"})
	arns, _ := out["serviceArns"].([]any)
	if len(arns) != 1 || !strings.HasSuffix(arns[0].(string), ":service/web-cluster/web") {
		t.Fatalf("ListServices in the stack's cluster = %v, want its service alone", out)
	}
	if _, out := ecsCall(t, h, mgmtDoorCaller(), "ListServices", map[string]any{}); len(out["serviceArns"].([]any)) != 0 {
		t.Errorf("the default cluster has none of the stack's services: %v", out)
	}
}

// DescribeServices finds a stack's service where the stack made it: its Application, in the stack's
// namespace, with the task definition the stack's service names. In another cluster it is not that service.
func TestECSStack_DescribeServicesFindsAStacksService(t *testing.T) {
	h := ecsStackDoorway(t)
	ap := &impersonatingApplier{ns: ecsTestNS, shim: h.shimDyn}
	at := h.locateService(context.Background(), ap, "web", "web-cluster")
	if at.ap.ns != "open-infra-cfn" || at.app != "web-stack-service" || at.cluster != "web-cluster" {
		t.Fatalf("the stack's service is at %s/%s in %s, want open-infra-cfn/web-stack-service in web-cluster",
			at.ap.ns, at.app, at.cluster)
	}
	if !strings.HasSuffix(at.taskDefinition, ":task-definition/web:1") || at.launchType != "FARGATE" ||
		at.createdAt != "2026-01-02T03:04:05Z" {
		t.Errorf("the service's record: task definition %q, launch type %q, created %q", at.taskDefinition,
			at.launchType, at.createdAt)
	}
	if ap.ns != ecsTestNS {
		t.Error("the caller's applier is not changed")
	}
	if at := h.locateService(context.Background(), ap, "web", "default"); at.app == "web-stack-service" {
		t.Error("in another cluster the name is not the stack's service")
	}
	if at := h.locateService(context.Background(), ap, "not-yet", "web-cluster"); at.ap.ns != ecsTestNS {
		t.Error("a service the stack has not made is not found in the stack")
	}
}

// A cluster a stack made is the account's: ListClusters and DescribeClusters report it, and a service can
// be created in it.
func TestECSStack_AStacksClusterIsTheAccounts(t *testing.T) {
	h := ecsStackDoorway(t)
	_, out := ecsCall(t, h, mgmtDoorCaller(), "ListClusters", map[string]any{})
	if arns, _ := out["clusterArns"].([]any); len(arns) != 1 || !strings.HasSuffix(arns[0].(string), ":cluster/web-cluster") {
		t.Errorf("ListClusters = %v, want the stack's cluster", out)
	}
	code, out := ecsCall(t, h, mgmtDoorCaller(), "DescribeClusters", map[string]any{"clusters": []any{"web-cluster"}})
	cs, _ := out["clusters"].([]any)
	if code != http.StatusOK || len(cs) != 1 || cs[0].(map[string]any)["status"] != "ACTIVE" {
		t.Errorf("DescribeClusters = %d %v, want the stack's cluster ACTIVE", code, out)
	}
	if found, err := h.clusterExists(context.Background(), "web-cluster"); err != nil || !found {
		t.Errorf("CreateService's cluster check does not find the stack's cluster: %v %v", found, err)
	}
	if found, _ := h.clusterExists(context.Background(), "other"); found {
		t.Error("a cluster no one made exists")
	}
}

func TestECSStack_ServiceARNParts(t *testing.T) {
	for arn, want := range map[string][2]string{
		"arn:aws:ecs:us-east-1:111122223333:service/prod/web": {"prod", "web"},
		"arn:aws:ecs:us-east-1:111122223333:service/web":      {"", ""}, // the old short form names no cluster
		"web": {"", ""},
	} {
		c, n, ok := ecsServiceARNParts(arn)
		if want[0] == "" {
			if ok {
				t.Errorf("%q parsed as %q/%q", arn, c, n)
			}
			continue
		}
		if !ok || c != want[0] || n != want[1] {
			t.Errorf("%q = %q/%q %v, want %v", arn, c, n, ok, want)
		}
	}
	if got := requestedCluster("arn:aws:ecs:us-east-1:111122223333:service/prod/web", "default"); got != "prod" {
		t.Errorf("a service ARN's cluster = %q", got)
	}
	if got := requestedCluster("web", "prod"); got != "prod" {
		t.Errorf("a name's cluster is the request's: %q", got)
	}
}
