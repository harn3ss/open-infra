package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
      Cpu: "256"
      Memory: "512"
      ContainerDefinitions:
        - Name: web
          Image: nginx
          PortMappings: [{ ContainerPort: 80 }]
          LogConfiguration:
            LogDriver: awslogs
            Options: { awslogs-group: /ecs/web, awslogs-stream-prefix: web }
  Service:
    Type: AWS::ECS::Service
    Properties:
      ServiceName: web
      Cluster: !Ref Cluster
      TaskDefinition: !Ref Task
      LaunchType: FARGATE
      NetworkConfiguration: { AwsvpcConfiguration: { Subnets: [subnet-0abc], AssignPublicIp: ENABLED } }
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
	avc, _ := at.network["awsvpcConfiguration"].(map[string]any)
	if subs, _ := avc["subnets"].([]any); len(subs) != 1 || subs[0] != "subnet-0abc" || avc["assignPublicIp"] != "ENABLED" {
		t.Errorf("the stack's service's networkConfiguration, in the ECS API's form: %v", at.network)
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

// DescribeTaskDefinition describes a task definition a stack made, in the ECS API's form (a log driver's
// options as written), by family:revision or by its family alone; another family is still not found.
func TestECSStack_DescribeTaskDefinitionDescribesAStacksTaskDefinition(t *testing.T) {
	h := ecsStackDoorway(t)
	for _, ref := range []string{"web", "web:1"} {
		code, out := ecsCall(t, h, mgmtDoorCaller(), "DescribeTaskDefinition", map[string]any{"taskDefinition": ref})
		td, _ := out["taskDefinition"].(map[string]any)
		if code != http.StatusOK || td == nil {
			t.Fatalf("DescribeTaskDefinition %s = %d %v", ref, code, out)
		}
		if td["family"] != "web" || td["revision"] != float64(1) || td["status"] != "ACTIVE" || td["cpu"] != "256" ||
			td["memory"] != "512" || !strings.HasSuffix(fnStr(td["taskDefinitionArn"]), ":task-definition/web:1") {
			t.Errorf("%s: %v", ref, td)
		}
		cds, _ := td["containerDefinitions"].([]any)
		c, _ := cds[0].(map[string]any)
		lc, _ := c["logConfiguration"].(map[string]any)
		opts, _ := lc["options"].(map[string]any)
		pm, _ := c["portMappings"].([]any)
		if c["name"] != "web" || c["image"] != "nginx" || lc["logDriver"] != "awslogs" || opts["awslogs-group"] != "/ecs/web" ||
			len(pm) != 1 || pm[0].(map[string]any)["containerPort"] != float64(80) {
			t.Errorf("%s: container %v", ref, c)
		}
	}
	if _, out := ecsCall(t, h, mgmtDoorCaller(), "DescribeTaskDefinition", map[string]any{"taskDefinition": "other"}); jsonErrType(out) != "ClientException" {
		t.Errorf("a family no stack made: %v", out)
	}
	if _, out := ecsCall(t, h, mgmtDoorCaller(), "DescribeTaskDefinition", map[string]any{"taskDefinition": "web:2"}); jsonErrType(out) != "ClientException" {
		t.Errorf("a revision the stack did not make: %v", out)
	}
}

// A stack that rolled back made nothing in ECS.
func TestECSStack_ARolledBackStackMadeNothing(t *testing.T) {
	h := ecsStackDoorway(t)
	recs, _ := h.stacks(context.Background())
	recs[0].Status = "ROLLBACK_COMPLETE"
	h.stacks = func(context.Context) ([]*cfn.StackRecord, error) { return recs, nil }
	if v := h.stackECS(context.Background()); len(v.services)+len(v.clusters)+len(v.taskDefs) != 0 {
		t.Errorf("a rolled-back stack's ECS resources: %+v", v)
	}
}

// DescribeClusters counts a cluster's services and their tasks as ECS does, the same counts its services'
// DescribeServices give: the stack's service, one task running and one pending.
func TestECSStack_DescribeClustersCountsItsServices(t *testing.T) {
	h := ecsStackDoorway(t)
	two, one := int32(2), int32(1)
	cs := h.cs.(*fake.Clientset)
	if _, err := cs.AppsV1().Deployments("open-infra-cfn").Create(context.Background(), &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web-stack-service", Namespace: "open-infra-cfn"},
		Spec:       appsv1.DeploymentSpec{Replicas: &two},
		Status:     appsv1.DeploymentStatus{Replicas: two, ReadyReplicas: one},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	_, out := ecsCall(t, h, mgmtDoorCaller(), "DescribeClusters", map[string]any{"clusters": []any{"web-cluster"}})
	cs0, _ := out["clusters"].([]any)
	if len(cs0) != 1 {
		t.Fatalf("DescribeClusters = %v", out)
	}
	c := cs0[0].(map[string]any)
	if c["activeServicesCount"] != float64(1) || c["runningTasksCount"] != float64(1) || c["pendingTasksCount"] != float64(1) {
		t.Errorf("counts: services %v running %v pending %v; want 1 1 1", c["activeServicesCount"], c["runningTasksCount"], c["pendingTasksCount"])
	}
	_, out = ecsCall(t, h, mgmtDoorCaller(), "DescribeClusters", map[string]any{})
	for _, x := range out["clusters"].([]any) {
		if c := x.(map[string]any); c["clusterName"] == "web-cluster" && c["activeServicesCount"] != float64(1) {
			t.Errorf("the cluster listing counts it too: %v", c)
		}
	}
}

// ecsStackTasks gives the stack's service two tasks: one running, one whose image can't be pulled.
func ecsStackTasks(t *testing.T, h *ecsDoorway) {
	t.Helper()
	cs := h.cs.(*fake.Clientset)
	labels := map[string]string{"app.kubernetes.io/name": "web-stack-service"}
	owner := []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-stack-service-5f6d8", UID: "rs-uid"}}
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "web-stack-service-5f6d8-aaaaa", Namespace: "open-infra-cfn", Labels: labels, OwnerReferences: owner, UID: "p1"},
			Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, StartTime: &metav1.Time{},
				ContainerStatuses: []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
					ImageID: "docker.io/library/nginx@sha256:abc"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "web-stack-service-5f6d8-bbbbb", Namespace: "open-infra-cfn", Labels: labels, OwnerReferences: owner, UID: "p2"},
			Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app", Image: "registry/web:1"}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending,
				ContainerStatuses: []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "ErrImagePull", Message: "failed to pull image \"registry/web:1\": 403 Forbidden"}}}}}},
	} {
		if _, err := cs.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

// ListTasks lists a service's tasks by cluster, service and desired status, as ECS does; DescribeTasks
// describes each, and a task whose image can't be pulled carries ECS's CannotPullContainerError.
func TestECSStack_ListAndDescribeTasks(t *testing.T) {
	h := ecsStackDoorway(t)
	ecsStackTasks(t, h)
	caller := mgmtDoorCaller()
	_, out := ecsCall(t, h, caller, "ListTasks", map[string]any{"cluster": "web-cluster"})
	arns, _ := out["taskArns"].([]any)
	if len(arns) != 2 || !strings.Contains(arns[0].(string), ":task/web-cluster/") {
		t.Fatalf("ListTasks = %v", out)
	}
	if _, out := ecsCall(t, h, caller, "ListTasks", map[string]any{"cluster": "web-cluster", "serviceName": "web"}); len(out["taskArns"].([]any)) != 2 {
		t.Errorf("ListTasks by service: %v", out)
	}
	if _, out := ecsCall(t, h, caller, "ListTasks", map[string]any{"cluster": "web-cluster", "desiredStatus": "STOPPED"}); len(out["taskArns"].([]any)) != 0 {
		t.Errorf("no task is stopped: %v", out)
	}
	if _, out := ecsCall(t, h, caller, "ListTasks", map[string]any{"cluster": "web-cluster", "serviceName": "nope"}); jsonErrType(out) != "ServiceNotFoundException" {
		t.Errorf("an unknown service: %v", out)
	}
	if _, out := ecsCall(t, h, caller, "ListTasks", map[string]any{"cluster": "nope"}); jsonErrType(out) != "ClusterNotFoundException" {
		t.Errorf("an unknown cluster: %v", out)
	}

	_, out = ecsCall(t, h, caller, "DescribeTasks", map[string]any{"cluster": "web-cluster", "tasks": append(arns, "0123")})
	tasks, _ := out["tasks"].([]any)
	if fs, _ := out["failures"].([]any); len(tasks) != 2 || len(fs) != 1 || fs[0].(map[string]any)["reason"] != "MISSING" {
		t.Fatalf("DescribeTasks = %v", out)
	}
	by := map[string]map[string]any{}
	for _, x := range tasks {
		task := x.(map[string]any)
		by[fnStr(task["lastStatus"])] = task
	}
	run, pend := by["RUNNING"], by["PENDING"]
	if run == nil || pend == nil {
		t.Fatalf("want a RUNNING and a PENDING task: %v", tasks)
	}
	if run["cpu"] != "256" || run["memory"] != "512" {
		t.Errorf("a task's size is its task definition's: cpu %v memory %v", run["cpu"], run["memory"])
	}
	if run["group"] != "service:web" || !strings.HasSuffix(fnStr(run["taskDefinitionArn"]), ":task-definition/web:1") ||
		!strings.HasPrefix(fnStr(run["startedBy"]), "ecs-svc/") || run["desiredStatus"] != "RUNNING" {
		t.Errorf("running task: %v", run)
	}
	rc := run["containers"].([]any)[0].(map[string]any)
	if rc["lastStatus"] != "RUNNING" || rc["imageDigest"] != "sha256:abc" {
		t.Errorf("running container: %v", rc)
	}
	pc := pend["containers"].([]any)[0].(map[string]any)
	if !strings.HasPrefix(fnStr(pc["reason"]), "CannotPullContainerError: ") || !strings.Contains(fnStr(pc["reason"]), "403 Forbidden") {
		t.Errorf("a task that can't pull its image: %v", pc)
	}
	// The task ids are the ones its awslogs streams carry.
	if id := lastSlashSeg(fnStr(run["taskArn"])); id != podID("open-infra-cfn", "web-stack-service-5f6d8-aaaaa") {
		t.Errorf("task id %s is not its log stream's", id)
	}
}

// A service with a task that can't pull its image says so in its events, in ECS's words.
func TestECSStack_PullFailureIsAServiceEvent(t *testing.T) {
	h := ecsStackDoorway(t)
	ecsStackTasks(t, h)
	evs := pullFailureEvents("web", h.tasksOf(context.Background(), ecsSvcLoc{name: "web", ns: "open-infra-cfn", app: "web-stack-service"}))
	if len(evs) != 1 || evs[0].Message != "(service web) is unable to consistently start tasks successfully." {
		t.Fatalf("events = %+v", evs)
	}
}

// ListTaskDefinitions lists the account's task definitions, a stack's among them, by family when asked.
func TestECSStack_ListTaskDefinitions(t *testing.T) {
	h := ecsStackDoorway(t)
	caller := mgmtDoorCaller()
	if code, out := ecsCall(t, h, caller, "RegisterTaskDefinition", ecsTaskDefBody("api", "nginx")); code != http.StatusOK {
		t.Fatalf("register: %d %v", code, out)
	}
	_, out := ecsCall(t, h, caller, "ListTaskDefinitions", map[string]any{})
	arns, _ := out["taskDefinitionArns"].([]any)
	if len(arns) != 2 || !strings.HasSuffix(arns[0].(string), ":task-definition/api:1") || !strings.HasSuffix(arns[1].(string), ":task-definition/web:1") {
		t.Fatalf("ListTaskDefinitions = %v", out)
	}
	if _, out := ecsCall(t, h, caller, "ListTaskDefinitions", map[string]any{"familyPrefix": "web"}); len(out["taskDefinitionArns"].([]any)) != 1 {
		t.Errorf("by family: %v", out)
	}
	if _, out := ecsCall(t, h, caller, "ListTaskDefinitions", map[string]any{"sort": "DESC"}); !strings.HasSuffix(out["taskDefinitionArns"].([]any)[0].(string), "web:1") {
		t.Errorf("DESC: %v", out)
	}
}

// A task in a subnet (its service's NetworkConfiguration) has its network interface, as ECS reports an awsvpc
// task's: the subnet's id (the default subnet's, as EC2 names it) and the task's private address.
func TestECSStack_TaskInASubnetHasItsInterface(t *testing.T) {
	h := ecsStackDoorway(t)
	h.defaultSubnets = func(context.Context) map[string]string { return map[string]string{"subnet-0abc": "default-vpc"} }
	cs := h.cs.(*fake.Clientset)
	if _, err := cs.CoreV1().Pods("open-infra-cfn").Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-stack-service-5f6d8-ccccc", Namespace: "open-infra-cfn", UID: "p3",
			Labels:      map[string]string{"app.kubernetes.io/name": "web-stack-service"},
			Annotations: map[string]string{"ovn.kubernetes.io/logical_switch": "default-vpc"}},
		Spec:   corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "172.31.0.9"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	_, out := ecsCall(t, h, mgmtDoorCaller(), "DescribeTasks", map[string]any{"cluster": "web-cluster",
		"tasks": []any{podID("open-infra-cfn", "web-stack-service-5f6d8-ccccc")}})
	task := out["tasks"].([]any)[0].(map[string]any)
	att, _ := task["attachments"].([]any)
	if len(att) != 1 {
		t.Fatalf("attachments %v", task)
	}
	a := att[0].(map[string]any)
	got := map[string]string{}
	for _, d := range a["details"].([]any) {
		m := d.(map[string]any)
		got[m["name"].(string)] = m["value"].(string)
	}
	if a["type"] != "ElasticNetworkInterface" || a["status"] != "ATTACHED" || got["subnetId"] != "subnet-0abc" ||
		got["privateIPv4Address"] != "172.31.0.9" || !strings.HasPrefix(got["networkInterfaceId"], "eni-") {
		t.Fatalf("interface %v", a)
	}
}
