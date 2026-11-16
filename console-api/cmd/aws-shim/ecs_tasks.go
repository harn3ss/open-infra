package main

// ECS tasks and task-definition listings, as ECS reports them.
//
// A service's tasks are its Application's pods: ListTasks lists them by cluster, service, family, launch type
// and desired status, and DescribeTasks describes each as ECS does — its ARN (task/<cluster>/<task id>, the id
// its awslogs stream carries), its task definition, the deployment that started it (startedBy ecs-svc/…),
// its status and its containers. A task whose image can't be pulled is reported in ECS's terms: its container's
// reason is a CannotPullContainerError, and the service's events say it is unable to consistently start tasks.
// Unlike ECS, which stops such a task and starts another, the platform keeps pulling in the same task (with
// back-off), so it stays PENDING with that reason until the pull succeeds.
//
// ListTaskDefinitions lists the account's task definitions: those registered through ECS and those its
// CloudFormation stacks made (ecs_stack.go).

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ecsSvcLoc is one of a cluster's services and where its tasks run.
type ecsSvcLoc struct {
	name, cluster, ns, app string
	taskDefinition         string // its current task definition (family:revision, or an ARN)
	launchType             string
	history                []ecsTaskDefRecord
}

// clusterServices are a cluster's services: those created through ECS and those a stack made in it.
func (h *ecsDoorway) clusterServices(ctx context.Context, cluster string) []ecsSvcLoc {
	var out []ecsSvcLoc
	seen := map[string]bool{}
	byShim := &impersonatingApplier{shim: h.shimDyn, ns: h.nsFor(ctx)} // the doorway's own records alone
	for _, ref := range h.listServiceRefs(ctx) {
		if strOrDefault(ref.Cluster, "default") != cluster {
			continue
		}
		seen[ref.ServiceName] = true
		out = append(out, ecsSvcLoc{name: ref.ServiceName, cluster: cluster, ns: h.nsFor(ctx),
			app: ecsAppObject(ctx, byShim, ecsName(ref.ServiceName)), taskDefinition: firstString(ref.Body, "taskDefinition"),
			launchType: firstString(ref.Body, "launchType"), history: ref.History})
	}
	for _, ss := range h.stackECS(ctx).services {
		if ss.cluster == cluster && !seen[ss.name] {
			out = append(out, ecsSvcLoc{name: ss.name, cluster: cluster, ns: ss.ns, app: ss.app,
				taskDefinition: ss.taskDefinition, launchType: ss.launchType})
		}
	}
	return out
}

// ecsTask is one task of a service: its pod.
type ecsTask struct {
	svc ecsSvcLoc
	pod corev1.Pod
}

func (t ecsTask) id() string { return ecsTaskID(t.pod.Namespace, t.pod.Name) }

// tasksOf are a service's tasks.
func (h *ecsDoorway) tasksOf(ctx context.Context, s ecsSvcLoc) []ecsTask {
	if h.cs == nil {
		return nil
	}
	list, err := h.cs.CoreV1().Pods(s.ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + s.app})
	if err != nil {
		h.logger.Warn("ecs: listing a service's tasks", "service", s.name, "error", err.Error())
		return nil
	}
	var out []ecsTask
	for _, p := range list.Items {
		out = append(out, ecsTask{svc: s, pod: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pod.CreationTimestamp.Before(&out[j].pod.CreationTimestamp) })
	return out
}

// pullFailure is why a task's image can't be pulled, in ECS's words ("" when it is not failing to pull).
func pullFailure(p corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull":
				msg := strings.TrimSpace(w.Message)
				if msg == "" {
					msg = w.Reason
				}
				return "CannotPullContainerError: " + msg
			}
		}
	}
	return ""
}

// ecsTaskStatus is a task's lastStatus and desiredStatus.
func ecsTaskStatus(p corev1.Pod) (last, desired string) {
	switch {
	case p.DeletionTimestamp != nil:
		return "STOPPING", "STOPPED"
	case p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed:
		return "STOPPED", "STOPPED"
	case p.Status.Phase == corev1.PodRunning:
		return "RUNNING", "RUNNING"
	case p.Spec.NodeName == "":
		return "PROVISIONING", "RUNNING"
	}
	return "PENDING", "RUNNING"
}

func (h *ecsDoorway) taskArn(ctx context.Context, cluster, id string) string {
	return "arn:aws:ecs:" + h.region + ":" + h.arnAccount(ctx) + ":task/" + cluster + "/" + id
}

// taskObject is a task as DescribeTasks returns it. containerName is the name the task definition gives the
// pod's app container ("" = app).
func (h *ecsDoorway) taskObject(ctx context.Context, t ecsTask, containerName string) map[string]any {
	p := t.pod
	last, desired := ecsTaskStatus(p)
	arn := h.taskArn(ctx, t.svc.cluster, t.id())
	td := t.svc.taskDefinition
	var deployment string
	for _, o := range p.OwnerReferences {
		if o.Kind == "ReplicaSet" {
			deployment = ecsDeploymentID(o.UID)
		}
	}
	if len(t.svc.history) > 0 {
		td = ecsTaskDefAt(t.svc.history, p.CreationTimestamp.Time, td)
	}
	task := map[string]any{
		"taskArn":           arn,
		"clusterArn":        h.clusterArn(ctx, t.svc.cluster),
		"taskDefinitionArn": h.taskDefArnFromRef(ctx, td),
		"group":             "service:" + t.svc.name,
		"lastStatus":        last,
		"desiredStatus":     desired,
		"createdAt":         ecsEpoch(p.CreationTimestamp.Time),
		"connectivity":      "CONNECTED",
		"healthStatus":      "UNKNOWN",
		"version":           1,
	}
	if deployment != "" {
		task["startedBy"] = deployment
	}
	if t.svc.launchType != "" {
		task["launchType"] = t.svc.launchType
	}
	if p.Status.StartTime != nil && last == "RUNNING" {
		task["startedAt"] = ecsEpoch(p.Status.StartTime.Time)
	}
	if p.DeletionTimestamp != nil {
		task["stoppingAt"] = ecsEpoch(p.DeletionTimestamp.Time)
	}
	statuses := map[string]corev1.ContainerStatus{}
	for _, cs := range p.Status.ContainerStatuses {
		statuses[cs.Name] = cs
	}
	containers := []any{}
	for i, c := range p.Spec.Containers {
		name := c.Name
		if name == "app" && containerName != "" {
			name = containerName
		}
		cs := statuses[c.Name]
		cl := "PENDING"
		switch {
		case cs.State.Running != nil:
			cl = "RUNNING"
		case cs.State.Terminated != nil:
			cl = "STOPPED"
		}
		cont := map[string]any{
			"containerArn": "arn:aws:ecs:" + h.region + ":" + h.arnAccount(ctx) + ":container/" + t.svc.cluster + "/" + t.id() + "/" +
				ecsEventID(string(p.UID), strconv.Itoa(i)),
			"taskArn":    arn,
			"name":       name,
			"image":      c.Image,
			"lastStatus": cl,
		}
		if d := cs.ImageID; d != "" {
			if i := strings.LastIndex(d, "@"); i >= 0 {
				cont["imageDigest"] = d[i+1:]
			}
		}
		if w := cs.State.Waiting; w != nil {
			if r := pullFailure(corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{cs}}}); r != "" {
				cont["reason"] = r
			}
		}
		if term := cs.State.Terminated; term != nil {
			cont["exitCode"] = term.ExitCode
			if term.Reason != "" {
				cont["reason"] = term.Reason
			}
		}
		containers = append(containers, cont)
	}
	task["containers"] = containers
	// A task in a subnet (an awsvpc task's NetworkConfiguration) has its network interface, as ECS reports it:
	// the subnet's id and the task's private address.
	if ls := p.Annotations["ovn.kubernetes.io/logical_switch"]; ls != "" {
		subnet := ls
		if h.defaultSubnets != nil {
			for id, sw := range h.defaultSubnets(ctx) {
				if sw == ls {
					subnet = id
				}
			}
		}
		details := []any{map[string]any{"name": "subnetId", "value": subnet},
			map[string]any{"name": "networkInterfaceId", "value": shortHashID("eni-", "task/"+string(p.UID), 17)}}
		if ip := p.Status.PodIP; ip != "" {
			details = append(details, map[string]any{"name": "privateIPv4Address", "value": ip})
		}
		task["attachments"] = []any{map[string]any{"id": ecsEventID("eni", string(p.UID)), "type": "ElasticNetworkInterface",
			"status": "ATTACHED", "details": details}}
	}
	return task
}

// pullFailureEvents are the service's events for its tasks that can't pull their image, in ECS's words: the
// service is unable to consistently start tasks.
func pullFailureEvents(service string, tasks []ecsTask) []ecsEvent {
	var out []ecsEvent
	for _, t := range tasks {
		if pullFailure(t.pod) == "" {
			continue
		}
		at := t.pod.CreationTimestamp.Time
		for _, c := range t.pod.Status.Conditions {
			if c.Type == corev1.ContainersReady && c.LastTransitionTime.After(at) {
				at = c.LastTransitionTime.Time
			}
		}
		out = append(out, ecsEvent{ID: ecsEventID("pull", string(t.pod.UID)), CreatedAt: ecsEpoch(at),
			Message: "(service " + service + ") is unable to consistently start tasks successfully."})
	}
	return out
}

// --- the operations ---

func (h *ecsDoorway) listTasks(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	cluster := lastSlashSeg(strOrDefault(firstString(body, "cluster"), "default"))
	service := lastSlashSeg(firstString(body, "serviceName"))
	family := firstString(body, "family")
	launchType := firstString(body, "launchType")
	desired := strOrDefault(firstString(body, "desiredStatus"), "RUNNING")
	if desired != "RUNNING" && desired != "PENDING" && desired != "STOPPED" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "desiredStatus must be RUNNING, PENDING or STOPPED.")
		return
	}
	if found, err := h.clusterExists(ctx, cluster); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !found && cluster != "default" {
		writeECSError(w, http.StatusBadRequest, "ClusterNotFoundException", requestID, "Cluster not found.")
		return
	}
	arns := []any{}
	matched := service == ""
	for _, s := range h.clusterServices(ctx, cluster) {
		if service != "" && s.name != service {
			continue
		}
		matched = true
		if launchType != "" && s.launchType != launchType {
			continue
		}
		for _, t := range h.tasksOf(ctx, s) {
			if family != "" {
				if fam, _ := parseTaskDef(t.svc.taskDefinition); fam != family {
					continue
				}
			}
			if _, d := ecsTaskStatus(t.pod); d != desired && !(desired == "PENDING" && d == "RUNNING") {
				continue
			}
			arns = append(arns, h.taskArn(ctx, cluster, t.id()))
		}
	}
	if !matched {
		writeECSError(w, http.StatusBadRequest, "ServiceNotFoundException", requestID, "Service not found.")
		return
	}
	h.audit(ctx, "ListTasks", cluster, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"taskArns": arns})
}

func (h *ecsDoorway) describeTasks(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	wanted := stringSlice(body["tasks"])
	if len(wanted) == 0 {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "Tasks cannot be empty.")
		return
	}
	cluster := lastSlashSeg(strOrDefault(firstString(body, "cluster"), "default"))
	byID := map[string]ecsTask{}
	for _, s := range h.clusterServices(ctx, cluster) {
		for _, t := range h.tasksOf(ctx, s) {
			byID[t.id()] = t
		}
	}
	containerNames := map[string]string{} // app -> its task definition's container name
	ap, _ := h.applierFor(ctx, claims)
	tasks, failures := []any{}, []any{}
	for _, raw := range wanted {
		t, ok := byID[lastSlashSeg(raw)]
		if !ok || h.otherAccountsARN(ctx, raw) {
			failures = append(failures, map[string]any{"arn": h.taskArn(ctx, cluster, lastSlashSeg(raw)), "reason": "MISSING"})
			continue
		}
		cn, seen := containerNames[t.svc.ns+"/"+t.svc.app]
		if !seen && ap != nil {
			in := *ap
			in.ns = t.svc.ns
			if spec, found, _ := in.GetSpec(ctx, ecsAppAPIVersion, "Application", t.svc.app); found {
				cn, _ = spec["containerName"].(string)
			}
			containerNames[t.svc.ns+"/"+t.svc.app] = cn
		}
		tasks = append(tasks, h.taskObject(ctx, t, cn))
	}
	h.audit(ctx, "DescribeTasks", cluster, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"tasks": tasks, "failures": failures})
}

func (h *ecsDoorway) listTaskDefinitions(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	prefix := firstString(body, "familyPrefix")
	status := strOrDefault(firstString(body, "status"), "ACTIVE")
	type td struct {
		family string
		rev    int
	}
	var all []td
	if status == "ACTIVE" {
		list, err := h.shimDyn.Resource(configMapGVR).Namespace(h.nsFor(ctx)).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=" + ecsManagedBy})
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		seen := map[string]bool{}
		for i := range list.Items {
			if !strings.HasPrefix(list.Items[i].GetName(), "ecs-taskdef-") {
				continue
			}
			fam := cmData(&list.Items[i], "family")
			rev, err := strconv.Atoi(cmData(&list.Items[i], "revision"))
			if fam == "" || err != nil {
				continue
			}
			seen[fam+":"+strconv.Itoa(rev)] = true
			all = append(all, td{fam, rev})
		}
		for _, s := range h.stackECS(ctx).taskDefs {
			if !seen[s.family+":"+strconv.Itoa(s.revision)] {
				all = append(all, td{s.family, s.revision})
			}
		}
	}
	// As ECS lists them: by family, then revision; DESC reverses the order.
	sort.Slice(all, func(i, j int) bool {
		if all[i].family != all[j].family {
			return all[i].family < all[j].family
		}
		return all[i].rev < all[j].rev
	})
	if strings.EqualFold(firstString(body, "sort"), "DESC") {
		for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
			all[i], all[j] = all[j], all[i]
		}
	}
	arns := []any{}
	for _, t := range all {
		if prefix == "" || t.family == prefix { // familyPrefix is the full family name, as ECS takes it
			arns = append(arns, h.taskDefArn(ctx, t.family, t.rev))
		}
	}
	h.audit(ctx, "ListTaskDefinitions", prefix, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"taskDefinitionArns": arns})
}
