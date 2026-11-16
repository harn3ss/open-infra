// What ECS DescribeServices reports of a running service: its task counts, its deployments and its events.
//
// An ECS service is a kind: Application whose workload is a Deployment; each rollout of it is a ReplicaSet.
// So, as ECS reports them:
//   - runningCount is the tasks started and ready, pendingCount those started and not yet ready, over all of
//     the service's ReplicaSets; a task that could not be placed (refused by the account's capacity) is
//     neither, as on ECS, and shows as an event instead;
//   - each ReplicaSet still running tasks is a deployment: the newest is PRIMARY, an older one still
//     draining is ACTIVE, each with its counts and rollout state;
//   - the service's events are ECS's own messages, made from what the ReplicaSets' controller recorded (a
//     task started or stopped, a task that could not be placed and why), and the steady state a finished
//     rollout reaches. ECS keeps a service's 100 most recent events; the shim keeps them likewise, in its
//     own namespace, so they outlive the platform's one-hour record.
//
// The workload is read with the shim's own read access, once the caller was allowed ecs:DescribeServices
// on the service, and only in the caller's account's namespace. Only ECS's fields are returned.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ecsMaxEvents is how many of a service's events ECS keeps and returns.
const ecsMaxEvents = 100

// ecsEvent is one service event, as ECS's DescribeServices returns it.
type ecsEvent struct {
	ID        string  `json:"id"`
	CreatedAt float64 `json:"createdAt"`
	Message   string  `json:"message"`
}

// ecsTaskDefRecord is one task definition the service ran, from when (CreateService, UpdateService).
type ecsTaskDefRecord struct {
	TaskDefinition string `json:"taskDefinition"`
	At             string `json:"at"`
}

// ecsWorkload is a service's state as ECS reports it.
type ecsWorkload struct {
	desired, running, pending int
	deployments               []any
	events                    []ecsEvent // newest first
}

// ecsTaskID is the ECS task id of one of the service's tasks: 32 hex digits, as ECS's are, stable for the
// task's life, and the id its awslogs stream carries (podID, cloudwatchlogs_loki.go).
func ecsTaskID(ns, pod string) string { return podID(ns, pod) }

// ecsDeploymentID is the id of the deployment a ReplicaSet is: ecs-svc/ and 19 digits, as ECS's are.
func ecsDeploymentID(uid types.UID) string {
	sum := sha256.Sum256([]byte("ecs-deployment/" + string(uid)))
	return fmt.Sprintf("ecs-svc/%019d", binary.BigEndian.Uint64(sum[:8])%10_000_000_000_000_000_000)
}

// ecsEventID is an event's id: a UUID-shaped digest of what it records, so the same occurrence read twice
// is the same event.
func ecsEventID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func ecsEpoch(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }

// eventTime is when a recorded event last happened.
func eventTime(e corev1.Event) time.Time {
	switch {
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case e.Series != nil && !e.Series.LastObservedTime.IsZero():
		return e.Series.LastObservedTime.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	}
	return e.FirstTimestamp.Time
}

// ecsPlacementReason is ECS's reason a task could not be placed, for the account capacity a pod was refused
// by: its task count, its vCPUs or its memory
// (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-event-messages-list.html).
func ecsPlacementReason(message string) string {
	requested := message
	if i := strings.Index(requested, "requested: "); i >= 0 {
		requested = requested[i+len("requested: "):]
	}
	if i := strings.Index(requested, ", used: "); i >= 0 {
		requested = requested[:i]
	}
	var cpu, mem bool
	for _, kv := range strings.Split(requested, ",") {
		key, _, _ := strings.Cut(strings.TrimSpace(kv), "=")
		switch {
		case key == "pods" || key == "count/pods":
			return "You've reached the limit on the number of tasks you can run concurrently"
		case strings.HasSuffix(key, "cpu"):
			cpu = true
		case strings.HasSuffix(key, "memory"):
			mem = true
		}
	}
	switch {
	case cpu:
		return "You’ve reached the limit on the number of vCPUs you can run concurrently"
	case mem:
		return "The requested MEMORY configuration is above your limit."
	}
	return "You've reached the limit on the number of tasks you can run concurrently"
}

// ecsEventsOf turns what the ReplicaSets' controller recorded into ECS's service events. An event ECS has
// no counterpart for is left out.
func ecsEventsOf(service, ns string, recorded []corev1.Event) []ecsEvent {
	var out []ecsEvent
	for _, e := range recorded {
		at := eventTime(e)
		var msg string
		switch e.Reason {
		case "SuccessfulCreate":
			if pod, ok := strings.CutPrefix(e.Message, "Created pod: "); ok {
				msg = fmt.Sprintf("(service %s) has started 1 tasks: (task %s).", service, ecsTaskID(ns, strings.TrimSpace(pod)))
			}
		case "SuccessfulDelete":
			if pod, ok := strings.CutPrefix(e.Message, "Deleted pod: "); ok {
				msg = fmt.Sprintf("(service %s) has stopped 1 running tasks: (task %s).", service, ecsTaskID(ns, strings.TrimSpace(pod)))
			}
		case "FailedCreate":
			if strings.Contains(e.Message, "exceeded quota") {
				msg = fmt.Sprintf("(service %s) was unable to place a task. Reason: %s", service, ecsPlacementReason(e.Message))
			} else {
				msg = fmt.Sprintf("(service %s) is unable to consistently start tasks successfully.", service)
			}
		}
		if msg == "" || at.IsZero() {
			continue
		}
		out = append(out, ecsEvent{ID: ecsEventID(string(e.UID), at.UTC().Format(time.RFC3339Nano), msg), CreatedAt: ecsEpoch(at), Message: msg})
	}
	return out
}

// ecsRevision is a ReplicaSet's rollout number.
func ecsRevision(rs appsv1.ReplicaSet) int {
	n, _ := strconv.Atoi(rs.Annotations["deployment.kubernetes.io/revision"])
	return n
}

// ecsTaskDefAt is the task definition the service ran when a rollout began: the last one it was given
// before then.
func ecsTaskDefAt(history []ecsTaskDefRecord, at time.Time, current string) string {
	best := ""
	for _, r := range history {
		t, err := time.Parse(time.RFC3339, r.At)
		if err == nil && !t.After(at.Add(2*time.Second)) {
			best = r.TaskDefinition
		}
	}
	if best == "" {
		return current
	}
	return best
}

// ecsServiceState is the service's state as ECS reports it, from its Deployment, the Deployment's
// ReplicaSets and what their controller recorded. taskDefArn turns a task-definition reference into its ARN.
func ecsServiceState(service, ns, launchType string, dep *appsv1.Deployment, rss []appsv1.ReplicaSet,
	recorded []corev1.Event, history []ecsTaskDefRecord, currentTD string, taskDefArn func(string) string) ecsWorkload {
	w := ecsWorkload{desired: 1}
	if dep.Spec.Replicas != nil {
		w.desired = int(*dep.Spec.Replicas)
	}
	sort.SliceStable(rss, func(i, j int) bool { return ecsRevision(rss[i]) > ecsRevision(rss[j]) })
	lastEvent := map[string]time.Time{}
	for _, e := range recorded {
		if t := eventTime(e); t.After(lastEvent[e.InvolvedObject.Name]) {
			lastEvent[e.InvolvedObject.Name] = t
		}
	}
	activeLeft := false
	var primary map[string]any
	var primaryID string
	var primaryDone bool
	for i, rs := range rss {
		if i > 0 && rs.Status.Replicas == 0 {
			continue // an earlier rollout with nothing left running: INACTIVE, which ECS no longer lists
		}
		running := int(rs.Status.ReadyReplicas)
		pending := int(rs.Status.Replicas) - running
		if pending < 0 {
			pending = 0
		}
		w.running += running
		w.pending += pending
		created := rs.CreationTimestamp.Time
		updated := created
		if t := lastEvent[rs.Name]; t.After(updated) {
			updated = t
		}
		id := ecsDeploymentID(rs.UID)
		d := map[string]any{
			"id":             id,
			"taskDefinition": taskDefArn(ecsTaskDefAt(history, created, currentTD)),
			"pendingCount":   pending,
			"runningCount":   running,
			"failedTasks":    0,
			"createdAt":      ecsEpoch(created),
			"updatedAt":      ecsEpoch(updated),
		}
		if launchType != "" {
			d["launchType"] = launchType
		}
		if i == 0 {
			d["status"], d["desiredCount"] = "PRIMARY", w.desired
			primary, primaryID = d, id
			primaryDone = pending == 0 && running == w.desired
		} else {
			desired := 0
			if rs.Spec.Replicas != nil {
				desired = int(*rs.Spec.Replicas)
			}
			d["status"], d["desiredCount"], d["rolloutState"] = "ACTIVE", desired, "COMPLETED"
			d["rolloutStateReason"] = "ECS deployment " + id + " completed."
			activeLeft = true
		}
		w.deployments = append(w.deployments, d)
	}
	w.events = ecsEventsOf(service, ns, recorded)
	if primary != nil {
		if primaryDone && !activeLeft {
			primary["rolloutState"] = "COMPLETED"
			primary["rolloutStateReason"] = "ECS deployment " + primaryID + " completed."
			// The steady state is reached when the rollout last progressed.
			at := dep.CreationTimestamp.Time
			for _, c := range dep.Status.Conditions {
				if c.Type == appsv1.DeploymentProgressing && c.LastUpdateTime.After(at) {
					at = c.LastUpdateTime.Time
				}
				if c.Type == appsv1.DeploymentAvailable && c.LastTransitionTime.After(at) {
					at = c.LastTransitionTime.Time
				}
			}
			stamp := at.UTC().Format(time.RFC3339Nano)
			w.events = append(w.events,
				ecsEvent{ID: ecsEventID("completed", primaryID), CreatedAt: ecsEpoch(at),
					Message: fmt.Sprintf("(service %s) (deployment %s) deployment completed.", service, primaryID)},
				// A steady state is reported after what led to it, so it sorts first at the same instant.
				ecsEvent{ID: ecsEventID("steady", primaryID, stamp), CreatedAt: ecsEpoch(at) + 0.001,
					Message: fmt.Sprintf("(service %s) has reached a steady state.", service)})
		} else {
			primary["rolloutState"] = "IN_PROGRESS"
			primary["rolloutStateReason"] = "ECS deployment " + primaryID + " in progress."
		}
	}
	w.events = mergeECSEvents(nil, w.events)
	return w
}

// mergeECSEvents adds fresh events to the kept ones: newest first, each once, the 100 most recent.
func mergeECSEvents(kept, fresh []ecsEvent) []ecsEvent {
	seen := map[string]bool{}
	var out []ecsEvent
	for _, e := range append(append([]ecsEvent{}, fresh...), kept...) {
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	if len(out) > ecsMaxEvents {
		out = out[:ecsMaxEvents]
	}
	return out
}

func eventsCMName(service string) string { return "ecs-events-" + ecsLabel(service) }

// keptEvents are the service's events the shim kept from earlier reads.
func (h *ecsDoorway) keptEvents(ctx context.Context, service string) []ecsEvent {
	u, found, err := h.getConfigMap(ctx, eventsCMName(service))
	if err != nil || !found {
		return nil
	}
	var kept []ecsEvent
	_ = json.Unmarshal([]byte(cmData(u, "events.json")), &kept)
	return kept
}

// workload reads the state of the service whose Application is app, in ns, as ECS reports it. ok is false
// while the service has no workload yet (its Application has not made its Deployment), when
// DescribeServices reports from the Application alone.
func (h *ecsDoorway) workload(ctx context.Context, ns, app, service, launchType string, history []ecsTaskDefRecord,
	currentTD string) (ecsWorkload, bool) {
	dep, err := h.cs.AppsV1().Deployments(ns).Get(ctx, app, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			h.logger.Warn("ecs DescribeServices: reading the service's workload", "service", service, "error", err.Error())
		}
		return ecsWorkload{}, false
	}
	list, err := h.cs.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + app})
	if err != nil {
		h.logger.Warn("ecs DescribeServices: reading the service's deployments", "service", service, "error", err.Error())
		return ecsWorkload{}, false
	}
	var rss []appsv1.ReplicaSet
	for _, rs := range list.Items {
		if metav1.IsControlledBy(&rs, dep) {
			rss = append(rss, rs)
		}
	}
	// What the controller recorded about each rollout (the platform keeps it an hour; the kept events
	// outlive it).
	var recorded []corev1.Event
	for _, rs := range rss {
		evs, err := h.cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{
			FieldSelector: "involvedObject.kind=ReplicaSet,involvedObject.name=" + rs.Name,
		})
		if err != nil {
			continue
		}
		for _, e := range evs.Items {
			if e.InvolvedObject.Kind == "ReplicaSet" && e.InvolvedObject.Name == rs.Name {
				recorded = append(recorded, e)
			}
		}
	}
	w := ecsServiceState(service, ns, launchType, dep, rss, recorded, history, currentTD,
		func(ref string) string { return h.taskDefArnFromRef(ctx, ref) })
	kept := h.keptEvents(ctx, service)
	merged := mergeECSEvents(kept, w.events)
	if !sameECSEvents(kept, merged) {
		if blob, err := json.Marshal(merged); err == nil {
			if err := h.putConfigMap(ctx, eventsCMName(service), map[string]any{"events.json": string(blob), "name": service},
				map[string]any{"ecs.openinfra.dev/service": ecsLabel(service)}); err != nil {
				h.logger.Warn("ecs DescribeServices: keeping the service's events", "service", service, "error", err.Error())
			}
		}
	}
	w.events = merged
	return w, true
}

func sameECSEvents(a, b []ecsEvent) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

// eventsJSON is the events as DescribeServices returns them.
func eventsJSON(evs []ecsEvent) []any {
	out := make([]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, map[string]any{"id": e.ID, "createdAt": e.CreatedAt, "message": e.Message})
	}
	return out
}
