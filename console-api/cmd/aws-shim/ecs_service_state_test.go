package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var ecsT0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func i32(n int32) *int32 { return &n }

func testDeployment(desired int32, conds ...appsv1.DeploymentCondition) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "acct", UID: "dep-uid", CreationTimestamp: metav1.NewTime(ecsT0)},
		Spec:       appsv1.DeploymentSpec{Replicas: i32(desired)},
		Status:     appsv1.DeploymentStatus{Conditions: conds},
	}
}

func testRS(name, uid string, rev int, created time.Time, desired, replicas, ready int32) appsv1.ReplicaSet {
	return appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "acct", UID: types.UID(uid), CreationTimestamp: metav1.NewTime(created),
			Annotations: map[string]string{"deployment.kubernetes.io/revision": fmt.Sprint(rev)}},
		Spec:   appsv1.ReplicaSetSpec{Replicas: i32(desired)},
		Status: appsv1.ReplicaSetStatus{Replicas: replicas, ReadyReplicas: ready},
	}
}

func testEvent(uid, rs, reason, msg string, at time.Time) corev1.Event {
	return corev1.Event{ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid)}, Reason: reason, Message: msg,
		InvolvedObject: corev1.ObjectReference{Kind: "ReplicaSet", Name: rs}, LastTimestamp: metav1.NewTime(at)}
}

func arnOf(ref string) string { return "arn:aws:ecs:us-east-1:111122223333:task-definition/" + ref }

func messages(evs []ecsEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Message)
	}
	return out
}

// Seven tasks wanted, six allowed by the account's capacity: six run, none is pending, and the seventh is
// ECS's placement event naming the task limit. The rollout is not complete, so no steady state.
func TestECSState_CapacityCeiling(t *testing.T) {
	rs := testRS("web-5d9c7", "rs-1", 1, ecsT0, 7, 6, 6)
	var evs []corev1.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, testEvent(fmt.Sprintf("e%d", i), rs.Name, "SuccessfulCreate",
			fmt.Sprintf("Created pod: web-5d9c7-p%d", i), ecsT0.Add(time.Duration(i)*time.Second)))
	}
	evs = append(evs, testEvent("q", rs.Name, "FailedCreate",
		`pods "web-5d9c7-p6" is forbidden: exceeded quota: account-capacity-quota, requested: pods=1, used: pods=6, limited: pods=6`,
		ecsT0.Add(10*time.Second)))
	w := ecsServiceState("web", "acct", "FARGATE", testDeployment(7), []appsv1.ReplicaSet{rs}, evs,
		[]ecsTaskDefRecord{{TaskDefinition: "web:1", At: ecsT0.Add(-time.Minute).Format(time.RFC3339)}}, "web:1", arnOf)

	if w.desired != 7 || w.running != 6 || w.pending != 0 {
		t.Fatalf("desired/running/pending = %d/%d/%d; want 7/6/0", w.desired, w.running, w.pending)
	}
	if len(w.deployments) != 1 {
		t.Fatalf("deployments = %v; want the PRIMARY alone", w.deployments)
	}
	d := w.deployments[0].(map[string]any)
	if d["status"] != "PRIMARY" || d["desiredCount"] != 7 || d["runningCount"] != 6 || d["rolloutState"] != "IN_PROGRESS" ||
		d["taskDefinition"] != arnOf("web:1") || d["launchType"] != "FARGATE" || !strings.HasPrefix(d["id"].(string), "ecs-svc/") ||
		len(d["id"].(string)) != len("ecs-svc/")+19 {
		t.Fatalf("PRIMARY = %v", d)
	}
	got := messages(w.events)
	want := "(service web) was unable to place a task. Reason: You've reached the limit on the number of tasks you can run concurrently"
	if len(got) != 7 || got[0] != want {
		t.Fatalf("events = %q; want the placement event newest, then six started", got)
	}
	for _, m := range got[1:] {
		if !strings.HasPrefix(m, "(service web) has started 1 tasks: (task ") || len(m) != len("(service web) has started 1 tasks: (task ).")+32 {
			t.Fatalf("started event %q", m)
		}
	}
	for _, m := range got {
		if strings.Contains(m, "pod") || strings.Contains(m, "quota") || strings.Contains(m, "ReplicaSet") {
			t.Fatalf("an event speaks the platform's terms, not ECS's: %q", m)
		}
	}
}

// At its desired count with nothing pending and no older rollout left, the deployment is COMPLETED and the
// service has reached a steady state, reported newest.
func TestECSState_SteadyState(t *testing.T) {
	done := ecsT0.Add(time.Minute)
	dep := testDeployment(2, appsv1.DeploymentCondition{Type: appsv1.DeploymentProgressing, Reason: "NewReplicaSetAvailable",
		LastUpdateTime: metav1.NewTime(done), LastTransitionTime: metav1.NewTime(ecsT0)})
	w := ecsServiceState("web", "acct", "", dep, []appsv1.ReplicaSet{testRS("web-a", "rs-a", 1, ecsT0, 2, 2, 2)},
		[]corev1.Event{testEvent("e1", "web-a", "SuccessfulCreate", "Created pod: web-a-1", ecsT0.Add(time.Second))}, nil, "web:3", arnOf)
	d := w.deployments[0].(map[string]any)
	if d["rolloutState"] != "COMPLETED" || d["rolloutStateReason"] != "ECS deployment "+d["id"].(string)+" completed." {
		t.Fatalf("PRIMARY = %v", d)
	}
	got := messages(w.events)
	if len(got) != 3 || got[0] != "(service web) has reached a steady state." ||
		got[1] != "(service web) (deployment "+d["id"].(string)+") deployment completed." {
		t.Fatalf("events = %q", got)
	}
	if w.events[0].CreatedAt < ecsEpoch(done) {
		t.Fatalf("the steady state is dated %v, before the rollout finished", w.events[0].CreatedAt)
	}
}

// Mid-rollout: the new ReplicaSet is PRIMARY with its task definition, the old one still running is ACTIVE
// with the one it was started with, and the service's counts are both's.
func TestECSState_RollingDeployment(t *testing.T) {
	history := []ecsTaskDefRecord{{TaskDefinition: "web:1", At: ecsT0.Format(time.RFC3339)},
		{TaskDefinition: "web:2", At: ecsT0.Add(time.Hour).Format(time.RFC3339)}}
	old := testRS("web-old", "rs-old", 1, ecsT0.Add(time.Second), 2, 2, 2)
	cur := testRS("web-new", "rs-new", 2, ecsT0.Add(time.Hour+time.Second), 1, 1, 0)
	w := ecsServiceState("web", "acct", "", testDeployment(2), []appsv1.ReplicaSet{old, cur,
		testRS("web-older", "rs-older", 0, ecsT0.Add(-time.Hour), 0, 0, 0)}, nil, history, "web:2", arnOf)
	if w.running != 2 || w.pending != 1 || len(w.deployments) != 2 {
		t.Fatalf("running/pending = %d/%d, %d deployments; want 2/1, 2 (the emptied one is INACTIVE)", w.running, w.pending, len(w.deployments))
	}
	p, a := w.deployments[0].(map[string]any), w.deployments[1].(map[string]any)
	if p["status"] != "PRIMARY" || p["taskDefinition"] != arnOf("web:2") || p["pendingCount"] != 1 || p["rolloutState"] != "IN_PROGRESS" {
		t.Fatalf("PRIMARY = %v", p)
	}
	if a["status"] != "ACTIVE" || a["taskDefinition"] != arnOf("web:1") || a["runningCount"] != 2 || a["desiredCount"] != 2 {
		t.Fatalf("ACTIVE = %v", a)
	}
	if p["id"] == a["id"] {
		t.Fatal("two deployments share an id")
	}
}

// An earlier rollout whose task never started (it is still waiting) keeps rolloutState IN_PROGRESS, as ECS's
// does: it never completed. One that did, and is draining, is COMPLETED.
func TestECSState_ActiveRolloutThatNeverCompleted(t *testing.T) {
	stuck := testRS("web-old", "rs-old", 1, ecsT0.Add(time.Second), 1, 1, 0) // its task never ready
	cur := testRS("web-new", "rs-new", 2, ecsT0.Add(time.Hour), 1, 1, 0)
	w := ecsServiceState("web", "acct", "", testDeployment(1), []appsv1.ReplicaSet{stuck, cur}, nil, nil, "web:2", arnOf)
	if a := w.deployments[1].(map[string]any); a["status"] != "ACTIVE" || a["rolloutState"] != "IN_PROGRESS" || a["pendingCount"] != 1 {
		t.Fatalf("an earlier rollout still waiting to start a task = %v", a)
	}
	draining := testRS("web-old", "rs-old", 1, ecsT0.Add(time.Second), 0, 1, 1)
	w = ecsServiceState("web", "acct", "", testDeployment(1), []appsv1.ReplicaSet{draining, cur}, nil, nil, "web:2", arnOf)
	if a := w.deployments[1].(map[string]any); a["rolloutState"] != "COMPLETED" {
		t.Fatalf("a draining earlier rollout = %v", a)
	}
}

func TestECSState_PlacementReasons(t *testing.T) {
	for msg, want := range map[string]string{
		`exceeded quota: q, requested: pods=1, used: pods=6, limited: pods=6`:                                  "You've reached the limit on the number of tasks you can run concurrently",
		`exceeded quota: q, requested: requests.cpu=500m, used: requests.cpu=2, limited: requests.cpu=2`:       "You’ve reached the limit on the number of vCPUs you can run concurrently",
		`exceeded quota: q, requested: limits.memory=1Gi, used: limits.memory=2Gi, limited: limits.memory=2Gi`: "The requested MEMORY configuration is above your limit.",
		`exceeded quota: q, requested: pods=1,requests.cpu=1, used: pods=6, limited: pods=6`:                   "You've reached the limit on the number of tasks you can run concurrently",
	} {
		if got := ecsPlacementReason(msg); got != want {
			t.Errorf("%s: %q; want %q", msg, got, want)
		}
	}
	// Any other refusal is ECS's start failure, never the platform's own message.
	evs := ecsEventsOf("web", "acct", []corev1.Event{
		testEvent("x", "web-a", "FailedCreate", `admission webhook "validate.kyverno.svc" denied the request: secret not found`, ecsT0),
		testEvent("y", "web-a", "ScalingReplicaSet", "Scaled up replica set web-a to 1", ecsT0),
	})
	if len(evs) != 1 || evs[0].Message != "(service web) is unable to consistently start tasks successfully." {
		t.Fatalf("events = %q", messages(evs))
	}
}

func TestECSState_EventsKeptNewestFirstAndCapped(t *testing.T) {
	var kept []ecsEvent
	for i := 0; i < 150; i++ {
		kept = append(kept, ecsEvent{ID: fmt.Sprint("k", i), CreatedAt: float64(i), Message: "m"})
	}
	fresh := []ecsEvent{{ID: "k149", CreatedAt: 149, Message: "m"}, {ID: "new", CreatedAt: 500, Message: "m"}}
	got := mergeECSEvents(kept, fresh)
	if len(got) != ecsMaxEvents || got[0].ID != "new" || got[1].ID != "k149" || got[2].ID != "k148" {
		t.Fatalf("merged %d, first %v %v %v", len(got), got[0].ID, got[1].ID, got[2].ID)
	}
	// The same occurrence read twice is one event.
	e := testEvent("u", "web-a", "SuccessfulCreate", "Created pod: web-a-1", ecsT0)
	a, b := ecsEventsOf("web", "acct", []corev1.Event{e}), ecsEventsOf("web", "acct", []corev1.Event{e})
	if len(mergeECSEvents(a, b)) != 1 {
		t.Fatal("a re-read event was kept twice")
	}
}

// A task's id in the service's events is the id its log stream (ecs/<container>/<task id>) carries.
func TestECSState_TaskIDIsTheLogStreams(t *testing.T) {
	evs := ecsEventsOf("web", "acct", []corev1.Event{testEvent("u", "web-a", "SuccessfulCreate", "Created pod: web-a-1", ecsT0)})
	stream := streamName(derivedGroup{Kind: "ecs"}, derivedSource{}, map[string]string{"namespace": "acct", "pod": "web-a-1", "container": "app"}, 0)
	id := strings.TrimPrefix(stream, "ecs/app/")
	if len(evs) != 1 || !strings.Contains(evs[0].Message, "(task "+id+")") {
		t.Fatalf("event %q does not name the task its log stream %q does", evs[0].Message, stream)
	}
}
