// ECS doorway bookkeeping (polyhedron#177).
//
// The ECS front door keeps three kinds of small ConfigMap records in the shim's namespace, written
// with the shim's OWN ServiceAccount (h.shimDyn) — they are the doorway's internal metadata, not the
// caller's workload resources (those are the kind: Application the impersonatingApplier creates under
// the caller's authority). The records are:
//
//   - ecs-taskdef-<family>-<rev>  : a registered task definition (the raw RegisterTaskDefinition body
//   - family/revision). A task definition provisions nothing on its own; it is inlined into an
//     AWS::ECS::TaskDefinition resource when a service that references it is created.
//   - ecs-cluster-<name>          : a cluster record. A cluster provisions nothing (per cfn/mapping.go:
//     the k3s cluster is the cluster); the record exists so CreateCluster/DescribeClusters/ListClusters
//     have something faithful to report and CreateService can validate a named cluster exists.
//   - ecs-service-<name>          : the last-applied Create/UpdateService request body. A service's
//     authoritative state is the live kind: Application (read for Describe/List); this record is kept
//     ONLY so UpdateService can faithfully re-synthesize the CloudFormation stack (a desiredCount-only
//     update must preserve the original loadBalancers / networkConfiguration / task-definition inputs,
//     which neither the live Application nor the cfn stack record preserves).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	ecsFieldManager = "ecs-doorway"
	ecsManagedBy    = "ecs" // app.kubernetes.io/managed-by value on every ECS doorway record
)


// ecsInvalidName matches everything a CloudFormation logical id / k8s object name may NOT contain.
// It mirrors cfn.k8sName exactly ([^a-z0-9-] -> "-", trimmed) so an ECS service name sanitizes to the
// SAME value the cfn engine derives for the Application it creates — the round-trip Describe relies on.
var ecsInvalidName = regexp.MustCompile(`[^a-z0-9-]+`)

// ecsName sanitizes an AWS name to the identical form cfn.k8sName produces (lowercased, invalid runs
// collapsed to "-", trimmed). appName = ecsName(serviceName) is used as BOTH the Service logical id in
// the synthesized template AND the stack name, so k8sName(appName) == appName (idempotent) and the
// created kind: Application is named exactly appName.
func ecsName(s string) string {
	return strings.Trim(ecsInvalidName.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// ecsLabel is ecsName capped at the 63-char k8s label/name-segment limit (for the ConfigMap name
// segments and the family label). The exact, uncapped name is always stored in the record data and
// verified on read, so two names sharing a 63-char sanitized prefix can never be confused.
func ecsLabel(s string) string {
	n := ecsName(s)
	if len(n) > 63 {
		n = strings.Trim(n[:63], "-")
	}
	return n
}

func taskDefCMName(family string, rev int) string {
	return fmt.Sprintf("ecs-taskdef-%s-%d", ecsLabel(family), rev)
}
func clusterCMName(name string) string { return "ecs-cluster-" + ecsLabel(name) }
func serviceCMName(name string) string { return "ecs-service-" + ecsLabel(name) }

// --- generic ConfigMap bookkeeping (shim SA) ---

func (h *ecsDoorway) putConfigMap(ctx context.Context, name string, data, labels map[string]any) error {
	labels["app.kubernetes.io/managed-by"] = ecsManagedBy
	cm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": name, "namespace": h.ns, "labels": labels},
		"data":       data,
	}}
	_, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Apply(ctx, name, cm, metav1.ApplyOptions{FieldManager: ecsFieldManager, Force: true})
	return err
}

func (h *ecsDoorway) getConfigMap(ctx context.Context, name string) (*unstructured.Unstructured, bool, error) {
	u, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return u, true, nil
}

func (h *ecsDoorway) deleteConfigMap(ctx context.Context, name string) error {
	err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func cmData(u *unstructured.Unstructured, key string) string {
	s, _, _ := unstructured.NestedString(u.Object, "data", key)
	return s
}

// --- task definitions ---

type ecsStoredTaskDef struct {
	Family   string         `json:"family"`
	Revision int            `json:"revision"`
	Body     map[string]any `json:"body"` // the raw RegisterTaskDefinition request (camelCase wire JSON)
}

func (h *ecsDoorway) storeTaskDef(ctx context.Context, family string, rev int, body map[string]any) error {
	rec := ecsStoredTaskDef{Family: family, Revision: rev, Body: body}
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data := map[string]any{"taskdef.json": string(blob), "family": family, "revision": strconv.Itoa(rev)}
	labels := map[string]any{"ecs.openinfra.dev/family": ecsLabel(family)}
	return h.putConfigMap(ctx, taskDefCMName(family, rev), data, labels)
}

// getTaskDef fetches a stored task definition. rev==0 means "the latest revision of this family".
func (h *ecsDoorway) getTaskDef(ctx context.Context, family string, rev int) (ecsStoredTaskDef, bool, error) {
	if rev == 0 {
		rev = h.latestRevision(ctx, family)
		if rev == 0 {
			return ecsStoredTaskDef{}, false, nil
		}
	}
	u, found, err := h.getConfigMap(ctx, taskDefCMName(family, rev))
	if err != nil || !found {
		return ecsStoredTaskDef{}, found, err
	}
	var rec ecsStoredTaskDef
	if err := json.Unmarshal([]byte(cmData(u, "taskdef.json")), &rec); err != nil {
		return ecsStoredTaskDef{}, false, err
	}
	// Collision guard: a different family that sanitized to the same capped name is NOT a match.
	if rec.Family != family {
		return ecsStoredTaskDef{}, false, nil
	}
	return rec, true, nil
}

// latestRevision returns the highest registered revision for a family (0 when none are registered).
func (h *ecsDoorway) latestRevision(ctx context.Context, family string) int {
	list, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=" + ecsManagedBy + ",ecs.openinfra.dev/family=" + ecsLabel(family),
	})
	if err != nil {
		return 0
	}
	max := 0
	for i := range list.Items {
		if cmData(&list.Items[i], "family") != family { // exact-family guard
			continue
		}
		if rev, err := strconv.Atoi(cmData(&list.Items[i], "revision")); err == nil && rev > max {
			max = rev
		}
	}
	return max
}

func (h *ecsDoorway) nextRevision(ctx context.Context, family string) int {
	return h.latestRevision(ctx, family) + 1
}

func (h *ecsDoorway) deleteTaskDef(ctx context.Context, family string, rev int) error {
	return h.deleteConfigMap(ctx, taskDefCMName(family, rev))
}

// --- clusters ---

type ecsStoredCluster struct {
	ClusterName string `json:"clusterName"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
}

func (h *ecsDoorway) storeCluster(ctx context.Context, rec ecsStoredCluster) error {
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data := map[string]any{"cluster.json": string(blob), "name": rec.ClusterName}
	return h.putConfigMap(ctx, clusterCMName(rec.ClusterName), data, map[string]any{"ecs.openinfra.dev/cluster": ecsLabel(rec.ClusterName)})
}

func (h *ecsDoorway) getCluster(ctx context.Context, name string) (ecsStoredCluster, bool, error) {
	u, found, err := h.getConfigMap(ctx, clusterCMName(name))
	if err != nil || !found {
		return ecsStoredCluster{}, found, err
	}
	var rec ecsStoredCluster
	if err := json.Unmarshal([]byte(cmData(u, "cluster.json")), &rec); err != nil {
		return ecsStoredCluster{}, false, err
	}
	if rec.ClusterName != name {
		return ecsStoredCluster{}, false, nil
	}
	return rec, true, nil
}

func (h *ecsDoorway) removeCluster(ctx context.Context, name string) error {
	return h.deleteConfigMap(ctx, clusterCMName(name))
}

func (h *ecsDoorway) listClusters(ctx context.Context) []ecsStoredCluster {
	list, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=" + ecsManagedBy,
	})
	if err != nil {
		return nil
	}
	var out []ecsStoredCluster
	for i := range list.Items {
		if !strings.HasPrefix(list.Items[i].GetName(), "ecs-cluster-") {
			continue
		}
		var rec ecsStoredCluster
		if json.Unmarshal([]byte(cmData(&list.Items[i], "cluster.json")), &rec) == nil && rec.ClusterName != "" {
			out = append(out, rec)
		}
	}
	return out
}

// --- service pointers (last-applied request body; see the file header) ---

type ecsServiceRef struct {
	ServiceName string         `json:"serviceName"`
	Cluster     string         `json:"cluster"`
	CreatedAt   string         `json:"createdAt"`
	Body        map[string]any `json:"body"` // the last-applied Create/UpdateService request body
}

func (h *ecsDoorway) putServiceRef(ctx context.Context, ref *ecsServiceRef) error {
	blob, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	data := map[string]any{"service.json": string(blob), "name": ref.ServiceName}
	return h.putConfigMap(ctx, serviceCMName(ref.ServiceName), data, map[string]any{"ecs.openinfra.dev/service": ecsLabel(ref.ServiceName)})
}

func (h *ecsDoorway) getServiceRef(ctx context.Context, name string) (*ecsServiceRef, bool, error) {
	u, found, err := h.getConfigMap(ctx, serviceCMName(name))
	if err != nil || !found {
		return nil, found, err
	}
	var ref ecsServiceRef
	if err := json.Unmarshal([]byte(cmData(u, "service.json")), &ref); err != nil {
		return nil, false, err
	}
	if ref.ServiceName != name {
		return nil, false, nil
	}
	return &ref, true, nil
}

func (h *ecsDoorway) deleteServiceRef(ctx context.Context, name string) error {
	return h.deleteConfigMap(ctx, serviceCMName(name))
}

func (h *ecsDoorway) listServiceRefs(ctx context.Context) []*ecsServiceRef {
	list, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=" + ecsManagedBy,
	})
	if err != nil {
		return nil
	}
	var out []*ecsServiceRef
	for i := range list.Items {
		if !strings.HasPrefix(list.Items[i].GetName(), "ecs-service-") {
			continue
		}
		var ref ecsServiceRef
		if json.Unmarshal([]byte(cmData(&list.Items[i], "service.json")), &ref) == nil && ref.ServiceName != "" {
			out = append(out, &ref)
		}
	}
	return out
}

// --- reference parsing ---

// parseTaskDef splits a task-definition reference into family + revision (0 == unspecified/latest).
// Accepts "family", "family:revision", or a task-definition ARN (…:task-definition/family:revision).
func parseTaskDef(ref string) (family string, rev int) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "task-definition/"); i >= 0 {
		ref = ref[i+len("task-definition/"):]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		if n, err := strconv.Atoi(ref[i+1:]); err == nil {
			return ref[:i], n
		}
	}
	return ref, 0
}

// lastSlashSeg returns the final "/"-separated segment (an ARN's resource name), or s unchanged.
func lastSlashSeg(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
