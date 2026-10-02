// AWS ECS front door for the aws-shim (polyhedron#177).
//
// Speaks the Amazon ECS API (AWS JSON 1.1, the operation named in X-Amz-Target:
// AmazonEC2ContainerServiceV20141113.<Op>), authenticates through the shared SigV4 path, authorizes with
// the one policy world every front door uses (coarse impersonated SubjectAccessReview + fine-grained
// Cedar dataPlane), and provisions services through the owned cfn engine — an ECS service + its task
// definition are collated into one kind: Application (Deployment+Service+Ingress+HPA).
//
// Authority — the way AWS does it: a service operation provisions under the CALLER's own authority, never
// the shim's. This is the SAME seam as the CloudFormation doorway (polyhedron#175): every resource
// mutation (CreateService/UpdateService/DeleteService) runs through an impersonatingApplier that
// impersonates openinfra:<sub> + the caller's groups, so the API server's RBAC + Cedar admission bound the
// whole service to exactly what the caller may do. The ONLY shim-SA writes are the doorway's own
// bookkeeping ConfigMaps (task-definition / cluster / service-pointer records — see ecs_store.go).
//
// Deliberate carve-outs, refused honestly rather than faked:
//   - RunTask / StartTask (one-off tasks) have no long-lived kind: Application form — refused;
//   - Fargate launch specifics the translator cannot honor (raw/opaque awsvpc subnets), host-path/EFS
//     volumes, Command/EntryPoint overrides, and any untranslatable property are refused at the
//     synchronous validation gate (nothing is created), surfacing the engine's own blockers/findings.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/api/meta"
	discoveryclient "k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// the AWS JSON 1.1 X-Amz-Target prefix the ECS SDKs and aws CLI sign for (unchanged since 2014).
const ecsTargetPrefix = "AmazonEC2ContainerServiceV20141113"

// ecsAppAPIVersion is the kind: Application apiVersion the service collation produces (see cfn/translate.go).
const ecsAppAPIVersion = "openinfra.dev/v1"

type ecsDoorway struct {
	cfg     *rest.Config            // base in-cluster config; copied + impersonated per caller
	shimDyn dynamic.Interface       // shim SA client for the doorway's own ConfigMap bookkeeping
	cs      kubernetes.Interface    // for the coarse impersonated SubjectAccessReview gate
	mapper  meta.RESTMapper         // apiVersion+Kind -> GVR for the impersonatingApplier
	authz   *dataplaneauthz.Checker // fine-grained kind: Policy dataPlane check (additive; may be nil)
	authzNS string
	account string
	region  string
	ns      string
	logger  *slog.Logger
}

func newECSDoorway(cfg *rest.Config, shimDyn dynamic.Interface, cs kubernetes.Interface, authz *dataplaneauthz.Checker, authzNS, account, region, ns string, logger *slog.Logger) (*ecsDoorway, error) {
	dc, err := discoveryclient.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("ecs doorway discovery client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	if region == "" {
		region = "us-east-1"
	}
	return &ecsDoorway{cfg: cfg, shimDyn: shimDyn, cs: cs, mapper: mapper, authz: authz,
		authzNS: authzNS, account: account, region: region, ns: ns, logger: logger}, nil
}

// --- error dialect (AWS JSON 1.1). ECS surfaces the bare exception name in __type, like KMS. ---

func writeECSError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeECSJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *ecsDoorway) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeECSError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// applierFor builds an Applier that impersonates the caller for resource ops (the authority seam —
// VERBATIM the CloudFormation doorway's, so ECS provisions with exactly the caller's authority).
func (h *ecsDoorway) applierFor(claims iam.Claims) (*impersonatingApplier, error) {
	user, groups, ok := iam.Identity(claims)
	if !ok {
		return nil, fmt.Errorf("no caller identity")
	}
	icfg := rest.CopyConfig(h.cfg)
	icfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
	cdyn, err := dynamic.NewForConfig(icfg)
	if err != nil {
		return nil, err
	}
	return &impersonatingApplier{caller: cdyn, shim: h.shimDyn, mapper: h.mapper, ns: h.ns}, nil
}

// verbForECSOp maps an ECS operation to the coarse RBAC verb its SubjectAccessReview checks
// (Register/Create/Update/Run -> create, Describe/List -> get, Delete/Deregister -> delete).
func verbForECSOp(op string) (string, bool) {
	switch op {
	case "DescribeServices", "ListServices", "DescribeTaskDefinition", "DescribeClusters", "ListClusters":
		return "get", true
	case "RegisterTaskDefinition", "CreateService", "UpdateService", "RunTask", "CreateCluster":
		return "create", true
	case "DeleteService", "DeregisterTaskDefinition", "DeleteCluster":
		return "delete", true
	}
	return "", false
}

// ecsResource resolves the resource id an op scopes to (service name / task-def family / cluster name),
// for the authz gate. Ops with no single resource (ListServices/ListClusters) return "".
func ecsResource(op string, body map[string]any) string {
	switch op {
	case "CreateService":
		return firstString(body, "serviceName")
	case "UpdateService", "DeleteService":
		return firstString(body, "service", "serviceName")
	case "DescribeServices":
		if n := stringSlice(body["services"]); len(n) > 0 {
			return lastSlashSeg(n[0])
		}
	case "RegisterTaskDefinition":
		return firstString(body, "family")
	case "DescribeTaskDefinition", "DeregisterTaskDefinition", "RunTask":
		fam, _ := parseTaskDef(firstString(body, "taskDefinition"))
		return fam
	case "CreateCluster":
		return firstString(body, "clusterName")
	case "DeleteCluster":
		return firstString(body, "cluster")
	case "DescribeClusters":
		if n := stringSlice(body["clusters"]); len(n) > 0 {
			return lastSlashSeg(n[0])
		}
	}
	return ""
}

func (h *ecsDoorway) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID,
			"No operation named in the X-Amz-Target header (expected "+ecsTargetPrefix+".<Op>).")
		return
	}
	verb, known := verbForECSOp(op)
	if !known {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID,
			"ECS "+op+" is not implemented by the open-infra shim.")
		return
	}
	body := readJSONBody(r)
	res := ecsResource(op, body)

	// Carry the resolved principal on the context so every audit record names *who* (AU-2/AU-9).
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// One policy world: coarse impersonated SubjectAccessReview on openinfra.dev/applications.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, res); !allowed {
		h.audit(ctx, op, res, "deny", reason)
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only tighten. Scoped when a resource is named.
	if res != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "ecs:"+op, "Service", res, r); denied {
			h.audit(ctx, op, res, "deny", reason)
			writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
			return
		}
	}

	switch op {
	case "RegisterTaskDefinition":
		h.registerTaskDefinition(ctx, w, requestID, body)
	case "DescribeTaskDefinition":
		h.describeTaskDefinition(ctx, w, requestID, body)
	case "DeregisterTaskDefinition":
		h.deregisterTaskDefinition(ctx, w, requestID, body)
	case "CreateService":
		h.createService(ctx, w, r, requestID, claims, body)
	case "UpdateService":
		h.updateService(ctx, w, r, requestID, claims, body)
	case "DeleteService":
		h.deleteService(ctx, w, r, requestID, claims, body)
	case "DescribeServices":
		h.describeServices(ctx, w, requestID, claims, body)
	case "ListServices":
		h.listServices(ctx, w, requestID, claims, body)
	case "CreateCluster":
		h.createCluster(ctx, w, requestID, body)
	case "DeleteCluster":
		h.deleteCluster(ctx, w, requestID, body)
	case "DescribeClusters":
		h.describeClusters(ctx, w, requestID, body)
	case "ListClusters":
		h.listClustersOp(ctx, w, requestID)
	case "RunTask":
		// A one-off task has no long-lived kind: Application form; a fake would be a false green.
		h.audit(ctx, op, res, "refuse", "no Application form")
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"RunTask one-off tasks have no open-infra Application form; use CreateService.")
	default:
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID,
			"ECS "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- task definitions ---

func (h *ecsDoorway) registerTaskDefinition(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	family := firstString(body, "family")
	if family == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "RegisterTaskDefinition requires a family.")
		return
	}
	if containers, _ := body["containerDefinitions"].([]any); len(containers) == 0 {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID, "RegisterTaskDefinition requires at least one containerDefinition.")
		return
	}
	rev := h.nextRevision(ctx, family)
	if err := h.storeTaskDef(ctx, family, rev, body); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "RegisterTaskDefinition", family, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"taskDefinition": h.taskDefObject(family, rev, "ACTIVE", body)})
}

func (h *ecsDoorway) describeTaskDefinition(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	ref := firstString(body, "taskDefinition")
	if ref == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "DescribeTaskDefinition requires a taskDefinition.")
		return
	}
	family, rev := parseTaskDef(ref)
	stored, found, err := h.getTaskDef(ctx, family, rev)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID, "Unable to describe task definition: "+ref)
		return
	}
	h.audit(ctx, "DescribeTaskDefinition", stored.Family, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"taskDefinition": h.taskDefObject(stored.Family, stored.Revision, "ACTIVE", stored.Body)})
}

func (h *ecsDoorway) deregisterTaskDefinition(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	ref := firstString(body, "taskDefinition")
	family, rev := parseTaskDef(ref)
	if rev == 0 {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"DeregisterTaskDefinition requires an explicit family:revision.")
		return
	}
	stored, found, err := h.getTaskDef(ctx, family, rev)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID, "Unable to describe task definition: "+ref)
		return
	}
	if err := h.deleteTaskDef(ctx, family, rev); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeregisterTaskDefinition", family, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"taskDefinition": h.taskDefObject(stored.Family, stored.Revision, "INACTIVE", stored.Body)})
}

// taskDefObject echoes the registered task definition (faithful round-trip) plus the synthesized
// family/revision/arn/status the SDK expects.
func (h *ecsDoorway) taskDefObject(family string, rev int, status string, body map[string]any) map[string]any {
	td := cloneMap(body)
	td["family"] = family
	td["revision"] = rev
	td["status"] = status
	td["taskDefinitionArn"] = h.taskDefArn(family, rev)
	return td
}

// --- clusters (inert groupings: a cluster provisions nothing, per cfn/mapping.go) ---

func (h *ecsDoorway) createCluster(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := strOrDefault(firstString(body, "clusterName"), "default")
	now := time.Now().UTC().Format(time.RFC3339)
	if err := h.storeCluster(ctx, ecsStoredCluster{ClusterName: name, Status: "ACTIVE", CreatedAt: now}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateCluster", name, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"cluster": h.clusterObject(name, "ACTIVE")})
}

func (h *ecsDoorway) deleteCluster(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := firstString(body, "cluster")
	if name == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "DeleteCluster requires a cluster.")
		return
	}
	_, found, err := h.getCluster(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeECSError(w, http.StatusBadRequest, "ClusterNotFoundException", requestID, "Cluster not found: "+name)
		return
	}
	if err := h.removeCluster(ctx, name); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteCluster", name, "allow", "")
	writeECSJSON(w, requestID, map[string]any{"cluster": h.clusterObject(name, "INACTIVE")})
}

func (h *ecsDoorway) describeClusters(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	names := stringSlice(body["clusters"])
	var clusters, failures []any
	if len(names) == 0 {
		for _, c := range h.listClusters(ctx) {
			clusters = append(clusters, h.clusterObject(c.ClusterName, c.Status))
		}
	} else {
		for _, raw := range names {
			cn := lastSlashSeg(raw)
			if _, found, _ := h.getCluster(ctx, cn); found {
				clusters = append(clusters, h.clusterObject(cn, "ACTIVE"))
			} else {
				failures = append(failures, map[string]any{"arn": h.clusterArn(cn), "reason": "MISSING"})
			}
		}
	}
	writeECSJSON(w, requestID, map[string]any{"clusters": clusters, "failures": failures})
}

func (h *ecsDoorway) listClustersOp(ctx context.Context, w http.ResponseWriter, requestID string) {
	arns := []any{}
	for _, c := range h.listClusters(ctx) {
		arns = append(arns, h.clusterArn(c.ClusterName))
	}
	writeECSJSON(w, requestID, map[string]any{"clusterArns": arns})
}

func (h *ecsDoorway) clusterObject(name, status string) map[string]any {
	return map[string]any{
		"clusterArn":                        h.clusterArn(name),
		"clusterName":                       name,
		"status":                            status,
		"registeredContainerInstancesCount": 0,
		"runningTasksCount":                 0,
		"pendingTasksCount":                 0,
		"activeServicesCount":               0,
	}
}

// --- shared helpers ---

func (h *ecsDoorway) deployOpts(stackName string) cfn.DeployOptions {
	return cfn.DeployOptions{StackName: stackName, Namespace: h.ns, Wait: true, Timeout: cfnWaitTimeout}
}

func (h *ecsDoorway) serviceObject(serviceName, cluster, tdRef string, desired, running int, status, createdAt, launchType string) map[string]any {
	obj := map[string]any{
		"serviceArn":         h.serviceArn(cluster, serviceName),
		"serviceName":        serviceName,
		"clusterArn":         h.clusterArn(cluster),
		"taskDefinition":     h.taskDefArnFromRef(tdRef),
		"desiredCount":       desired,
		"runningCount":       running,
		"pendingCount":       0,
		"status":             status,
		"schedulingStrategy": "REPLICA",
	}
	if launchType != "" {
		obj["launchType"] = launchType
	}
	if createdAt != "" {
		obj["createdAt"] = epochOf(createdAt)
	}
	return obj
}

func (h *ecsDoorway) serviceArn(cluster, name string) string {
	return fmt.Sprintf("arn:aws:ecs:%s:%s:service/%s/%s", h.region, h.account, strOrDefault(cluster, "default"), name)
}
func (h *ecsDoorway) clusterArn(name string) string {
	return fmt.Sprintf("arn:aws:ecs:%s:%s:cluster/%s", h.region, h.account, name)
}
func (h *ecsDoorway) taskDefArn(family string, rev int) string {
	return fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/%s:%d", h.region, h.account, family, rev)
}
func (h *ecsDoorway) taskDefArnFromRef(ref string) string {
	fam, rev := parseTaskDef(ref)
	if fam == "" {
		return ref
	}
	return h.taskDefArn(fam, rev)
}

func (h *ecsDoorway) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("ecs backend error", "error", err.Error())
	writeECSError(w, http.StatusInternalServerError, "ServerException", requestID, "The server encountered an internal error.")
}

func (h *ecsDoorway) audit(ctx context.Context, op, res, decision, detail string) {
	args := []any{"service", "ecs", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if res != "" {
		args = append(args, "resource", res)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "ecs audit", args...)
}

// --- small value helpers ---

func cloneMap(m map[string]any) map[string]any {
	out := map[string]any{}
	if m == nil {
		return out
	}
	b, err := json.Marshal(m)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func strOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func epochOf(rfc string) float64 {
	if t, err := time.Parse(time.RFC3339, rfc); err == nil {
		return float64(t.Unix())
	}
	return float64(time.Now().Unix())
}
