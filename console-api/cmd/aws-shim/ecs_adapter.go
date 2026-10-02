// ECS-JSON -> CloudFormation-template adapter (polyhedron#177).
//
// The ECS doorway reuses the owned cfn engine (NO changes to package cfn): an ECS service + its
// referenced task definition are synthesized into a minimal CloudFormation template whose
// AWS::ECS::Service + AWS::ECS::TaskDefinition resources the engine already collates into one
// kind: Application. CreateService -> cfn.Deploy, UpdateService -> cfn.Update, DeleteService ->
// cfn.Destroy — every mutation driven through the impersonatingApplier, so the workload is
// provisioned under the CALLER's authority exactly as the CloudFormation doorway does it.
//
// The gate is SYNCHRONOUS and fail-closed. BuildPlan catches structural problems (bad refs,
// cycles, unmappable types); BuildChangeSet runs the engine's translate gate read-only (it applies
// nothing) and is what catches the ECS-specific refusals — a raw/opaque awsvpc subnet, a host-path
// or EFS volume, a Command/EntryPoint override, an untranslatable property. (BuildPlan alone does
// NOT run translators, so it would let those slip to the async deploy; running the translate gate
// synchronously keeps the contract "refused at validation, nothing created".) A rejected template
// returns a 400 and provisions nothing.
package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// ecsTDLogicalID is the fixed logical id of the inlined task definition in every synthesized
// single-service template. It is alphanumeric and distinct from any sanitized service name, so the
// service's TaskDefinition !Ref always resolves to the in-stack task definition the engine requires.
const ecsTDLogicalID = "OpenInfraEcsTaskDef"

// cfnKeyOverrides maps the few camelCase ECS wire keys whose CloudFormation property name is NOT a
// simple first-letter upper-casing (acronyms the translator matches case-sensitively). Without this
// an EFS volume would be mis-cased to "EfsVolumeConfiguration", slip past the translator's EFS check,
// and be silently mapped to an ephemeral emptyDir — a durable-mount false green. Mapping it correctly
// makes the translator REFUSE it, honestly.
var cfnKeyOverrides = map[string]string{
	"efsVolumeConfiguration": "EFSVolumeConfiguration",
}

// camelToCFN recursively converts an ECS wire object's camelCase keys to the PascalCase CloudFormation
// property names the cfn translators' `known`/`cknown` allowlists expect. It upper-cases the first rune
// of every key (with the acronym overrides above) and passes EVERY key through — an unsupported key
// therefore reaches blockUnknownProps and is refused, never silently dropped.
func camelToCFN(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[cfnKey(k)] = camelToCFN(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = camelToCFN(t[i])
		}
		return t
	default:
		return v
	}
}

func cfnKey(k string) string {
	if k == "" {
		return k
	}
	if over, ok := cfnKeyOverrides[k]; ok {
		return over
	}
	r := []rune(k)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// buildECSTemplate synthesizes the minimal CloudFormation template for one ECS service: the referenced
// task definition inlined as an AWS::ECS::TaskDefinition, and the service as an AWS::ECS::Service whose
// TaskDefinition is a !Ref to it. appName (== ecsName(serviceName)) is BOTH the Service logical id and
// the stack name, so the cfn engine names the resulting kind: Application exactly appName.
func buildECSTemplate(appName string, svc, td map[string]any) ([]byte, error) {
	if appName == "" {
		return nil, fmt.Errorf("serviceName does not reduce to a valid resource name")
	}
	svcProps, _ := camelToCFN(cloneMap(svc)).(map[string]any)
	// The service's TaskDefinition is the in-stack !Ref, never the wire string/ARN.
	svcProps["TaskDefinition"] = map[string]any{"Ref": ecsTDLogicalID}
	tdProps, _ := camelToCFN(cloneMap(td)).(map[string]any)

	tmpl := map[string]any{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Resources": map[string]any{
			appName:        map[string]any{"Type": "AWS::ECS::Service", "Properties": svcProps},
			ecsTDLogicalID: map[string]any{"Type": "AWS::ECS::TaskDefinition", "Properties": tdProps},
		},
	}
	return jsonMarshal(tmpl)
}

// --- service lifecycle (driven through the caller-impersonating applier) ---

func (h *ecsDoorway) createService(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, body map[string]any) {
	serviceName := firstString(body, "serviceName")
	if serviceName == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "CreateService requires a serviceName.")
		return
	}
	appName := ecsName(serviceName)
	if appName == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "serviceName must contain alphanumeric characters.")
		return
	}
	cluster := strOrDefault(firstString(body, "cluster"), "default")
	if cluster != "default" {
		if _, found, err := h.getCluster(ctx, cluster); err != nil {
			h.internal(w, requestID, err)
			return
		} else if !found {
			writeECSError(w, http.StatusBadRequest, "ClusterNotFoundException", requestID, "Cluster not found: "+cluster)
			return
		}
	}

	tdRef := firstString(body, "taskDefinition")
	if tdRef == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "CreateService requires a taskDefinition.")
		return
	}
	family, rev := parseTaskDef(tdRef)
	stored, foundTD, err := h.getTaskDef(ctx, family, rev)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !foundTD {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID,
			"task definition is not registered via this shim: "+tdRef+" (register it with RegisterTaskDefinition; an external task-definition ARN has no open-infra form)")
		return
	}

	tmpl, ok := h.gateTemplate(ctx, w, requestID, claims, appName, body, stored.Body)
	if !ok {
		return
	}
	ap, aerr := h.applierFor(claims)
	if aerr != nil {
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, aerr.Error())
		return
	}
	if spec, found, _ := ap.GetSpec(ctx, ecsAppAPIVersion, "Application", appName); found && spec != nil {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "A service named "+serviceName+" already exists.")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	body["taskDefinition"] = fmt.Sprintf("%s:%d", family, stored.Revision) // pin the resolved revision
	if err := h.putServiceRef(ctx, &ecsServiceRef{ServiceName: serviceName, Cluster: cluster, CreatedAt: now, Body: body}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		if _, derr := cfn.Deploy(bctx, tmpl, h.deployOpts(appName), ap); derr != nil {
			h.logger.Warn("ecs CreateService deploy failed", "service", serviceName, "error", derr.Error())
			ap.backstopTerminal(bctx, appName, "CREATE_FAILED", derr.Error())
		}
	}()
	h.audit(ctx, "CreateService", serviceName, "allow", "")
	writeECSJSON(w, requestID, map[string]any{
		"service": h.serviceObject(serviceName, cluster, body["taskDefinition"].(string), ecsDesired(body), 0, "ACTIVE", now, firstString(body, "launchType")),
	})
}

func (h *ecsDoorway) updateService(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, body map[string]any) {
	serviceName := firstString(body, "service", "serviceName")
	if serviceName == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "UpdateService requires a service.")
		return
	}
	appName := ecsName(serviceName)
	ref, found, err := h.getServiceRef(ctx, serviceName)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeECSError(w, http.StatusBadRequest, "ServiceNotFoundException", requestID, "Service not found: "+serviceName)
		return
	}
	// Start from the last-applied body and overlay the mutable fields the caller changed. Other inputs
	// (loadBalancers, networkConfiguration) are preserved, so a desiredCount-only update is faithful.
	newBody := cloneMap(ref.Body)
	if v := firstString(body, "taskDefinition"); v != "" {
		newBody["taskDefinition"] = v
	}
	if v, ok := body["desiredCount"]; ok {
		newBody["desiredCount"] = v
	}
	family, rev := parseTaskDef(firstString(newBody, "taskDefinition"))
	stored, foundTD, err := h.getTaskDef(ctx, family, rev)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !foundTD {
		writeECSError(w, http.StatusBadRequest, "ClientException", requestID, "task definition is not registered via this shim: "+firstString(newBody, "taskDefinition"))
		return
	}
	newBody["taskDefinition"] = fmt.Sprintf("%s:%d", family, stored.Revision)

	tmpl, ok := h.gateTemplate(ctx, w, requestID, claims, appName, newBody, stored.Body)
	if !ok {
		return
	}
	ap, aerr := h.applierFor(claims)
	if aerr != nil {
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, aerr.Error())
		return
	}
	ref.Body = newBody
	if err := h.putServiceRef(ctx, ref); err != nil {
		h.internal(w, requestID, err)
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		if _, derr := cfn.Update(bctx, tmpl, h.deployOpts(appName), ap); derr != nil {
			h.logger.Warn("ecs UpdateService update failed", "service", serviceName, "error", derr.Error())
			ap.backstopTerminal(bctx, appName, "UPDATE_FAILED", derr.Error())
		}
	}()
	h.audit(ctx, "UpdateService", serviceName, "allow", "")
	writeECSJSON(w, requestID, map[string]any{
		"service": h.serviceObject(serviceName, strOrDefault(ref.Cluster, "default"), newBody["taskDefinition"].(string), ecsDesired(newBody), 0, "ACTIVE", ref.CreatedAt, firstString(newBody, "launchType")),
	})
}

func (h *ecsDoorway) deleteService(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, body map[string]any) {
	serviceName := firstString(body, "service", "serviceName")
	if serviceName == "" {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "DeleteService requires a service.")
		return
	}
	appName := ecsName(serviceName)
	ref, found, err := h.getServiceRef(ctx, serviceName)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		writeECSError(w, http.StatusBadRequest, "ServiceNotFoundException", requestID, "Service not found: "+serviceName)
		return
	}
	ap, aerr := h.applierFor(claims)
	if aerr != nil {
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, aerr.Error())
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		if _, derr := cfn.Destroy(bctx, h.deployOpts(appName), ap); derr != nil {
			h.logger.Warn("ecs DeleteService destroy failed", "service", serviceName, "error", derr.Error())
			ap.backstopTerminal(bctx, appName, "DELETE_FAILED", derr.Error())
		}
	}()
	if err := h.deleteServiceRef(ctx, serviceName); err != nil {
		h.logger.Warn("ecs DeleteService: could not delete service pointer", "service", serviceName, "error", err.Error())
	}
	h.audit(ctx, "DeleteService", serviceName, "allow", "")
	writeECSJSON(w, requestID, map[string]any{
		"service": h.serviceObject(serviceName, strOrDefault(ref.Cluster, "default"), firstString(ref.Body, "taskDefinition"), ecsDesired(ref.Body), 0, "DRAINING", ref.CreatedAt, firstString(ref.Body, "launchType")),
	})
}

func (h *ecsDoorway) describeServices(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	names := stringSlice(body["services"])
	if len(names) == 0 {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "DescribeServices requires at least one service.")
		return
	}
	ap, aerr := h.applierFor(claims)
	if aerr != nil {
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, aerr.Error())
		return
	}
	defCluster := strOrDefault(firstString(body, "cluster"), "default")
	var services, failures []any
	for _, raw := range names {
		svcName := lastSlashSeg(raw)
		appName := ecsName(svcName)
		cluster := defCluster
		tdRef := ""
		if ref, found, _ := h.getServiceRef(ctx, svcName); found {
			tdRef = firstString(ref.Body, "taskDefinition")
			if ref.Cluster != "" {
				cluster = ref.Cluster
			}
		}
		spec, found, err := ap.GetSpec(ctx, ecsAppAPIVersion, "Application", appName)
		if err != nil || !found {
			failures = append(failures, map[string]any{"arn": h.serviceArn(cluster, svcName), "reason": "MISSING"})
			continue
		}
		desired := specScalingMin(spec)
		running := 0
		// Readiness is read via the CALLER (ap, caller-authority) like the spec above — not the shim SA — so
		// the doorway needs no read access to the caller's workload. The composite is Ready only when its
		// Deployment's replicas are available, so runningCount == desiredCount is an honest report of Ready.
		if rdy, _, _ := ap.GetReady(ctx, ecsAppAPIVersion, "Application", appName); rdy {
			running = desired
		}
		services = append(services, h.serviceObject(svcName, cluster, tdRef, desired, running, "ACTIVE", "", ""))
	}
	writeECSJSON(w, requestID, map[string]any{"services": services, "failures": failures})
}

func (h *ecsDoorway) listServices(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	ap, aerr := h.applierFor(claims)
	if aerr != nil {
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, aerr.Error())
		return
	}
	arns := []any{}
	for _, ref := range h.listServiceRefs(ctx) {
		appName := ecsName(ref.ServiceName)
		if _, found, _ := ap.GetSpec(ctx, ecsAppAPIVersion, "Application", appName); !found {
			continue // the service record outlived its Application (mid-delete) — don't report a dead ARN
		}
		arns = append(arns, h.serviceArn(strOrDefault(ref.Cluster, "default"), ref.ServiceName))
	}
	writeECSJSON(w, requestID, map[string]any{"serviceArns": arns})
}

// gateTemplate synthesizes the template and runs the fail-closed synchronous gate (BuildPlan +
// translate-gate via BuildChangeSet, which applies nothing). On any rejection it writes a 400 with the
// blockers/findings and returns ok=false (nothing is created). ok=true returns the validated template.
func (h *ecsDoorway) gateTemplate(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, appName string, svc, td map[string]any) ([]byte, bool) {
	tmpl, terr := buildECSTemplate(appName, svc, td)
	if terr != nil {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, terr.Error())
		return nil, false
	}
	plan, perr := cfn.BuildPlan(tmpl, nil, appName)
	if perr != nil {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID, perr.Error())
		return nil, false
	}
	if plan.Verdict == cfn.Rejected {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"service refused (nothing created):\n  - "+strings.Join(plan.Blockers, "\n  - "))
		return nil, false
	}
	// The translate gate — the ECS-specific refusals (raw subnet, host/EFS volume, Command override,
	// untranslatable property) live here, and BuildChangeSet runs it read-only (applies nothing).
	ap, aerr := h.applierFor(claims)
	if aerr != nil {
		writeECSError(w, http.StatusBadRequest, "AccessDeniedException", requestID, aerr.Error())
		return nil, false
	}
	if _, _, _, cerr := cfn.BuildChangeSet(ctx, tmpl, h.deployOpts(appName), ap); cerr != nil {
		writeECSError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"service refused (nothing created): "+cerr.Error())
		return nil, false
	}
	return tmpl, true
}

// ecsDesired reads a desiredCount from a (wire) body, defaulting to 1 (AWS's default when omitted).
func ecsDesired(body map[string]any) int {
	if v, ok := body["desiredCount"]; ok {
		return toInt(v)
	}
	return 1
}

// specScalingMin reads spec.scaling.min (the fixed replica count the DesiredCount collation sets).
func specScalingMin(spec map[string]any) int {
	if sc, ok := spec["scaling"].(map[string]any); ok {
		if v, ok := sc["min"]; ok {
			return toInt(v)
		}
	}
	return 0
}
