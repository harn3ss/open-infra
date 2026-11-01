// AWS CloudFormation front door for the aws-shim — the cloudformation.* API over the
// existing owned cfn engine (github.com/harn3ss/open-infra/cfn: plan/deploy/changeset/update/destroy/
// drift + the resource-type->kind mapping table).
//
// Speaks the AWS query protocol (form-encoded request, XML response; API version 2010-05-15) — the
// classic CloudFormation wire shape (it has not migrated to JSON).
//
// Authority — the way AWS does it: a stack operation provisions under the CALLER's own authority (AWS
// CloudFormation's default: the calling principal's IAM permissions), never the shim's. This is realized
// by driving the engine through an impersonatingApplier (see cfn_applier.go): every resource op runs as
// the caller (Impersonate-User openinfra:<sub> + their groups), so the API server's RBAC + Cedar
// admission bound the whole stack to exactly the caller's authority. A stack service role (AWS's
// RoleARN mode) is the natural follow-on, reusing the STS->groups mechanism from Step Functions (#172).
//
// Long-running operations (CreateStack/UpdateStack/DeleteStack/ExecuteChangeSet) are ASYNCHRONOUS like
// AWS: they validate synchronously, then run the engine in the background and return a StackId; the
// caller polls DescribeStacks. Read/preview ops (Validate/ChangeSet/Drift/Describe) run synchronously.
// A background operation is owned and leased on its stack record, so one interrupted by a front-door
// restart is failed and rolled back by the next front door instead of staying *_IN_PROGRESS forever
// (cloudformation_ops.go).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	discoveryclient "k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

const cfnXMLNamespace = "http://cloudformation.amazonaws.com/doc/2010-05-15/"

// how long an async stack operation may run in the background.
const cfnAsyncTimeout = 15 * time.Minute
const cfnWaitTimeout = 10 * time.Minute

type cfnDoorway struct {
	cfg       *rest.Config      // base in-cluster config; copied + impersonated per caller
	shimDyn   dynamic.Interface // shim SA client for stack-record / changeset / drift bookkeeping
	mapper    meta.RESTMapper
	account   string
	region    string
	ns        string
	svcSuffix string       // cluster-local DNS suffix for Knative Functions (custom-resource invoke, #269)
	invoker   *http.Client // invokes a custom resource's backing Function synchronously
	logger    *slog.Logger
	restV1    *apigwV1Handler // drives the apigateway REST v1 store for AWS::ApiGateway::* resources (#295); nil = unconfigured
	// authz is the data-plane engine: an assumed role's stack operations are default-deny under it
	// (cloudformation:<Action> on Stack::<name>). nil = no engine — a role is then denied every action.
	authz *dataplaneauthz.Checker
	// objectEncryption (OBJECT_ENCRYPTION=true) asserts that every NEW MinIO bucket is SSE-KMS-encrypted
	// at rest by default — an outcome, not "KMS is configured": KES being deployed, or MinIO carrying the
	// MINIO_KMS_KES_* config while only buckets with `mc encrypt set` are encrypted, is not enough, since
	// a bucket this front door creates later would be unencrypted (docs/encryption.md). Default false =
	// fail-closed: an S3 BucketEncryption request refuses rather than deploy an unencrypted bucket the
	// template asked to encrypt (#347 Phase 1.8).
	objectEncryption bool
	// ops makes the long stack operations durable across a front-door restart: ownership leases on the
	// stack records, the recovery pass for interrupted operations, and refusal of new operations while
	// shutting down (cloudformation_ops.go).
	ops cfnOps
	// callerDyn, when set, builds the caller-impersonating client instead of impersonating via cfg (tests).
	callerDyn func(user string, groups []string) (dynamic.Interface, error)
}

// caps are the deploy-environment Capabilities this doorway vouches for. Plan, changeset, validate and
// deploy all use the same value, so a PROVISIONABLE* plan still means deploy won't refuse.
func (h *cfnDoorway) caps() cfn.Capabilities {
	return cfn.Capabilities{ObjectEncryption: h.objectEncryption}
}

func newCFNDoorway(cfg *rest.Config, shimDyn dynamic.Interface, account, region, ns, svcSuffix string, logger *slog.Logger) (*cfnDoorway, error) {
	dc, err := discoveryclient.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cfn doorway discovery client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	if region == "" {
		region = "us-east-1"
	}
	if svcSuffix == "" {
		svcSuffix = "svc.cluster.local"
	}
	// A generous timeout: Knative scale-from-zero makes the FIRST request to a custom resource's Function
	// block while the pod cold-starts; the request is queued, not dropped.
	return &cfnDoorway{cfg: cfg, shimDyn: shimDyn, mapper: mapper, account: account, region: region, ns: ns,
		svcSuffix: svcSuffix, invoker: &http.Client{Timeout: 3 * time.Minute}, logger: logger,
		objectEncryption: os.Getenv("OBJECT_ENCRYPTION") == "true"}, nil
}

// invokeCustomResourceFn is the cfn.InvokeFunc for a Lambda-backed custom resource (#269): it POSTs the
// CloudFormation custom-resource event to the in-stack Function's cluster-local Knative URL and parses the
// handler's {Status, Data, Reason} response. The open-infra adaptation of the ResponseURL callback — the
// handler RETURNS its response synchronously rather than PUT-ing it to a pre-signed S3 URL.
func (h *cfnDoorway) invokeCustomResourceFn(ctx context.Context, namespace, functionName string, event []byte) (map[string]any, error) {
	target := "http://" + functionName + "." + namespace + "." + h.svcSuffix + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(event))
	if err != nil {
		return nil, fmt.Errorf("building custom-resource invoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.invoker.Do(req)
	if err != nil {
		return nil, fmt.Errorf("invoking custom-resource Function %q at %s: %w", functionName, target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("custom-resource Function %q returned HTTP %d: %s", functionName, resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("custom-resource Function %q returned a non-JSON response: %w", functionName, err)
	}
	return out, nil
}

func (h *cfnDoorway) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", cfnXMLNamespace)
}

// applierFor builds an Applier that impersonates the caller for resource ops (the authority seam).
func (h *cfnDoorway) applierFor(claims iam.Claims) (*impersonatingApplier, error) {
	user, groups, ok := iam.Identity(claims)
	if !ok {
		return nil, fmt.Errorf("no caller identity")
	}
	return h.applierForIdentity(user, groups)
}

// applierForIdentity builds the Applier impersonating an already-resolved identity — a request's caller,
// or (recovery) the caller recorded on an interrupted operation's stack record.
func (h *cfnDoorway) applierForIdentity(user string, groups []string) (*impersonatingApplier, error) {
	var cdyn dynamic.Interface
	var err error
	if h.callerDyn != nil {
		cdyn, err = h.callerDyn(user, groups)
	} else {
		icfg := rest.CopyConfig(h.cfg)
		icfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
		cdyn, err = dynamic.NewForConfig(icfg)
	}
	if err != nil {
		return nil, err
	}
	return &impersonatingApplier{caller: cdyn, shim: h.shimDyn, mapper: h.mapper, ns: h.ns, user: user, groups: groups}, nil
}

func (h *cfnDoorway) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	normalizeStackArgs(r)
	action := r.PostFormValue("Action")
	if action == "" {
		writeQueryError(w, http.StatusBadRequest, "MissingAction", requestID, "no Action in the request.", cfnXMLNamespace)
		return
	}
	// A stack op provisions under the caller's own authority (impersonation); for a User that is its RBAC.
	// An assumed role's authority is its data-plane policy, so its stack operations are default-deny under
	// it: cloudformation:<Action> on the stack it names (normalizeStackArgs has reduced a stack ARN to its
	// name), ListStacks/ListExports/ValidateTemplate on Stack::*.
	if claims.AssumedRole != "" {
		if denied, reason := dataPlaneDenied(r.Context(), h.authz, claims, "cloudformation:"+action, "Stack",
			r.PostFormValue("StackName"), r); denied {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cfnXMLNamespace)
			return
		}
	}
	ap, err := h.applierFor(claims)
	if err != nil {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	switch action {
	case "CreateStack":
		h.createStack(w, r, ap, requestID)
	case "UpdateStack":
		h.updateStack(w, r, ap, requestID)
	case "DeleteStack":
		h.deleteStack(w, r, ap, requestID)
	case "DescribeStacks":
		h.describeStacks(w, r, ap, requestID)
	case "DescribeStackResources":
		h.describeStackResources(w, r, ap, requestID)
	case "ListStacks":
		h.listStacks(w, r, ap, requestID)
	case "ListExports":
		h.listExports(w, r, requestID)
	case "ValidateTemplate":
		h.validateTemplate(w, r, requestID)
	case "CreateChangeSet":
		h.createChangeSet(w, r, ap, requestID)
	case "DescribeChangeSet":
		h.describeChangeSet(w, r, ap, requestID)
	case "ExecuteChangeSet":
		h.executeChangeSet(w, r, ap, requestID)
	case "DeleteChangeSet":
		h.deleteChangeSet(w, r, ap, requestID)
	case "DetectStackDrift":
		h.detectStackDrift(w, r, ap, requestID)
	case "DescribeStackDriftDetectionStatus":
		h.describeDriftStatus(w, r, ap, requestID)
	case "DescribeStackResourceDrifts":
		h.describeResourceDrifts(w, r, ap, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"CloudFormation "+action+" is not implemented by the open-infra shim.", cfnXMLNamespace)
	}
}

// --- template + params ---

// templateBody returns the inline TemplateBody, refusing TemplateURL (no remote fetch — SSRF-safe and
// this v1 has no template store).
func (h *cfnDoorway) templateBody(r *http.Request) (string, error) {
	if b := r.PostFormValue("TemplateBody"); strings.TrimSpace(b) != "" {
		return b, nil
	}
	if u := r.PostFormValue("TemplateURL"); strings.TrimSpace(u) != "" {
		return "", fmt.Errorf("TemplateURL is not supported — pass the template inline as TemplateBody")
	}
	return "", fmt.Errorf("TemplateBody is required")
}

func parseCFNParams(r *http.Request) map[string]string {
	out := map[string]string{}
	for i := 1; ; i++ {
		k := r.PostFormValue(fmt.Sprintf("Parameters.member.%d.ParameterKey", i))
		if k == "" {
			break
		}
		out[k] = r.PostFormValue(fmt.Sprintf("Parameters.member.%d.ParameterValue", i))
	}
	return out
}

func (h *cfnDoorway) stackID(name string) string {
	sum := sha256.Sum256([]byte(h.ns + "/" + name))
	uid := hex.EncodeToString(sum[:])[:32]
	return fmt.Sprintf("arn:aws:cloudformation:%s:%s:stack/%s/%s", h.region, h.account, name, uid)
}

func (h *cfnDoorway) opts(name string, params map[string]string) cfn.DeployOptions {
	o := cfn.DeployOptions{
		StackName: name, Namespace: h.ns, Params: params, Wait: true, Timeout: cfnWaitTimeout,
		// In-cluster: a custom resource's backing Function is invokable (#269). The CLI deploy path leaves
		// this nil, so a custom-resource stack there refuses rather than guessing.
		Invoke: h.invokeCustomResourceFn,
		// The same Capabilities the doorway's plan/changeset/validate use (#347 Phase 1.8).
		Caps: h.caps(),
	}
	// In-cluster: an AWS::ApiGateway::RestApi stack is provisioned via the apigateway REST v1 store (#295).
	// Nil when the apigateway data layer is unconfigured (or on the CLI), so such a stack refuses.
	if h.restV1 != nil && h.restV1.store != nil {
		o.ProvisionRestAPI = func(ctx context.Context, planSpec map[string]any) (string, error) {
			plan, perr := cfn.ParseRestAPIPlan(planSpec)
			if perr != nil {
				return "", perr
			}
			return h.restV1.provisionRestAPIPlan(ctx, plan)
		}
		o.DeprovisionRestAPI = h.restV1.deprovisionRestAPI
	}
	return o
}

// --- stack lifecycle (async) ---

func (h *cfnDoorway) createStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	if name == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "StackName is required.", cfnXMLNamespace)
		return
	}
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	params := parseCFNParams(r)
	ctx := r.Context()
	ex := h.exportsFor(ctx, name) // other stacks' exports, for Fn::ImportValue

	// Synchronous validation gate — an unsupported type / bad template is refused WHOLE here, before
	// anything is created (the DoD's "refused at validation, nothing created"). This mirrors the engine's
	// own plan gate but surfaces it as an immediate ValidationError to the caller.
	plan, perr := cfn.BuildPlanWithCaps([]byte(body), params, ex.values, name, h.caps())
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused (nothing created):\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	if msg := exportCollision(body, params, ex, name); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}

	alreadyExists := func() {
		writeQueryError(w, http.StatusBadRequest, "AlreadyExistsException", requestID,
			"Stack ["+name+"] already exists.", cfnXMLNamespace)
	}
	if _, found, _ := ap.GetStack(ctx, name); found {
		alreadyExists()
		return
	}
	if err := h.ops.begin(name); err != nil {
		h.refuseOp(w, requestID, err, "AlreadyExistsException", "Stack ["+name+"] already exists.")
		return
	}
	// The record is created already owned by this operation (lease + caller), in one atomic Create.
	now := time.Now().UTC().Format(time.RFC3339)
	seed := &cfn.StackRecord{Name: name, Namespace: h.ns, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now}
	if err := h.seedRecord(ctx, seed, "CreateStack", ap.identity()); err != nil {
		h.ops.end(name)
		if apierrors.IsAlreadyExists(err) {
			alreadyExists()
			return
		}
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not seed stack record: "+err.Error(), cfnXMLNamespace)
		return
	}
	h.runStackOp(name, "CreateStack", "CREATE_FAILED", ap, func(bctx context.Context) error {
		rec, derr := cfn.Deploy(bctx, []byte(body), h.optsFor(name, params, ex), ap)
		if derr == nil {
			h.logOutputs("CreateStack", name, rec)
		}
		return derr
	})
	h.writeResult(w, requestID, "CreateStack", "<StackId>"+xesc(h.stackID(name))+"</StackId>")
}

func (h *cfnDoorway) updateStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	params := parseCFNParams(r)
	ctx := r.Context()
	current, found, _ := ap.GetStack(ctx, name)
	if !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
		return
	}
	if msg := h.notUpdatable(name, current.Status); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	ex := h.exportsFor(ctx, name)
	plan, perr := cfn.BuildPlanWithCaps([]byte(body), params, ex.values, name, h.caps())
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused (nothing changed):\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	if msg := h.exportGuards(ctx, current, body, params, ex, name); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	if err := h.ops.begin(name); err != nil {
		h.refuseOp(w, requestID, err, "ValidationError", "Stack ["+name+"] is being changed by another operation; retry once it settles.")
		return
	}
	if cur, err := h.claimRecord(ctx, name, "UpdateStack", ap.identity()); err != nil || cur == nil {
		h.ops.end(name)
		if err == nil {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
			return
		}
		h.claimRefusal(w, requestID, name, "update", err)
		return
	}
	h.runStackOp(name, "UpdateStack", "UPDATE_FAILED", ap, func(bctx context.Context) error {
		rec, derr := cfn.Update(bctx, []byte(body), h.optsFor(name, params, ex), ap)
		if derr == nil {
			h.logOutputs("UpdateStack", name, rec)
		}
		return derr
	})
	h.writeResult(w, requestID, "UpdateStack", "<StackId>"+xesc(h.stackID(name))+"</StackId>")
}

func (h *cfnDoorway) deleteStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	ctx := r.Context()
	rec, found, _ := ap.GetStack(ctx, name)
	if !found || rec.Status == "DELETE_IN_PROGRESS" {
		// AWS treats deleting an absent stack — or one already being deleted — as a successful no-op. (An
		// orphaned DELETE_IN_PROGRESS is resumed by the recovery pass.)
		h.writeResult(w, requestID, "DeleteStack", "")
		return
	}
	if inProgress(rec.Status) {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Stack ["+name+"] cannot be deleted while in status "+rec.Status+".", cfnXMLNamespace)
		return
	}
	// AWS's export rule: a stack whose export another stack imports can't be deleted from under it.
	if msg := exportsInUse(h.allRecords(ctx), name, exportNames(rec)); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	if err := h.ops.begin(name); err != nil {
		h.refuseOp(w, requestID, err, "ValidationError", "Stack ["+name+"] cannot be deleted while another operation on it is in progress.")
		return
	}
	if cur, err := h.claimRecord(ctx, name, "DeleteStack", ap.identity()); err != nil || cur == nil {
		h.ops.end(name)
		if err == nil { // gone since it was read: already deleted
			h.writeResult(w, requestID, "DeleteStack", "")
			return
		}
		h.claimRefusal(w, requestID, name, "delete", err)
		return
	}
	h.runStackOp(name, "DeleteStack", "DELETE_FAILED", ap, func(bctx context.Context) error {
		_, derr := cfn.Destroy(bctx, h.opts(name, nil), ap)
		if derr == nil {
			// As on AWS, deleting a stack deletes its change sets.
			h.deleteChangeSetsOf(bctx, name)
		}
		return derr
	})
	h.writeResult(w, requestID, "DeleteStack", "")
}

// --- describe (sync) ---

func (h *cfnDoorway) describeStacks(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	var recs []*cfn.StackRecord
	if name != "" {
		rec, found, err := ap.GetStack(r.Context(), name)
		if err != nil {
			writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
			return
		}
		if !found {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+name+" does not exist", cfnXMLNamespace)
			return
		}
		recs = []*cfn.StackRecord{rec}
	} else {
		recs = h.allRecords(r.Context())
	}
	var members strings.Builder
	for _, rec := range recs {
		members.WriteString(h.stackMemberXML(rec))
	}
	h.writeResult(w, requestID, "DescribeStacks", "<Stacks>"+members.String()+"</Stacks>")
}

func (h *cfnDoorway) stackMemberXML(rec *cfn.StackRecord) string {
	var b strings.Builder
	b.WriteString("<member>")
	b.WriteString("<StackId>" + xesc(h.stackID(rec.Name)) + "</StackId>")
	b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
	b.WriteString("<StackStatus>" + xesc(rec.Status) + "</StackStatus>")
	if rec.Message != "" {
		b.WriteString("<StackStatusReason>" + xesc(rec.Message) + "</StackStatusReason>")
	}
	if rec.CreatedAt != "" {
		b.WriteString("<CreationTime>" + xesc(rec.CreatedAt) + "</CreationTime>")
	}
	if rec.UpdatedAt != "" {
		b.WriteString("<LastUpdatedTime>" + xesc(rec.UpdatedAt) + "</LastUpdatedTime>")
	}
	b.WriteString(outputsXML(rec)) // evaluated against the deployed stack at *_COMPLETE (#347)
	b.WriteString("</member>")
	return b.String()
}

func (h *cfnDoorway) describeStackResources(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	rec, found, err := ap.GetStack(r.Context(), name)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	for _, res := range rec.Resources {
		b.WriteString("<member>")
		b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
		b.WriteString("<LogicalResourceId>" + xesc(res.LogicalID) + "</LogicalResourceId>")
		b.WriteString("<PhysicalResourceId>" + xesc(res.Name) + "</PhysicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(res.Kind) + "</ResourceType>")
		b.WriteString("<ResourceStatus>" + xesc(rec.Status) + "</ResourceStatus>")
		b.WriteString("<Timestamp>" + xesc(recTime(rec)) + "</Timestamp>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "DescribeStackResources", "<StackResources>"+b.String()+"</StackResources>")
}

func (h *cfnDoorway) listStacks(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	var b strings.Builder
	for _, rec := range h.allRecords(r.Context()) {
		b.WriteString("<member>")
		b.WriteString("<StackId>" + xesc(h.stackID(rec.Name)) + "</StackId>")
		b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
		b.WriteString("<StackStatus>" + xesc(rec.Status) + "</StackStatus>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "ListStacks", "<StackSummaries>"+b.String()+"</StackSummaries>")
}

// allRecords lists every stack-record ConfigMap in the namespace (shim client).
func (h *cfnDoorway) allRecords(ctx context.Context) []*cfn.StackRecord {
	list, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		return nil
	}
	var out []*cfn.StackRecord
	for i := range list.Items {
		name := list.Items[i].GetName()
		if !strings.HasPrefix(name, "cfn-stack-") {
			continue
		}
		data, _, _ := unstructured.NestedString(list.Items[i].Object, "data", "stack.json")
		if data == "" {
			continue
		}
		var rec cfn.StackRecord
		if json.Unmarshal([]byte(data), &rec) == nil {
			out = append(out, &rec)
		}
	}
	return out
}

// --- validate (sync) ---

func (h *cfnDoorway) validateTemplate(w http.ResponseWriter, r *http.Request, requestID string) {
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	plan, perr := cfn.BuildPlanWithCaps([]byte(body), nil, h.exportsFor(r.Context(), "").values, "validate", h.caps())
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused:\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "ValidateTemplate", "<Description>open-infra: "+xesc(string(plan.Verdict))+"</Description><Capabilities/><Parameters/>")
}

// --- change sets ---

// changeSet is the doorway's persisted change-set bookkeeping (a ConfigMap cfn-changeset-<stack>-<name>).
type changeSet struct {
	StackName    string            `json:"stackName"`
	Name         string            `json:"name"`
	TemplateBody string            `json:"templateBody"`
	Params       map[string]string `json:"params,omitempty"`
	Type         string            `json:"type"` // CREATE | UPDATE
	Changes      []cfn.Change      `json:"changes"`
}

func changeSetCMName(stack, name string) string { return "cfn-changeset-" + stack + "-" + name }

func (h *cfnDoorway) createChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	if stack == "" || csName == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "StackName and ChangeSetName are required.", cfnXMLNamespace)
		return
	}
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	params := parseCFNParams(r)
	ctx := r.Context()
	ex := h.exportsFor(ctx, stack)

	// BuildChangeSet computes the diff against the current stack record and APPLIES NOTHING.
	cs, _, current, cerr := cfn.BuildChangeSet(ctx, []byte(body), h.optsFor(stack, params, ex), ap)
	if cerr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, cerr.Error(), cfnXMLNamespace)
		return
	}
	if !cs.Exists {
		current = nil
	}
	if msg := h.exportGuards(ctx, current, body, params, ex, stack); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	csType := "UPDATE"
	if !cs.Exists {
		csType = "CREATE"
	}
	rec := &changeSet{StackName: stack, Name: csName, TemplateBody: body, Params: params, Type: csType, Changes: cs.Changes}
	if err := h.putChangeSet(ctx, rec); err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	csID := fmt.Sprintf("arn:aws:cloudformation:%s:%s:changeSet/%s/%s", h.region, h.account, csName, shortHash(stack+"/"+csName))
	h.writeResult(w, requestID, "CreateChangeSet",
		"<Id>"+xesc(csID)+"</Id><StackId>"+xesc(h.stackID(stack))+"</StackId>")
}

func (h *cfnDoorway) describeChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	cs, err := h.getChangeSet(r.Context(), stack, csName)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ChangeSetNotFound", requestID, "ChangeSet ["+csName+"] not found for stack ["+stack+"].", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	for _, c := range cs.Changes {
		if c.Action == cfn.Unchanged {
			continue
		}
		b.WriteString("<member><Type>Resource</Type><ResourceChange>")
		b.WriteString("<Action>" + xesc(string(c.Action)) + "</Action>")
		b.WriteString("<LogicalResourceId>" + xesc(c.LogicalID) + "</LogicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(c.Kind) + "</ResourceType>")
		b.WriteString("</ResourceChange></member>")
	}
	status, exec, reason := "CREATE_COMPLETE", "AVAILABLE", ""
	if cs.Type != "CREATE" && b.Len() == 0 {
		// AWS reports an update with nothing to change as a FAILED change set with this exact reason;
		// `aws cloudformation deploy` recognizes it and reports "No changes to deploy".
		status, exec = "FAILED", "UNAVAILABLE"
		reason = "The submitted information didn't contain changes. Submit different information to create a change set."
	}
	csID := fmt.Sprintf("arn:aws:cloudformation:%s:%s:changeSet/%s/%s", h.region, h.account, cs.Name, shortHash(cs.StackName+"/"+cs.Name))
	inner := "<ChangeSetName>" + xesc(cs.Name) + "</ChangeSetName>" +
		"<ChangeSetId>" + xesc(csID) + "</ChangeSetId>" +
		"<StackName>" + xesc(cs.StackName) + "</StackName>" +
		"<StackId>" + xesc(h.stackID(cs.StackName)) + "</StackId>" +
		"<Status>" + status + "</Status><ExecutionStatus>" + exec + "</ExecutionStatus>" +
		"<StatusReason>" + xesc(reason) + "</StatusReason>" +
		"<Changes>" + b.String() + "</Changes>"
	h.writeResult(w, requestID, "DescribeChangeSet", inner)
}

func (h *cfnDoorway) executeChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	cs, err := h.getChangeSet(r.Context(), stack, csName)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ChangeSetNotFound", requestID, "ChangeSet ["+csName+"] not found.", cfnXMLNamespace)
		return
	}
	body := cs.TemplateBody
	params := cs.Params
	create := cs.Type == "CREATE"
	// Re-check the export rules at execute time: another stack may have taken an export name, or started
	// importing one this change set would drop, since the change set was created.
	ctx := r.Context()
	ex := h.exportsFor(ctx, stack)
	var current *cfn.StackRecord
	if !create {
		var found bool
		current, found, _ = ap.GetStack(ctx, stack)
		if !found {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+stack+"] does not exist.", cfnXMLNamespace)
			return
		}
		if msg := h.notUpdatable(stack, current.Status); msg != "" {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
			return
		}
	}
	if msg := h.exportGuards(ctx, current, body, params, ex, stack); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	if err := h.ops.begin(stack); err != nil {
		h.refuseOp(w, requestID, err, "ValidationError", "Stack ["+stack+"] is being changed by another operation; retry once it settles.")
		return
	}
	status := "UPDATE_FAILED"
	if create {
		status = "CREATE_FAILED"
		// A CREATE change set seeds the record like CreateStack: already owned, atomically (a stack that
		// was created since the change set was is refused, never overwritten).
		now := time.Now().UTC().Format(time.RFC3339)
		seed := &cfn.StackRecord{Name: stack, Namespace: h.ns, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now}
		if err := h.seedRecord(ctx, seed, "ExecuteChangeSet", ap.identity()); err != nil {
			h.ops.end(stack)
			if apierrors.IsAlreadyExists(err) {
				writeQueryError(w, http.StatusBadRequest, "AlreadyExistsException", requestID, "Stack ["+stack+"] already exists.", cfnXMLNamespace)
				return
			}
			writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not seed stack record: "+err.Error(), cfnXMLNamespace)
			return
		}
	} else if cur, err := h.claimRecord(ctx, stack, "ExecuteChangeSet", ap.identity()); err != nil || cur == nil {
		h.ops.end(stack)
		if err == nil {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+stack+"] does not exist.", cfnXMLNamespace)
			return
		}
		h.claimRefusal(w, requestID, stack, "update", err)
		return
	}
	h.runStackOp(stack, "ExecuteChangeSet", status, ap, func(bctx context.Context) error {
		var rec *cfn.StackRecord
		var derr error
		if create {
			rec, derr = cfn.Deploy(bctx, []byte(body), h.optsFor(stack, params, ex), ap)
		} else {
			rec, derr = cfn.Update(bctx, []byte(body), h.optsFor(stack, params, ex), ap)
		}
		if derr == nil {
			h.logOutputs("ExecuteChangeSet", stack, rec)
		}
		return derr
	})
	h.writeResult(w, requestID, "ExecuteChangeSet", "")
}

func (h *cfnDoorway) deleteChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	_ = h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Delete(r.Context(), changeSetCMName(stack, csName), metav1.DeleteOptions{})
	h.writeResult(w, requestID, "DeleteChangeSet", "")
}

func (h *cfnDoorway) putChangeSet(ctx context.Context, cs *changeSet) error {
	data, err := json.Marshal(cs)
	if err != nil {
		return err
	}
	cm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": changeSetCMName(cs.StackName, cs.Name), "namespace": h.ns,
			"labels": map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/changeset": cs.StackName}},
		"data": map[string]any{"changeset.json": string(data)},
	}}
	_, err = h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Apply(ctx, changeSetCMName(cs.StackName, cs.Name), cm, metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	return err
}

func (h *cfnDoorway) getChangeSet(ctx context.Context, stack, csName string) (*changeSet, error) {
	u, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Get(ctx, changeSetCMName(stack, csName), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	data, _, _ := unstructured.NestedString(u.Object, "data", "changeset.json")
	var cs changeSet
	if err := json.Unmarshal([]byte(data), &cs); err != nil {
		return nil, err
	}
	return &cs, nil
}

// --- drift ---

func (h *cfnDoorway) detectStackDrift(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	// DetectDrift is read-only and fast, so run it synchronously and store the result under a detection id.
	report, err := cfn.DetectDrift(r.Context(), h.opts(stack, nil), ap)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	detID := shortHash(stack + "/" + time.Now().UTC().Format(time.RFC3339Nano))
	if err := h.putDrift(r.Context(), stack, detID, report); err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "DetectStackDrift", "<StackDriftDetectionId>"+xesc(detID)+"</StackDriftDetectionId>")
}

func (h *cfnDoorway) describeDriftStatus(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	detID := r.PostFormValue("StackDriftDetectionId")
	report, stack, err := h.getDrift(r.Context(), detID)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "drift detection "+detID+" not found.", cfnXMLNamespace)
		return
	}
	status := "DRIFTED"
	if report.InSync {
		status = "IN_SYNC"
	}
	drifted := 0
	for _, rd := range report.Resources {
		if rd.Status != cfn.InSync {
			drifted++
		}
	}
	inner := "<StackId>" + xesc(h.stackID(stack)) + "</StackId>" +
		"<StackDriftDetectionId>" + xesc(detID) + "</StackDriftDetectionId>" +
		"<DetectionStatus>DETECTION_COMPLETE</DetectionStatus>" +
		"<StackDriftStatus>" + status + "</StackDriftStatus>" +
		"<DriftedStackResourceCount>" + strconv.Itoa(drifted) + "</DriftedStackResourceCount>"
	h.writeResult(w, requestID, "DescribeStackDriftDetectionStatus", inner)
}

func (h *cfnDoorway) describeResourceDrifts(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	report, found := h.latestDrift(r.Context(), stack)
	if !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "no drift detection has been run for stack ["+stack+"].", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	for _, rd := range report.Resources {
		cfnStatus := "IN_SYNC"
		switch rd.Status {
		case cfn.Modified:
			cfnStatus = "MODIFIED"
		case cfn.Deleted:
			cfnStatus = "DELETED"
		}
		b.WriteString("<member>")
		b.WriteString("<StackId>" + xesc(h.stackID(stack)) + "</StackId>")
		b.WriteString("<LogicalResourceId>" + xesc(rd.LogicalID) + "</LogicalResourceId>")
		b.WriteString("<PhysicalResourceId>" + xesc(rd.Name) + "</PhysicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(rd.Kind) + "</ResourceType>")
		b.WriteString("<StackResourceDriftStatus>" + cfnStatus + "</StackResourceDriftStatus>")
		b.WriteString("<Timestamp>" + xesc(time.Now().UTC().Format(time.RFC3339)) + "</Timestamp>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "DescribeStackResourceDrifts", "<StackResourceDrifts>"+b.String()+"</StackResourceDrifts>")
}

func (h *cfnDoorway) putDrift(ctx context.Context, stack, detID string, report *cfn.DriftReport) error {
	data, _ := json.Marshal(report)
	cm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "cfn-drift-" + stack, "namespace": h.ns,
			"labels":      map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/drift": stack},
			"annotations": map[string]any{"cfn.openinfra.dev/detection-id": detID}},
		"data": map[string]any{"drift.json": string(data), "detectionId": detID, "stack": stack},
	}}
	_, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Apply(ctx, "cfn-drift-"+stack, cm, metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	return err
}

func (h *cfnDoorway) getDrift(ctx context.Context, detID string) (*cfn.DriftReport, string, error) {
	list, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		return nil, "", err
	}
	for i := range list.Items {
		id, _, _ := unstructured.NestedString(list.Items[i].Object, "data", "detectionId")
		if id != detID {
			continue
		}
		data, _, _ := unstructured.NestedString(list.Items[i].Object, "data", "drift.json")
		stack, _, _ := unstructured.NestedString(list.Items[i].Object, "data", "stack")
		var rep cfn.DriftReport
		if err := json.Unmarshal([]byte(data), &rep); err != nil {
			return nil, "", err
		}
		return &rep, stack, nil
	}
	return nil, "", fmt.Errorf("not found")
}

func (h *cfnDoorway) latestDrift(ctx context.Context, stack string) (*cfn.DriftReport, bool) {
	u, err := h.shimDyn.Resource(configMapGVR).Namespace(h.ns).Get(ctx, "cfn-drift-"+stack, metav1.GetOptions{})
	if err != nil {
		return nil, false
	}
	data, _, _ := unstructured.NestedString(u.Object, "data", "drift.json")
	var rep cfn.DriftReport
	if json.Unmarshal([]byte(data), &rep) != nil {
		return nil, false
	}
	return &rep, true
}

// --- XML rendering ---

// writeResult wraps an operation's result body in the standard CFN query-protocol envelope.
func (h *cfnDoorway) writeResult(w http.ResponseWriter, requestID, op, resultInner string) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<` + op + `Response xmlns="` + cfnXMLNamespace + `">`)
	if resultInner != "" {
		b.WriteString(`<` + op + `Result>` + resultInner + `</` + op + `Result>`)
	} else {
		b.WriteString(`<` + op + `Result/>`)
	}
	b.WriteString(`<ResponseMetadata><RequestId>` + xesc(requestID) + `</RequestId></ResponseMetadata>`)
	b.WriteString(`</` + op + `Response>`)
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func xesc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// recTime returns a record's most recent timestamp (for the required Timestamp output member).
func recTime(rec *cfn.StackRecord) string {
	if rec.UpdatedAt != "" {
		return rec.UpdatedAt
	}
	if rec.CreatedAt != "" {
		return rec.CreatedAt
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// normalizeStackArgs lets StackName and ChangeSetName be given as their ARNs, as AWS allows: `aws
// cloudformation deploy` creates a change set and then describes/executes it by the Id CreateChangeSet
// returned (arn:...:changeSet/<name>/<id>), and clients pass a stack's StackId (arn:...:stack/<name>/<id>).
// Both are reduced to the bare name every handler keys on.
func normalizeStackArgs(r *http.Request) {
	for key, marker := range map[string]string{"StackName": ":stack/", "ChangeSetName": ":changeSet/"} {
		vals, ok := r.PostForm[key]
		if !ok || len(vals) == 0 {
			continue
		}
		if name, ok := nameFromCFNArn(vals[0], marker); ok {
			r.PostForm.Set(key, name)
			r.Form.Set(key, name)
		}
	}
}

// nameFromCFNArn returns <name> from arn:aws:cloudformation:<region>:<account>:<marker><name>/<id>.
func nameFromCFNArn(v, marker string) (string, bool) {
	if !strings.HasPrefix(v, "arn:") || !strings.Contains(v, ":cloudformation:") {
		return "", false
	}
	i := strings.Index(v, marker)
	if i < 0 {
		return "", false
	}
	rest := v[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		rest = rest[:j]
	}
	return rest, rest != ""
}

// deleteChangeSetsOf removes every change-set record of a stack (best effort; a leftover record
// provisions nothing, it would only be listed).
func (h *cfnDoorway) deleteChangeSetsOf(ctx context.Context, stack string) {
	cms := h.shimDyn.Resource(configMapGVR).Namespace(h.ns)
	list, err := cms.List(ctx, metav1.ListOptions{LabelSelector: "cfn.openinfra.dev/changeset=" + stack})
	if err != nil {
		h.logger.Warn("cfn: could not list the stack's change sets", "stack", stack, "error", err.Error())
		return
	}
	for _, it := range list.Items {
		if err := cms.Delete(ctx, it.GetName(), metav1.DeleteOptions{}); err != nil {
			h.logger.Warn("cfn: could not delete a change set", "stack", stack, "changeSet", it.GetName(), "error", err.Error())
		}
	}
}
