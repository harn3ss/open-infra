// AWS CloudFormation front door for the aws-shim (polyhedron#175) — the cloudformation.* API over the
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
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
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
	cfg     *rest.Config      // base in-cluster config; copied + impersonated per caller
	shimDyn dynamic.Interface // shim SA client for stack-record / changeset / drift bookkeeping
	mapper  meta.RESTMapper
	account string
	region  string
	ns      string
	logger  *slog.Logger
}

func newCFNDoorway(cfg *rest.Config, shimDyn dynamic.Interface, account, region, ns string, logger *slog.Logger) (*cfnDoorway, error) {
	dc, err := discoveryclient.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cfn doorway discovery client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	if region == "" {
		region = "us-east-1"
	}
	return &cfnDoorway{cfg: cfg, shimDyn: shimDyn, mapper: mapper, account: account, region: region, ns: ns, logger: logger}, nil
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
	icfg := rest.CopyConfig(h.cfg)
	icfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
	cdyn, err := dynamic.NewForConfig(icfg)
	if err != nil {
		return nil, err
	}
	return &impersonatingApplier{caller: cdyn, shim: h.shimDyn, mapper: h.mapper, ns: h.ns}, nil
}

func (h *cfnDoorway) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	action := r.PostFormValue("Action")
	if action == "" {
		writeQueryError(w, http.StatusBadRequest, "MissingAction", requestID, "no Action in the request.", cfnXMLNamespace)
		return
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
	return cfn.DeployOptions{StackName: name, Namespace: h.ns, Params: params, Wait: true, Timeout: cfnWaitTimeout}
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

	// Synchronous validation gate — an unsupported type / bad template is refused WHOLE here, before
	// anything is created (the DoD's "refused at validation, nothing created"). This mirrors the engine's
	// own plan gate but surfaces it as an immediate ValidationError to the caller.
	plan, perr := cfn.BuildPlan([]byte(body), params, name)
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused (nothing created):\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}

	ctx := r.Context()
	if _, found, _ := ap.GetStack(ctx, name); found {
		writeQueryError(w, http.StatusBadRequest, "AlreadyExistsException", requestID,
			"Stack ["+name+"] already exists.", cfnXMLNamespace)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := ap.putRecord(ctx, &cfn.StackRecord{Name: name, Namespace: h.ns, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now}); err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not seed stack record: "+err.Error(), cfnXMLNamespace)
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		if _, derr := cfn.Deploy(bctx, []byte(body), h.opts(name, params), ap); derr != nil {
			h.logger.Warn("cfn CreateStack failed", "stack", name, "error", derr.Error())
			ap.backstopTerminal(bctx, name, "CREATE_FAILED", derr.Error())
		}
	}()
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
	if _, found, _ := ap.GetStack(ctx, name); !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
		return
	}
	plan, perr := cfn.BuildPlan([]byte(body), params, name)
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused (nothing changed):\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		if _, derr := cfn.Update(bctx, []byte(body), h.opts(name, params), ap); derr != nil {
			h.logger.Warn("cfn UpdateStack failed", "stack", name, "error", derr.Error())
			ap.backstopTerminal(bctx, name, "UPDATE_FAILED", derr.Error())
		}
	}()
	h.writeResult(w, requestID, "UpdateStack", "<StackId>"+xesc(h.stackID(name))+"</StackId>")
}

func (h *cfnDoorway) deleteStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	ctx := r.Context()
	if _, found, _ := ap.GetStack(ctx, name); !found {
		// AWS treats deleting an absent stack as a successful no-op.
		h.writeResult(w, requestID, "DeleteStack", "")
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		if _, derr := cfn.Destroy(bctx, h.opts(name, nil), ap); derr != nil {
			h.logger.Warn("cfn DeleteStack failed", "stack", name, "error", derr.Error())
			ap.backstopTerminal(bctx, name, "DELETE_FAILED", derr.Error())
		}
	}()
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
	plan, perr := cfn.BuildPlan([]byte(body), nil, "validate")
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

	// BuildChangeSet computes the diff against the current stack record and APPLIES NOTHING.
	cs, _, _, cerr := cfn.BuildChangeSet(ctx, []byte(body), h.opts(stack, params), ap)
	if cerr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, cerr.Error(), cfnXMLNamespace)
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
	inner := "<ChangeSetName>" + xesc(cs.Name) + "</ChangeSetName>" +
		"<StackName>" + xesc(cs.StackName) + "</StackName>" +
		"<Status>CREATE_COMPLETE</Status><ExecutionStatus>AVAILABLE</ExecutionStatus>" +
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
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), cfnAsyncTimeout)
		defer cancel()
		var derr error
		if create {
			_, derr = cfn.Deploy(bctx, []byte(body), h.opts(stack, params), ap)
		} else {
			_, derr = cfn.Update(bctx, []byte(body), h.opts(stack, params), ap)
		}
		if derr != nil {
			h.logger.Warn("cfn ExecuteChangeSet failed", "stack", stack, "error", derr.Error())
			status := "UPDATE_FAILED"
			if create {
				status = "CREATE_FAILED"
			}
			ap.backstopTerminal(bctx, stack, status, derr.Error())
		}
	}()
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
