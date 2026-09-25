// AWS Step Functions front door for the aws-shim (polyhedron#172) — the states.* management + execution
// API over the platform's existing kind: StateMachine (an ASL workflow) and kind: Execution (one run),
// driven by the singleton statemachine controller (platform/abstraction/statemachine-controller.yaml).
//
// Speaks AWS JSON 1.0 (X-Amz-Target: AWSStepFunctions.<Op>).
//
// Faithful subset, refused-not-faked: v1 implements Standard workflows with Task/Choice/Wait/Pass/
// Succeed/Fail + Retry/Catch. CreateStateMachine REFUSES what the engine does not implement — Express
// type, Parallel/Map states, .waitForTaskToken / .sync callback patterns, and non-Lambda service
// integrations — rather than accepting a definition that would fail (or silently mis-run) later. AWS
// Lambda Task Resources (a Lambda ARN, or arn:aws:states:::lambda:invoke) are TRANSLATED to the engine's
// function:<name> form so an AWS-authored definition runs unchanged.
//
// Execution-role authority (the confused-deputy fix, with #168): a state machine created with a roleArn
// gets, at StartExecution, a freshly minted STS session for that role, stored in a per-execution Secret
// the controller injects into every Task. A Task therefore acts under the role's authority — it can do
// exactly what the role's policies grant and no more — instead of the controller's ambient position.
// Running a state machine under a role requires the caller to be trusted to assume it (the PassRole
// analog): fail closed if the role is unknown or its trust does not name the caller.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	gvrStateMachines = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "statemachines"}
	gvrExecutions    = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "executions"}
)

type sfnHandler struct {
	cs      kubernetes.Interface
	dyn     dynamic.Interface
	minter  *awssts.Minter // mints the execution-role STS session; nil ⇒ role authority unavailable
	roles   roleResolver   // resolves a role's trust + session groups; nil ⇒ role authority unavailable
	authz   *dataplaneauthz.Checker
	ns      string // where StateMachines, Executions, per-execution creds Secrets and Functions live
	account string
	region  string
	logger  *slog.Logger
}

func newSFNHandler(cs kubernetes.Interface, dyn dynamic.Interface, minter *awssts.Minter, roles roleResolver, authz *dataplaneauthz.Checker, ns, account, region string, logger *slog.Logger) *sfnHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &sfnHandler{cs: cs, dyn: dyn, minter: minter, roles: roles, authz: authz, ns: ns, account: account, region: region, logger: logger}
}

func writeSFNError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("x-amzn-ErrorType", code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeSFNJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *sfnHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeSFNError(w, http.StatusForbidden, "AccessDeniedException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForSFNOp maps a Step Functions op to its coarse RBAC verb + the CRD resource it authorizes against,
// so states management is gated by the caller's k8s RBAC on the openinfra.dev CRDs (no new authz surface).
func verbForSFNOp(op string) (verb, resource string, ok bool) {
	switch op {
	case "CreateStateMachine":
		return "create", "statemachines", true
	case "UpdateStateMachine":
		return "update", "statemachines", true
	case "DeleteStateMachine":
		return "delete", "statemachines", true
	case "DescribeStateMachine", "ListStateMachines", "DescribeStateMachineForExecution":
		return "get", "statemachines", true
	case "StartExecution", "StartSyncExecution":
		return "create", "executions", true
	case "StopExecution":
		return "update", "executions", true
	case "DescribeExecution", "GetExecutionHistory", "ListExecutions":
		return "get", "executions", true
	}
	return "", "", false
}

func (h *sfnHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeSFNError(w, http.StatusBadRequest, "InvalidAction", requestID, "no X-Amz-Target (expected AWSStepFunctions.<Op>).")
		return
	}
	verb, resource, known := verbForSFNOp(op)
	if !known {
		writeSFNError(w, http.StatusBadRequest, "InvalidAction", requestID, "Step Functions "+op+" is not implemented by the open-infra shim.")
		return
	}
	if h.dyn == nil {
		writeSFNError(w, http.StatusServiceUnavailable, "InternalFailure", requestID,
			"the Step Functions control plane is not configured on this shim (no dynamic client).")
		return
	}
	body := readJSONBody(r)
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// Coarse authz: the caller must hold k8s RBAC on the openinfra.dev CRD (impersonated SAR) — the same
	// RBAC the console's state-machine pages use.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", resource, h.ns, ""); !allowed {
		writeSFNError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}

	switch op {
	case "CreateStateMachine":
		h.createStateMachine(ctx, w, requestID, body, claims)
	case "UpdateStateMachine":
		h.updateStateMachine(ctx, w, requestID, body)
	case "DeleteStateMachine":
		h.deleteStateMachine(ctx, w, requestID, body)
	case "DescribeStateMachine":
		h.describeStateMachine(ctx, w, requestID, body)
	case "ListStateMachines":
		h.listStateMachines(ctx, w, requestID)
	case "StartExecution":
		h.startExecution(ctx, w, requestID, body, claims)
	case "StopExecution":
		h.stopExecution(ctx, w, requestID, body)
	case "DescribeExecution":
		h.describeExecution(ctx, w, requestID, body)
	case "GetExecutionHistory":
		h.getExecutionHistory(ctx, w, requestID, body)
	case "ListExecutions":
		h.listExecutions(ctx, w, requestID, body)
	default:
		writeSFNError(w, http.StatusBadRequest, "InvalidAction", requestID, "Step Functions "+op+" is recognized but not implemented.")
	}
}

// --- ARNs ---

func (h *sfnHandler) smArn(name string) string {
	return fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:%s", h.region, h.account, name)
}
func (h *sfnHandler) execArn(sm, name string) string {
	return fmt.Sprintf("arn:aws:states:%s:%s:execution:%s:%s", h.region, h.account, sm, name)
}

// smNameFromArn extracts the state-machine name from an ARN, or returns the input if it is a bare name.
func smNameFromArn(arn string) string {
	if i := strings.LastIndex(arn, ":stateMachine:"); i >= 0 {
		return arn[i+len(":stateMachine:"):]
	}
	return arn
}

// execParts extracts (stateMachine, executionName) from an execution ARN.
func execParts(arn string) (sm, name string) {
	if i := strings.LastIndex(arn, ":execution:"); i >= 0 {
		rest := arn[i+len(":execution:"):]
		if j := strings.Index(rest, ":"); j >= 0 {
			return rest[:j], rest[j+1:]
		}
		return rest, ""
	}
	return "", arn
}

var k8sNameInvalid = regexp.MustCompile(`[^a-z0-9.-]+`)

// sanitizeName maps an AWS name to a DNS-1123 object name (lowercased, invalid runs → "-", trimmed). The
// same value is used in the returned ARN so Describe/Stop/History can map the ARN back to the object.
func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = k8sNameInvalid.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-.")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-.")
	}
	return s
}

// --- state machines ---

func (h *sfnHandler) createStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, claims iam.Claims) {
	name := sanitizeName(str(body["name"]))
	if name == "" {
		writeSFNError(w, http.StatusBadRequest, "InvalidName", requestID, "CreateStateMachine requires a name.")
		return
	}
	if t := strings.ToUpper(str(body["type"])); t != "" && t != "STANDARD" {
		writeSFNError(w, http.StatusBadRequest, "StateMachineTypeNotSupported", requestID,
			"only STANDARD state machines are supported (got "+t+"); EXPRESS is not implemented.")
		return
	}
	translated, err := validateAndTranslateDefinition(str(body["definition"]))
	if err != nil {
		writeSFNError(w, http.StatusBadRequest, "InvalidDefinition", requestID, err.Error())
		return
	}
	roleName := roleNameFromArn(str(body["roleArn"]))
	if roleName != "" {
		if h.roles == nil {
			writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID,
				"a roleArn was given but execution-role authority is not enabled on this shim (STS disabled).")
			return
		}
		if _, _, ok := h.roles.Resolve(ctx, roleName); !ok {
			writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "role "+roleName+" does not exist.")
			return
		}
	}

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1",
		"kind":       "StateMachine",
		"metadata":   map[string]any{"name": name, "namespace": h.ns},
		"spec":       map[string]any{"definition": translated, "type": "Standard", "roleArn": roleName},
	}}
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeSFNError(w, http.StatusBadRequest, "StateMachineAlreadyExists", requestID, "State Machine "+name+" already exists.")
			return
		}
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{
		"stateMachineArn": h.smArn(name),
		"creationDate":    epoch(time.Now()),
	})
}

func (h *sfnHandler) updateStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := smNameFromArn(str(body["stateMachineArn"]))
	u, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		writeSFNError(w, http.StatusBadRequest, "StateMachineDoesNotExist", requestID, "State Machine "+name+" does not exist.")
		return
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	if spec == nil {
		spec = map[string]any{}
	}
	if d := str(body["definition"]); d != "" {
		translated, verr := validateAndTranslateDefinition(d)
		if verr != nil {
			writeSFNError(w, http.StatusBadRequest, "InvalidDefinition", requestID, verr.Error())
			return
		}
		spec["definition"] = translated
	}
	if ra, ok := body["roleArn"]; ok {
		roleName := roleNameFromArn(str(ra))
		if roleName != "" && h.roles != nil {
			if _, _, ok := h.roles.Resolve(ctx, roleName); !ok {
				writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "role "+roleName+" does not exist.")
				return
			}
		}
		spec["roleArn"] = roleName
	}
	_ = unstructured.SetNestedMap(u.Object, spec, "spec")
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{"updateDate": epoch(time.Now())})
}

func (h *sfnHandler) deleteStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := smNameFromArn(str(body["stateMachineArn"]))
	err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) { // Delete is idempotent in SFN
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{})
}

func (h *sfnHandler) describeStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := smNameFromArn(str(body["stateMachineArn"]))
	u, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		writeSFNError(w, http.StatusBadRequest, "StateMachineDoesNotExist", requestID, "State Machine "+name+" does not exist.")
		return
	}
	def, _, _ := unstructured.NestedString(u.Object, "spec", "definition")
	roleName, _, _ := unstructured.NestedString(u.Object, "spec", "roleArn")
	writeSFNJSON(w, requestID, map[string]any{
		"stateMachineArn": h.smArn(name),
		"name":            name,
		"status":          "ACTIVE",
		"definition":      def,
		"roleArn":         h.iamRoleArn(roleName),
		"type":            "STANDARD",
		"creationDate":    epoch(u.GetCreationTimestamp().Time),
	})
}

func (h *sfnHandler) listStateMachines(ctx context.Context, w http.ResponseWriter, requestID string) {
	list, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(list.Items))
	for i := range list.Items {
		n := list.Items[i].GetName()
		items = append(items, map[string]any{
			"stateMachineArn": h.smArn(n), "name": n, "type": "STANDARD",
			"creationDate": epoch(list.Items[i].GetCreationTimestamp().Time),
		})
	}
	writeSFNJSON(w, requestID, map[string]any{"stateMachines": items})
}

// --- executions ---

func (h *sfnHandler) startExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, claims iam.Claims) {
	smName := smNameFromArn(str(body["stateMachineArn"]))
	if smName == "" {
		writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "StartExecution requires stateMachineArn.")
		return
	}
	sm, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Get(ctx, smName, metav1.GetOptions{})
	if err != nil {
		writeSFNError(w, http.StatusBadRequest, "StateMachineDoesNotExist", requestID, "State Machine "+smName+" does not exist.")
		return
	}
	execName := sanitizeName(str(body["name"]))
	if execName == "" {
		execName = fmt.Sprintf("exec-%d", time.Now().UnixNano())
	}
	input := str(body["input"])
	if strings.TrimSpace(input) == "" {
		input = "{}"
	}

	// Execution-role authority: mint an STS session for the state machine's role and hand it to the
	// controller via a per-execution Secret, so every Task runs under the role (the #168 pattern).
	credsSecret := ""
	if roleName, _, _ := unstructured.NestedString(sm.Object, "spec", "roleArn"); roleName != "" {
		secretName, aerr := h.mintExecutionCreds(ctx, roleName, execName, claims)
		if aerr != nil {
			writeSFNError(w, aerr.status, aerr.code, requestID, aerr.message)
			return
		}
		credsSecret = secretName
	}

	spec := map[string]any{
		"stateMachineRef": map[string]any{"name": smName},
		"input":           input,
	}
	if credsSecret != "" {
		spec["credentialsSecret"] = credsSecret
		spec["credentialsNamespace"] = h.ns
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1",
		"kind":       "Execution",
		"metadata":   map[string]any{"name": execName, "namespace": h.ns},
		"spec":       spec,
	}}
	if _, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeSFNError(w, http.StatusBadRequest, "ExecutionAlreadyExists", requestID, "Execution "+execName+" already exists.")
			return
		}
		// Best-effort: don't leave an orphaned creds Secret if the Execution create failed.
		if credsSecret != "" {
			_ = h.cs.CoreV1().Secrets(h.ns).Delete(ctx, credsSecret, metav1.DeleteOptions{})
		}
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{
		"executionArn": h.execArn(smName, execName),
		"startDate":    epoch(time.Now()),
	})
}

type sfnErr struct {
	status  int
	code    string
	message string
}

// mintExecutionCreds resolves the role, enforces the caller-is-trusted (PassRole analog) gate, mints an
// STS session, and stores it in a per-execution Secret the controller injects into Tasks.
func (h *sfnHandler) mintExecutionCreds(ctx context.Context, roleName, execName string, claims iam.Claims) (string, *sfnErr) {
	if h.minter == nil || h.roles == nil {
		return "", &sfnErr{http.StatusBadRequest, "InvalidArn",
			"this state machine has a roleArn but execution-role authority is not enabled on this shim (STS disabled)."}
	}
	trust, groups, ok := h.roles.Resolve(ctx, roleName)
	if !ok {
		return "", &sfnErr{http.StatusBadRequest, "InvalidArn", "role " + roleName + " does not exist."}
	}
	caller := callerName(claims)
	if !trusted(caller, trust) {
		return "", &sfnErr{http.StatusForbidden, "AccessDeniedException",
			caller + " is not authorized to run executions under role " + roleName + " (not named by its trust policy)."}
	}
	akid, sk, token, exp, err := h.minter.Mint(roleName, groups, execName, caller, awssts.DefaultDuration)
	if err != nil {
		return "", &sfnErr{http.StatusInternalServerError, "InternalFailure", "could not mint execution credentials."}
	}
	secretName := execName + "-creds"
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName, Namespace: h.ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":     "open-infra-aws-shim",
				"openinfra.dev/statemachine-creds": "true",
			},
		},
		Data: map[string][]byte{
			"accessKeyId":     []byte(akid),
			"secretAccessKey": []byte(sk),
			"sessionToken":    []byte(token),
			"expiration":      []byte(exp.UTC().Format(time.RFC3339)),
			"role":            []byte(roleName),
		},
	}
	if _, err := h.cs.CoreV1().Secrets(h.ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if _, uerr := h.cs.CoreV1().Secrets(h.ns).Update(ctx, sec, metav1.UpdateOptions{}); uerr == nil {
				return secretName, nil
			}
		}
		return "", &sfnErr{http.StatusInternalServerError, "InternalFailure", "could not store execution credentials: " + err.Error()}
	}
	return secretName, nil
}

func (h *sfnHandler) stopExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	_, execName := execParts(str(body["executionArn"]))
	if execName == "" {
		writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "StopExecution requires executionArn.")
		return
	}
	cause := str(body["cause"])
	if cause == "" {
		cause = "Execution stopped"
	}
	// Signal the controller (it performs the actual abort and writes the terminal ABORTED phase, so the
	// shim never races the running goroutine). Patch the status subresource.
	patch := map[string]any{"status": map[string]any{"stopRequested": true, "stopCause": cause, "error": str(body["error"])}}
	pb, _ := json.Marshal(patch)
	if _, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).Patch(ctx, execName, types.MergePatchType, pb, metav1.PatchOptions{}, "status"); err != nil {
		if apierrors.IsNotFound(err) {
			writeSFNError(w, http.StatusBadRequest, "ExecutionDoesNotExist", requestID, "Execution "+execName+" does not exist.")
			return
		}
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{"stopDate": epoch(time.Now())})
}

func (h *sfnHandler) describeExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	_, execName := execParts(str(body["executionArn"]))
	u, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).Get(ctx, execName, metav1.GetOptions{})
	if err != nil {
		writeSFNError(w, http.StatusBadRequest, "ExecutionDoesNotExist", requestID, "Execution "+execName+" does not exist.")
		return
	}
	smName, _, _ := unstructured.NestedString(u.Object, "spec", "stateMachineRef", "name")
	input, _, _ := unstructured.NestedString(u.Object, "spec", "input")
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	out := map[string]any{
		"executionArn":    h.execArn(smName, execName),
		"stateMachineArn": h.smArn(smName),
		"name":            execName,
		"status":          awsExecStatus(phase),
		"input":           input,
		"startDate":       epoch(u.GetCreationTimestamp().Time),
	}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "output"); ok && v != "" {
		out["output"] = v
	}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "error"); ok && v != "" {
		out["error"] = v
	}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "cause"); ok && v != "" {
		out["cause"] = v
	}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "stoppedAt"); ok && v != "" {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			out["stopDate"] = epoch(t)
		}
	}
	writeSFNJSON(w, requestID, out)
}

func (h *sfnHandler) getExecutionHistory(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	_, execName := execParts(str(body["executionArn"]))
	u, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).Get(ctx, execName, metav1.GetOptions{})
	if err != nil {
		writeSFNError(w, http.StatusBadRequest, "ExecutionDoesNotExist", requestID, "Execution "+execName+" does not exist.")
		return
	}
	hist, _, _ := unstructured.NestedSlice(u.Object, "status", "history")
	events := make([]map[string]any, 0, len(hist))
	for i, e := range hist {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		ev := map[string]any{"id": float64(i + 1), "type": str(m["type"])}
		if ts := str(m["time"]); ts != "" {
			if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
				ev["timestamp"] = epoch(t)
			}
		}
		// Carry the engine's per-event detail through so a caller can see the state, error and retry
		// attempt (a superset of the AWS history detail shapes, kept flat for a faithful-enough view).
		for _, k := range []string{"state", "error", "cause", "next", "attempt"} {
			if v, has := m[k]; has {
				ev[k] = v
			}
		}
		events = append(events, ev)
	}
	writeSFNJSON(w, requestID, map[string]any{"events": events})
}

func (h *sfnHandler) listExecutions(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	list, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	filter := smNameFromArn(str(body["stateMachineArn"]))
	items := make([]map[string]any, 0, len(list.Items))
	for i := range list.Items {
		obj := list.Items[i].Object
		smName, _, _ := unstructured.NestedString(obj, "spec", "stateMachineRef", "name")
		if filter != "" && smName != filter {
			continue
		}
		n := list.Items[i].GetName()
		phase, _, _ := unstructured.NestedString(obj, "status", "phase")
		items = append(items, map[string]any{
			"executionArn":    h.execArn(smName, n),
			"stateMachineArn": h.smArn(smName),
			"name":            n,
			"status":          awsExecStatus(phase),
			"startDate":       epoch(list.Items[i].GetCreationTimestamp().Time),
		})
	}
	writeSFNJSON(w, requestID, map[string]any{"executions": items})
}

// --- helpers ---

func (h *sfnHandler) iamRoleArn(name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", h.account, name)
}

// awsExecStatus maps the engine's phase to the Step Functions ExecutionStatus enum.
func awsExecStatus(phase string) string {
	switch phase {
	case "Succeeded":
		return "SUCCEEDED"
	case "Failed":
		return "FAILED"
	case "TimedOut":
		return "TIMED_OUT"
	case "Aborted":
		return "ABORTED"
	case "", "Running":
		return "RUNNING"
	}
	return strings.ToUpper(phase)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
