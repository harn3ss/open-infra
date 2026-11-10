// AWS Step Functions front door for the aws-shim — the states.* management + execution
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
// Running a state machine under a role requires the role to trust the Step Functions service
// (states.amazonaws.com), as on AWS, whose passing of it took iam:PassRole, or to name the caller: fail
// closed if the role is unknown or its trust names neither.
//
// Accounts: each account's state machines and executions are its own. A member account's StateMachines,
// Executions and execution credentials are kept in its home namespace (the management account's in the
// Step Functions namespace, where they always were), so the same state-machine name lives in each account
// independently and each account lists only its own; every ARN carries the caller's account, and a
// member's reference by another account's ARN is not found. A member account's execution role is a Role
// of its own account (in its home: iam:PassRole of another account's role is refused, as on AWS), and its
// execution's session acts in the member account.
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

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
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
	cs     kubernetes.Interface
	dyn    dynamic.Interface
	minter *awssts.Minter // mints the execution-role STS session; nil ⇒ role authority unavailable
	roles  roleResolver   // resolves a role's trust + session groups; nil ⇒ role authority unavailable
	authz  *dataplaneauthz.Checker
	ns     string // where StateMachines, Executions, per-execution creds Secrets and Functions live
	// rolesNS is where execution roles live (the role resolver's namespace); "" = the IAM home namespace.
	rolesNS string
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

// Step Functions keeps each account's state machines and executions apart (see the file header).
func init() { accountScopedServices["states"] = true }

// nsFor is the namespace the caller's account's state machines, executions and execution credentials are
// kept in: the Step Functions namespace for the management account, a member account's home for a member's.
func (h *sfnHandler) nsFor(ctx context.Context) string { return accountNamespace(ctx, h.ns) }

// arnAccount is the account of the request's ARNs: the install's for the management account (exactly as
// before), the member account's for a member's.
func (h *sfnHandler) arnAccount(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return h.account
	}
	return callerAccount(ctx)
}

// memberAccount is the caller's account for a member account's request, "" for the management account's.
func (h *sfnHandler) memberAccount(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return ""
	}
	return callerAccount(ctx)
}

// otherAccountsARN reports whether a member account's request names a state machine, an execution or a
// role by an ARN of another account: none is ever one of the member's, so it is not found (never the
// member's resource of the same name, nor the other account's). The management account's references
// resolve by name, as they always did.
func (h *sfnHandler) otherAccountsARN(ctx context.Context, arn string) bool {
	arn = strings.TrimSpace(arn)
	return isMemberRequest(ctx) && strings.HasPrefix(arn, "arn:") && awsidentity.AccountOfARN(arn) != callerAccount(ctx)
}

// resolveRole resolves an execution role of the caller's account: the management account's in the role
// resolver's namespace (as always), a member account's in its home — where its IAM roles live. A resolver
// that cannot resolve in another namespace resolves no member account's role.
func (h *sfnHandler) resolveRole(ctx context.Context, roleName string) (resolvedRole, bool) {
	if h.roles == nil {
		return resolvedRole{}, false
	}
	if !isMemberRequest(ctx) {
		return h.roles.Resolve(ctx, roleName)
	}
	in, ok := h.roles.(roleResolverIn)
	if !ok {
		return resolvedRole{}, false
	}
	return in.ResolveIn(ctx, h.passRoleNamespace(ctx), roleName)
}

func writeSFNError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
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

func (h *sfnHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeSFNError(w, http.StatusForbidden, authCode(r, "AccessDeniedException"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."))
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

	// The data-plane check, states:<Op> on the state machine the op names (an execution resolves to its
	// state machine, and the handler holds it to that one: boundExecution). An assumed role's authority is
	// its data-plane policy alone (CanDo passes a role), default-deny on every op, ListStateMachines on
	// StateMachine::*. A User's policy can only tighten the RBAC gate above, on an op naming a state machine.
	// In enforce IAM policy alone decides (decide); in legacy the coarse check above runs first.
	sm := sfnStateMachine(op, body)
	if ok, reason := decide(ctx, r, h.authz, claims, "states:"+op, "StateMachine", sm,
		coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "openinfra.dev", resource, h.nsFor(ctx), "",
			"states:"+op, "StateMachine", sm)); !ok {
		writeSFNError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	// iam:PassRole: giving a state machine an execution role needs permission to pass that Role, as on
	// AWS (passrole.go). The shim writes the StateMachine with its own identity, so the check is here,
	// as the caller. (StartExecution separately requires the role's trust policy to name the caller.)
	if op == "CreateStateMachine" || op == "UpdateStateMachine" {
		if role := roleNameFromArn(str(body["roleArn"])); role != "" {
			// A role is passed only within its own account, as on AWS: a member account's state machine
			// runs under a role of its own account.
			if h.otherAccountsARN(ctx, str(body["roleArn"])) {
				writeSFNError(w, http.StatusForbidden, "AccessDeniedException", requestID, "Cross-account pass role is not allowed.")
				return
			}
			if ok, reason := callerMayPassRole(ctx, h.cs, h.authz, claims, h.passRoleNamespace(ctx), role, "states.amazonaws.com", r); !ok {
				writeSFNError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
				return
			}
		}
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
	case "StartSyncExecution":
		h.startSyncExecution(ctx, w, requestID, body, claims)
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

func (h *sfnHandler) smArn(ctx context.Context, name string) string {
	return fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:%s", h.region, h.arnAccount(ctx), name)
}
func (h *sfnHandler) execArn(ctx context.Context, sm, name string) string {
	return fmt.Sprintf("arn:aws:states:%s:%s:execution:%s:%s", h.region, h.arnAccount(ctx), sm, name)
}

// sfnStateMachine is the state machine an op is authorized on: the name being created, the one a
// stateMachineArn names, or the one an executionArn belongs to. "" for ListStateMachines.
func sfnStateMachine(op string, body map[string]any) string {
	switch op {
	case "CreateStateMachine":
		return str(body["name"])
	case "StopExecution", "DescribeExecution", "GetExecutionHistory", "DescribeStateMachineForExecution":
		sm, _ := execParts(str(body["executionArn"]))
		return sm
	case "ListStateMachines":
		return ""
	}
	if a := str(body["stateMachineArn"]); a != "" {
		return smNameFromArn(a)
	}
	return ""
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
	smType := "Standard"
	switch strings.ToUpper(str(body["type"])) {
	case "", "STANDARD":
		smType = "Standard"
	case "EXPRESS":
		smType = "Express"
	default:
		writeSFNError(w, http.StatusBadRequest, "StateMachineTypeNotSupported", requestID,
			"type must be STANDARD or EXPRESS (got "+strings.ToUpper(str(body["type"]))+").")
		return
	}
	translated, err := validateAndTranslateDefinitionIn(str(body["definition"]), h.memberAccount(ctx))
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
		if _, ok := h.resolveRole(ctx, roleName); !ok {
			writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "role "+roleName+" does not exist.")
			return
		}
	}

	ns := h.nsFor(ctx)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1",
		"kind":       "StateMachine",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       map[string]any{"definition": translated, "type": smType, "roleArn": roleName},
	}}
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeSFNError(w, http.StatusBadRequest, "StateMachineAlreadyExists", requestID, "State Machine "+name+" already exists.")
			return
		}
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{
		"stateMachineArn": h.smArn(ctx, name),
		"creationDate":    epoch(time.Now()),
	})
}

func (h *sfnHandler) updateStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := smNameFromArn(str(body["stateMachineArn"]))
	u, err := h.dyn.Resource(gvrStateMachines).Namespace(h.nsFor(ctx)).Get(ctx, name, metav1.GetOptions{})
	if err != nil || h.otherAccountsARN(ctx, str(body["stateMachineArn"])) {
		writeSFNError(w, http.StatusBadRequest, "StateMachineDoesNotExist", requestID, "State Machine "+name+" does not exist.")
		return
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	if spec == nil {
		spec = map[string]any{}
	}
	if d := str(body["definition"]); d != "" {
		translated, verr := validateAndTranslateDefinitionIn(d, h.memberAccount(ctx))
		if verr != nil {
			writeSFNError(w, http.StatusBadRequest, "InvalidDefinition", requestID, verr.Error())
			return
		}
		spec["definition"] = translated
	}
	if ra, ok := body["roleArn"]; ok {
		roleName := roleNameFromArn(str(ra))
		if roleName != "" && h.roles != nil {
			if _, ok := h.resolveRole(ctx, roleName); !ok {
				writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "role "+roleName+" does not exist.")
				return
			}
		}
		spec["roleArn"] = roleName
	}
	_ = unstructured.SetNestedMap(u.Object, spec, "spec")
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(h.nsFor(ctx)).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{"updateDate": epoch(time.Now())})
}

func (h *sfnHandler) deleteStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := smNameFromArn(str(body["stateMachineArn"]))
	if h.otherAccountsARN(ctx, str(body["stateMachineArn"])) {
		writeSFNJSON(w, requestID, map[string]any{}) // no state machine of the member's: nothing to delete
		return
	}
	err := h.dyn.Resource(gvrStateMachines).Namespace(h.nsFor(ctx)).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) { // Delete is idempotent in SFN
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	writeSFNJSON(w, requestID, map[string]any{})
}

func (h *sfnHandler) describeStateMachine(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := smNameFromArn(str(body["stateMachineArn"]))
	u, err := h.dyn.Resource(gvrStateMachines).Namespace(h.nsFor(ctx)).Get(ctx, name, metav1.GetOptions{})
	if err != nil || h.otherAccountsARN(ctx, str(body["stateMachineArn"])) {
		writeSFNError(w, http.StatusBadRequest, "StateMachineDoesNotExist", requestID, "State Machine "+name+" does not exist.")
		return
	}
	def, _, _ := unstructured.NestedString(u.Object, "spec", "definition")
	roleName, _, _ := unstructured.NestedString(u.Object, "spec", "roleArn")
	smType, _, _ := unstructured.NestedString(u.Object, "spec", "type")
	if smType == "" {
		smType = "Standard"
	}
	writeSFNJSON(w, requestID, map[string]any{
		"stateMachineArn": h.smArn(ctx, name),
		"name":            name,
		"status":          "ACTIVE",
		"definition":      def,
		"roleArn":         h.iamRoleArn(ctx, roleName),
		"type":            strings.ToUpper(smType),
		"creationDate":    epoch(u.GetCreationTimestamp().Time),
	})
}

func (h *sfnHandler) listStateMachines(ctx context.Context, w http.ResponseWriter, requestID string) {
	list, err := h.dyn.Resource(gvrStateMachines).Namespace(h.nsFor(ctx)).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(list.Items))
	for i := range list.Items {
		n := list.Items[i].GetName()
		smType, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "type")
		if smType == "" {
			smType = "Standard"
		}
		items = append(items, map[string]any{
			"stateMachineArn": h.smArn(ctx, n), "name": n, "type": strings.ToUpper(smType),
			"creationDate": epoch(list.Items[i].GetCreationTimestamp().Time),
		})
	}
	writeSFNJSON(w, requestID, map[string]any{"stateMachines": items})
}

// --- executions ---

func (h *sfnHandler) startExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, claims iam.Claims) {
	smName, execName, _, serr := h.createExecution(ctx, body, claims, "")
	if serr != nil {
		writeSFNError(w, serr.status, serr.code, requestID, serr.message)
		return
	}
	writeSFNJSON(w, requestID, map[string]any{
		"executionArn": h.execArn(ctx, smName, execName),
		"startDate":    epoch(time.Now()),
	})
}

// createExecution is the shared create path for StartExecution (async) and StartSyncExecution (sync):
// resolve the state machine, mint the per-execution STS session (if the machine carries a role), and
// create the Execution CR the controller runs. requireType, when non-empty, rejects a machine whose
// spec.type does not match BEFORE anything is created (StartSyncExecution passes "Express", since AWS
// only allows a synchronous start on an Express machine). It returns the names + the machine's type.
func (h *sfnHandler) createExecution(ctx context.Context, body map[string]any, claims iam.Claims, requireType string) (smName, execName, smType string, serr *sfnErr) {
	smName = smNameFromArn(str(body["stateMachineArn"]))
	if smName == "" {
		return "", "", "", &sfnErr{http.StatusBadRequest, "InvalidArn", "StartExecution requires stateMachineArn."}
	}
	ns := h.nsFor(ctx)
	sm, err := h.dyn.Resource(gvrStateMachines).Namespace(ns).Get(ctx, smName, metav1.GetOptions{})
	if err != nil || h.otherAccountsARN(ctx, str(body["stateMachineArn"])) {
		return "", "", "", &sfnErr{http.StatusBadRequest, "StateMachineDoesNotExist", "State Machine " + smName + " does not exist."}
	}
	smType, _, _ = unstructured.NestedString(sm.Object, "spec", "type")
	if smType == "" {
		smType = "Standard"
	}
	if requireType != "" && !strings.EqualFold(smType, requireType) {
		return "", "", smType, &sfnErr{http.StatusBadRequest, "StateMachineTypeNotSupported",
			"StartSyncExecution is only supported for EXPRESS state machines (this one is " + smType + ")."}
	}
	execName = sanitizeName(str(body["name"]))
	if execName == "" {
		execName = fmt.Sprintf("exec-%d", time.Now().UnixNano())
	}
	input := str(body["input"])
	if strings.TrimSpace(input) == "" {
		input = "{}"
	}

	// Execution-role authority: mint an STS session for the state machine's role and hand it to the
	// controller via a per-execution Secret, so every Task runs under the role (the #168 pattern).
	// Minted first (no side effects), so a trust or role failure leaves nothing behind.
	var creds *executionCreds
	if roleName, _, _ := unstructured.NestedString(sm.Object, "spec", "roleArn"); roleName != "" {
		c, aerr := h.mintExecutionCreds(ctx, roleName, execName, claims)
		if aerr != nil {
			return "", "", smType, aerr
		}
		creds = c
	}

	spec := map[string]any{
		"stateMachineRef": map[string]any{"name": smName},
		"input":           input,
	}
	if creds != nil {
		// The Secret lives beside its Execution (it is owned by it), in the caller's account's namespace.
		spec["credentialsSecret"] = executionCredsSecretName(execName)
		spec["credentialsNamespace"] = ns
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1",
		"kind":       "Execution",
		"metadata":   map[string]any{"name": execName, "namespace": ns},
		"spec":       spec,
	}}
	created, err := h.dyn.Resource(gvrExecutions).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return "", "", smType, &sfnErr{http.StatusBadRequest, "ExecutionAlreadyExists", "Execution " + execName + " already exists."}
		}
		return "", "", smType, &sfnErr{http.StatusInternalServerError, "InternalFailure", err.Error()}
	}
	// The Secret is written after the Execution, owned by it: the controller hands the session only to
	// the Execution whose UID owns the Secret, so naming another execution's Secret gets nothing, and the
	// Secret is garbage-collected with its Execution.
	if creds != nil {
		if aerr := h.storeExecutionCreds(ctx, created, creds); aerr != nil {
			_ = h.dyn.Resource(gvrExecutions).Namespace(ns).Delete(ctx, execName, metav1.DeleteOptions{})
			return "", "", smType, aerr
		}
	}
	return smName, execName, smType, nil
}

// syncWaitCap bounds how long StartSyncExecution blocks for a terminal result. Express workflows are
// short; if one exceeds this, the call returns the current (RUNNING) status with the executionArn — the
// engine is durable (unlike AWS Express), so the client can finish with DescribeExecution.
const syncWaitCap = 110 * time.Second

// startSyncExecution runs an EXPRESS state machine and returns its output inline (AWS StartSyncExecution).
// It creates the execution through the shared path (which enforces the Express-only rule), then polls the
// Execution CR until it reaches a terminal phase, and renders the synchronous result.
func (h *sfnHandler) startSyncExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, claims iam.Claims) {
	start := time.Now()
	smName, execName, _, serr := h.createExecution(ctx, body, claims, "Express")
	if serr != nil {
		writeSFNError(w, serr.status, serr.code, requestID, serr.message)
		return
	}
	deadline := start.Add(syncWaitCap)
	var phase, output, execErr, cause string
	for {
		u, err := h.dyn.Resource(gvrExecutions).Namespace(h.nsFor(ctx)).Get(ctx, execName, metav1.GetOptions{})
		if err == nil {
			phase, _, _ = unstructured.NestedString(u.Object, "status", "phase")
			output, _, _ = unstructured.NestedString(u.Object, "status", "output")
			execErr, _, _ = unstructured.NestedString(u.Object, "status", "error")
			cause, _, _ = unstructured.NestedString(u.Object, "status", "cause")
		}
		switch phase {
		case "Succeeded", "Failed", "TimedOut", "Aborted":
			resp := map[string]any{
				"executionArn":    h.execArn(ctx, smName, execName),
				"stateMachineArn": h.smArn(ctx, smName),
				"name":            execName,
				"status":          awsExecStatus(phase),
				"startDate":       epoch(start),
				"stopDate":        epoch(time.Now()),
				"input":           str(body["input"]),
			}
			if phase == "Succeeded" {
				if output == "" {
					output = "{}"
				}
				resp["output"] = output
			}
			if execErr != "" {
				resp["error"] = execErr
			}
			if cause != "" {
				resp["cause"] = cause
			}
			writeSFNJSON(w, requestID, resp)
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			// Exceeded the synchronous wait — the execution keeps running (durable engine). Return the
			// current status + arn so the caller can finish via DescribeExecution. A superset of AWS,
			// where Express keeps no history; honest, never a false terminal result.
			writeSFNJSON(w, requestID, map[string]any{
				"executionArn":    h.execArn(ctx, smName, execName),
				"stateMachineArn": h.smArn(ctx, smName),
				"name":            execName,
				"status":          "RUNNING",
				"startDate":       epoch(start),
				"input":           str(body["input"]),
			})
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type sfnErr struct {
	status  int
	code    string
	message string
}

// mintExecutionCreds resolves the role, enforces the caller-is-trusted (PassRole analog) gate, mints an
// STS session, and stores it in a per-execution Secret the controller injects into Tasks.
func (h *sfnHandler) mintExecutionCreds(ctx context.Context, roleName, execName string, claims iam.Claims) (*executionCreds, *sfnErr) {
	if h.minter == nil || h.roles == nil {
		return nil, &sfnErr{http.StatusBadRequest, "InvalidArn",
			"this state machine has a roleArn but execution-role authority is not enabled on this shim (STS disabled)."}
	}
	role, ok := h.resolveRole(ctx, roleName)
	if !ok {
		return nil, &sfnErr{http.StatusBadRequest, "InvalidArn", "role " + roleName + " does not exist."}
	}
	who := callerTrust(claims)
	who.account = callerAccount(ctx) // a role may name its own account's principals by ARN
	// The role is the state machine's to run under when its trust names the Step Functions service, as on
	// AWS (passing it took iam:PassRole at CreateStateMachine/UpdateStateMachine), or names the caller.
	if !trustsService(role.trust, "states.amazonaws.com") && !trusted(who, role.trust) {
		return nil, &sfnErr{http.StatusForbidden, "AccessDeniedException",
			who.String() + " is not authorized to run executions under role " + roleName + " (not named by its trust policy)."}
	}
	caller := callerName(claims)
	var akid, sk, token string
	var exp time.Time
	var err error
	if !isMemberRequest(ctx) {
		akid, sk, token, exp, err = h.minter.Mint(roleName, role.groups, execName, caller, executionSessionDuration(role))
	} else {
		// A member account's execution acts in the member account, as its role (in its home).
		akid, sk, token, exp, err = h.minter.MintInAccount(callerAccount(ctx), h.passRoleNamespace(ctx),
			roleName, role.groups, execName, caller, executionSessionDuration(role))
	}
	if err != nil {
		return nil, &sfnErr{http.StatusInternalServerError, "InternalFailure", "could not mint execution credentials."}
	}
	return &executionCreds{role: roleName, akid: akid, sk: sk, token: token, exp: exp}, nil
}

// executionSessionDuration is how long an execution's role session lasts: the role's maximum session
// (spec.maxSessionDuration, AWS's MaxSessionDuration: 1h by default, at most 12h). The session is minted
// once, at StartExecution, so a long execution keeps its role's authority for as long as the role allows,
// and never longer.
func executionSessionDuration(role resolvedRole) time.Duration {
	d := role.maxSession
	if d <= 0 {
		d = defaultMaxSession
	}
	return min(d, awssts.MaxDuration)
}

// executionCreds is a minted execution-role session, not yet stored.
type executionCreds struct {
	role, akid, sk, token string
	exp                   time.Time
}

// Label on an execution credentials Secret. The statemachine controller reads only a Secret whose
// controller owner reference is the Execution it runs (statemachine/k8s.go).
const execCredsLabel = "openinfra.dev/statemachine-creds"

func executionCredsSecretName(execName string) string { return execName + "-creds" }

// storeExecutionCreds writes the session into a Secret owned by the Execution (controller owner
// reference with its UID). A leftover Secret of the same name, from an earlier execution that had the
// same name, is replaced.
func (h *sfnHandler) storeExecutionCreds(ctx context.Context, exec *unstructured.Unstructured, c *executionCreds) *sfnErr {
	isController := true
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: executionCredsSecretName(exec.GetName()), Namespace: exec.GetNamespace(),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "open-infra-aws-shim",
				execCredsLabel:                 "true",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "openinfra.dev/v1", Kind: "Execution",
				Name: exec.GetName(), UID: exec.GetUID(), Controller: &isController,
			}},
		},
		Data: map[string][]byte{
			"accessKeyId":     []byte(c.akid),
			"secretAccessKey": []byte(c.sk),
			"sessionToken":    []byte(c.token),
			"expiration":      []byte(c.exp.UTC().Format(time.RFC3339)),
			"role":            []byte(c.role),
		},
	}
	_, err := h.cs.CoreV1().Secrets(sec.Namespace).Create(ctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = h.cs.CoreV1().Secrets(sec.Namespace).Update(ctx, sec, metav1.UpdateOptions{})
	}
	if err != nil {
		return &sfnErr{http.StatusInternalServerError, "InternalFailure", "could not store execution credentials: " + err.Error()}
	}
	return nil
}

// boundExecution is the Execution an executionArn names, only if it runs the state machine the ARN names:
// the op was authorized on that state machine (sfnStateMachine), so an ARN pairing an authorized state
// machine with another one's execution is ExecutionDoesNotExist, as an ARN that names no execution.
func (h *sfnHandler) boundExecution(ctx context.Context, w http.ResponseWriter, requestID, arn string) (*unstructured.Unstructured, string, bool) {
	sm, execName := execParts(arn)
	if execName == "" {
		writeSFNError(w, http.StatusBadRequest, "InvalidArn", requestID, "Invalid executionArn: "+arn)
		return nil, "", false
	}
	if h.otherAccountsARN(ctx, arn) {
		writeSFNError(w, http.StatusBadRequest, "ExecutionDoesNotExist", requestID, "Execution "+arn+" does not exist.")
		return nil, "", false
	}
	u, err := h.dyn.Resource(gvrExecutions).Namespace(h.nsFor(ctx)).Get(ctx, execName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			writeSFNError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error())
			return nil, "", false
		}
		writeSFNError(w, http.StatusBadRequest, "ExecutionDoesNotExist", requestID, "Execution "+execName+" does not exist.")
		return nil, "", false
	}
	if runs, _, _ := unstructured.NestedString(u.Object, "spec", "stateMachineRef", "name"); runs != sm {
		writeSFNError(w, http.StatusBadRequest, "ExecutionDoesNotExist", requestID, "Execution "+arn+" does not exist.")
		return nil, "", false
	}
	return u, execName, true
}

func (h *sfnHandler) stopExecution(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	_, execName, ok := h.boundExecution(ctx, w, requestID, str(body["executionArn"]))
	if !ok {
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
	if _, err := h.dyn.Resource(gvrExecutions).Namespace(h.nsFor(ctx)).Patch(ctx, execName, types.MergePatchType, pb, metav1.PatchOptions{}, "status"); err != nil {
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
	u, execName, ok := h.boundExecution(ctx, w, requestID, str(body["executionArn"]))
	if !ok {
		return
	}
	smName, _, _ := unstructured.NestedString(u.Object, "spec", "stateMachineRef", "name")
	input, _, _ := unstructured.NestedString(u.Object, "spec", "input")
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	out := map[string]any{
		"executionArn":    h.execArn(ctx, smName, execName),
		"stateMachineArn": h.smArn(ctx, smName),
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
	u, _, ok := h.boundExecution(ctx, w, requestID, str(body["executionArn"]))
	if !ok {
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
	if h.otherAccountsARN(ctx, str(body["stateMachineArn"])) {
		writeSFNJSON(w, requestID, map[string]any{"executions": []map[string]any{}}) // no state machine of the member's
		return
	}
	list, err := h.dyn.Resource(gvrExecutions).Namespace(h.nsFor(ctx)).List(ctx, metav1.ListOptions{})
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
			"executionArn":    h.execArn(ctx, smName, n),
			"stateMachineArn": h.smArn(ctx, smName),
			"name":            n,
			"status":          awsExecStatus(phase),
			"startDate":       epoch(list.Items[i].GetCreationTimestamp().Time),
		})
	}
	writeSFNJSON(w, requestID, map[string]any{"executions": items})
}

// --- helpers ---

func (h *sfnHandler) iamRoleArn(ctx context.Context, name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", h.arnAccount(ctx), name)
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
