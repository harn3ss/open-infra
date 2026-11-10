// Lambda's read operations over kind: Function: GetFunction, GetFunctionConfiguration, ListFunctions and
// GetPolicy, in the Lambda REST-JSON shapes the AWS CLI and SDKs parse.
//
// A function is found where it lives (the Lambda API's namespace or a CloudFormation stack's, fn_locate.go)
// and read with the shim's `get`/`list` on functions there. The caller's authority is checked the way Invoke
// checks it: the coarse RBAC verb on functions in the function's namespace (get to read one, list to list
// a namespace), and the data-plane action AWS names (lambda:GetFunction, lambda:GetFunctionConfiguration,
// lambda:GetPolicy on Function::<name>; lambda:ListFunctions on Resource "*").
//
// ListFunctions pages through the claims with the API server's own limit/continue, so a page reads at most
// 50 claims (AWS's per-page maximum) and nothing holds every function in memory. Its Marker names the
// namespace it stopped in and that namespace's continue token; a namespace the caller may not list is
// skipped, so the listing holds only functions the caller may read.
//
// A function belongs to an account: a member account's are found and listed in its own namespaces alone,
// and named by ARNs carrying its account; the management account's are where they always were.
//
// A function's execution role (spec.role) is its Role, the role's ARN in the function's account; a stored
// deployment package (spec.code.source.package) gives CodeSha256 (its SHA-256, base64, as Lambda gives it)
// and CodeSize; the Description is the one CreateFunction kept; RevisionId is the object's version, which
// an update may name to change only that revision. What a Function does not have, the answer leaves out
// rather than invents: no Role when it names none, no code size or hash for code that is not a stored
// package, and no download location for a zip's code. A function has no resource policy (a stack's
// AWS::Lambda::Permission provisions nothing: the integration that invokes the function is authorized
// against its creator's authority when it is created), so GetPolicy answers as AWS does for a function with
// no policy: ResourceNotFoundException.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// lambdaListMax is the most functions one ListFunctions page holds (AWS returns at most 50 whatever
// MaxItems asks for) — and so the most claims one page reads.
const lambdaListMax = 50

// parseLambdaReadPath matches the read operations' routes and returns the operation, the function name and
// its qualifier (from the name's :qualifier or ?Qualifier=):
//
//	GET /2015-03-31/functions/                         ListFunctions
//	GET /2015-03-31/functions/{name}                   GetFunction
//	GET /2015-03-31/functions/{name}/configuration     GetFunctionConfiguration
//	GET /2015-03-31/functions/{name}/policy            GetPolicy
//
// ok is false for any other request (Invoke is matched by parseInvokePath); bad is true when the route is
// a read but its function name is not one a Function can have.
func parseLambdaReadPath(r *http.Request) (op, name, qualifier string, ok, bad bool) {
	if r.Method != http.MethodGet {
		return "", "", "", false, false
	}
	p := strings.TrimPrefix(r.URL.Path, "/2015-03-31/functions")
	if p == r.URL.Path {
		return "", "", "", false, false
	}
	if p == "" || p == "/" {
		return "ListFunctions", "", "", true, false
	}
	if !strings.HasPrefix(p, "/") {
		return "", "", "", false, false
	}
	fn, rest, _ := strings.Cut(p[1:], "/")
	switch rest {
	case "":
		op = "GetFunction"
	case "configuration":
		op = "GetFunctionConfiguration"
	case "policy":
		op = "GetPolicy"
	default:
		return "", "", "", false, false
	}
	name, qualifier, valid := parseFunctionRef(fn, r.URL.Query().Get("Qualifier"))
	if !valid {
		return op, "", "", true, true
	}
	return op, name, qualifier, true, false
}

// parseFunctionRef reads a FunctionName as a request carries it — a name, an ARN or partial ARN
// (arn:aws:lambda:<region>:<acct>:function:<name>[:<qualifier>], <acct>:function:<name>), optionally
// with :<qualifier> — plus a ?Qualifier=, which must agree with the name's. The name must be an RFC-1123
// label (it is part of the function's cluster address); a qualifier is $LATEST, a version number or an
// alias name, as Lambda's are (a version is invoked at its own address, v<version>-<name>: lambda_versions.go).
func parseFunctionRef(fn, queryQualifier string) (name, qualifier string, ok bool) {
	if i := strings.Index(fn, ":function:"); i >= 0 {
		fn = fn[i+len(":function:"):]
	}
	name, qualifier, _ = strings.Cut(fn, ":")
	if queryQualifier != "" {
		if qualifier != "" && qualifier != queryQualifier {
			return "", "", false
		}
		qualifier = queryQualifier
	}
	if !fnNameRE.MatchString(name) {
		return "", "", false
	}
	if qualifier != "" && qualifier != "$LATEST" {
		if len(qualifier) > 128 || !(versionNumberRe.MatchString(qualifier) || aliasNameRe.MatchString(qualifier)) {
			return "", "", false
		}
	}
	return name, qualifier, true
}

// lambdaReadAction is the IAM action AWS authorizes each read operation with.
func lambdaReadAction(op string) string {
	switch op {
	case "GetFunction":
		return "lambda:GetFunction"
	case "GetFunctionConfiguration":
		return "lambda:GetFunctionConfiguration"
	case "GetPolicy":
		return "lambda:GetPolicy"
	case "ListFunctions":
		return "lambda:ListFunctions"
	}
	return ""
}

func (h *lambdaHandler) serveRead(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, op, name, qualifier string) {
	if h.fns == nil || h.fns.dyn == nil || len(h.fns.namespaces) == 0 {
		writeLambdaError(w, http.StatusNotImplemented, "ServiceException", requestID,
			"reading functions needs the shim's cluster access, which this shim does not have")
		return
	}
	if op == "ListFunctions" {
		h.listFunctions(w, r, claims, requestID)
		return
	}
	ctx := r.Context()
	action := lambdaReadAction(op)
	ns := h.fns.namespaceFor(ctx, name, h.fnNS) // the caller's account's function (fn_locate.go)
	if ok, reason := decide(ctx, r, h.authz, claims, action, "Function", name, func() (bool, string) {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, action, "Function", name, r); denied {
			return false, reason
		}
		if allowed, reason := iam.CanDo(ctx, h.cs, claims, "get", "openinfra.dev", "functions", ns, name); !allowed {
			h.logger.Warn("lambda read denied", "user", claims.Sub, "function", name, "op", op, "reason", reason)
			return false, "User: " + claims.Sub + " is not authorized to perform: " + action + " on resource: " + h.functionARNIn(ctx, name)
		}
		return true, ""
	}); !ok {
		h.logger.Warn("lambda read denied", "user", claims.Sub, "function", name, "op", op, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	var obj *unstructured.Unstructured
	var err error = apierrors.NewNotFound(functionClaimGVR.GroupResource(), name) // a member account with no namespace has none
	if ns != noFnNamespace {
		obj, err = h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	}
	if apierrors.IsNotFound(err) {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"Function not found: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		h.logger.Warn("lambda read failed", "function", name, "namespace", ns, "error", err.Error())
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not read the function")
		return
	}
	// A qualified read answers with the version's own configuration (an alias's: its version's,
	// lambda_versions.go); one the function does not have is not found.
	h.fillPendingVersions(ctx, ns, obj)
	cfg, code, found := h.qualifiedFunction(ctx, obj, qualifier)
	if !found {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"Function not found: "+h.functionARNIn(ctx, name)+":"+qualifier)
		return
	}
	if qualifier == "" || qualifier == "$LATEST" {
		h.withUpdateStatus(ctx, obj, cfg) // an update that failed beyond the claim says so (#418)
	}
	switch op {
	case "GetFunctionConfiguration":
		writeLambdaJSON(w, requestID, cfg)
	case "GetFunction":
		out := map[string]any{"Configuration": cfg}
		if code != nil {
			out["Code"] = code
		}
		if n, found, _ := unstructured.NestedInt64(obj.Object, "spec", "reservedConcurrency"); found {
			out["Concurrency"] = map[string]any{"ReservedConcurrentExecutions": n}
		}
		writeLambdaJSON(w, requestID, out)
	case "GetPolicy":
		// A function has no resource policy (see the file comment): AWS's answer for one with none.
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"The resource you requested does not exist.")
	}
}

// lambdaMarker is a ListFunctions Marker: the index of the namespace the previous page stopped in and that
// namespace's continue token ("" = start it from the top).
type lambdaMarker struct {
	NS       int    `json:"n"`
	Continue string `json:"c,omitempty"`
}

func encodeLambdaMarker(m lambdaMarker) string {
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeLambdaMarker(s string) (lambdaMarker, bool) {
	var m lambdaMarker
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &m) != nil || m.NS < 0 {
		return lambdaMarker{}, false
	}
	return m, true
}

func (h *lambdaHandler) listFunctions(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	ctx := r.Context()
	// AWS evaluates lambda:ListFunctions on Resource "*" (an assumed role needs a grant on Function::*).
	if ok, reason := decide(ctx, r, h.authz, claims, "lambda:ListFunctions", "Function", "",
		dataPlaneOnly(ctx, r, h.authz, claims, "lambda:ListFunctions", "Function", "")); !ok {
		h.logger.Warn("lambda ListFunctions denied", "user", claims.Sub, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	q := r.URL.Query()
	limit := lambdaListMax
	if s := q.Get("MaxItems"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 10000 {
			writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID,
				"MaxItems must be between 1 and 10000")
			return
		}
		if n < limit {
			limit = n
		}
	}
	// The caller's account's namespaces: the management account's are the locator's own; a member
	// account's are its own, never the management account's (fn_locate.go).
	namespaces := h.fns.namespacesFor(ctx)
	start := lambdaMarker{}
	if s := q.Get("Marker"); s != "" {
		m, ok := decodeLambdaMarker(s)
		if !ok || m.NS >= len(namespaces) {
			writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID, "Invalid Marker")
			return
		}
		start = m
	}
	// The namespaces the caller may list functions in; one it may not is not listed (its functions are not
	// the caller's to see). A caller who may list none is refused, as AWS refuses ListFunctions.
	// In enforce, IAM policy allowed lambda:ListFunctions above: the account's functions are listed, as on
	// AWS. In legacy each namespace is listed only where the caller may list functions.
	readable := make([]bool, len(namespaces))
	anyReadable := false
	enforce := enforcing(ctx, h.authz, claims)
	for i, ns := range namespaces {
		if enforce {
			readable[i], anyReadable = true, true
			continue
		}
		if ok, _ := coarseOnly(ctx, h.cs, claims, "list", "openinfra.dev", "functions", ns, "")(); ok {
			readable[i], anyReadable = true, true
		}
	}
	if !anyReadable && !(enforce && len(namespaces) == 0) { // an account with no namespace has no functions
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID,
			"User: "+claims.Sub+" is not authorized to perform: lambda:ListFunctions on resource: *")
		return
	}
	fns := []any{}
	next := ""
	for i := start.NS; i < len(namespaces); i++ {
		if !readable[i] {
			continue
		}
		cont := ""
		if i == start.NS {
			cont = start.Continue
		}
		for len(fns) < limit {
			list, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(namespaces[i]).List(ctx,
				metav1.ListOptions{Limit: int64(limit - len(fns)), Continue: cont})
			if apierrors.IsResourceExpired(err) {
				writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID,
					"The Marker has expired: list the functions again from the start")
				return
			} else if err != nil {
				h.logger.Warn("lambda ListFunctions failed", "namespace", namespaces[i], "error", err.Error())
				writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not list the functions")
				return
			}
			for j := range list.Items {
				if len(fns) == limit {
					break // a server that ignores Limit still yields a page of at most limit
				}
				fns = append(fns, h.functionConfiguration(ctx, &list.Items[j], ""))
			}
			cont = list.GetContinue()
			if cont == "" {
				break
			}
		}
		if len(fns) == limit {
			if cont != "" {
				next = encodeLambdaMarker(lambdaMarker{NS: i, Continue: cont})
			} else if h.moreReadable(readable, i+1) {
				next = encodeLambdaMarker(lambdaMarker{NS: i + 1})
			}
			break
		}
	}
	out := map[string]any{"Functions": fns}
	if next != "" {
		out["NextMarker"] = next
	}
	writeLambdaJSON(w, requestID, out)
}

// moreReadable reports whether a namespace from index from on is one the caller may list.
func (h *lambdaHandler) moreReadable(readable []bool, from int) bool {
	for i := from; i < len(readable); i++ {
		if readable[i] {
			return true
		}
	}
	return false
}

// functionARN is the function's ARN in this install's region and account, as a stack reports it.
func (h *lambdaHandler) functionARN(name string) string {
	return "arn:aws:lambda:" + h.region + ":" + h.account + ":function:" + name
}

// functionARNIn is the ARN of the request's account's function named name: functionARN for the
// management account, the member account's own for a member's.
func (h *lambdaHandler) functionARNIn(ctx context.Context, name string) string {
	if !isMemberRequest(ctx) {
		return h.functionARN(name)
	}
	return "arn:aws:lambda:" + h.regionIn(ctx) + ":" + callerAccount(ctx) + ":function:" + name
}

// regionIn is the region of the handler's ARNs (the request's identity's when the handler has none).
func (h *lambdaHandler) regionIn(ctx context.Context) string {
	if h.region != "" {
		return h.region
	}
	return awsidentity.FromContext(ctx).Region
}

// functionConfiguration is a kind: Function in Lambda's FunctionConfiguration shape. qualifier is ""
// (the unqualified function) or an alias it has. Its ARN is the request's account's.
func (h *lambdaHandler) functionConfiguration(ctx context.Context, obj *unstructured.Unstructured, qualifier string) map[string]any {
	name := obj.GetName()
	spec, _ := obj.Object["spec"].(map[string]any)
	arn := h.functionARNIn(ctx, name)
	if qualifier != "" {
		arn += ":" + qualifier
	}
	c := map[string]any{
		"FunctionName": name,
		"FunctionArn":  arn,
		"Version":      "$LATEST",
		"LastModified": lambdaTime(fnLastModified(obj)),
	}
	if img, _ := spec["image"].(string); img != "" {
		c["PackageType"] = "Image"
	} else {
		c["PackageType"] = "Zip"
		code, _ := spec["code"].(map[string]any)
		if rt := lambdaRuntime(fnStr(code["runtime"])); rt != "" {
			c["Runtime"] = rt
		}
		if hd := fnStr(code["handler"]); hd != "" {
			c["Handler"] = hd
		}
	}
	// The execution role, as its ARN in the function's account (a role ARN as the function names it).
	if role := fnStr(spec["role"]); role != "" {
		if !strings.HasPrefix(role, "arn:") {
			id := awsidentity.FromContext(ctx)
			if !isMemberRequest(ctx) && h.account != "" {
				id.AccountID = h.account
			}
			role = id.IAMARN("role/" + role)
		}
		c["Role"] = role
	}
	if m := fnStr(spec["memory"]); m != "" {
		if q, err := resource.ParseQuantity(m); err == nil {
			c["MemorySize"] = q.Value() / (1 << 20)
		}
	}
	// Unset, a function's requests run for Knative's default of 300 seconds.
	timeout := int64(300)
	if t, found, _ := unstructured.NestedInt64(obj.Object, "spec", "timeout"); found {
		timeout = t
	}
	c["Timeout"] = timeout
	if vc := vpcConfigOf(spec); vc != nil {
		c["VpcConfig"] = vc
	}
	if env, _ := spec["env"].([]any); len(env) > 0 {
		vars := map[string]string{}
		for _, e := range env {
			if m, ok := e.(map[string]any); ok && fnStr(m["name"]) != "" {
				vars[fnStr(m["name"])] = fnStr(m["value"])
			}
		}
		if len(vars) > 0 {
			c["Environment"] = map[string]any{"Variables": vars}
		}
	}
	if sha, _, _ := unstructured.NestedString(obj.Object, "spec", "code", "source", "package", "sha256"); len(sha) == 64 {
		if raw, err := hex.DecodeString(sha); err == nil {
			c["CodeSha256"] = base64.StdEncoding.EncodeToString(raw)
		}
		if n, found, _ := unstructured.NestedInt64(obj.Object, "spec", "code", "source", "package", "size"); found {
			c["CodeSize"] = n
		}
	}
	if d := obj.GetAnnotations()[fnDescriptionAnnotation]; d != "" {
		c["Description"] = d
	}
	if rv := obj.GetResourceVersion(); rv != "" {
		c["RevisionId"] = rv
	}
	state, update, reason := functionState(obj)
	c["State"], c["LastUpdateStatus"] = state, update
	if reason != "" {
		c["StateReason"] = reason
	}
	return c
}

// functionCode is GetFunction's Code: the image of an image function; a zip function's code is in a
// bucket this answer does not hand out a location for. nil when the function names neither.
func functionCode(obj *unstructured.Unstructured) map[string]any {
	spec, _ := obj.Object["spec"].(map[string]any)
	if img, _ := spec["image"].(string); img != "" {
		return map[string]any{"RepositoryType": "ECR", "ImageUri": img}
	}
	if b, _, _ := unstructured.NestedString(obj.Object, "spec", "code", "source", "bucket"); b != "" {
		return map[string]any{"RepositoryType": "S3"}
	}
	return nil
}

// lambdaRuntime maps a Function's spec.code.runtime onto the Lambda runtime identifier ("" when unset or
// a runtime image of the caller's own).
func lambdaRuntime(rt string) string {
	switch {
	case rt == "":
		return ""
	case strings.HasPrefix(rt, "nodejs"):
		return rt + ".x"
	}
	return rt
}

// xfunctionGVR is the Function claims' composite resource, cluster-scoped.
var xfunctionGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "xfunctions"}

// withUpdateStatus completes one function's State and LastUpdateStatus (GetFunction, GetFunctionConfiguration)
// from where an update fails beyond its claim: the composite not rendering (Synced=False), or the latest
// revision failing while the previous one serves. Lambda answers such an update LastUpdateStatus Failed, with
// its reason and reason code, and the function stays Active while its previous configuration serves (#418).
// A list (ListFunctions) keeps the claim's own conditions: these reads are per function.
func (h *lambdaHandler) withUpdateStatus(ctx context.Context, obj *unstructured.Unstructured, cfg map[string]any) {
	if h.fns == nil || h.fns.dyn == nil || cfg == nil || obj == nil {
		return
	}
	reason, code := "", ""
	if xr, _, _ := unstructured.NestedString(obj.Object, "spec", "resourceRef", "name"); xr != "" {
		if x, err := h.fns.dyn.Resource(xfunctionGVR).Get(ctx, xr, metav1.GetOptions{}); err == nil {
			if c := conditionOf(x, "Synced"); fnStr(c["status"]) == "False" {
				reason, code = renderFailure(fnStr(c["message"])), "InvalidConfiguration"
			}
		}
	}
	serving := false
	if ks, err := h.fns.dyn.Resource(knativeServiceGVR).Namespace(obj.GetNamespace()).Get(ctx, obj.GetName(), metav1.GetOptions{}); err == nil {
		latestReady, _, _ := unstructured.NestedString(ks.Object, "status", "latestReadyRevisionName")
		serving = latestReady != ""
		if c := conditionOf(ks, "ConfigurationsReady"); reason == "" && fnStr(c["status"]) == "False" {
			reason, code = fnStr(c["message"]), "FunctionError"
		}
	}
	if reason == "" {
		return
	}
	cfg["LastUpdateStatus"], cfg["LastUpdateStatusReason"], cfg["LastUpdateStatusReasonCode"] = "Failed", reason, code
	if serving {
		cfg["State"] = "Active"
		delete(cfg, "StateReason")
		return
	}
	cfg["State"], cfg["StateReason"], cfg["StateReasonCode"] = "Failed", reason, code
}

// conditionOf is obj's status condition of type t (nil when it has none).
func conditionOf(obj *unstructured.Unstructured, t string) map[string]any {
	conds, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, c := range conds {
		if m, _ := c.(map[string]any); fnStr(m["type"]) == t {
			return m
		}
	}
	return nil
}

// renderFailure is a composite's render error as the function's update failure: the composition's own
// message ("Lambda function: ...") when it gave one, else the error as it is.
func renderFailure(msg string) string {
	if i := strings.Index(msg, "Lambda function: "); i >= 0 {
		out := msg[i:]
		if j := strings.IndexAny(out, "\"\n"); j > 0 {
			out = out[:j]
		}
		return out
	}
	return msg
}

// functionState maps the claim's Synced/Ready conditions onto Lambda's State and LastUpdateStatus.
func functionState(obj *unstructured.Unstructured) (state, update, reason string) {
	conds, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	var ready, synced map[string]any
	for _, c := range conds {
		m, _ := c.(map[string]any)
		switch fnStr(m["type"]) {
		case "Ready":
			ready = m
		case "Synced":
			synced = m
		}
	}
	if synced != nil && fnStr(synced["status"]) == "False" {
		return "Failed", "Failed", fnStr(synced["message"])
	}
	if ready != nil && fnStr(ready["status"]) == "True" {
		return "Active", "Successful", ""
	}
	if ready != nil {
		return "Pending", "InProgress", fnStr(ready["message"])
	}
	return "Pending", "InProgress", ""
}

// fnLastModified is when the claim was last written (its newest managed-fields entry), else its creation.
func fnLastModified(obj *unstructured.Unstructured) time.Time {
	t := obj.GetCreationTimestamp().Time
	for _, mf := range obj.GetManagedFields() {
		if mf.Time != nil && mf.Time.After(t) {
			t = mf.Time.Time
		}
	}
	return t
}

// lambdaTime is Lambda's LastModified form: 2026-11-03T10:15:30.000+0000.
func lambdaTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000-0700")
}

func writeLambdaJSON(w http.ResponseWriter, requestID string, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func fnStr(v any) string { s, _ := v.(string); return s }
