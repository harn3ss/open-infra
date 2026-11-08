// Lambda's control plane over kind: Function: CreateFunction, UpdateFunctionCode, UpdateFunctionConfiguration
// and DeleteFunction, in the Lambda REST-JSON shapes the AWS CLI and SDKs send.
//
//	POST   /2015-03-31/functions                        CreateFunction
//	PUT    /2015-03-31/functions/{name}/code            UpdateFunctionCode
//	PUT    /2015-03-31/functions/{name}/configuration   UpdateFunctionConfiguration
//	DELETE /2015-03-31/functions/{name}                 DeleteFunction
//
// Each operation is decided by the one evaluator (decide) as AWS names it — lambda:<Operation> on the
// function's ARN — and then written with the shim's own identity, as the Step Functions front door writes a
// state machine. A function is the caller's account's: one the Lambda API creates is in the Lambda API's
// namespace (a member account's in its home), and one it changes is found where it lives (fn_locate.go), so a
// stack's function can be changed too, as on AWS.
//
// The execution role (Role) is required, as AWS requires it. It must be a role of the caller's account
// ("Cross-account pass role is not allowed."), the caller must be allowed iam:PassRole on it (decided as the
// caller: passrole.go), and its trust policy must name lambda.amazonaws.com with no conditions, or Lambda
// cannot assume it ("The role defined for the function cannot be assumed by Lambda.").
//
// A .zip deployment package (Code.ZipFile, or Code.S3Bucket/S3Key read as the caller may read it) is checked
// and stored as a stack's is (lambda_packages.go); an image function names its image (Code.ImageUri). What
// a Function cannot be refuses, naming the field, rather than being dropped: layers, VPC configuration,
// published versions, tags, an architecture other than x86_64, and the rest listed in lambdaUnsupported.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// maxLambdaWriteRequest is Lambda's request limit for CreateFunction and UpdateFunctionCode: a 50 MB
	// .zip, base64-encoded, in its JSON body.
	maxLambdaWriteRequest = 69905067
	// fnDescriptionAnnotation keeps a function's Description (a Function has no field for it).
	fnDescriptionAnnotation = "openinfra.dev/description"
	// zipUploadOrigin is a stored package's origin when it was uploaded as a .zip (Code.ZipFile).
	zipUploadOrigin = "zipfile"
)

var (
	// roleARNRe is a role ARN as Lambda's Role takes it, and as the Function's spec.role allows one.
	roleARNRe = regexp.MustCompile(`^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}$`)
	// lambdaEnvNameRe is Lambda's pattern for an environment variable's name.
	lambdaEnvNameRe = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9_])+$`)
	// lambdaHandlerRe is the handlers open-infra's runtimes take (index.handler, pkg/mod.fn,
	// Assembly::Namespace.Class::Method).
	lambdaHandlerRe = regexp.MustCompile(`^[A-Za-z0-9_.:/$-]{1,128}$`)
)

// lambdaReservedEnv are the environment variables a function's own configuration may not set: Lambda's
// reserved keys, and the ones the platform sets for the function's runtime, role and code (an endpoint or
// token file named by the caller would send the function's identity elsewhere).
var lambdaReservedEnv = map[string]bool{
	"_HANDLER": true, "_X_AMZN_TRACE_ID": true, "AWS_DEFAULT_REGION": true, "AWS_REGION": true,
	"AWS_EXECUTION_ENV": true, "AWS_LAMBDA_FUNCTION_NAME": true, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": true,
	"AWS_LAMBDA_FUNCTION_VERSION": true, "AWS_LAMBDA_INITIALIZATION_TYPE": true, "AWS_LAMBDA_LOG_GROUP_NAME": true,
	"AWS_LAMBDA_LOG_STREAM_NAME": true, "AWS_ACCESS_KEY": true, "AWS_ACCESS_KEY_ID": true,
	"AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_LAMBDA_RUNTIME_API": true,
	"LAMBDA_TASK_ROOT": true, "LAMBDA_RUNTIME_DIR": true,
	"AWS_ROLE_ARN": true, "AWS_ROLE_SESSION_NAME": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true, "NATS_URL": true,
}

func lambdaEnvReserved(name string) bool {
	return lambdaReservedEnv[name] || strings.HasPrefix(name, "OPENINFRA_") || name == "AWS_ENDPOINT_URL" ||
		strings.HasPrefix(name, "AWS_ENDPOINT_URL_")
}

// lambdaUnsupported are request members a Function cannot carry, with what is accepted when it is
// Lambda's default (nil: never accepted).
var lambdaUnsupported = map[string]func(v any) bool{
	"Layers": nil,
	"VpcConfig": func(v any) bool {
		m, _ := v.(map[string]any)
		return len(anySlice(m["SubnetIds"])) == 0 && len(anySlice(m["SecurityGroupIds"])) == 0
	},
	"DeadLetterConfig": func(v any) bool { m, _ := v.(map[string]any); return str(m["TargetArn"]) == "" },
	"KMSKeyArn":        func(v any) bool { return str(v) == "" },
	"TracingConfig": func(v any) bool {
		m, _ := v.(map[string]any)
		mode := str(m["Mode"])
		return mode == "" || mode == "PassThrough"
	},
	"FileSystemConfigs":    func(v any) bool { return len(anySlice(v)) == 0 },
	"ImageConfig":          nil,
	"CodeSigningConfigArn": func(v any) bool { return str(v) == "" },
	"EphemeralStorage":     func(v any) bool { m, _ := v.(map[string]any); n, ok := jsonInt(m["Size"]); return ok && n == 512 },
	"SnapStart":            func(v any) bool { m, _ := v.(map[string]any); a := str(m["ApplyOn"]); return a == "" || a == "None" },
	"LoggingConfig":        nil,
	"Tags":                 func(v any) bool { m, _ := v.(map[string]any); return len(m) == 0 },
	"Architectures": func(v any) bool {
		l := anySlice(v)
		return len(l) == 0 || len(l) == 1 && str(l[0]) == "x86_64"
	},
	"SourceKMSKeyArn": func(v any) bool { return str(v) == "" },
}

// lambdaWriteFields are the members each operation takes (the ones in lambdaUnsupported are checked there).
var lambdaWriteFields = map[string]map[string]bool{
	"CreateFunction": lambdaFieldSet("FunctionName", "Runtime", "Role", "Handler", "Code", "Description", "Timeout", "MemorySize",
		"Environment", "PackageType", "Publish", "Architectures", "Tags", "Layers", "VpcConfig", "DeadLetterConfig", "KMSKeyArn",
		"TracingConfig", "FileSystemConfigs", "ImageConfig", "CodeSigningConfigArn", "EphemeralStorage", "SnapStart", "LoggingConfig"),
	"UpdateFunctionCode": lambdaFieldSet("ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri", "Publish", "DryRun", "RevisionId",
		"Architectures", "SourceKMSKeyArn"),
	"UpdateFunctionConfiguration": lambdaFieldSet("Role", "Handler", "Description", "Timeout", "MemorySize", "Environment", "Runtime",
		"RevisionId", "Layers", "VpcConfig", "DeadLetterConfig", "KMSKeyArn", "TracingConfig", "FileSystemConfigs", "ImageConfig",
		"EphemeralStorage", "SnapStart", "LoggingConfig"),
}

func lambdaFieldSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// lambdaErr is an error answer of Lambda's.
type lambdaErr struct {
	status        int
	code, message string
}

func (e *lambdaErr) write(w http.ResponseWriter, requestID string) {
	writeLambdaError(w, e.status, e.code, requestID, e.message)
}

func invalidParam(format string, a ...any) *lambdaErr {
	return &lambdaErr{http.StatusBadRequest, "InvalidParameterValueException", fmt.Sprintf(format, a...)}
}

// validationErr is AWS's constraint-failure message.
func lambdaValidation(field string, value any, constraint string) *lambdaErr {
	return &lambdaErr{http.StatusBadRequest, "ValidationException",
		fmt.Sprintf("1 validation error detected: Value '%v' at '%s' failed to satisfy constraint: %s", value, field, constraint)}
}

// parseLambdaWritePath matches the control-plane operations' routes; ok is false for any other request, bad
// true when the route is one but its function name is not one a Function can have.
func parseLambdaWritePath(r *http.Request) (op, name, qualifier string, ok, bad bool) {
	p := strings.TrimPrefix(r.URL.Path, "/2015-03-31/functions")
	if p == r.URL.Path {
		return "", "", "", false, false
	}
	if p == "" || p == "/" {
		if r.Method == http.MethodPost {
			return "CreateFunction", "", "", true, false
		}
		return "", "", "", false, false
	}
	if !strings.HasPrefix(p, "/") {
		return "", "", "", false, false
	}
	fn, rest, _ := strings.Cut(p[1:], "/")
	switch {
	case r.Method == http.MethodPut && rest == "code":
		op = "UpdateFunctionCode"
	case r.Method == http.MethodPut && rest == "configuration":
		op = "UpdateFunctionConfiguration"
	case r.Method == http.MethodDelete && rest == "":
		op = "DeleteFunction"
	default:
		return "", "", "", false, false
	}
	name, qualifier, valid := parseFunctionRef(fn, r.URL.Query().Get("Qualifier"))
	if !valid {
		return op, "", "", true, true
	}
	return op, name, qualifier, true, false
}

// lambdaWriteAction is the IAM action AWS authorizes each operation with, and the coarse
// RBAC verb on functions it needed before IAM policy decided.
func lambdaWriteAction(op string) (action, verb string) {
	switch op {
	case "CreateFunction":
		return "lambda:CreateFunction", "create"
	case "UpdateFunctionCode":
		return "lambda:UpdateFunctionCode", "update"
	case "UpdateFunctionConfiguration":
		return "lambda:UpdateFunctionConfiguration", "update"
	case "DeleteFunction":
		return "lambda:DeleteFunction", "delete"
	}
	return "", ""
}

func (h *lambdaHandler) serveWrite(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, op, name, qualifier string) {
	if h.fns == nil || h.fns.dyn == nil || len(h.fns.namespaces) == 0 {
		writeLambdaError(w, http.StatusNotImplemented, "ServiceException", requestID,
			"changing functions needs the shim's cluster access, which this shim does not have")
		return
	}
	ctx := r.Context()
	body := map[string]any{}
	if op != "DeleteFunction" {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLambdaWriteRequest))
		if err != nil {
			writeLambdaError(w, http.StatusRequestEntityTooLarge, "RequestEntityTooLargeException", requestID,
				fmt.Sprintf("Request must be smaller than %d bytes for the %s operation", maxLambdaWriteRequest, op))
			return
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if len(bytes.TrimSpace(raw)) > 0 && dec.Decode(&body) != nil {
			writeLambdaError(w, http.StatusBadRequest, "InvalidRequestContentException", requestID, "Could not parse request body into json")
			return
		}
	}
	if op == "CreateFunction" {
		ref := str(body["FunctionName"])
		if ref == "" {
			lambdaValidation("functionName", nil, "Member must not be null").write(w, requestID)
			return
		}
		if acct := functionRefAccount(ref); acct != "" && acct != h.accountOf(ctx) {
			writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID,
				notAuthorized(principalOf(ctx, claims), "lambda:CreateFunction", ref, "")+" because no resource-based policy allows the lambda:CreateFunction action")
			return
		}
		n, q, valid := parseFunctionRef(ref, "")
		if !valid || q != "" {
			invalidParam("FunctionName %q is not a name open-infra can give a function: lowercase letters, digits and hyphens, at most 63 characters, starting and ending with a letter or digit", ref).write(w, requestID)
			return
		}
		name = n
	}
	if qualifier != "" && op != "DeleteFunction" {
		invalidParam("%s takes no Qualifier: it changes the function's unpublished version, $LATEST", op).write(w, requestID)
		return
	}

	// Where the function is: a new one in the account's Lambda namespace, an existing one where it lives.
	var ns string
	if op == "CreateFunction" {
		ns = h.fnNS
		if isMemberRequest(ctx) {
			ns = noFnNamespace
			if own := h.fns.namespacesFor(ctx); len(own) > 0 {
				ns = own[0]
			}
		}
	} else {
		ns = h.fns.namespaceFor(ctx, name, h.fnNS)
	}
	action, verb := lambdaWriteAction(op)
	if ok, reason := decide(ctx, r, h.authz, claims, action, "Function", name, func() (bool, string) {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, action, "Function", name, r); denied {
			return false, reason
		}
		if allowed, _ := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "functions", ns, name); !allowed {
			return false, notAuthorized(principalOf(ctx, claims), action, h.functionARNIn(ctx, name), "")
		}
		return true, ""
	}); !ok {
		h.logger.Warn("lambda write denied", "user", claims.Sub, "function", name, "op", op, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if ns == noFnNamespace {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"Function not found: "+h.functionARNIn(ctx, name))
		return
	}
	if e := checkLambdaFields(op, body); e != nil {
		e.write(w, requestID)
		return
	}
	switch op {
	case "CreateFunction":
		h.createFunction(w, r, claims, requestID, ns, name, body)
	case "DeleteFunction":
		// A Qualifier deletes one published version (lambda_versions.go); $LATEST and an alias are not
		// deleted that way, as on Lambda.
		switch {
		case qualifier == "":
			h.deleteFunction(w, r, requestID, ns, name)
		case versionNumberRe.MatchString(qualifier):
			h.deleteVersion(w, r, requestID, ns, name, qualifier)
		case qualifier == "$LATEST":
			invalidParam("$LATEST version cannot be deleted without deleting the function.").write(w, requestID)
		default:
			invalidParam("Deletion of aliases is not supported by DeleteFunction: use DeleteAlias").write(w, requestID)
		}
	case "UpdateFunctionCode", "UpdateFunctionConfiguration":
		h.updateFunction(w, r, claims, requestID, op, ns, name, body)
	}
}

// checkLambdaFields refuses a member the operation does not take, and one a Function cannot carry.
func checkLambdaFields(op string, body map[string]any) *lambdaErr {
	known := lambdaWriteFields[op]
	if known == nil {
		return nil
	}
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			return invalidParam("%s is not a parameter of %s", k, op)
		}
		if def, unsupported := lambdaUnsupported[k]; unsupported && (def == nil || !def(body[k])) {
			return invalidParam("%s", unsupportedReason(k))
		}
	}
	if code, ok := body["Code"].(map[string]any); ok {
		for _, k := range sortedMapKeys(code) {
			switch k {
			case "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri":
			case "SourceKMSKeyArn":
				if str(code[k]) != "" {
					return invalidParam("%s", unsupportedReason(k))
				}
			default:
				return invalidParam("Code.%s is not a property of a function's code", k)
			}
		}
	}
	return nil
}

func unsupportedReason(field string) string {
	switch field {
	case "Layers":
		return "Layers are not supported by open-infra's Lambda yet: bundle what a layer provides into the deployment package"
	case "Architectures":
		return "Architectures other than x86_64 are not supported"
	case "Tags":
		return "Tags on a function are not supported by open-infra's Lambda yet"
	case "SourceKMSKeyArn":
		return "SourceKMSKeyArn is not supported: a stored deployment package is encrypted at rest with the platform's key"
	}
	return field + " is not supported by open-infra's Lambda"
}

func (h *lambdaHandler) createFunction(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, ns, name string, body map[string]any) {
	ctx := r.Context()
	if other, err := h.fns.elsewhereFor(ctx, name, ns); err != nil {
		h.logger.Warn("lambda CreateFunction: looking for the name failed", "function", name, "error", err.Error())
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not check the function name")
		return
	} else if other != "" {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID, "Function already exist: "+name)
		return
	}
	role := str(body["Role"])
	if role == "" {
		lambdaValidation("role", nil, "Member must not be null").write(w, requestID)
		return
	}
	spec := map[string]any{}
	if e := h.passExecutionRole(r, claims, ns, role); e != nil {
		e.write(w, requestID)
		return
	}
	spec["role"] = role
	if e := applyLambdaSettings(spec, body); e != nil {
		e.write(w, requestID)
		return
	}
	code, _ := body["Code"].(map[string]any)
	switch pt := str(body["PackageType"]); pt {
	case "Image":
		if _, ok := body["Runtime"]; ok {
			invalidParam("Runtime and Handler are not supported for a function with PackageType Image: its image sets them").write(w, requestID)
			return
		}
		if _, ok := body["Handler"]; ok {
			invalidParam("Runtime and Handler are not supported for a function with PackageType Image: its image sets them").write(w, requestID)
			return
		}
		img := str(code["ImageUri"])
		if img == "" || hasAny(code, "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion") {
			invalidParam("A function with PackageType Image needs Code.ImageUri, and only that").write(w, requestID)
			return
		}
		spec["image"] = img
	case "", "Zip":
		if hasAny(code, "ImageUri") {
			invalidParam("Please don't provide ImageUri when creating a function with packageType Zip.").write(w, requestID)
			return
		}
		rt, handler := str(body["Runtime"]), str(body["Handler"])
		if rt == "" || handler == "" {
			invalidParam("Runtime and Handler are mandatory parameters for functions created with deployment packages.").write(w, requestID)
			return
		}
		fc := map[string]any{}
		if e := setRuntimeAndHandler(fc, rt, handler); e != nil {
			e.write(w, requestID)
			return
		}
		if region := h.regionIn(ctx); region != "" {
			fc["region"] = region // AWS_REGION, as Lambda sets it for the function's own region
		}
		pkg, e := h.storePackage(r, claims, ns, code)
		if e != nil {
			e.write(w, requestID)
			return
		}
		fc["source"] = map[string]any{"package": pkg}
		spec["code"] = fc
	default:
		lambdaValidation("packageType", pt, "Member must satisfy enum value set: [Image, Zip]").write(w, requestID)
		return
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     spec,
	}}
	ann := map[string]string{fnUpdatedAtAnnotation: time.Now().UTC().Format(time.RFC3339Nano)}
	if d := str(body["Description"]); d != "" {
		ann[fnDescriptionAnnotation] = d
	}
	obj.SetAnnotations(ann)
	// Publish: the function's first version, recorded now (its revision once the function has rolled out),
	// and the answer is that version's, as Lambda gives it.
	var published *fnVersion
	if pub, _ := body["Publish"].(bool); pub {
		v, e := h.appendVersion(ctx, obj, "", "")
		if e != nil {
			e.write(w, requestID)
			return
		}
		published = &v
	}
	created, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID, "Function already exist: "+name)
		return
	} else if err != nil {
		h.writeApplyError(w, requestID, "CreateFunction", name, err)
		return
	}
	h.fns.forgetFor(ctx, name)
	h.logger.Info("lambda function created", "user", claims.Sub, "function", name)
	cfg := h.functionConfiguration(ctx, created, "")
	if published != nil {
		go h.followPendingVersions(ns, name)
		cfg = h.versionConfiguration(ctx, created, *published, "")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cfg)
}

func (h *lambdaHandler) updateFunction(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, op, ns, name string, body map[string]any) {
	ctx := r.Context()
	obj, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Function not found: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		h.logger.Warn("lambda update: reading the function failed", "function", name, "error", err.Error())
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not read the function")
		return
	}
	if rev := str(body["RevisionId"]); rev != "" && rev != obj.GetResourceVersion() {
		writeLambdaError(w, http.StatusPreconditionFailed, "PreconditionFailedException", requestID,
			"The RevisionId provided does not match the latest RevisionId for the Lambda function or alias. Call the GetFunction or the GetAlias API to retrieve the latest RevisionId for your resource.")
		return
	}
	spec, _ := obj.Object["spec"].(map[string]any)
	if spec == nil {
		spec = map[string]any{}
		obj.Object["spec"] = spec
	}
	before, _ := json.Marshal(spec)
	image := str(spec["image"]) != ""
	if op == "UpdateFunctionCode" {
		if image {
			if hasAny(body, "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion") || str(body["ImageUri"]) == "" {
				invalidParam("Please provide ImageUri when updating a function with packageType Image.").write(w, requestID)
				return
			}
			spec["image"] = str(body["ImageUri"])
		} else {
			if hasAny(body, "ImageUri") {
				invalidParam("Please don't provide ImageUri when updating a function with packageType Zip.").write(w, requestID)
				return
			}
			fc, _ := spec["code"].(map[string]any)
			if fc == nil {
				invalidParam("The function has no deployment package to update: it names neither an image nor code").write(w, requestID)
				return
			}
			pkg, e := h.storePackage(r, claims, ns, body)
			if e != nil {
				e.write(w, requestID)
				return
			}
			fc["source"] = map[string]any{"package": pkg}
		}
		if dry, _ := body["DryRun"].(bool); dry {
			writeLambdaJSON(w, requestID, h.functionConfiguration(ctx, obj, ""))
			return
		}
	} else {
		if role, ok := body["Role"]; ok {
			if e := h.passExecutionRole(r, claims, ns, str(role)); e != nil {
				e.write(w, requestID)
				return
			}
			spec["role"] = str(role)
		}
		if e := applyLambdaSettings(spec, body); e != nil {
			e.write(w, requestID)
			return
		}
		_, hasRT := body["Runtime"]
		_, hasHandler := body["Handler"]
		if hasRT || hasHandler {
			fc, _ := spec["code"].(map[string]any)
			if image || fc == nil {
				invalidParam("Runtime and Handler are not supported for a function with PackageType Image: its image sets them").write(w, requestID)
				return
			}
			rt, handler := str(body["Runtime"]), str(body["Handler"])
			if !hasRT {
				rt = lambdaRuntime(fnStr(fc["runtime"]))
			}
			if !hasHandler {
				handler = fnStr(fc["handler"])
			}
			if e := setRuntimeAndHandler(fc, rt, handler); e != nil {
				e.write(w, requestID)
				return
			}
		}
		if d, ok := body["Description"]; ok {
			ann := obj.GetAnnotations()
			if ann == nil {
				ann = map[string]string{}
			}
			if str(d) == "" {
				delete(ann, fnDescriptionAnnotation)
			} else {
				ann[fnDescriptionAnnotation] = str(d)
			}
			obj.SetAnnotations(ann)
		}
	}
	// A change to what the function runs is stamped, so a version is published only from the revision that
	// runs it (lambda_versions.go).
	if after, _ := json.Marshal(spec); !bytes.Equal(before, after) {
		ann := obj.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann[fnUpdatedAtAnnotation] = time.Now().UTC().Format(time.RFC3339Nano)
		obj.SetAnnotations(ann)
	}
	// Publish (UpdateFunctionCode): a version of the new code, recorded now and given its revision once the
	// change has rolled out; the answer is that version's, as Lambda gives it.
	var published *fnVersion
	if pub, _ := body["Publish"].(bool); pub && op == "UpdateFunctionCode" {
		v, e := h.appendVersion(ctx, obj, "", "")
		if e != nil {
			e.write(w, requestID)
			return
		}
		published = &v
	}
	updated, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID,
			"The operation cannot be performed at this time. An update is in progress for resource: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		h.writeApplyError(w, requestID, op, name, err)
		return
	}
	h.timeouts.forget(ns, name)
	h.logger.Info("lambda function updated", "user", claims.Sub, "function", name, "op", op)
	// The update has been accepted, not yet rolled out: AWS's answer says so (LastUpdateStatus InProgress).
	cfg := h.functionConfiguration(ctx, updated, "")
	if published != nil {
		go h.followPendingVersions(ns, name)
		cfg = h.versionConfiguration(ctx, updated, *published, "")
	}
	cfg["LastUpdateStatus"] = "InProgress"
	delete(cfg, "StateReason")
	writeLambdaJSON(w, requestID, cfg)
}

func (h *lambdaHandler) deleteFunction(w http.ResponseWriter, r *http.Request, requestID, ns, name string) {
	ctx := r.Context()
	err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Function not found: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		h.writeApplyError(w, requestID, "DeleteFunction", name, err)
		return
	}
	h.fns.forgetFor(ctx, name)
	h.timeouts.forget(ns, name)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusNoContent)
}

// writeApplyError answers a write the API server refused: the Function's own validation as Lambda's
// invalid-parameter error, anything else as a service error (the cause is logged, not handed out).
func (h *lambdaHandler) writeApplyError(w http.ResponseWriter, requestID, op, name string, err error) {
	h.logger.Warn("lambda write failed", "op", op, "function", name, "error", err.Error())
	if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
		var st apierrors.APIStatus
		msg := "the function's configuration is not valid"
		if errors.As(err, &st) {
			msg = st.Status().Message
		}
		writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID, msg)
		return
	}
	writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not "+op+" "+name)
}

// accountOf is the request's account: a member account's, or the management account's.
func (h *lambdaHandler) accountOf(ctx context.Context) string {
	if isMemberRequest(ctx) || h.account == "" {
		return callerAccount(ctx)
	}
	return h.account
}

// passExecutionRole checks the function's execution role as Lambda does when it is set: a role ARN of the
// caller's account, which the caller may pass, and which Lambda can assume.
func (h *lambdaHandler) passExecutionRole(r *http.Request, claims iam.Claims, ns, role string) *lambdaErr {
	ctx := r.Context()
	if !roleARNRe.MatchString(role) {
		return lambdaValidation("role", role, `Member must satisfy regular expression pattern: arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+`)
	}
	if acct := strings.Split(role, ":")[4]; acct != h.accountOf(ctx) {
		return &lambdaErr{http.StatusForbidden, "AccessDeniedException", "Cross-account pass role is not allowed."}
	}
	name := roleNameOf(role)
	if ok, _ := callerMayPassRole(ctx, h.cs, h.authz, claims, ns, name, lambdaService, r); !ok {
		return &lambdaErr{http.StatusForbidden, "AccessDeniedException",
			notAuthorized(principalOf(ctx, claims), "iam:PassRole", role, "")}
	}
	rr, found := h.executionRole(ctx, ns, name)
	if !found || !trustsService(rr.trust, lambdaService) {
		return invalidParam("The role defined for the function cannot be assumed by Lambda.")
	}
	if trustConditioned(rr.trustDoc) {
		return invalidParam("The role defined for the function cannot be assumed by Lambda: its trust policy has conditions, which open-infra does not evaluate for the Lambda service")
	}
	return nil
}

// executionRole finds a function's execution role as the function's credentials will (service_role.go): in
// the function's namespace, else its account's IAM home.
func (h *lambdaHandler) executionRole(ctx context.Context, ns, name string) (resolvedRole, bool) {
	if h.roles == nil {
		return resolvedRole{}, false
	}
	in, canIn := h.roles.(roleResolverIn)
	if canIn {
		if rr, ok := in.ResolveIn(ctx, ns, name); ok {
			return rr, true
		}
	}
	if !isMemberRequest(ctx) {
		return h.roles.Resolve(ctx, name)
	}
	if home := accountHomeOf(ctx); canIn && home != "" && home != ns {
		return in.ResolveIn(ctx, home, name)
	}
	return resolvedRole{}, false
}

// applyLambdaSettings sets what CreateFunction and UpdateFunctionConfiguration share: Timeout, MemorySize and
// Environment (which replaces the function's variables, as on AWS).
func applyLambdaSettings(spec, body map[string]any) *lambdaErr {
	if v, ok := body["Timeout"]; ok {
		n, isInt := jsonInt(v)
		switch {
		case !isInt:
			return lambdaValidation("timeout", v, "Member must be an integer")
		case n < 1:
			return lambdaValidation("timeout", v, "Member must have value greater than or equal to 1")
		case n > 900:
			return lambdaValidation("timeout", v, "Member must have value less than or equal to 900")
		}
		spec["timeout"] = n
	}
	if v, ok := body["MemorySize"]; ok {
		n, isInt := jsonInt(v)
		switch {
		case !isInt:
			return lambdaValidation("memorySize", v, "Member must be an integer")
		case n < 128:
			return lambdaValidation("memorySize", v, "Member must have value greater than or equal to 128")
		case n > 10240:
			return lambdaValidation("memorySize", v, "Member must have value less than or equal to 10240")
		}
		spec["memory"] = fmt.Sprintf("%dMi", n)
	}
	if d, ok := body["Description"]; ok && len(str(d)) > 256 {
		return lambdaValidation("description", "…", "Member must have length less than or equal to 256")
	}
	if v, ok := body["Environment"]; ok {
		envBlock, _ := v.(map[string]any)
		vars, _ := envBlock["Variables"].(map[string]any)
		env := []any{}
		var reserved []string
		for _, k := range sortedMapKeys(vars) {
			if !lambdaEnvNameRe.MatchString(k) {
				return lambdaValidation("environment.variables", k, "Member must satisfy regular expression pattern: [a-zA-Z]([a-zA-Z0-9_])+")
			}
			if lambdaEnvReserved(k) {
				reserved = append(reserved, k)
				continue
			}
			val, isStr := vars[k].(string)
			if !isStr {
				return lambdaValidation("environment.variables", k, "Member must be a string")
			}
			// The function's template carries a value in double quotes: a quote, a backslash or a line break
			// would not survive it.
			if strings.ContainsAny(val, "\"\\\n\r") {
				return invalidParam("The value of environment variable %s has a double quote, a backslash or a line break, which open-infra's functions do not carry yet", k)
			}
			env = append(env, map[string]any{"name": k, "value": val})
		}
		if len(reserved) > 0 {
			return invalidParam("Lambda was unable to configure your environment variables because the environment variables you have provided contains reserved keys that are currently not supported for modification. Reserved keys used in this request: %s", strings.Join(reserved, ", "))
		}
		if len(env) > 0 {
			spec["env"] = env
		} else {
			delete(spec, "env")
		}
	}
	return nil
}

// setRuntimeAndHandler sets a .zip function's runtime and handler.
func setRuntimeAndHandler(fc map[string]any, rt, handler string) *lambdaErr {
	runtime, ok := cfn.LambdaRuntime(rt)
	if !ok {
		return invalidParam("The runtime parameter of %s is not a runtime open-infra runs; the supported runtimes are %s", rt, cfn.LambdaRuntimeList)
	}
	if !lambdaHandlerRe.MatchString(handler) {
		return lambdaValidation("handler", handler, `Member must satisfy regular expression pattern: [A-Za-z0-9_.:/$-]{1,128}`)
	}
	fc["runtime"], fc["handler"] = runtime, handler
	return nil
}

// storePackage checks and stores a .zip deployment package — code's ZipFile, or the S3 object its S3Bucket
// and S3Key name, read as the caller may read it — and returns the Function's spec.code.source.package.
func (h *lambdaHandler) storePackage(r *http.Request, claims iam.Claims, ns string, code map[string]any) (map[string]any, *lambdaErr) {
	if h.pkgDoor == nil || h.pkgDoor.packages == nil {
		return nil, &lambdaErr{http.StatusNotImplemented, "ServiceException",
			"this shim has no deployment package store: a .zip function needs one (an image function does not)"}
	}
	store := h.pkgDoor.packages
	zipB64, hasZip := code["ZipFile"].(string)
	bucket, key := str(code["S3Bucket"]), str(code["S3Key"])
	var body []byte
	var origin string
	switch {
	case hasZip && (bucket != "" || key != ""):
		return nil, invalidParam("Code has both ZipFile and S3Bucket; a deployment package is one or the other")
	case hasZip:
		b, err := base64.StdEncoding.DecodeString(zipB64)
		if err != nil {
			return nil, invalidParam("Could not unzip uploaded file. Please check your file, then try to upload again.")
		}
		body, origin = b, zipUploadOrigin
	case bucket != "" && key != "":
		pkg := &cfn.CodePackage{S3Bucket: bucket, S3Key: key, S3Version: str(code["S3ObjectVersion"])}
		src := &lambdaPackages{h: h.pkgDoor, req: withCallerClaims(r, claims), store: store}
		b, err := src.readS3(r.Context(), pkg)
		if cfn.IsUnauthorized(err) {
			return nil, &lambdaErr{http.StatusForbidden, "AccessDeniedException", err.Error()}
		} else if err != nil {
			return nil, invalidParam("%s", err.Error())
		}
		body, origin = b, pkg.Origin()
	default:
		return nil, invalidParam("Please provide a source for function code: a .zip file (ZipFile), or its S3Bucket and S3Key")
	}
	if err := checkPackage(body); err != nil {
		return nil, invalidParam("%s", err.Error())
	}
	sp, err := store.put(r.Context(), ns, body)
	if err != nil {
		h.logger.Warn("lambda: storing the deployment package failed", "error", err.Error())
		return nil, &lambdaErr{http.StatusInternalServerError, "ServiceException", "could not store the deployment package"}
	}
	return map[string]any{"sha256": sp.SHA256, "size": sp.Size, "origin": origin}, nil
}

func hasAny(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func anySlice(v any) []any { l, _ := v.([]any); return l }

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jsonInt reads a JSON number decoded with UseNumber (or a float64) as an integer.
func jsonInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), n == float64(int64(n))
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}
