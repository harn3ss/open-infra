// Lambda versions and aliases: PublishVersion, ListVersionsByFunction, CreateAlias, GetAlias, UpdateAlias,
// DeleteAlias, ListAliases; a version's own configuration on a qualified read; deleting a version; and
// invoking a version or an alias.
//
// A version is an immutable snapshot of the function's code and configuration, as on AWS: the Knative
// revision that runs that code (spec.versions[].revision, pinned by the composition at a 0% traffic tag
// v<version>, so Knative keeps it) and the configuration it was published with (spec.versions[].configuration,
// Lambda's FunctionConfiguration). The function's own traffic stays on its latest revision, $LATEST.
//
// A version is published from the revision the function's latest change runs: the Knative Service's
// latest ready revision, once it is also its latest created one and was created after the function's last
// change through this API (lambda.openinfra.dev/updated-at). Until then PublishVersion answers Lambda's
// ResourceConflictException for an update in progress. Publish: true on CreateFunction / UpdateFunctionCode
// records the version at once, as Lambda answers with it, and fills its revision when the change has rolled
// out; until then it is invoked as a function still being created (ResourceConflictException).
//
// An alias names a version ($LATEST or a number) and may send a share of its invocations to one other
// version (RoutingConfig.AdditionalVersionWeights). The shim resolves it for each invocation and reports the
// version that ran (X-Amz-Executed-Version), as Lambda does.
//
// The Knative Service is read for its status and a revision for its metadata (creationTimestamp) only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	knativeServiceGVR  = schema.GroupVersionResource{Group: "serving.knative.dev", Version: "v1", Resource: "services"}
	knativeRevisionGVR = schema.GroupVersionResource{Group: "serving.knative.dev", Version: "v1", Resource: "revisions"}

	versionNumberRe = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)
	aliasNameRe     = regexp.MustCompile(`^[a-zA-Z0-9_-]*[a-zA-Z_-][a-zA-Z0-9_-]*$`)
)

const (
	// fnUpdatedAtAnnotation is when the Lambda API last changed what a function runs: a version is published
	// only from a revision created after it.
	fnUpdatedAtAnnotation = "lambda.openinfra.dev/updated-at"
	maxVersions           = 100
	maxAliases            = 50
)

// fnVersion is one of a function's published versions (spec.versions).
type fnVersion struct {
	Version       string `json:"version"`
	Revision      string `json:"revision,omitempty"`
	Description   string `json:"description,omitempty"`
	Published     string `json:"published,omitempty"`
	Configuration string `json:"configuration,omitempty"`
	Code          string `json:"code,omitempty"`
}

// fnAlias is one of a function's aliases (spec.aliases).
type fnAlias struct {
	Name            string             `json:"name"`
	FunctionVersion string             `json:"functionVersion"`
	Description     string             `json:"description,omitempty"`
	Weights         map[string]float64 `json:"additionalVersionWeights,omitempty"`
}

func versionsOf(obj *unstructured.Unstructured) []fnVersion {
	var out []fnVersion
	l, _, _ := unstructured.NestedSlice(obj.Object, "spec", "versions")
	b, _ := json.Marshal(l)
	_ = json.Unmarshal(b, &out)
	return out
}

func aliasesOf(obj *unstructured.Unstructured) []fnAlias {
	var out []fnAlias
	l, _, _ := unstructured.NestedSlice(obj.Object, "spec", "aliases")
	b, _ := json.Marshal(l)
	_ = json.Unmarshal(b, &out)
	return out
}

// setSpecList writes v (a list of fnVersion or fnAlias) to spec.<field>, removing the field when empty.
func setSpecList(obj *unstructured.Unstructured, field string, v any) {
	var l []any
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, &l)
	if len(l) == 0 {
		unstructured.RemoveNestedField(obj.Object, "spec", field)
		return
	}
	_ = unstructured.SetNestedSlice(obj.Object, l, "spec", field)
}

func findVersion(vs []fnVersion, v string) (fnVersion, bool) {
	for _, x := range vs {
		if x.Version == v {
			return x, true
		}
	}
	return fnVersion{}, false
}

func findAlias(as []fnAlias, name string) (fnAlias, int) {
	for i, a := range as {
		if a.Name == name {
			return a, i
		}
	}
	return fnAlias{}, -1
}

// nextVersion is the number the next published version takes.
func nextVersion(vs []fnVersion) string {
	n := 0
	for _, v := range vs {
		if i, err := strconv.Atoi(v.Version); err == nil && i > n {
			n = i
		}
	}
	return strconv.Itoa(n + 1)
}

// versionTagHost is the host a version is invoked at: its Knative traffic tag.
func versionTagHost(version, name string) string { return "v" + version + "-" + name }

// parseLambdaVersionPath matches the version and alias operations' routes.
func parseLambdaVersionPath(r *http.Request) (op, name, alias string, ok, bad bool) {
	p := strings.TrimPrefix(r.URL.Path, "/2015-03-31/functions/")
	if p == r.URL.Path {
		return "", "", "", false, false
	}
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return "", "", "", false, false
	}
	switch {
	case len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodPost:
		op = "PublishVersion"
	case len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodGet:
		op = "ListVersionsByFunction"
	case len(parts) == 2 && parts[1] == "aliases" && r.Method == http.MethodPost:
		op = "CreateAlias"
	case len(parts) == 2 && parts[1] == "aliases" && r.Method == http.MethodGet:
		op = "ListAliases"
	case len(parts) == 3 && parts[1] == "aliases" && r.Method == http.MethodGet:
		op, alias = "GetAlias", parts[2]
	case len(parts) == 3 && parts[1] == "aliases" && r.Method == http.MethodPut:
		op, alias = "UpdateAlias", parts[2]
	case len(parts) == 3 && parts[1] == "aliases" && r.Method == http.MethodDelete:
		op, alias = "DeleteAlias", parts[2]
	default:
		return "", "", "", false, false
	}
	n, q, valid := parseFunctionRef(parts[0], "")
	if !valid || q != "" || (alias != "" && !aliasNameRe.MatchString(alias)) {
		return op, "", "", true, true
	}
	return op, n, alias, true, false
}

// lambdaVersionAction is the IAM action of each version and alias operation, and the coarse verb on
// functions it needed before IAM policy decided.
func lambdaVersionAction(op string) (action, verb string) {
	switch op {
	case "PublishVersion":
		return "lambda:PublishVersion", "update"
	case "ListVersionsByFunction":
		return "lambda:ListVersionsByFunction", "get"
	case "CreateAlias":
		return "lambda:CreateAlias", "update"
	case "GetAlias":
		return "lambda:GetAlias", "get"
	case "UpdateAlias":
		return "lambda:UpdateAlias", "update"
	case "DeleteAlias":
		return "lambda:DeleteAlias", "update"
	case "ListAliases":
		return "lambda:ListAliases", "get"
	}
	return "", ""
}

func (h *lambdaHandler) serveVersions(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, op, name, alias string) {
	if h.fns == nil || h.fns.dyn == nil || len(h.fns.namespaces) == 0 {
		writeLambdaError(w, http.StatusNotImplemented, "ServiceException", requestID,
			"versions and aliases need the shim's cluster access, which this shim does not have")
		return
	}
	ctx := r.Context()
	ns := h.fns.namespaceFor(ctx, name, h.fnNS)
	action, verb := lambdaVersionAction(op)
	if ok, reason := decide(ctx, r, h.authz, claims, action, "Function", name, func() (bool, string) {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, action, "Function", name, r); denied {
			return false, reason
		}
		if allowed, _ := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "functions", ns, name); !allowed {
			return false, notAuthorized(principalOf(ctx, claims), action, h.functionARNIn(ctx, name), "")
		}
		return true, ""
	}); !ok {
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if ns == noFnNamespace {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Function not found: "+h.functionARNIn(ctx, name))
		return
	}
	obj, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Function not found: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not read the function")
		return
	}
	body := map[string]any{}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil && err.Error() != "EOF" {
			writeLambdaError(w, http.StatusBadRequest, "InvalidRequestContentException", requestID, "Could not parse request body into json")
			return
		}
	}
	h.fillPendingVersions(ctx, ns, obj)
	switch op {
	case "PublishVersion":
		h.publishVersion(w, r, requestID, ns, obj, body)
	case "ListVersionsByFunction":
		h.listVersions(w, r, requestID, obj)
	case "CreateAlias", "UpdateAlias":
		h.putAlias(w, r, requestID, op, ns, obj, alias, body)
	case "GetAlias":
		a, i := findAlias(aliasesOf(obj), alias)
		if i < 0 {
			writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Alias not found: "+h.functionARNIn(ctx, name)+":"+alias)
			return
		}
		writeLambdaJSON(w, requestID, h.aliasConfiguration(ctx, obj, a))
	case "DeleteAlias":
		as := aliasesOf(obj)
		if _, i := findAlias(as, alias); i >= 0 {
			setSpecList(obj, "aliases", append(as[:i], as[i+1:]...))
			if _, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				h.writeApplyError(w, requestID, op, name, err)
				return
			}
		}
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(http.StatusNoContent) // AWS answers 204 whether or not the alias existed
	case "ListAliases":
		filter := r.URL.Query().Get("FunctionVersion")
		out := []any{}
		for _, a := range aliasesOf(obj) {
			if filter == "" || a.FunctionVersion == filter {
				out = append(out, h.aliasConfiguration(ctx, obj, a))
			}
		}
		writeLambdaJSON(w, requestID, map[string]any{"Aliases": out})
	}
}

// publishVersion publishes the function's current code and configuration as a new version, or answers with
// the latest version when nothing has changed since it was published, as Lambda does.
func (h *lambdaHandler) publishVersion(w http.ResponseWriter, r *http.Request, requestID, ns string, obj *unstructured.Unstructured, body map[string]any) {
	ctx := r.Context()
	name := obj.GetName()
	if rev := str(body["RevisionId"]); rev != "" && rev != obj.GetResourceVersion() {
		writeLambdaError(w, http.StatusPreconditionFailed, "PreconditionFailedException", requestID,
			"The RevisionId provided does not match the latest RevisionId for the Lambda function or alias. Call the GetFunction or the GetAlias API to retrieve the latest RevisionId for your resource.")
		return
	}
	cfg := h.functionConfiguration(ctx, obj, "")
	if want := str(body["CodeSha256"]); want != "" && want != str(cfg["CodeSha256"]) {
		writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID,
			fmt.Sprintf("CodeSHA256 (%s) is different from current CodeSHA256 in $LATEST (%s). Please try again with the CodeSHA256 in $LATEST.", want, str(cfg["CodeSha256"])))
		return
	}
	rev, inProgress, err := h.settledRevision(ctx, ns, obj)
	if err != nil {
		h.logger.Warn("lambda PublishVersion: reading the function's revision failed", "function", name, "error", err.Error())
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not read the function's current revision")
		return
	}
	if inProgress {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID,
			"The operation cannot be performed at this time. An update is in progress for resource: "+h.functionARNIn(ctx, name))
		return
	}
	vs := versionsOf(obj)
	if n := len(vs); n > 0 && vs[n-1].Revision == rev {
		writeVersionJSON(w, requestID, h.versionConfiguration(ctx, obj, vs[n-1], ""))
		return
	}
	v, e := h.appendVersion(ctx, obj, str(body["Description"]), rev)
	if e != nil {
		e.write(w, requestID)
		return
	}
	updated, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID,
			"The operation cannot be performed at this time. An update is in progress for resource: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		h.writeApplyError(w, requestID, "PublishVersion", name, err)
		return
	}
	writeVersionJSON(w, requestID, h.versionConfiguration(ctx, updated, v, ""))
}

// writeVersionJSON is PublishVersion's answer: 201 with the version's configuration, whether the version is
// new or the latest one, unchanged since, as Lambda answers.
func writeVersionJSON(w http.ResponseWriter, requestID string, cfg map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cfg)
}

// appendVersion adds the next version to obj — its configuration now, and rev ("" while it waits for the
// change to roll out) — and returns it.
func (h *lambdaHandler) appendVersion(ctx context.Context, obj *unstructured.Unstructured, description, rev string) (fnVersion, *lambdaErr) {
	vs := versionsOf(obj)
	if len(vs) >= maxVersions {
		return fnVersion{}, &lambdaErr{http.StatusBadRequest, "CodeStorageExceededException",
			fmt.Sprintf("The function has %d published versions, the most open-infra keeps: delete one first", maxVersions)}
	}
	v := fnVersion{Version: nextVersion(vs), Revision: rev, Description: description, Published: lambdaTime(time.Now())}
	if len(versionTagHost(v.Version, obj.GetName())) > 63 {
		return fnVersion{}, invalidParam("The function name %q is too long for a published version: a version is addressed as v<version>-<name>, at most 63 characters", obj.GetName())
	}
	cfg := h.functionConfiguration(ctx, obj, "")
	cfg["Version"] = v.Version
	if description != "" {
		cfg["Description"] = description
	} else {
		delete(cfg, "Description")
	}
	delete(cfg, "State")
	delete(cfg, "LastUpdateStatus")
	delete(cfg, "StateReason")
	delete(cfg, "RevisionId")
	b, _ := json.Marshal(cfg)
	v.Configuration = string(b)
	if code := functionCode(obj); code != nil {
		b, _ = json.Marshal(code)
		v.Code = string(b)
	}
	setSpecList(obj, "versions", append(vs, v))
	return v, nil
}

// settledRevision is the Knative revision the function's latest change runs; inProgress when that change
// has not rolled out yet (the latest revision is not ready, or predates the change).
func (h *lambdaHandler) settledRevision(ctx context.Context, ns string, obj *unstructured.Unstructured) (rev string, inProgress bool, err error) {
	ks, err := h.fns.dyn.Resource(knativeServiceGVR).Namespace(ns).Get(ctx, obj.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", true, nil
	} else if err != nil {
		return "", false, err
	}
	ready, _, _ := unstructured.NestedString(ks.Object, "status", "latestReadyRevisionName")
	created, _, _ := unstructured.NestedString(ks.Object, "status", "latestCreatedRevisionName")
	observed, _, _ := unstructured.NestedInt64(ks.Object, "status", "observedGeneration")
	if ready == "" || ready != created || observed != ks.GetGeneration() {
		return "", true, nil
	}
	if at := obj.GetAnnotations()[fnUpdatedAtAnnotation]; at != "" && h.meta != nil {
		t, perr := time.Parse(time.RFC3339Nano, at)
		if perr == nil {
			rm, merr := h.meta.Resource(knativeRevisionGVR).Namespace(ns).Get(ctx, ready, metav1.GetOptions{})
			if merr != nil {
				return "", false, merr
			}
			if rm.GetCreationTimestamp().Time.Before(t.Truncate(time.Second)) {
				return "", true, nil
			}
		}
	}
	return ready, false, nil
}

// fillPendingVersions gives the versions published with Publish: true their revision once the change has
// rolled out; it changes obj (and the stored function) only when it fills one.
func (h *lambdaHandler) fillPendingVersions(ctx context.Context, ns string, obj *unstructured.Unstructured) {
	vs := versionsOf(obj)
	pending := false
	for _, v := range vs {
		if v.Revision == "" {
			pending = true
		}
	}
	if !pending {
		return
	}
	rev, inProgress, err := h.settledRevision(ctx, ns, obj)
	if err != nil || inProgress {
		return
	}
	for i := range vs {
		if vs[i].Revision == "" {
			vs[i].Revision = rev
		}
	}
	setSpecList(obj, "versions", vs)
	if updated, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err == nil {
		obj.Object = updated.Object
	}
}

// followPendingVersions fills a Publish: true version's revision in the background once its change has
// rolled out (reads fill it too, should the shim restart meanwhile).
func (h *lambdaHandler) followPendingVersions(ns, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		obj, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return
		}
		h.fillPendingVersions(ctx, ns, obj)
		done := true
		for _, v := range versionsOf(obj) {
			if v.Revision == "" {
				done = false
			}
		}
		if done {
			return
		}
	}
}

// versionConfiguration is a version's FunctionConfiguration: the configuration it was published with, its
// ARN qualified by arnQualifier (the version, or an alias that resolves to it).
func (h *lambdaHandler) versionConfiguration(ctx context.Context, obj *unstructured.Unstructured, v fnVersion, arnQualifier string) map[string]any {
	cfg := map[string]any{}
	_ = json.Unmarshal([]byte(v.Configuration), &cfg)
	if arnQualifier == "" {
		arnQualifier = v.Version
	}
	cfg["Version"] = v.Version
	cfg["FunctionArn"] = h.functionARNIn(ctx, obj.GetName()) + ":" + arnQualifier
	if v.Published != "" {
		cfg["LastModified"] = v.Published // a version was last changed when it was published
	}
	if v.Revision == "" {
		cfg["State"], cfg["LastUpdateStatus"] = "Pending", "InProgress"
	} else {
		cfg["State"], cfg["LastUpdateStatus"] = "Active", "Successful"
	}
	return cfg
}

// qualifiedConfiguration is a qualified read's configuration: $LATEST, a version, or the version an alias
// names (its ARN alias-qualified); found=false when the qualifier names neither.
func (h *lambdaHandler) qualifiedConfiguration(ctx context.Context, obj *unstructured.Unstructured, qualifier string) (map[string]any, bool) {
	cfg, _, found := h.qualifiedFunction(ctx, obj, qualifier)
	return cfg, found
}

// qualifiedFunction is a qualified GetFunction's Configuration and Code: those of $LATEST, of a version, or
// of the version an alias names; found=false when the qualifier names neither.
func (h *lambdaHandler) qualifiedFunction(ctx context.Context, obj *unstructured.Unstructured, qualifier string) (cfg, code map[string]any, found bool) {
	if qualifier == "" || qualifier == "$LATEST" {
		return h.functionConfiguration(ctx, obj, qualifier), functionCode(obj), true
	}
	version, arnQualifier := qualifier, ""
	if a, i := findAlias(aliasesOf(obj), qualifier); i >= 0 && !versionNumberRe.MatchString(qualifier) {
		if a.FunctionVersion == "$LATEST" {
			return h.functionConfiguration(ctx, obj, a.Name), functionCode(obj), true
		}
		version, arnQualifier = a.FunctionVersion, a.Name
	}
	v, ok := findVersion(versionsOf(obj), version)
	if !ok {
		return nil, nil, false
	}
	if v.Code != "" {
		_ = json.Unmarshal([]byte(v.Code), &code)
	}
	return h.versionConfiguration(ctx, obj, v, arnQualifier), code, true
}

func (h *lambdaHandler) listVersions(w http.ResponseWriter, r *http.Request, requestID string, obj *unstructured.Unstructured) {
	ctx := r.Context()
	all := []any{h.qualifiedLatest(ctx, obj)}
	for _, v := range versionsOf(obj) {
		all = append(all, h.versionConfiguration(ctx, obj, v, ""))
	}
	start := 0
	if m := r.URL.Query().Get("Marker"); m != "" {
		n, err := strconv.Atoi(m)
		if err != nil || n < 0 || n > len(all) {
			writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID, "Invalid Marker")
			return
		}
		start = n
	}
	limit := lambdaListMax
	if s := r.URL.Query().Get("MaxItems"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n < limit {
			limit = n
		}
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	out := map[string]any{"Versions": all[start:end]}
	if end < len(all) {
		out["NextMarker"] = strconv.Itoa(end)
	}
	writeLambdaJSON(w, requestID, out)
}

// qualifiedLatest is $LATEST as ListVersionsByFunction lists it.
func (h *lambdaHandler) qualifiedLatest(ctx context.Context, obj *unstructured.Unstructured) map[string]any {
	cfg, _ := h.qualifiedConfiguration(ctx, obj, "$LATEST")
	return cfg
}

// putAlias creates (CreateAlias) or changes (UpdateAlias) an alias.
func (h *lambdaHandler) putAlias(w http.ResponseWriter, r *http.Request, requestID, op, ns string, obj *unstructured.Unstructured, alias string, body map[string]any) {
	ctx := r.Context()
	name := obj.GetName()
	as := aliasesOf(obj)
	var a fnAlias
	i := -1
	if op == "CreateAlias" {
		a.Name = str(body["Name"])
		if !aliasNameRe.MatchString(a.Name) || len(a.Name) > 128 {
			lambdaValidation("name", a.Name, `Member must satisfy regular expression pattern: (?!^[0-9]+$)([a-zA-Z0-9-_]+)`).write(w, requestID)
			return
		}
		if _, j := findAlias(as, a.Name); j >= 0 {
			writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID, "Alias already exists: "+h.functionARNIn(ctx, name)+":"+a.Name)
			return
		}
		if len(as) >= maxAliases {
			writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID,
				fmt.Sprintf("The function has %d aliases, the most open-infra keeps", maxAliases))
			return
		}
		a.FunctionVersion = str(body["FunctionVersion"])
		a.Description = str(body["Description"])
	} else {
		if a, i = findAlias(as, alias); i < 0 {
			writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Alias not found: "+h.functionARNIn(ctx, name)+":"+alias)
			return
		}
		if rev := str(body["RevisionId"]); rev != "" && rev != obj.GetResourceVersion() {
			writeLambdaError(w, http.StatusPreconditionFailed, "PreconditionFailedException", requestID,
				"The RevisionId provided does not match the latest RevisionId for the Lambda function or alias. Call the GetFunction or the GetAlias API to retrieve the latest RevisionId for your resource.")
			return
		}
		if v, ok := body["FunctionVersion"]; ok {
			a.FunctionVersion = str(v)
		}
		if d, ok := body["Description"]; ok {
			a.Description = str(d)
		}
	}
	if rc, ok := body["RoutingConfig"].(map[string]any); ok {
		a.Weights = nil
		if ws, ok := rc["AdditionalVersionWeights"].(map[string]any); ok && len(ws) > 0 {
			a.Weights = map[string]float64{}
			for k, v := range ws {
				f, isNum := v.(float64)
				if !isNum {
					invalidParam("RoutingConfig.AdditionalVersionWeights values must be numbers").write(w, requestID)
					return
				}
				a.Weights[k] = f
			}
		}
	}
	vs := versionsOf(obj)
	if e := checkAlias(a, vs); e != nil {
		e.write(w, requestID)
		return
	}
	if i >= 0 {
		as[i] = a
	} else {
		as = append(as, a)
	}
	setSpecList(obj, "aliases", as)
	updated, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID,
			"The operation cannot be performed at this time. An update is in progress for resource: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		h.writeApplyError(w, requestID, op, name, err)
		return
	}
	status := http.StatusOK
	if op == "CreateAlias" {
		status = http.StatusCreated
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(h.aliasConfiguration(ctx, updated, a))
}

// checkAlias refuses an alias Lambda would refuse: a version that is not $LATEST or a published one, and a
// routing config that is not one other published version with a weight from 0 to 1 (on an alias of a
// published version, not $LATEST).
func checkAlias(a fnAlias, vs []fnVersion) *lambdaErr {
	if a.FunctionVersion != "$LATEST" {
		if !versionNumberRe.MatchString(a.FunctionVersion) {
			return lambdaValidation("functionVersion", a.FunctionVersion, `Member must satisfy regular expression pattern: (\$LATEST|[0-9]+)`)
		}
		if _, ok := findVersion(vs, a.FunctionVersion); !ok {
			return &lambdaErr{http.StatusNotFound, "ResourceNotFoundException", "Function version " + a.FunctionVersion + " not found"}
		}
	}
	if len(a.Weights) > 1 {
		return invalidParam("RoutingConfig.AdditionalVersionWeights takes one version")
	}
	for k, w := range a.Weights {
		if a.FunctionVersion == "$LATEST" {
			return invalidParam("$LATEST is not supported for an alias pointing to more than 1 version")
		}
		if k == a.FunctionVersion {
			return invalidParam("RoutingConfig.AdditionalVersionWeights names the alias's own version %s", k)
		}
		if _, ok := findVersion(vs, k); !ok {
			return &lambdaErr{http.StatusNotFound, "ResourceNotFoundException", "Function version " + k + " not found"}
		}
		if w < 0 || w > 1 {
			return lambdaValidation("additionalVersionWeights", w, "Member must have value between 0.0 and 1.0")
		}
	}
	return nil
}

// aliasConfiguration is Lambda's AliasConfiguration.
func (h *lambdaHandler) aliasConfiguration(ctx context.Context, obj *unstructured.Unstructured, a fnAlias) map[string]any {
	out := map[string]any{
		"AliasArn":        h.functionARNIn(ctx, obj.GetName()) + ":" + a.Name,
		"Name":            a.Name,
		"FunctionVersion": a.FunctionVersion,
		"RevisionId":      obj.GetResourceVersion(),
	}
	if a.Description != "" {
		out["Description"] = a.Description
	}
	if len(a.Weights) > 0 {
		out["RoutingConfig"] = map[string]any{"AdditionalVersionWeights": a.Weights}
	}
	return out
}

// invocationTarget is where an invocation runs: the host (the function's own route, or a version's tag),
// the version that runs ($LATEST or a number), and that version's timeout (0 = $LATEST's, read as usual).
type invocationTarget struct {
	host, version string
	timeout       time.Duration
}

// resolveInvocation resolves an invocation's qualifier to where it runs: $LATEST (or none) is the
// function's own route; a version its tag; an alias the version it routes this invocation to (by its
// weights).
func (h *lambdaHandler) resolveInvocation(ctx context.Context, ns, name, qualifier string) (invocationTarget, *lambdaErr) {
	t, e := h.resolveVersion(ctx, ns, name, qualifier)
	if e != nil {
		return invocationTarget{}, e
	}
	if t.version == "$LATEST" {
		t.host = name
	} else {
		t.host = versionTagHost(t.version, name)
	}
	return t, nil
}

func (h *lambdaHandler) resolveVersion(ctx context.Context, ns, name, qualifier string) (invocationTarget, *lambdaErr) {
	latest := invocationTarget{version: "$LATEST"}
	if qualifier == "" || qualifier == "$LATEST" {
		return latest, nil
	}
	if h.fns == nil || h.fns.dyn == nil {
		return invocationTarget{}, &lambdaErr{http.StatusNotImplemented, "ServiceException", "invoking a version needs the shim's cluster access"}
	}
	notFound := &lambdaErr{http.StatusNotFound, "ResourceNotFoundException", "Function not found: " + h.functionARNIn(ctx, name) + ":" + qualifier}
	obj, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return invocationTarget{}, notFound
	} else if err != nil {
		return invocationTarget{}, &lambdaErr{http.StatusInternalServerError, "ServiceException", "could not read the function"}
	}
	h.fillPendingVersions(ctx, ns, obj)
	version := qualifier
	if !versionNumberRe.MatchString(qualifier) {
		a, i := findAlias(aliasesOf(obj), qualifier)
		if i < 0 {
			return invocationTarget{}, notFound
		}
		version = a.FunctionVersion
		keys := make([]string, 0, len(a.Weights))
		for k := range a.Weights {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		roll := rand.Float64()
		for _, k := range keys {
			if roll < a.Weights[k] {
				version = k
				break
			}
			roll -= a.Weights[k]
		}
		if version == "$LATEST" {
			return latest, nil
		}
	}
	v, ok := findVersion(versionsOf(obj), version)
	if !ok {
		return invocationTarget{}, notFound
	}
	if v.Revision == "" {
		return invocationTarget{}, &lambdaErr{http.StatusConflict, "ResourceConflictException",
			"The operation cannot be performed at this time. The function is currently in the following state: Pending"}
	}
	t := invocationTarget{version: v.Version}
	var cfg struct{ Timeout int }
	if json.Unmarshal([]byte(v.Configuration), &cfg) == nil && cfg.Timeout > 0 {
		t.timeout = time.Duration(cfg.Timeout) * time.Second // the version runs with the timeout it was published with
	}
	return t, nil
}

// deleteVersion deletes one published version (DeleteFunction with a version Qualifier); one an alias
// still names is refused, as Lambda refuses it.
func (h *lambdaHandler) deleteVersion(w http.ResponseWriter, r *http.Request, requestID, ns, name, version string) {
	ctx := r.Context()
	obj, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Function not found: "+h.functionARNIn(ctx, name))
		return
	} else if err != nil {
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not read the function")
		return
	}
	var users []string
	for _, a := range aliasesOf(obj) {
		_, weighted := a.Weights[version]
		if a.FunctionVersion == version || weighted {
			users = append(users, a.Name)
		}
	}
	if len(users) > 0 {
		writeLambdaError(w, http.StatusConflict, "ResourceConflictException", requestID,
			"Unable to delete version because the following aliases reference it: ["+strings.Join(users, ", ")+"]")
		return
	}
	vs := versionsOf(obj)
	kept := vs[:0]
	found := false
	for _, v := range vs {
		if v.Version == version {
			found = true
			continue
		}
		kept = append(kept, v)
	}
	if !found {
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID, "Function not found: "+h.functionARNIn(ctx, name)+":"+version)
		return
	}
	setSpecList(obj, "versions", kept)
	if _, err := h.fns.dyn.Resource(functionClaimGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		h.writeApplyError(w, requestID, "DeleteFunction", name, err)
		return
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusNoContent)
}
