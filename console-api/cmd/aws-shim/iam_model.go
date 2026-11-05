// The IAM front door's object model: what each IAM API call writes, which is exactly what the console
// and CloudFormation write, so the one evaluator reads one shape whoever made it.
//
//   - a customer managed policy is a kind: Policy whose spec.document is the AWS policy document as
//     written (CreatePolicy, CreatePolicyVersion); its other versions are kept on the object;
//   - an AWS managed policy (arn:aws:iam::aws:policy/<Name>) is the shipped library's kind: Policy
//     (aws-<name>, in the management account's IAM home), read-only;
//   - attaching a managed policy to a user, group or role adds the policy's object name to its
//     spec.policies (Attach{User,Group,Role}Policy), an inline policy is a {name, document} entry of its
//     spec.inlinePolicies (Put{User,Group,Role}Policy), and a permissions boundary its spec.permissionBoundary;
//   - a group is a container of policies (kind: Group), and membership is the user's spec.groups
//     (AddUserToGroup).
//
// Every entity lives in the namespace of the caller's account: the management account's IAM home, or a
// member account's home namespace (iamScope).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var gvrGroups = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "groups"}

const (
	// policyDefaultVersionAnnotation is a customer managed policy's default version id (absent: v1).
	policyDefaultVersionAnnotation = "openinfra.dev/policy-default-version"
	// policyVersionsAnnotation holds a customer managed policy's other versions, as JSON
	// {"<id>": {"document": "<json>", "created": "<RFC 3339>"}}; the default is spec.document.
	policyVersionsAnnotation = "openinfra.dev/policy-versions"
	// assumeRolePolicyAnnotation is the trust policy a role was created with, as written (GetRole returns it).
	assumeRolePolicyAnnotation = "openinfra.dev/assume-role-policy"
	// awsManagedPolicyLabel marks the shipped library's AWS managed policies.
	awsManagedPolicyLabel = "openinfra.dev/aws-managed-policy"
	// maxPolicyVersions is AWS's limit on a managed policy's versions.
	maxPolicyVersions = 5
)

// iamScope is where an IAM request acts: the caller's account and the namespace its IAM entities live
// in — the management account's IAM home, or a member account's home namespace.
type iamScope struct{ ns, account string }

func (h *iamHandler) scope(ctx context.Context) iamScope {
	id := awsidentity.FromContext(ctx)
	if home, _ := ctx.Value(accountHomeKey{}).(string); home != "" && !awsidentity.Current().IsManagement(id.AccountID) {
		return iamScope{ns: home, account: id.AccountID}
	}
	return iamScope{ns: h.usersNS, account: h.account}
}

func (sc iamScope) arn(resource string) string { return "arn:aws:iam::" + sc.account + ":" + resource }

// iamEntity is a kind of principal the IAM API manages policies on.
type iamEntity struct {
	kind  string // Role, User, Group
	gvr   schema.GroupVersionResource
	param string // the request parameter that names it (RoleName …)
	arn   string // its ARN's resource type (role, user, group)
}

var (
	roleEntity  = iamEntity{kind: "Role", gvr: gvrRoles, param: "RoleName", arn: "role"}
	userEntity  = iamEntity{kind: "User", gvr: gvrUsers, param: "UserName", arn: "user"}
	groupEntity = iamEntity{kind: "Group", gvr: gvrGroups, param: "GroupName", arn: "group"}
)

// iamError is an IAM error response: its code, HTTP status and message.
type iamError struct {
	status     int
	code, text string
}

func (e *iamError) Error() string { return e.code + ": " + e.text }

func noSuchEntityErr(msg string) error { return &iamError{http.StatusNotFound, "NoSuchEntity", msg} }
func deleteConflictErr(msg string) error {
	return &iamError{http.StatusConflict, "DeleteConflict", msg}
}
func invalidInputErr(msg string) error { return &iamError{http.StatusBadRequest, "InvalidInput", msg} }
func validationErr(msg string) error   { return &iamError{http.StatusBadRequest, "ValidationError", msg} }

// fail writes err as IAM's error: an iamError as itself, anything else as a service failure.
func (h *iamHandler) fail(w http.ResponseWriter, requestID string, err error) {
	var ie *iamError
	if errors.As(err, &ie) {
		writeQueryError(w, ie.status, ie.code, requestID, ie.text, iamXMLNamespace)
		return
	}
	h.internal(w, requestID, err)
}

// required returns the named form values, or a ValidationError naming the first one missing.
func required(r *http.Request, names ...string) ([]string, error) {
	out := make([]string, len(names))
	for i, n := range names {
		if out[i] = r.PostFormValue(n); out[i] == "" {
			return nil, validationErr("1 validation error detected: Value null at '" + lowerFirst(n) + "' failed to satisfy constraint: Member must not be null")
		}
	}
	return out, nil
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// mutate reads ns/name, applies fn to it and writes it back, retrying on a write conflict. A missing
// object is NoSuchEntity (the kind and name in the message); fn's error is returned as is.
func (h *iamHandler) mutate(ctx context.Context, e iamEntity, ns, name string, fn func(u *unstructured.Unstructured) error) error {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var u *unstructured.Unstructured
		u, err = h.dyn.Resource(e.gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return noSuchEntityErr("The " + strings.ToLower(e.kind) + " with name " + name + " cannot be found.")
			}
			return err
		}
		if err = fn(u); err != nil {
			return err
		}
		if _, err = h.dyn.Resource(e.gvr).Namespace(ns).Update(ctx, u, metav1.UpdateOptions{}); err == nil || !apierrors.IsConflict(err) {
			return err
		}
	}
	return err
}

func (h *iamHandler) get(ctx context.Context, e iamEntity, ns, name string) (*unstructured.Unstructured, error) {
	u, err := h.dyn.Resource(e.gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, noSuchEntityErr("The " + strings.ToLower(e.kind) + " with name " + name + " cannot be found.")
	}
	return u, err
}

// --- policy documents ---

// parseDocument checks an AWS policy document as the one evaluator reads it (iamauthz.CompileDocument)
// and returns it as the object spec.document stores. A document that is not a policy document is
// MalformedPolicyDocument; one with a part the evaluator cannot honour is stored as written, as on AWS —
// the part is reported and never widens a grant (an Allow it cannot evaluate is dropped, a Deny applies).
func parseDocument(doc string) (map[string]any, []string, error) {
	stmts, report, err := iamauthz.CompileDocument(doc)
	if err != nil {
		return nil, nil, &iamError{http.StatusBadRequest, "MalformedPolicyDocument", "The policy document is malformed: " + err.Error()}
	}
	var obj map[string]any
	if json.Unmarshal([]byte(doc), &obj) != nil || obj == nil {
		return nil, nil, &iamError{http.StatusBadRequest, "MalformedPolicyDocument", "The policy document is not a JSON object."}
	}
	if _, ok := obj["Statement"]; !ok || (len(stmts) == 0 && len(report) == 0) {
		return nil, nil, &iamError{http.StatusBadRequest, "MalformedPolicyDocument", "Syntax errors in policy: the document has no Statement."}
	}
	return obj, report, nil
}

// documentJSON is a stored document as JSON text.
func documentJSON(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// encodeDocument is a policy document as IAM returns one: URL-encoded (RFC 3986).
func encodeDocument(doc string) string {
	return strings.ReplaceAll(url.QueryEscape(doc), "+", "%20")
}

// --- policy references ---

// policyObjectName is the kind: Policy name of a customer policy named policyName: the name itself when
// it is a Kubernetes name, else lowercased with each character a Kubernetes name cannot hold replaced by
// "-" (IAM names are unique regardless of case, as Kubernetes names are lower-case). The IAM name is kept
// in spec.policyName.
func policyObjectName(policyName string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(policyName) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// policyTarget is the kind: Policy a PolicyArn names.
type policyTarget struct {
	ns, name string // where the object is
	ref      string // how a principal in the caller's account attaches it (spec.policies)
	managed  bool   // an AWS managed policy (the shipped library), read-only
}

// policyByARN resolves a PolicyArn: an AWS managed policy's ARN (arn:aws:iam::aws:policy/<Name>) is the
// shipped library's object in the management account's IAM home (referenced by namespace from a member
// account, so a member's own policy of that name never stands in for it); a customer policy's ARN is a
// policy of the caller's account — another account's is NoSuchEntity.
func (h *iamHandler) policyByARN(sc iamScope, arn string) (policyTarget, error) {
	notFound := noSuchEntityErr("Policy " + arn + " does not exist or is not attachable.")
	if strings.HasPrefix(arn, "arn:aws:iam::aws:policy/") {
		mp, ok := cfn.ManagedPolicyByARN(arn)
		if !ok {
			return policyTarget{}, notFound
		}
		ref := mp.ObjectName()
		if sc.ns != h.usersNS {
			ref = h.usersNS + "/" + ref
		}
		return policyTarget{ns: h.usersNS, name: mp.ObjectName(), ref: ref, managed: true}, nil
	}
	if acct := awsidentity.AccountOfARN(arn); acct != "" && acct != sc.account {
		return policyTarget{}, notFound
	}
	name := policyNameFromArn(arn)
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return policyTarget{}, notFound
	}
	obj := policyObjectName(name)
	return policyTarget{ns: sc.ns, name: obj, ref: obj}, nil
}

// policyIdentity is a stored Policy's IAM name and ARN.
func policyIdentity(sc iamScope, u *unstructured.Unstructured) (name, arn string) {
	name, _, _ = unstructured.NestedString(u.Object, "spec", "policyName")
	if name == "" {
		name = u.GetName()
	}
	arn, _, _ = unstructured.NestedString(u.Object, "spec", "arn")
	if arn == "" {
		arn = sc.arn("policy/" + name)
	}
	return name, arn
}

func isAWSManaged(u *unstructured.Unstructured) bool {
	l := u.GetLabels()
	return l[awsManagedPolicyLabel] == "true" || l[managedPolicyLabelShim] == "true"
}

// managedPolicyLabelShim marks an out-of-the-box managed policy (the console's read-only policies).
const managedPolicyLabelShim = "openinfra.dev/managed-policy"

// attachedPolicy is an attachment as IAM lists it: the policy's name and ARN.
func (h *iamHandler) attachedPolicy(ctx context.Context, sc iamScope, ref string) (name, arn string) {
	ns, obj := sc.ns, ref
	if i := strings.IndexByte(ref, '/'); i > 0 {
		ns, obj = ref[:i], ref[i+1:]
	}
	u, err := h.dyn.Resource(gvrPolicies).Namespace(ns).Get(ctx, obj, metav1.GetOptions{})
	if err != nil && ns != h.usersNS {
		u, err = h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Get(ctx, obj, metav1.GetOptions{})
	}
	if err != nil {
		return obj, sc.arn("policy/" + obj)
	}
	return policyIdentity(sc, u)
}

// --- policies ---

func (h *iamHandler) createPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	v, err := required(r, "PolicyName", "PolicyDocument")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	name, doc := v[0], v[1]
	obj, report, err := parseDocument(doc)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	spec := map[string]any{"description": r.PostFormValue("Description"), "document": obj}
	objName := policyObjectName(name)
	if objName != name {
		spec["policyName"] = name
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Policy",
		"metadata":   map[string]any{"name": objName, "namespace": sc.ns},
		"spec":       spec,
	}}
	created, err := h.dyn.Resource(gvrPolicies).Namespace(sc.ns).Create(ctx, u, metav1.CreateOptions{})
	if err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "A policy called "+name+" already exists. Duplicate names are not allowed.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreatePolicy", name, "allow", strings.Join(report, "; "))
	h.writeResult(w, requestID, "CreatePolicy", "<Policy>"+h.policyXML(ctx, sc, created)+"</Policy>")
}

// policyFor reads the Policy a request's PolicyArn names.
func (h *iamHandler) policyFor(ctx context.Context, sc iamScope, arn string) (policyTarget, *unstructured.Unstructured, error) {
	if arn == "" {
		return policyTarget{}, nil, validationErr("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null")
	}
	t, err := h.policyByARN(sc, arn)
	if err != nil {
		return t, nil, err
	}
	u, err := h.dyn.Resource(gvrPolicies).Namespace(t.ns).Get(ctx, t.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return t, nil, noSuchEntityErr("Policy " + arn + " was not found.")
	}
	if err == nil && isAWSManaged(u) {
		t.managed = true
	}
	return t, u, err
}

func (h *iamHandler) getPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	_, u, err := h.policyFor(ctx, sc, r.PostFormValue("PolicyArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "GetPolicy", "<Policy>"+h.policyXML(ctx, sc, u)+"</Policy>")
}

func (h *iamHandler) deletePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	t, u, err := h.policyFor(ctx, sc, r.PostFormValue("PolicyArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if t.managed {
		h.fail(w, requestID, invalidInputErr("Cannot delete an AWS managed policy."))
		return
	}
	if n, err := h.attachmentCount(ctx, sc, t.ref); err != nil {
		h.internal(w, requestID, err)
		return
	} else if n > 0 {
		h.fail(w, requestID, deleteConflictErr("Cannot delete a policy attached to entities."))
		return
	}
	if len(policyVersions(u)) > 0 {
		h.fail(w, requestID, deleteConflictErr("This policy has more than one version. Before you delete a policy, you must delete the policy's versions. The default version is deleted with the policy."))
		return
	}
	if err := h.dyn.Resource(gvrPolicies).Namespace(t.ns).Delete(ctx, t.name, metav1.DeleteOptions{}); err != nil {
		h.fail(w, requestID, noSuchEntityErr("Policy "+r.PostFormValue("PolicyArn")+" was not found."))
		return
	}
	h.audit(ctx, "DeletePolicy", t.name, "allow", "")
	h.writeResult(w, requestID, "DeletePolicy", "")
}

// listPolicies lists the account's customer managed policies (Scope Local) and the AWS managed library
// (Scope AWS); All (the default) both.
func (h *iamHandler) listPolicies(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	scope := r.PostFormValue("Scope")
	if scope == "" {
		scope = "All"
	}
	var items []unstructured.Unstructured
	namespaces := []string{sc.ns}
	if sc.ns != h.usersNS && scope != "Local" {
		namespaces = append(namespaces, h.usersNS)
	}
	for _, ns := range namespaces {
		list, err := h.dyn.Resource(gvrPolicies).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		for _, it := range list.Items {
			managed := isAWSManaged(&it)
			if ns != sc.ns && !managed {
				continue // another account's customer policy
			}
			if (scope == "AWS" && !managed) || (scope == "Local" && managed) {
				continue
			}
			items = append(items, it)
		}
	}
	var b strings.Builder
	b.WriteString("<Policies>")
	for i := range items {
		b.WriteString("<member>" + h.policyXML(ctx, sc, &items[i]) + "</member>")
	}
	b.WriteString("</Policies><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListPolicies", b.String())
}

// attachmentCount is how many of the account's users, groups and roles attach the policy ref.
func (h *iamHandler) attachmentCount(ctx context.Context, sc iamScope, ref string) (int, error) {
	n := 0
	for _, e := range []iamEntity{userEntity, groupEntity, roleEntity} {
		list, err := h.dyn.Resource(e.gvr).Namespace(sc.ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return 0, err
		}
		for _, it := range list.Items {
			refs, _, _ := unstructured.NestedStringSlice(it.Object, "spec", "policies")
			if containsStr(refs, ref) {
				n++
			}
		}
	}
	return n, nil
}

// --- policy versions ---

type policyVersion struct {
	Document string `json:"document"`
	Created  string `json:"created,omitempty"`
}

func policyVersions(u *unstructured.Unstructured) map[string]policyVersion {
	out := map[string]policyVersion{}
	if raw := u.GetAnnotations()[policyVersionsAnnotation]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func defaultVersion(u *unstructured.Unstructured) string {
	if v := u.GetAnnotations()[policyDefaultVersionAnnotation]; v != "" {
		return v
	}
	return "v1"
}

func setPolicyVersions(u *unstructured.Unstructured, def string, versions map[string]policyVersion) {
	ann := u.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	if def == "v1" {
		delete(ann, policyDefaultVersionAnnotation)
	} else {
		ann[policyDefaultVersionAnnotation] = def
	}
	if len(versions) == 0 {
		delete(ann, policyVersionsAnnotation)
	} else {
		b, _ := json.Marshal(versions)
		ann[policyVersionsAnnotation] = string(b)
	}
	u.SetAnnotations(ann)
}

func versionNumber(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "v"))
	return n
}

// sortedVersions is a policy's version ids, newest first.
func sortedVersions(u *unstructured.Unstructured) []string {
	ids := []string{defaultVersion(u)}
	for id := range policyVersions(u) {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return versionNumber(ids[i]) > versionNumber(ids[j]) })
	return ids
}

func (h *iamHandler) createPolicyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	t, _, err := h.policyFor(ctx, sc, r.PostFormValue("PolicyArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if t.managed {
		h.fail(w, requestID, invalidInputErr("Cannot create a version of an AWS managed policy."))
		return
	}
	v, err := required(r, "PolicyDocument")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	obj, report, err := parseDocument(v[0])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	setDefault := strings.EqualFold(r.PostFormValue("SetAsDefault"), "true")
	var id string
	err = h.mutate(ctx, iamEntity{kind: "Policy", gvr: gvrPolicies}, t.ns, t.name, func(u *unstructured.Unstructured) error {
		versions := policyVersions(u)
		if 1+len(versions) >= maxPolicyVersions {
			return &iamError{http.StatusConflict, "LimitExceeded", "A managed policy can have up to " + strconv.Itoa(maxPolicyVersions) +
				" versions. Before you create a new version, you must delete an existing version."}
		}
		def := defaultVersion(u)
		next := versionNumber(def)
		for vid := range versions {
			if n := versionNumber(vid); n > next {
				next = n
			}
		}
		id = "v" + strconv.Itoa(next+1)
		now := time.Now().UTC().Format(time.RFC3339)
		if setDefault {
			cur, _, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "document")
			versions[def] = policyVersion{Document: documentJSON(cur), Created: u.GetCreationTimestamp().UTC().Format(time.RFC3339)}
			_ = unstructured.SetNestedField(u.Object, obj, "spec", "document")
			def = id
		} else {
			versions[id] = policyVersion{Document: documentJSON(obj), Created: now}
		}
		setPolicyVersions(u, def, versions)
		return nil
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "CreatePolicyVersion", t.name, "allow", "version="+id+" "+strings.Join(report, "; "))
	h.writeResult(w, requestID, "CreatePolicyVersion", "<PolicyVersion><VersionId>"+id+"</VersionId><IsDefaultVersion>"+
		strconv.FormatBool(setDefault)+"</IsDefaultVersion><CreateDate>"+time.Now().UTC().Format(time.RFC3339)+"</CreateDate></PolicyVersion>")
}

func (h *iamHandler) getPolicyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	_, u, err := h.policyFor(ctx, sc, r.PostFormValue("PolicyArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	id := r.PostFormValue("VersionId")
	doc, ok := versionDocument(u, id)
	if !ok {
		h.fail(w, requestID, noSuchEntityErr("Policy "+r.PostFormValue("PolicyArn")+" version "+id+" does not exist or is not attachable."))
		return
	}
	h.writeResult(w, requestID, "GetPolicyVersion", "<PolicyVersion><Document>"+xmlEscape(encodeDocument(doc))+
		"</Document><VersionId>"+xmlEscape(id)+"</VersionId><IsDefaultVersion>"+strconv.FormatBool(id == defaultVersion(u))+
		"</IsDefaultVersion><CreateDate>"+versionCreated(u, id)+"</CreateDate></PolicyVersion>")
}

// versionDocument is version id's document (the default: spec.document).
func versionDocument(u *unstructured.Unstructured, id string) (string, bool) {
	if id == defaultVersion(u) {
		cur, _, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "document")
		return documentJSON(cur), true
	}
	v, ok := policyVersions(u)[id]
	return v.Document, ok
}

func versionCreated(u *unstructured.Unstructured, id string) string {
	if v, ok := policyVersions(u)[id]; ok && v.Created != "" {
		return v.Created
	}
	return u.GetCreationTimestamp().UTC().Format(time.RFC3339)
}

func (h *iamHandler) listPolicyVersions(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	_, u, err := h.policyFor(ctx, sc, r.PostFormValue("PolicyArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Versions>")
	def := defaultVersion(u)
	for _, id := range sortedVersions(u) {
		b.WriteString("<member><VersionId>" + xmlEscape(id) + "</VersionId><IsDefaultVersion>" + strconv.FormatBool(id == def) +
			"</IsDefaultVersion><CreateDate>" + versionCreated(u, id) + "</CreateDate></member>")
	}
	b.WriteString("</Versions><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListPolicyVersions", b.String())
}

func (h *iamHandler) deletePolicyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	h.changePolicyVersion(ctx, w, r, requestID, "DeletePolicyVersion", func(u *unstructured.Unstructured, id string) error {
		if id == defaultVersion(u) {
			return deleteConflictErr("Cannot delete the default version of a policy.")
		}
		versions := policyVersions(u)
		delete(versions, id)
		setPolicyVersions(u, defaultVersion(u), versions)
		return nil
	})
}

func (h *iamHandler) setDefaultPolicyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	h.changePolicyVersion(ctx, w, r, requestID, "SetDefaultPolicyVersion", func(u *unstructured.Unstructured, id string) error {
		def := defaultVersion(u)
		if id == def {
			return nil
		}
		versions := policyVersions(u)
		next := versions[id]
		var obj map[string]any
		if json.Unmarshal([]byte(next.Document), &obj) != nil {
			return &iamError{http.StatusBadRequest, "MalformedPolicyDocument", "Policy version " + id + " is not a policy document."}
		}
		cur, _, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "document")
		versions[def] = policyVersion{Document: documentJSON(cur), Created: versionCreated(u, def)}
		delete(versions, id)
		_ = unstructured.SetNestedField(u.Object, obj, "spec", "document")
		setPolicyVersions(u, id, versions)
		return nil
	})
}

// changePolicyVersion applies fn to the policy's version VersionId (which must exist) and writes it back.
func (h *iamHandler) changePolicyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, op string,
	fn func(u *unstructured.Unstructured, id string) error) {
	sc := h.scope(ctx)
	t, _, err := h.policyFor(ctx, sc, r.PostFormValue("PolicyArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if t.managed {
		h.fail(w, requestID, invalidInputErr("Cannot change the versions of an AWS managed policy."))
		return
	}
	id := r.PostFormValue("VersionId")
	err = h.mutate(ctx, iamEntity{kind: "Policy", gvr: gvrPolicies}, t.ns, t.name, func(u *unstructured.Unstructured) error {
		if _, ok := versionDocument(u, id); !ok {
			return noSuchEntityErr("Policy " + r.PostFormValue("PolicyArn") + " version " + id + " does not exist.")
		}
		return fn(u, id)
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, op, t.name, "allow", "version="+id)
	h.writeResult(w, requestID, op, "")
}

// --- attachments ---

// attachPolicy attaches (or detaches) the managed policy PolicyArn to the user, group or role e names: its
// object name in spec.policies, as the console and CloudFormation attach one.
func (h *iamHandler) attachPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity, attach bool) {
	sc := h.scope(ctx)
	v, err := required(r, e.param, "PolicyArn")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	name, arn := v[0], v[1]
	t, err := h.policyByARN(sc, arn)
	if err == nil && attach {
		if _, gerr := h.dyn.Resource(gvrPolicies).Namespace(t.ns).Get(ctx, t.name, metav1.GetOptions{}); gerr != nil {
			err = noSuchEntityErr("Policy " + arn + " does not exist or is not attachable.")
		}
	}
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	err = h.mutate(ctx, e, sc.ns, name, func(u *unstructured.Unstructured) error {
		cur, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "policies")
		next := make([]string, 0, len(cur)+1)
		found := false
		for _, p := range cur {
			// an attachment of this policy, in today's form or an earlier one (the bare PolicyName)
			if p == t.ref || p == t.name || (!t.managed && p == policyNameFromArn(arn)) {
				found = true
				if !attach {
					continue
				}
			}
			next = append(next, p)
		}
		if attach && !found {
			next = append(next, t.ref)
		}
		if !attach && !found {
			return noSuchEntityErr("Policy " + arn + " was not found.")
		}
		return unstructured.SetNestedStringSlice(u.Object, next, "spec", "policies")
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	op := "Attach" + e.kind + "Policy"
	if !attach {
		op = "Detach" + e.kind + "Policy"
	}
	h.audit(ctx, op, name, "allow", "policy="+t.ref)
	h.writeResult(w, requestID, op, "")
}

func (h *iamHandler) listAttachedPolicies(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity) {
	sc := h.scope(ctx)
	v, err := required(r, e.param)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	u, err := h.get(ctx, e, sc.ns, v[0])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<AttachedPolicies>")
	b.WriteString(h.attachedPoliciesXML(ctx, sc, u))
	b.WriteString("</AttachedPolicies><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListAttached"+e.kind+"Policies", b.String())
}

func (h *iamHandler) attachedPoliciesXML(ctx context.Context, sc iamScope, u *unstructured.Unstructured) string {
	refs, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "policies")
	var b strings.Builder
	for _, ref := range refs {
		name, arn := h.attachedPolicy(ctx, sc, ref)
		b.WriteString("<member><PolicyName>" + xmlEscape(name) + "</PolicyName><PolicyArn>" + xmlEscape(arn) + "</PolicyArn></member>")
	}
	return b.String()
}

// --- inline policies ---

// putInlinePolicy writes PolicyName's document into the user's, group's or role's spec.inlinePolicies
// (replacing one of that name). A role's inline policy written by an earlier release as its own kind:
// Policy (role-<role>-<name>, applying to the role) is removed, so the role's grant is the new document
// alone.
func (h *iamHandler) putInlinePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity) {
	sc := h.scope(ctx)
	v, err := required(r, e.param, "PolicyName", "PolicyDocument")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	name, polName := v[0], v[1]
	obj, report, err := parseDocument(v[2])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	err = h.mutate(ctx, e, sc.ns, name, func(u *unstructured.Unstructured) error {
		cur, _, _ := unstructured.NestedSlice(u.Object, "spec", "inlinePolicies")
		next := make([]any, 0, len(cur)+1)
		for _, it := range cur {
			if m, _ := it.(map[string]any); m != nil && m["name"] == polName {
				continue
			}
			next = append(next, it)
		}
		next = append(next, map[string]any{"name": polName, "document": obj})
		return unstructured.SetNestedSlice(u.Object, next, "spec", "inlinePolicies")
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if e.kind == "Role" {
		h.removeLegacyInline(ctx, sc, name, polName)
	}
	op := "Put" + e.kind + "Policy"
	h.audit(ctx, op, name, "allow", "policy="+polName+" "+strings.Join(report, "; "))
	h.writeResult(w, requestID, op, "")
}

// removeLegacyInline deletes an earlier release's form of a role's inline policy: a kind: Policy named
// role-<role>-<policy> whose data plane applies to the role.
func (h *iamHandler) removeLegacyInline(ctx context.Context, sc iamScope, role, polName string) {
	name := "role-" + role + "-" + polName
	u, err := h.dyn.Resource(gvrPolicies).Namespace(sc.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return
	}
	applies, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "dataPlane", "appliesTo")
	if len(applies) == 1 && applies[0] == "Role::"+role {
		if err := h.dyn.Resource(gvrPolicies).Namespace(sc.ns).Delete(ctx, name, metav1.DeleteOptions{}); err == nil {
			h.audit(ctx, "PutRolePolicy", role, "allow", "removed the earlier form "+name)
		}
	}
}

func inlinePolicies(u *unstructured.Unstructured) []map[string]any {
	cur, _, _ := unstructured.NestedSlice(u.Object, "spec", "inlinePolicies")
	out := make([]map[string]any, 0, len(cur))
	for _, it := range cur {
		if m, _ := it.(map[string]any); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func (h *iamHandler) getInlinePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity) {
	sc := h.scope(ctx)
	v, err := required(r, e.param, "PolicyName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	u, err := h.get(ctx, e, sc.ns, v[0])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	for _, p := range inlinePolicies(u) {
		if p["name"] == v[1] {
			op := "Get" + e.kind + "Policy"
			h.writeResult(w, requestID, op, "<"+e.param+">"+xmlEscape(v[0])+"</"+e.param+"><PolicyName>"+xmlEscape(v[1])+
				"</PolicyName><PolicyDocument>"+xmlEscape(encodeDocument(documentJSON(p["document"])))+"</PolicyDocument>")
			return
		}
	}
	h.fail(w, requestID, noSuchEntityErr("The "+strings.ToLower(e.kind)+" policy with name "+v[1]+" cannot be found."))
}

func (h *iamHandler) deleteInlinePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity) {
	sc := h.scope(ctx)
	v, err := required(r, e.param, "PolicyName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	err = h.mutate(ctx, e, sc.ns, v[0], func(u *unstructured.Unstructured) error {
		cur := inlinePolicies(u)
		next := make([]any, 0, len(cur))
		found := false
		for _, p := range cur {
			if p["name"] == v[1] {
				found = true
				continue
			}
			next = append(next, p)
		}
		if !found {
			return noSuchEntityErr("The " + strings.ToLower(e.kind) + " policy with name " + v[1] + " cannot be found.")
		}
		return unstructured.SetNestedSlice(u.Object, next, "spec", "inlinePolicies")
	})
	if err != nil && e.kind == "Role" {
		// an inline policy an earlier release wrote as its own kind: Policy
		var ie *iamError
		if errors.As(err, &ie) && ie.code == "NoSuchEntity" {
			legacy := "role-" + v[0] + "-" + v[1]
			if derr := h.dyn.Resource(gvrPolicies).Namespace(sc.ns).Delete(ctx, legacy, metav1.DeleteOptions{}); derr == nil {
				err = nil
			}
		}
	}
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	op := "Delete" + e.kind + "Policy"
	h.audit(ctx, op, v[0], "allow", "policy="+v[1])
	h.writeResult(w, requestID, op, "")
}

func (h *iamHandler) listInlinePolicies(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity) {
	sc := h.scope(ctx)
	v, err := required(r, e.param)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	u, err := h.get(ctx, e, sc.ns, v[0])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<PolicyNames>")
	for _, p := range inlinePolicies(u) {
		if n, _ := p["name"].(string); n != "" {
			b.WriteString("<member>" + xmlEscape(n) + "</member>")
		}
	}
	b.WriteString("</PolicyNames><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "List"+e.kind+"Policies", b.String())
}

// --- permissions boundaries ---

// boundaryRef resolves a PermissionsBoundary ARN to the spec.permissionBoundary it is stored as.
func (h *iamHandler) boundaryRef(ctx context.Context, sc iamScope, arn string) (string, error) {
	t, err := h.policyByARN(sc, arn)
	if err != nil {
		return "", err
	}
	if _, err := h.dyn.Resource(gvrPolicies).Namespace(t.ns).Get(ctx, t.name, metav1.GetOptions{}); err != nil {
		return "", noSuchEntityErr("Policy " + arn + " does not exist or is not attachable.")
	}
	return t.ref, nil
}

func (h *iamHandler) putBoundary(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, e iamEntity, put bool) {
	sc := h.scope(ctx)
	params := []string{e.param}
	if put {
		params = append(params, "PermissionsBoundary")
	}
	v, err := required(r, params...)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	ref := ""
	if put {
		if ref, err = h.boundaryRef(ctx, sc, v[1]); err != nil {
			h.fail(w, requestID, err)
			return
		}
	}
	err = h.mutate(ctx, e, sc.ns, v[0], func(u *unstructured.Unstructured) error {
		if !put {
			unstructured.RemoveNestedField(u.Object, "spec", "permissionBoundary")
			return nil
		}
		return unstructured.SetNestedField(u.Object, ref, "spec", "permissionBoundary")
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	op := "Put" + e.kind + "PermissionsBoundary"
	if !put {
		op = "Delete" + e.kind + "PermissionsBoundary"
	}
	h.audit(ctx, op, v[0], "allow", ref)
	h.writeResult(w, requestID, op, "")
}

func (h *iamHandler) boundaryXML(ctx context.Context, sc iamScope, u *unstructured.Unstructured) string {
	ref, _, _ := unstructured.NestedString(u.Object, "spec", "permissionBoundary")
	if ref == "" {
		return ""
	}
	_, arn := h.attachedPolicy(ctx, sc, ref)
	return "<PermissionsBoundary><PermissionsBoundaryType>Policy</PermissionsBoundaryType><PermissionsBoundaryArn>" +
		xmlEscape(arn) + "</PermissionsBoundaryArn></PermissionsBoundary>"
}

// --- groups ---

func (h *iamHandler) createGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	v, err := required(r, "GroupName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Group",
		"metadata":   map[string]any{"name": v[0], "namespace": sc.ns},
		"spec":       map[string]any{"description": "", "policies": []any{}},
	}}
	if _, err := h.dyn.Resource(gvrGroups).Namespace(sc.ns).Create(ctx, u, metav1.CreateOptions{}); err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "Group with name "+v[0]+" already exists.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateGroup", v[0], "allow", "")
	h.writeResult(w, requestID, "CreateGroup", "<Group>"+groupXML(sc, v[0])+"</Group>")
}

func groupXML(sc iamScope, name string) string {
	return "<Path>/</Path><GroupName>" + xmlEscape(name) + "</GroupName><GroupId>AGPA" + roleID(name)[4:] + "</GroupId><Arn>" +
		xmlEscape(sc.arn("group/"+name)) + "</Arn><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate>"
}

// groupMembers are the account's users whose spec.groups names the group.
func (h *iamHandler) groupMembers(ctx context.Context, sc iamScope, group string) ([]string, error) {
	list, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, it := range list.Items {
		groups, _, _ := unstructured.NestedStringSlice(it.Object, "spec", "groups")
		if containsStr(groups, group) {
			out = append(out, it.GetName())
		}
	}
	sort.Strings(out)
	return out, nil
}

func (h *iamHandler) getGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	v, err := required(r, "GroupName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if _, err := h.get(ctx, groupEntity, sc.ns, v[0]); err != nil {
		h.fail(w, requestID, err)
		return
	}
	members, err := h.groupMembers(ctx, sc, v[0])
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Group>" + groupXML(sc, v[0]) + "</Group><Users>")
	for _, m := range members {
		b.WriteString("<member>" + h.userXML(ctx, m) + "</member>")
	}
	b.WriteString("</Users><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "GetGroup", b.String())
}

// deleteGroup deletes an empty group: as on AWS, one with members, attached policies or inline policies
// is a DeleteConflict.
func (h *iamHandler) deleteGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	v, err := required(r, "GroupName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	u, err := h.get(ctx, groupEntity, sc.ns, v[0])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	members, err := h.groupMembers(ctx, sc, v[0])
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	pols, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "policies")
	switch {
	case len(members) > 0:
		err = deleteConflictErr("Cannot delete entity, must remove users from group first.")
	case len(pols) > 0:
		err = deleteConflictErr("Cannot delete entity, must detach all policies first.")
	case len(inlinePolicies(u)) > 0:
		err = deleteConflictErr("Cannot delete entity, must delete policies first.")
	}
	if err == nil {
		err = h.dyn.Resource(gvrGroups).Namespace(sc.ns).Delete(ctx, v[0], metav1.DeleteOptions{})
	}
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteGroup", v[0], "allow", "")
	h.writeResult(w, requestID, "DeleteGroup", "")
}

func (h *iamHandler) listGroups(ctx context.Context, w http.ResponseWriter, requestID string) {
	sc := h.scope(ctx)
	list, err := h.dyn.Resource(gvrGroups).Namespace(sc.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Groups>")
	for _, it := range list.Items {
		b.WriteString("<member>" + groupXML(sc, it.GetName()) + "</member>")
	}
	b.WriteString("</Groups><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListGroups", b.String())
}

// groupMembership adds the user to the group (or removes it): the group's name in the user's spec.groups.
func (h *iamHandler) groupMembership(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, add bool) {
	sc := h.scope(ctx)
	v, err := required(r, "GroupName", "UserName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	group, user := v[0], v[1]
	if _, err := h.get(ctx, groupEntity, sc.ns, group); err != nil {
		h.fail(w, requestID, err)
		return
	}
	err = h.mutate(ctx, userEntity, sc.ns, user, func(u *unstructured.Unstructured) error {
		cur, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "groups")
		next := make([]string, 0, len(cur)+1)
		for _, g := range cur {
			if g != group {
				next = append(next, g)
			}
		}
		if add {
			next = append(next, group)
		}
		return unstructured.SetNestedStringSlice(u.Object, next, "spec", "groups")
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	op := "AddUserToGroup"
	if !add {
		op = "RemoveUserFromGroup"
	}
	h.audit(ctx, op, user, "allow", "group="+group)
	h.writeResult(w, requestID, op, "")
}

func (h *iamHandler) listGroupsForUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	v, err := required(r, "UserName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	u, err := h.get(ctx, userEntity, sc.ns, v[0])
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	groups, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "groups")
	var b strings.Builder
	b.WriteString("<Groups>")
	for _, g := range groups {
		b.WriteString("<member>" + groupXML(sc, g) + "</member>")
	}
	b.WriteString("</Groups><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListGroupsForUser", b.String())
}

// --- GetAccountAuthorizationDetails ---

// getAccountAuthorizationDetails is the account's users, groups, roles and managed policies with their
// attachments, inline policies and boundaries (Filter narrows by entity type: User, Role, Group,
// LocalManagedPolicy, AWSManagedPolicy).
func (h *iamHandler) getAccountAuthorizationDetails(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	filter := map[string]bool{}
	for _, f := range queryList(r, "Filter") {
		filter[f] = true
	}
	want := func(f string) bool { return len(filter) == 0 || filter[f] }
	list := func(e iamEntity) ([]unstructured.Unstructured, error) {
		l, err := h.dyn.Resource(e.gvr).Namespace(sc.ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return l.Items, nil
	}
	inlineXML := func(u *unstructured.Unstructured, tag string) string {
		var b strings.Builder
		b.WriteString("<" + tag + ">")
		for _, p := range inlinePolicies(u) {
			b.WriteString("<member><PolicyName>" + xmlEscape(str(p["name"])) + "</PolicyName><PolicyDocument>" +
				xmlEscape(encodeDocument(documentJSON(p["document"]))) + "</PolicyDocument></member>")
		}
		b.WriteString("</" + tag + ">")
		return b.String()
	}
	var b strings.Builder
	if want("User") {
		users, err := list(userEntity)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		b.WriteString("<UserDetailList>")
		for i := range users {
			u := &users[i]
			groups, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "groups")
			b.WriteString("<member>" + h.userXML(ctx, u.GetName()) + inlineXML(u, "UserPolicyList") + "<GroupList>")
			for _, g := range groups {
				b.WriteString("<member>" + xmlEscape(g) + "</member>")
			}
			b.WriteString("</GroupList><AttachedManagedPolicies>" + h.attachedPoliciesXML(ctx, sc, u) + "</AttachedManagedPolicies>" +
				h.boundaryXML(ctx, sc, u) + "</member>")
		}
		b.WriteString("</UserDetailList>")
	}
	if want("Group") {
		groups, err := list(groupEntity)
		if err != nil && !apierrors.IsNotFound(err) {
			h.internal(w, requestID, err)
			return
		}
		b.WriteString("<GroupDetailList>")
		for i := range groups {
			g := &groups[i]
			b.WriteString("<member>" + groupXML(sc, g.GetName()) + inlineXML(g, "GroupPolicyList") +
				"<AttachedManagedPolicies>" + h.attachedPoliciesXML(ctx, sc, g) + "</AttachedManagedPolicies></member>")
		}
		b.WriteString("</GroupDetailList>")
	}
	if want("Role") {
		roles, err := list(roleEntity)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		b.WriteString("<RoleDetailList>")
		for i := range roles {
			ro := &roles[i]
			b.WriteString("<member>" + h.roleXML(ctx, ro.GetName(), h.trustDocument(sc, ro)) + "<InstanceProfileList/>" +
				inlineXML(ro, "RolePolicyList") + "<AttachedManagedPolicies>" + h.attachedPoliciesXML(ctx, sc, ro) +
				"</AttachedManagedPolicies>" + h.boundaryXML(ctx, sc, ro) + "</member>")
		}
		b.WriteString("</RoleDetailList>")
	}
	if want("LocalManagedPolicy") || want("AWSManagedPolicy") {
		namespaces := []string{sc.ns}
		if sc.ns != h.usersNS && want("AWSManagedPolicy") {
			namespaces = append(namespaces, h.usersNS)
		}
		b.WriteString("<Policies>")
		for _, ns := range namespaces {
			l, err := h.dyn.Resource(gvrPolicies).Namespace(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				h.internal(w, requestID, err)
				return
			}
			for i := range l.Items {
				p := &l.Items[i]
				managed := isAWSManaged(p)
				if (managed && !want("AWSManagedPolicy")) || (!managed && (!want("LocalManagedPolicy") || ns != sc.ns)) {
					continue
				}
				b.WriteString("<member>" + h.policyXML(ctx, sc, p) + "<IsAttachable>true</IsAttachable><PolicyVersionList>")
				def := defaultVersion(p)
				for _, id := range sortedVersions(p) {
					doc, _ := versionDocument(p, id)
					b.WriteString("<member><Document>" + xmlEscape(encodeDocument(doc)) + "</Document><VersionId>" + xmlEscape(id) +
						"</VersionId><IsDefaultVersion>" + strconv.FormatBool(id == def) + "</IsDefaultVersion><CreateDate>" +
						versionCreated(p, id) + "</CreateDate></member>")
				}
				b.WriteString("</PolicyVersionList></member>")
			}
		}
		b.WriteString("</Policies>")
	}
	b.WriteString("<IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "GetAccountAuthorizationDetails", b.String())
}

// trustDocument is a role's trust policy as IAM returns it: as it was written, else built from spec.trust.
func (h *iamHandler) trustDocument(sc iamScope, u *unstructured.Unstructured) string {
	if doc := u.GetAnnotations()[assumeRolePolicyAnnotation]; doc != "" {
		return doc
	}
	trust, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "trust")
	var principals []string
	for _, t := range trust {
		switch {
		case t == "*":
			principals = append(principals, sc.arn("root"))
		case strings.HasPrefix(t, "arn:"):
			principals = append(principals, t)
		case strings.HasPrefix(t, "Role::"):
			principals = append(principals, sc.arn("role/"+strings.TrimPrefix(t, "Role::")))
		default:
			principals = append(principals, sc.arn("user/"+t))
		}
	}
	if len(principals) == 0 {
		return ""
	}
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
		"Effect": "Allow", "Principal": map[string]any{"AWS": principals}, "Action": "sts:AssumeRole"}}})
	return string(b)
}

// reservedUserName reports whether name is root's, in any case: the user name root is reserved for the
// account's root user, never an IAM user.
func reservedUserName(name string) bool { return strings.EqualFold(name, "root") }
