// SSM Parameter Store front door for the aws-shim (polyhedron#167).
//
// Recognizes SSM requests in the AWS JSON 1.1 protocol (X-Amz-Target: AmazonSSM.<Op>), authenticates them
// through the shared SigV4 path, authorizes them with the one policy world every front door uses (coarse
// impersonated SubjectAccessReview + fine-grained Cedar dataPlane at PER-PARAMETER / PER-PATH-PREFIX
// granularity — a principal scoped to Parameter::/app/a/* is denied /app/b/*), and executes them against a
// Postgres-backed name/version/label store (ssm_store.go).
//
// SecureString relationship (the parity point most often faked): a SecureString value is GENUINELY
// encrypted under a KMS key reachable through the shim's own KMS doorway — the Vault Transit key
// `kms-aws-ssm` (the analog of AWS's `aws/ssm` managed key), with the parameter name bound as AEAD
// associated-data. The plaintext never sits in Postgres; a Postgres compromise yields only ciphertext.
// GetParameter with WithDecryption=false on a SecureString returns the ENCRYPTED value verbatim (exactly
// as AWS does), and WithDecryption=true is a TWO-permission action: it needs ssm:GetParameter AND is
// additionally subject to a kms:Decrypt check on the managed key. In this platform's additive Cedar
// dataPlane (default-allow-unless-governed), that means a principal whose policy DENIES kms:Decrypt (or
// allows it only on other keys) can still read the SecureString CIPHERTEXT but is denied the PLAINTEXT —
// the real AWS split between value-read and key-decrypt, expressed in the dataPlane's own model.
//
// Deliberate carve-outs, refused honestly rather than faked:
//   - Advanced tier / Intelligent-Tiering — refused (ValidationException); Standard tier only (4 KB value
//     cap, no policies/expiration). A parameter reporting Advanced while none of its features work is a
//     false-green.
//   - Parameter policies (Expiration/NoChangeNotification) — an Advanced-tier feature; not offered.
//   - a caller-supplied non-default KeyId on a SecureString is REFUSED (the value is always under the
//     managed key), rather than accepted-and-ignored.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// ssmDefaultKeyID is the transit key id (→ Vault key kms-aws-ssm, matched by the aws-shim-kms policy's
// kms-* prefix) that protects SecureString values — the analog of AWS's aws/ssm managed key.
const ssmDefaultKeyID = "aws-ssm"

// ssmMaxValueStandard is the Standard-tier value size cap (4 KB). Advanced tier (8 KB) is refused.
const ssmMaxValueStandard = 4096

type ssmHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	transit *vaultTransit // nil => Vault not configured (SecureString answers honest 501)
	store   *ssmStore     // nil => data layer not configured (honest 501)
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger

	keyMu    sync.Mutex
	keyReady bool
}

func newSSMHandler(cs kubernetes.Interface, authzNS, account, region string, transit *vaultTransit, store *ssmStore, logger *slog.Logger) *ssmHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &ssmHandler{cs: cs, authzNS: authzNS, account: account, region: region, transit: transit, store: store, logger: logger}
}

// --- error dialect (AWS JSON 1.1) ---

func writeSSMError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeSSMJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *ssmHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeSSMError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForSSMOp maps an SSM op to its coarse RBAC verb.
func verbForSSMOp(op string) (string, bool) {
	switch op {
	case "GetParameter", "GetParameters", "GetParametersByPath", "DescribeParameters",
		"GetParameterHistory", "ListTagsForResource":
		return "get", true
	case "PutParameter", "LabelParameterVersion", "AddTagsToResource", "RemoveTagsFromResource":
		return "create", true
	case "DeleteParameter", "DeleteParameters":
		return "delete", true
	}
	return "", false
}

func (h *ssmHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
			"No operation named in the X-Amz-Target header (expected AmazonSSM.<Op>).")
		return
	}
	verb, known := verbForSSMOp(op)
	if !known {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
			"SSM "+op+" is not implemented by the open-infra shim.")
		return
	}
	body := readJSONBody(r)

	// The parameter (or path prefix) this op scopes to, for authz. Batch ops carry no single name — their
	// per-name Cedar checks happen inside the op.
	resName := ssmScopeName(op, body)

	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// One policy world: coarse impersonated SubjectAccessReview.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, resName); !allowed {
		h.auditDeny(ctx, op, resName, reason)
		writeSSMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, per-parameter / per-path. For batch ops (GetParameters,
	// DeleteParameters) the check is per-name inside the op; here we gate only the single-resource ops.
	if resName != "" && !ssmBatchOp(op) {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "ssm:"+op, "Parameter", resName, r); denied {
			h.auditDeny(ctx, op, resName, reason)
			writeSSMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}
	if h.store == nil {
		writeSSMError(w, http.StatusNotImplemented, "InternalServerError", requestID,
			"the SSM data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}

	switch op {
	case "PutParameter":
		h.putParameter(ctx, w, r, requestID, body, claims)
	case "GetParameter":
		h.getParameter(ctx, w, r, requestID, body, claims)
	case "GetParameters":
		h.getParameters(ctx, w, r, requestID, body, claims)
	case "GetParametersByPath":
		h.getParametersByPath(ctx, w, r, requestID, body, claims)
	case "DeleteParameter":
		h.deleteParameter(ctx, w, requestID, resName)
	case "DeleteParameters":
		h.deleteParameters(ctx, w, r, requestID, body, claims)
	case "DescribeParameters":
		h.describeParameters(ctx, w, requestID, body)
	case "GetParameterHistory":
		h.getParameterHistory(ctx, w, r, requestID, body, resName, claims)
	case "LabelParameterVersion":
		h.labelParameterVersion(ctx, w, requestID, body, resName)
	case "AddTagsToResource", "RemoveTagsFromResource":
		h.changeTags(ctx, w, requestID, body, op == "AddTagsToResource")
	case "ListTagsForResource":
		h.listTags(ctx, w, requestID, body)
	default:
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
			"SSM "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// ssmScopeName returns the single resource an op authorizes against (a parameter name or, for
// GetParametersByPath, the path prefix). "" for batch ops and DescribeParameters (account-wide).
func ssmScopeName(op string, body map[string]any) string {
	switch op {
	case "PutParameter", "GetParameter", "DeleteParameter", "GetParameterHistory", "LabelParameterVersion":
		base, _, _ := parseParamRef(strFromBody(body, "Name"))
		return base
	case "GetParametersByPath":
		return normalizePath(strFromBody(body, "Path"))
	case "AddTagsToResource", "RemoveTagsFromResource", "ListTagsForResource":
		if t, _ := body["ResourceType"].(string); t == "Parameter" || t == "" {
			return strFromBody(body, "ResourceId")
		}
	}
	return ""
}

func ssmBatchOp(op string) bool {
	return op == "GetParameters" || op == "DeleteParameters"
}

// --- crypto helpers (SecureString value <-> KMS ciphertext) ---

func (h *ssmHandler) ensureDefaultKey(ctx context.Context) error {
	h.keyMu.Lock()
	defer h.keyMu.Unlock()
	if h.keyReady {
		return nil
	}
	if err := h.transit.createKey(ctx, ssmDefaultKeyID); err != nil {
		return err
	}
	h.keyReady = true
	return nil
}

func (h *ssmHandler) encryptValue(ctx context.Context, name, plaintext string) (string, error) {
	if err := h.ensureDefaultKey(ctx); err != nil {
		return "", err
	}
	aad := base64.StdEncoding.EncodeToString([]byte(name))
	return h.transit.encrypt(ctx, ssmDefaultKeyID, base64.StdEncoding.EncodeToString([]byte(plaintext)), aad)
}

func (h *ssmHandler) decryptValue(ctx context.Context, name, ciphertext string) (string, error) {
	aad := base64.StdEncoding.EncodeToString([]byte(name))
	b64, err := h.transit.decrypt(ctx, ssmDefaultKeyID, ciphertext, aad)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// canDecrypt implements the second permission of the two-permission WithDecryption model: reading a
// SecureString plaintext needs kms:Decrypt on the managed key, additively to ssm:GetParameter.
func (h *ssmHandler) canDecrypt(ctx context.Context, claims iam.Claims, r *http.Request) bool {
	denied, _ := deniedByDataPlane(ctx, h.authz, claims, "kms:Decrypt", "Key", ssmDefaultKeyID, r)
	return !denied
}

// --- operations ---

func (h *ssmHandler) putParameter(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, claims iam.Claims) {
	name := strFromBody(body, "Name")
	if name == "" || strings.ContainsAny(name, ":") {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
			"PutParameter requires a Name without a ':' qualifier.")
		return
	}
	ptype := strFromBody(body, "Type")
	switch ptype {
	case "String", "StringList", "SecureString":
	case "":
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "PutParameter requires a Type (String | StringList | SecureString).")
		return
	default:
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "Type '"+ptype+"' is not one of String, StringList, SecureString.")
		return
	}
	if tier, _ := body["Tier"].(string); tier == "Advanced" || tier == "Intelligent-Tiering" {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
			"the open-infra shim supports the Standard parameter tier only (4 KB values, no parameter policies); Advanced/Intelligent-Tiering is not offered. Omit Tier.")
		return
	}
	value := strFromBody(body, "Value")
	if value == "" {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "PutParameter requires a Value.")
		return
	}
	if len(value) > ssmMaxValueStandard {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
			"value length exceeds the Standard-tier 4 KB limit (Advanced tier is not offered by this shim).")
		return
	}
	if ptype == "SecureString" {
		if k, _ := body["KeyId"].(string); k != "" && k != ssmDefaultKeyID && k != "alias/aws/ssm" {
			writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID,
				"the open-infra shim protects every SecureString under the default managed key (Vault Transit); a custom KeyId is not supported. Omit KeyId.")
			return
		}
		if h.transit == nil {
			writeSSMError(w, http.StatusNotImplemented, "InternalServerError", requestID,
				"the SecureString crypto backend (Vault Transit) is not configured on this shim (set VAULT_ADDR)")
			return
		}
	}
	overwrite, _ := body["Overwrite"].(bool)

	stored := value
	if ptype == "SecureString" {
		ct, err := h.encryptValue(ctx, name, value)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		stored = ct
	}
	ver, err := h.store.putParam(ctx, name, ptype, stored, overwrite, tagsFromBody(body["Tags"]))
	if err == errParamExists {
		writeSSMError(w, http.StatusBadRequest, "ParameterAlreadyExists", requestID,
			"The parameter already exists. To overwrite this value, set the overwrite option in the request to true.")
		return
	} else if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutParameter", name, "type", ptype, "version", ver)
	writeSSMJSON(w, requestID, map[string]any{"Version": ver, "Tier": "Standard"})
}

func (h *ssmHandler) getParameter(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, claims iam.Claims) {
	raw := strFromBody(body, "Name")
	withDec, _ := body["WithDecryption"].(bool)
	p, ok, err := h.resolveParam(ctx, raw)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "ParameterNotFound", requestID, "Parameter "+raw+" not found.")
		return
	}
	val, aerr := h.renderParamValue(ctx, w, r, requestID, p, withDec, claims)
	if aerr {
		return
	}
	h.audit(ctx, "GetParameter", p.base, "version", p.version, "withDecryption", withDec)
	writeSSMJSON(w, requestID, map[string]any{"Parameter": h.paramJSON(p, val, raw)})
}

func (h *ssmHandler) getParameters(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, claims iam.Claims) {
	names := stringSlice(body["Names"])
	if len(names) == 0 {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "GetParameters requires Names.")
		return
	}
	withDec, _ := body["WithDecryption"].(bool)
	out := make([]any, 0, len(names))
	invalid := make([]any, 0)
	for _, raw := range names {
		base, _, _ := parseParamRef(raw)
		// per-name Cedar
		if denied, _ := deniedByDataPlane(ctx, h.authz, claims, "ssm:GetParameters", "Parameter", base, r); denied {
			invalid = append(invalid, raw)
			continue
		}
		p, ok, err := h.resolveParam(ctx, raw)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !ok {
			invalid = append(invalid, raw)
			continue
		}
		val, aerr := h.renderParamValueBatch(ctx, r, p, withDec, claims)
		if aerr {
			// WithDecryption requested on a SecureString without kms:Decrypt — deny the whole call, as AWS does.
			writeSSMError(w, http.StatusForbidden, "AccessDeniedException", requestID,
				"principal is not permitted kms:Decrypt on the SSM managed key (WithDecryption requires ssm:GetParameters + kms:Decrypt)")
			return
		}
		out = append(out, h.paramJSON(p, val, raw))
	}
	h.audit(ctx, "GetParameters", "", "count", len(out))
	writeSSMJSON(w, requestID, map[string]any{"Parameters": out, "InvalidParameters": invalid})
}

func (h *ssmHandler) getParametersByPath(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, claims iam.Claims) {
	path := normalizePath(strFromBody(body, "Path"))
	if path == "" {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "GetParametersByPath requires a Path.")
		return
	}
	recursive, _ := body["Recursive"].(bool)
	withDec, _ := body["WithDecryption"].(bool)
	rows, err := h.store.byPath(ctx, path, recursive)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		val, _, terr := h.store.getVersion(ctx, row.Name, row.CurrentVer)
		if terr != nil {
			h.internal(w, requestID, terr)
			return
		}
		p := resolvedParam{base: row.Name, ptype: row.Type, version: row.CurrentVer, stored: val, lastModified: row.LastModified}
		rval, aerr := h.renderParamValueBatch(ctx, r, p, withDec, claims)
		if aerr {
			writeSSMError(w, http.StatusForbidden, "AccessDeniedException", requestID,
				"principal is not permitted kms:Decrypt on the SSM managed key (WithDecryption requires kms:Decrypt)")
			return
		}
		out = append(out, h.paramJSON(p, rval, row.Name))
	}
	h.audit(ctx, "GetParametersByPath", path, "count", len(out), "recursive", recursive)
	writeSSMJSON(w, requestID, map[string]any{"Parameters": out})
}

func (h *ssmHandler) deleteParameter(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	ok, err := h.store.deleteParam(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "ParameterNotFound", requestID, "Parameter "+name+" not found.")
		return
	}
	h.audit(ctx, "DeleteParameter", name)
	writeSSMJSON(w, requestID, map[string]any{})
}

func (h *ssmHandler) deleteParameters(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, claims iam.Claims) {
	names := stringSlice(body["Names"])
	deleted := make([]any, 0)
	invalid := make([]any, 0)
	for _, raw := range names {
		base, _, _ := parseParamRef(raw)
		if denied, _ := deniedByDataPlane(ctx, h.authz, claims, "ssm:DeleteParameters", "Parameter", base, r); denied {
			invalid = append(invalid, raw)
			continue
		}
		ok, err := h.store.deleteParam(ctx, base)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if ok {
			deleted = append(deleted, base)
		} else {
			invalid = append(invalid, raw)
		}
	}
	h.audit(ctx, "DeleteParameters", "", "deleted", len(deleted))
	writeSSMJSON(w, requestID, map[string]any{"DeletedParameters": deleted, "InvalidParameters": invalid})
}

func (h *ssmHandler) describeParameters(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	rows, err := h.store.list(ctx, toInt(body["MaxResults"]))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"Name": row.Name, "Type": row.Type, "Version": row.CurrentVer,
			"LastModifiedDate": epoch(row.LastModified), "Tier": "Standard",
			"ARN": h.paramARN(row.Name),
		})
	}
	writeSSMJSON(w, requestID, map[string]any{"Parameters": out})
}

func (h *ssmHandler) getParameterHistory(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, body map[string]any, name string, claims iam.Claims) {
	withDec, _ := body["WithDecryption"].(bool)
	meta, ok, err := h.store.getParam(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "ParameterNotFound", requestID, "Parameter "+name+" not found.")
		return
	}
	hist, err := h.store.history(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	dec := true
	if withDec && meta.Type == "SecureString" {
		dec = h.canDecrypt(ctx, claims, r)
		if !dec {
			writeSSMError(w, http.StatusForbidden, "AccessDeniedException", requestID,
				"principal is not permitted kms:Decrypt on the SSM managed key")
			return
		}
	}
	out := make([]any, 0, len(hist))
	for _, v := range hist {
		value := v.Value
		if meta.Type == "SecureString" && withDec {
			pt, derr := h.decryptValue(ctx, name, v.Value)
			if derr != nil {
				h.internal(w, requestID, derr)
				return
			}
			value = pt
		}
		out = append(out, map[string]any{
			"Name": name, "Type": meta.Type, "Value": value, "Version": v.Version,
			"LastModifiedDate": epoch(v.Created),
		})
	}
	writeSSMJSON(w, requestID, map[string]any{"Parameters": out})
}

func (h *ssmHandler) labelParameterVersion(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	meta, ok, err := h.store.getParam(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "ParameterNotFound", requestID, "Parameter "+name+" not found.")
		return
	}
	ver := meta.CurrentVer
	if v, has := body["ParameterVersion"]; has {
		ver = int64(toInt(v))
	}
	if _, vok, verr := h.store.getVersion(ctx, name, ver); verr != nil {
		h.internal(w, requestID, verr)
		return
	} else if !vok {
		writeSSMError(w, http.StatusBadRequest, "ParameterVersionNotFound", requestID, "The requested parameter version was not found.")
		return
	}
	labels := stringSlice(body["Labels"])
	invalid := make([]any, 0)
	for _, l := range labels {
		if l == "" || (l[0] >= '0' && l[0] <= '9') || strings.HasPrefix(l, "aws") || strings.HasPrefix(l, "ssm") {
			invalid = append(invalid, l) // AWS rejects labels starting with a digit or reserved prefixes
			continue
		}
		if err := h.store.labelVersion(ctx, name, l, ver); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "LabelParameterVersion", name, "version", ver)
	writeSSMJSON(w, requestID, map[string]any{"InvalidLabels": invalid, "ParameterVersion": ver})
}

func (h *ssmHandler) changeTags(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, add bool) {
	name := strFromBody(body, "ResourceId")
	if t, _ := body["ResourceType"].(string); t != "" && t != "Parameter" {
		writeSSMError(w, http.StatusBadRequest, "ValidationException", requestID, "the open-infra shim tags only ResourceType=Parameter.")
		return
	}
	meta, ok, err := h.store.getParam(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "InvalidResourceId", requestID, "Parameter "+name+" not found.")
		return
	}
	tags := meta.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	if add {
		for k, v := range tagsFromBody(body["Tags"]) {
			tags[k] = v
		}
	} else {
		for _, k := range stringSlice(body["TagKeys"]) {
			delete(tags, k)
		}
	}
	if _, err := h.store.setTags(ctx, name, tags); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, map[bool]string{true: "AddTagsToResource", false: "RemoveTagsFromResource"}[add], name)
	writeSSMJSON(w, requestID, map[string]any{})
}

func (h *ssmHandler) listTags(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := strFromBody(body, "ResourceId")
	meta, ok, err := h.store.getParam(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeSSMError(w, http.StatusBadRequest, "InvalidResourceId", requestID, "Parameter "+name+" not found.")
		return
	}
	writeSSMJSON(w, requestID, map[string]any{"TagList": tagList(meta.Tags)})
}

// --- resolution + rendering helpers ---

type resolvedParam struct {
	base         string
	ptype        string
	version      int64
	stored       string // plaintext for String/StringList; KMS ciphertext for SecureString
	lastModified time.Time
}

// resolveParam parses a Name (possibly Name:version or Name:label, or an ARN) and loads that exact version.
func (h *ssmHandler) resolveParam(ctx context.Context, raw string) (resolvedParam, bool, error) {
	base, version, label := parseParamRef(raw)
	meta, ok, err := h.store.getParam(ctx, base)
	if err != nil || !ok {
		return resolvedParam{}, ok, err
	}
	target := meta.CurrentVer
	switch {
	case version > 0:
		target = version
	case label != "":
		v, lok, lerr := h.store.versionForLabel(ctx, base, label)
		if lerr != nil {
			return resolvedParam{}, false, lerr
		}
		if !lok {
			return resolvedParam{}, false, nil
		}
		target = v
	}
	val, vok, verr := h.store.getVersion(ctx, base, target)
	if verr != nil || !vok {
		return resolvedParam{}, vok, verr
	}
	return resolvedParam{base: base, ptype: meta.Type, version: target, stored: val, lastModified: meta.LastModified}, true, nil
}

// renderParamValue decides the Value to return for a single-param op, applying the two-permission
// WithDecryption gate. Returns (value, wroteError).
func (h *ssmHandler) renderParamValue(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, p resolvedParam, withDec bool, claims iam.Claims) (string, bool) {
	if p.ptype != "SecureString" {
		return p.stored, false
	}
	if !withDec {
		return p.stored, false // ciphertext verbatim, exactly as AWS returns
	}
	if !h.canDecrypt(ctx, claims, r) {
		writeSSMError(w, http.StatusForbidden, "AccessDeniedException", requestID,
			"principal is not permitted kms:Decrypt on the SSM managed key (WithDecryption requires ssm:GetParameter + kms:Decrypt)")
		return "", true
	}
	pt, err := h.decryptValue(ctx, p.base, p.stored)
	if err != nil {
		h.internal(w, requestID, err)
		return "", true
	}
	return pt, false
}

// renderParamValueBatch is the batch analog: on a decryption-permission failure it returns aerr=true
// (the caller turns that into a whole-call AccessDenied) rather than writing directly.
func (h *ssmHandler) renderParamValueBatch(ctx context.Context, r *http.Request, p resolvedParam, withDec bool, claims iam.Claims) (string, bool) {
	if p.ptype != "SecureString" || !withDec {
		return p.stored, false
	}
	if !h.canDecrypt(ctx, claims, r) {
		return "", true
	}
	pt, err := h.decryptValue(ctx, p.base, p.stored)
	if err != nil {
		return "", true
	}
	return pt, false
}

func (h *ssmHandler) paramJSON(p resolvedParam, value, selector string) map[string]any {
	return map[string]any{
		"Name": p.base, "Type": p.ptype, "Value": value, "Version": p.version,
		"LastModifiedDate": epoch(p.lastModified),
		"ARN":              h.paramARN(p.base),
		"Selector":         selectorSuffix(selector),
		"DataType":         "text",
	}
}

func (h *ssmHandler) paramARN(name string) string {
	if strings.HasPrefix(name, "/") {
		return "arn:aws:ssm:" + h.region + ":" + h.account + ":parameter" + name
	}
	return "arn:aws:ssm:" + h.region + ":" + h.account + ":parameter/" + name
}

func (h *ssmHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("ssm backend error", "error", err.Error())
	writeSSMError(w, http.StatusInternalServerError, "InternalServerError", requestID, "An error occurred on the server side.")
}

func (h *ssmHandler) audit(ctx context.Context, op, name string, kv ...any) {
	args := []any{"service", "ssm", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if name != "" {
		args = append(args, "parameter", name)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "ssm audit", args...)
}

func (h *ssmHandler) auditDeny(ctx context.Context, op, name, reason string) {
	args := []any{"service", "ssm", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if name != "" {
		args = append(args, "parameter", name)
	}
	h.logger.InfoContext(ctx, "ssm audit", args...)
}

// --- pure helpers ---

// parseParamRef splits an SSM Name reference into its base name and an optional version or label
// qualifier. Accepts "name", "name:3" (version), "name:prod" (label), and the parameter ARN form.
func parseParamRef(raw string) (base string, version int64, label string) {
	base = raw
	if strings.HasPrefix(raw, "arn:") {
		if i := strings.Index(raw, ":parameter"); i >= 0 {
			base = raw[i+len(":parameter"):]
		}
	}
	// a version/label qualifier is the segment after the FIRST ':' that is not part of an ARN prefix.
	if i := strings.Index(base, ":"); i >= 0 {
		qual := base[i+1:]
		base = base[:i]
		if n, err := strconv.ParseInt(qual, 10, 64); err == nil && n > 0 {
			version = n
		} else {
			label = qual
		}
	}
	return base, version, label
}

// selectorSuffix echoes the version/label qualifier a caller used (AWS returns it in Parameter.Selector).
func selectorSuffix(raw string) string {
	base := raw
	if strings.HasPrefix(raw, "arn:") {
		if i := strings.Index(raw, ":parameter"); i >= 0 {
			base = raw[i+len(":parameter"):]
		}
	}
	if i := strings.Index(base, ":"); i >= 0 {
		return base[i:]
	}
	return ""
}

// normalizePath trims a trailing slash from a GetParametersByPath prefix (except the root "/").
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		return p[:len(p)-1]
	}
	return p
}
