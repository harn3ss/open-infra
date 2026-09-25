// Secrets Manager front door for the aws-shim (polyhedron#161).
//
// Recognizes Secrets Manager requests in the AWS JSON protocol (X-Amz-Target: secretsmanager.<Op>),
// authenticates them through the shared SigV4 path, authorizes them with the one policy world every front
// door uses (coarse SubjectAccessReview + fine-grained Cedar dataPlane at PER-SECRET granularity — this
// is where secretsmanager:GetSecretValue is separable from secretsmanager:DescribeSecret), and executes
// them against a Postgres-backed version/staging store (secrets_store.go).
//
// KMS relationship (the issue's item 6, decided): every secret value is genuinely encrypted under a KMS
// key reachable through the shim's own KMS doorway — the Vault Transit key `kms-aws-secretsmanager` (the
// analog of AWS's `aws/secretsmanager` managed key), with the secret name bound as AEAD associated-data.
// The value never sits in Postgres as plaintext; a Postgres compromise yields only ciphertext. A
// caller-supplied non-default KmsKeyId is REFUSED honestly (InvalidParameterException) rather than
// accepted-and-ignored — the caller must not believe they chose a key we did not use.
//
// Deliberate carve-outs, refused honestly rather than faked:
//   - automatic/scheduled rotation — RotateSecret is refused (a secret reporting RotationEnabled that
//     never rotates is a compliance false-green); the versioning + staging machinery that MAKES rotation
//     possible is implemented.
//   - resource policies (PutResourcePolicy) — authorization is the one Cedar policy world.
//
// This doorway is Vault/KMS-backed with its own path scoping; it is NOT generic read access to Kubernetes
// Secrets, so it does not bypass the shim's KEYS_NAMESPACE boundary (main.go). See docs/aws-shim.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// smDefaultKeyID is the transit key id (→ Vault key kms-aws-secretsmanager) that protects secrets when
// the caller does not choose one — the analog of AWS's aws/secretsmanager managed key.
const smDefaultKeyID = "aws-secretsmanager"

type secretsHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	transit *vaultTransit // nil => Vault not configured (honest 501)
	store   *secretsStore // nil => data layer not configured (honest 501)
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger

	keyMu    sync.Mutex
	keyReady bool
}

func newSecretsHandler(cs kubernetes.Interface, authzNS, account, region string, transit *vaultTransit, store *secretsStore, logger *slog.Logger) *secretsHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &secretsHandler{cs: cs, authzNS: authzNS, account: account, region: region, transit: transit, store: store, logger: logger}
}

// --- error dialect (AWS JSON 1.1) ---

func writeSMError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeSMJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *secretsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeSMError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForSMOp maps a Secrets Manager op to its coarse RBAC verb. DescribeSecret and GetSecretValue are
// BOTH "get" for the coarse gate but carry different fine-grained Cedar actions, so a principal can hold
// metadata-read (DescribeSecret) without value-read (GetSecretValue) — a real, common split.
func verbForSMOp(op string) (string, bool) {
	switch op {
	case "GetSecretValue", "DescribeSecret", "ListSecrets", "ListSecretVersionIds", "GetRandomPassword":
		return "get", true
	case "CreateSecret", "PutSecretValue", "UpdateSecret", "TagResource", "UntagResource",
		"UpdateSecretVersionStage", "RestoreSecret", "RotateSecret", "CancelRotateSecret":
		return "create", true
	case "DeleteSecret":
		return "delete", true
	}
	return "", false
}

func (h *secretsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"No operation named in the X-Amz-Target header (expected secretsmanager.<Op>).")
		return
	}
	verb, known := verbForSMOp(op)
	if !known {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"Secrets Manager "+op+" is not implemented by the open-infra shim.")
		return
	}
	body := readJSONBody(r)

	// The secret this op scopes to (for authz + policy), as a NAME. CreateSecret carries Name; the rest
	// carry SecretId (a name or an ARN). GetRandomPassword/ListSecrets have none.
	secretName := ""
	if op == "CreateSecret" {
		secretName, _ = body["Name"].(string)
	} else if id, _ := body["SecretId"].(string); id != "" {
		secretName = secretNameFromID(id)
	}

	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// One policy world: coarse impersonated SubjectAccessReview.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, secretName); !allowed {
		h.auditDeny(ctx, op, secretName, reason)
		writeSMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, per-secret. This is where GetSecretValue is separable from
	// DescribeSecret and where a principal scoped to secret A is denied secret B.
	if secretName != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "secretsmanager:"+op, "Secret", secretName, r); denied {
			h.auditDeny(ctx, op, secretName, reason)
			writeSMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}
	if h.transit == nil {
		writeSMError(w, http.StatusNotImplemented, "InternalServiceError", requestID,
			"the Secrets Manager crypto backend (Vault Transit) is not configured on this shim (set VAULT_ADDR)")
		return
	}
	if h.store == nil {
		writeSMError(w, http.StatusNotImplemented, "InternalServiceError", requestID,
			"the Secrets Manager data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}

	switch op {
	case "CreateSecret":
		h.createSecret(ctx, w, requestID, body)
	case "GetSecretValue":
		h.getSecretValue(ctx, w, requestID, body, secretName)
	case "PutSecretValue":
		h.putSecretValue(ctx, w, requestID, body, secretName)
	case "UpdateSecret":
		h.updateSecret(ctx, w, requestID, body, secretName)
	case "DescribeSecret":
		h.describeSecret(ctx, w, requestID, secretName)
	case "ListSecrets":
		h.listSecrets(ctx, w, requestID, body)
	case "ListSecretVersionIds":
		h.listSecretVersionIds(ctx, w, requestID, secretName)
	case "DeleteSecret":
		h.deleteSecret(ctx, w, requestID, body, secretName)
	case "RestoreSecret":
		h.restoreSecret(ctx, w, requestID, secretName)
	case "TagResource":
		h.tagResource(ctx, w, requestID, body, secretName, true)
	case "UntagResource":
		h.tagResource(ctx, w, requestID, body, secretName, false)
	case "UpdateSecretVersionStage":
		h.updateSecretVersionStage(ctx, w, requestID, body, secretName)
	case "GetRandomPassword":
		h.getRandomPassword(ctx, w, requestID, body)
	case "RotateSecret", "CancelRotateSecret":
		// Honest refusal — the machinery for rotation exists (versions + staging labels) but scheduled
		// rotation does not fire, and a secret that claims rotation while nothing rotates is a false-green.
		writeSMError(w, http.StatusBadRequest, "InvalidRequestException", requestID,
			"automatic rotation is not supported by the open-infra shim; manage rotation with PutSecretValue + UpdateSecretVersionStage (the AWSCURRENT/AWSPENDING/AWSPREVIOUS machinery is implemented).")
	default:
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"Secrets Manager "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- crypto helpers (value <-> KMS ciphertext) ---

// ensureDefaultKey creates the default managed transit key on first use (idempotent in Vault). Retried
// until it succeeds, so a transient Vault error does not permanently wedge the doorway.
func (h *secretsHandler) ensureDefaultKey(ctx context.Context) error {
	h.keyMu.Lock()
	defer h.keyMu.Unlock()
	if h.keyReady {
		return nil
	}
	if err := h.transit.createKey(ctx, smDefaultKeyID); err != nil {
		return err
	}
	h.keyReady = true
	return nil
}

// encryptValue wraps a value under the default managed key, binding the secret name as AAD. plaintextB64
// is base64 of the raw value bytes (SecretString => base64(utf8), SecretBinary => the blob as sent).
func (h *secretsHandler) encryptValue(ctx context.Context, name, plaintextB64 string) (string, error) {
	if err := h.ensureDefaultKey(ctx); err != nil {
		return "", err
	}
	aad := base64.StdEncoding.EncodeToString([]byte(name))
	return h.transit.encrypt(ctx, smDefaultKeyID, plaintextB64, aad)
}

func (h *secretsHandler) decryptValue(ctx context.Context, name, ciphertext string) (string, error) {
	aad := base64.StdEncoding.EncodeToString([]byte(name))
	return h.transit.decrypt(ctx, smDefaultKeyID, ciphertext, aad)
}

// valueFromBody extracts the value (as base64 plaintext for transit) and whether it is binary. Returns
// ok=false if neither SecretString nor SecretBinary is present.
func valueFromBody(body map[string]any) (plaintextB64 string, isBinary, ok bool) {
	if s, has := body["SecretString"].(string); has {
		return base64.StdEncoding.EncodeToString([]byte(s)), false, true
	}
	if b, has := body["SecretBinary"].(string); has && b != "" {
		return b, true, true // JSON blob == base64 of the raw bytes already
	}
	return "", false, false
}

// renderValue turns a decrypted base64 plaintext back into the response field the client wrote.
func renderValue(out map[string]any, plaintextB64 string, isBinary bool) {
	if isBinary {
		out["SecretBinary"] = plaintextB64 // JSON blob == base64
		return
	}
	if raw, err := base64.StdEncoding.DecodeString(plaintextB64); err == nil {
		out["SecretString"] = string(raw)
	}
}

// --- operations ---

func (h *secretsHandler) createSecret(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["Name"].(string)
	if name == "" {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "CreateSecret requires a Name.")
		return
	}
	if bad := h.rejectCustomKMS(w, requestID, body); bad {
		return
	}
	pt, isBinary, ok := valueFromBody(body)
	if !ok {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"CreateSecret requires either SecretString or SecretBinary.")
		return
	}
	ct, err := h.encryptValue(ctx, name, pt)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	versionID := clientTokenOrUUID(body)
	arn := h.secretARN(name)
	m := secretMeta{Name: name, Arn: arn, Description: strFromBody(body, "Description"), Tags: tagsFromBody(body["Tags"])}
	if err := h.store.createSecret(ctx, m, versionID, ct, isBinary); err == errSecretExists {
		writeSMError(w, http.StatusBadRequest, "ResourceExistsException", requestID,
			"The operation failed because the secret "+name+" already exists.")
		return
	} else if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateSecret", name, "versionId", versionID)
	writeSMJSON(w, requestID, map[string]any{"ARN": arn, "Name": name, "VersionId": versionID})
}

func (h *secretsHandler) getSecretValue(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	if m.DeletedAt.Valid {
		writeSMError(w, http.StatusBadRequest, "InvalidRequestException", requestID,
			"You can't perform this operation on the secret because it was marked for deletion.")
		return
	}
	var versionID, ct string
	var isBinary bool
	if vid, _ := body["VersionId"].(string); vid != "" {
		c, b, found, err := h.store.versionByID(ctx, m.Name, vid)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !found {
			writeSMError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "The requested version was not found.")
			return
		}
		versionID, ct, isBinary = vid, c, b
	} else {
		stage := strFromBody(body, "VersionStage")
		if stage == "" {
			stage = "AWSCURRENT"
		}
		vid, c, b, found, err := h.store.versionByStage(ctx, m.Name, stage)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !found {
			writeSMError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
				"Secrets Manager can't find the specified secret value for staging label: "+stage)
			return
		}
		versionID, ct, isBinary = vid, c, b
	}
	pt, err := h.decryptValue(ctx, m.Name, ct)
	if err != nil {
		writeSMError(w, http.StatusInternalServerError, "DecryptionFailure", requestID,
			"Secrets Manager can't decrypt the protected secret text using the provided KMS key.")
		return
	}
	h.store.touchAccessed(ctx, m.Name)
	stages := h.stagesFor(ctx, m.Name, versionID)
	h.audit(ctx, "GetSecretValue", m.Name, "versionId", versionID, "stages", strings.Join(stages, ","))
	out := map[string]any{"ARN": m.Arn, "Name": m.Name, "VersionId": versionID, "VersionStages": stages, "CreatedDate": epoch(time.Now())}
	renderValue(out, pt, isBinary)
	writeSMJSON(w, requestID, out)
}

func (h *secretsHandler) putSecretValue(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	if m.DeletedAt.Valid {
		writeSMError(w, http.StatusBadRequest, "InvalidRequestException", requestID,
			"You can't perform this operation on the secret because it was marked for deletion.")
		return
	}
	pt, isBinary, ok := valueFromBody(body)
	if !ok {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"PutSecretValue requires either SecretString or SecretBinary.")
		return
	}
	ct, err := h.encryptValue(ctx, m.Name, pt)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	versionID := clientTokenOrUUID(body)
	stages := stringSlice(body["VersionStages"])
	makeCurrent := len(stages) == 0 || containsStr(stages, "AWSCURRENT")
	if err := h.store.putVersion(ctx, m.Name, versionID, ct, isBinary, stages, makeCurrent); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutSecretValue", m.Name, "versionId", versionID)
	writeSMJSON(w, requestID, map[string]any{"ARN": m.Arn, "Name": m.Name, "VersionId": versionID, "VersionStages": h.stagesFor(ctx, m.Name, versionID)})
}

func (h *secretsHandler) updateSecret(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	if m.DeletedAt.Valid {
		writeSMError(w, http.StatusBadRequest, "InvalidRequestException", requestID,
			"You can't perform this operation on the secret because it was marked for deletion.")
		return
	}
	if bad := h.rejectCustomKMS(w, requestID, body); bad {
		return
	}
	if d, has := body["Description"].(string); has {
		if err := h.store.setDescription(ctx, m.Name, d); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	resp := map[string]any{"ARN": m.Arn, "Name": m.Name}
	if pt, isBinary, ok := valueFromBody(body); ok {
		ct, err := h.encryptValue(ctx, m.Name, pt)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		versionID := clientTokenOrUUID(body)
		if err := h.store.putVersion(ctx, m.Name, versionID, ct, isBinary, nil, true); err != nil {
			h.internal(w, requestID, err)
			return
		}
		resp["VersionId"] = versionID
	}
	h.audit(ctx, "UpdateSecret", m.Name)
	writeSMJSON(w, requestID, resp)
}

func (h *secretsHandler) describeSecret(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	v2s, _, err := h.store.stagesByVersion(ctx, m.Name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeSMJSON(w, requestID, h.describeJSON(m, v2s))
}

func (h *secretsHandler) listSecrets(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	secs, err := h.store.listSecrets(ctx, toInt(body["MaxResults"]))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(secs))
	for _, m := range secs {
		e := map[string]any{
			"ARN": m.Arn, "Name": m.Name, "Description": m.Description,
			"CreatedDate": epoch(m.Created), "LastChangedDate": epoch(m.LastChanged),
			"RotationEnabled": false, "Tags": tagList(m.Tags),
		}
		if m.DeletedAt.Valid {
			e["DeletedDate"] = epoch(m.DeletedAt.Time)
		}
		out = append(out, e)
	}
	writeSMJSON(w, requestID, map[string]any{"SecretList": out})
}

func (h *secretsHandler) listSecretVersionIds(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	v2s, order, err := h.store.stagesByVersion(ctx, m.Name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	versions := make([]any, 0, len(order))
	for _, vid := range order {
		versions = append(versions, map[string]any{"VersionId": vid, "VersionStages": v2s[vid]})
	}
	writeSMJSON(w, requestID, map[string]any{"ARN": m.Arn, "Name": m.Name, "Versions": versions})
}

func (h *secretsHandler) deleteSecret(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	force, _ := body["ForceDeleteWithoutRecovery"].(bool)
	_, hasWindow := body["RecoveryWindowInDays"]
	if force && hasWindow {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"You can't use ForceDeleteWithoutRecovery together with RecoveryWindowInDays.")
		return
	}
	if force {
		if err := h.store.forceDelete(ctx, m.Name); err != nil {
			h.internal(w, requestID, err)
			return
		}
		h.audit(ctx, "DeleteSecret", m.Name, "force", "true")
		writeSMJSON(w, requestID, map[string]any{"ARN": m.Arn, "Name": m.Name, "DeletionDate": epoch(time.Now())})
		return
	}
	window := 30
	if v, ok := body["RecoveryWindowInDays"]; ok {
		window = toInt(v)
	}
	if window < 7 || window > 30 {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"RecoveryWindowInDays must be between 7 and 30.")
		return
	}
	deletionDate := time.Now().Add(time.Duration(window) * 24 * time.Hour)
	if _, err := h.store.scheduleDelete(ctx, m.Name, deletionDate); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteSecret", m.Name, "recoveryWindowDays", window)
	writeSMJSON(w, requestID, map[string]any{"ARN": m.Arn, "Name": m.Name, "DeletionDate": epoch(deletionDate)})
}

func (h *secretsHandler) restoreSecret(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	if _, err := h.store.restore(ctx, m.Name); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "RestoreSecret", m.Name)
	writeSMJSON(w, requestID, map[string]any{"ARN": m.Arn, "Name": m.Name})
}

func (h *secretsHandler) tagResource(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string, add bool) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	tags := m.Tags
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
	if err := h.store.setTags(ctx, m.Name, tags); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, map[bool]string{true: "TagResource", false: "UntagResource"}[add], m.Name)
	writeSMJSON(w, requestID, map[string]any{})
}

func (h *secretsHandler) updateSecretVersionStage(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	m, ok := h.mustSecret(ctx, w, requestID, name)
	if !ok {
		return
	}
	stage := strFromBody(body, "VersionStage")
	if stage == "" {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "VersionStage is required.")
		return
	}
	moveTo := strFromBody(body, "MoveToVersionId")
	removeFrom := strFromBody(body, "RemoveFromVersionId")
	moved, err := h.store.moveStage(ctx, m.Name, stage, moveTo, removeFrom)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !moved {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"The staging label "+stage+" is not currently attached to RemoveFromVersionId.")
		return
	}
	h.audit(ctx, "UpdateSecretVersionStage", m.Name, "stage", stage)
	writeSMJSON(w, requestID, map[string]any{"ARN": m.Arn, "Name": m.Name})
}

func (h *secretsHandler) getRandomPassword(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	length := 32
	if v, ok := body["PasswordLength"]; ok {
		length = toInt(v)
	}
	if length < 1 || length > 4096 {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "PasswordLength must be between 1 and 4096.")
		return
	}
	const lower = "abcdefghijklmnopqrstuvwxyz"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	const punct = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	charset := lower + upper + digits
	if b, _ := body["ExcludePunctuation"].(bool); !b {
		if inc, ok := body["IncludeSpace"].(bool); ok && inc {
			charset += " "
		}
		charset += punct
	} else if inc, ok := body["IncludeSpace"].(bool); ok && inc {
		charset += " "
	}
	if b, _ := body["ExcludeNumbers"].(bool); b {
		charset = strings.ReplaceAll(charset, digits, "")
	}
	if b, _ := body["ExcludeLowercase"].(bool); b {
		charset = strings.ReplaceAll(charset, lower, "")
	}
	if b, _ := body["ExcludeUppercase"].(bool); b {
		charset = strings.ReplaceAll(charset, upper, "")
	}
	if ex, ok := body["ExcludeCharacters"].(string); ok && ex != "" {
		for _, c := range ex {
			charset = strings.ReplaceAll(charset, string(c), "")
		}
	}
	if charset == "" {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "The exclusion options removed every candidate character.")
		return
	}
	buf := make([]byte, length)
	rnd := make([]byte, length)
	if _, err := rand.Read(rnd); err != nil {
		h.internal(w, requestID, err)
		return
	}
	for i := range buf {
		buf[i] = charset[int(rnd[i])%len(charset)]
	}
	h.audit(ctx, "GetRandomPassword", "", "length", length)
	writeSMJSON(w, requestID, map[string]any{"RandomPassword": string(buf)})
}

// --- helpers ---

func (h *secretsHandler) mustSecret(ctx context.Context, w http.ResponseWriter, requestID, name string) (secretMeta, bool) {
	if name == "" {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "A SecretId is required.")
		return secretMeta{}, false
	}
	m, found, err := h.store.getSecret(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return secretMeta{}, false
	}
	if !found {
		writeSMError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
			"Secrets Manager can't find the specified secret.")
		return secretMeta{}, false
	}
	return m, true
}

// rejectCustomKMS refuses a caller-supplied non-default KmsKeyId honestly (item 6). Returns true if it
// wrote an error.
func (h *secretsHandler) rejectCustomKMS(w http.ResponseWriter, requestID string, body map[string]any) bool {
	if k, _ := body["KmsKeyId"].(string); k != "" && k != smDefaultKeyID && k != "alias/aws/secretsmanager" {
		writeSMError(w, http.StatusBadRequest, "InvalidParameterException", requestID,
			"the open-infra shim protects every secret under the default managed key (Vault Transit); a custom KmsKeyId is not supported. Omit KmsKeyId.")
		return true
	}
	return false
}

func (h *secretsHandler) stagesFor(ctx context.Context, name, versionID string) []string {
	v2s, _, err := h.store.stagesByVersion(ctx, name)
	if err != nil {
		return nil
	}
	return v2s[versionID]
}

func (h *secretsHandler) describeJSON(m secretMeta, v2s map[string][]string) map[string]any {
	stages := map[string]any{}
	for vid, ss := range v2s {
		arr := make([]any, len(ss))
		for i, s := range ss {
			arr[i] = s
		}
		stages[vid] = arr
	}
	out := map[string]any{
		"ARN": m.Arn, "Name": m.Name, "Description": m.Description,
		"KmsKeyId":           "", // default managed key (Vault barrier / transit); documented
		"RotationEnabled":    false,
		"VersionIdsToStages": stages,
		"Tags":               tagList(m.Tags),
		"CreatedDate":        epoch(m.Created),
		"LastChangedDate":    epoch(m.LastChanged),
	}
	if m.LastAccessed.Valid {
		out["LastAccessedDate"] = epoch(m.LastAccessed.Time)
	}
	if m.DeletedAt.Valid {
		out["DeletedDate"] = epoch(m.DeletedAt.Time)
	}
	return out
}

func (h *secretsHandler) secretARN(name string) string {
	sfx := make([]byte, 6)
	_, _ = rand.Read(sfx)
	return "arn:aws:secretsmanager:" + h.region + ":" + h.account + ":secret:" + name + "-" + arnSuffix(sfx)
}

func (h *secretsHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("secretsmanager backend error", "error", err.Error())
	writeSMError(w, http.StatusInternalServerError, "InternalServiceError", requestID, "An error occurred on the server side.")
}

func (h *secretsHandler) audit(ctx context.Context, op, secret string, kv ...any) {
	args := []any{"service", "secretsmanager", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if secret != "" {
		args = append(args, "secret", secret)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "secretsmanager audit", args...)
}

func (h *secretsHandler) auditDeny(ctx context.Context, op, secret, reason string) {
	args := []any{"service", "secretsmanager", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if secret != "" {
		args = append(args, "secret", secret)
	}
	h.logger.InfoContext(ctx, "secretsmanager audit", args...)
}

// --- pure helpers ---

// secretNameFromID resolves a SecretId (a name or an ARN) to the secret name. AWS ARNs append "-XXXXXX"
// (a hyphen + six chars) to the friendly name; strip exactly that when present.
func secretNameFromID(id string) string {
	if i := strings.Index(id, ":secret:"); i >= 0 {
		friendly := id[i+len(":secret:"):]
		if len(friendly) > 7 && friendly[len(friendly)-7] == '-' {
			return friendly[:len(friendly)-7]
		}
		return friendly
	}
	return id
}

func clientTokenOrUUID(body map[string]any) string {
	if t, _ := body["ClientRequestToken"].(string); t != "" {
		return t
	}
	return uuidLike()
}

func strFromBody(body map[string]any, key string) string {
	s, _ := body[key].(string)
	return s
}

func tagsFromBody(v any) map[string]string {
	out := map[string]string{}
	for _, e := range sliceOf(v) {
		if m, ok := e.(map[string]any); ok {
			k, _ := m["Key"].(string)
			val, _ := m["Value"].(string)
			if k != "" {
				out[k] = val
			}
		}
	}
	return out
}

func tagList(tags map[string]string) []any {
	out := make([]any, 0, len(tags))
	for k, v := range tags {
		out = append(out, map[string]any{"Key": k, "Value": v})
	}
	return out
}
