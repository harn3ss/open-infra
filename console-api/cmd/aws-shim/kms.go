// KMS front door for the aws-shim (polyhedron#160).
//
// Recognizes KMS requests in the AWS JSON protocol (the operation named in X-Amz-Target:
// TrentService.<Op>, which is what the SDKs and aws CLI v2 speak), authenticates them through the shared
// SigV4 path, authorizes them with the one policy world every other front door uses (coarse
// SubjectAccessReview + fine-grained Cedar dataPlane at KEY granularity — this is where kms:Encrypt is
// separable from kms:Decrypt), and executes the cryptography in HashiCorp Vault's Transit engine. A CMK
// is a Transit key named "kms-<keyId>"; the key material NEVER leaves Vault, so the trust boundary is
// exactly Vault's, not this process's.
//
// Faithful semantics:
//   - envelope encryption: GenerateDataKey returns a plaintext data key + its ciphertext under the CMK;
//   - EncryptionContext bound as AEAD associated-data (aes256-gcm96) — a decrypt with a different
//     context fails cryptographically, exactly like AWS;
//   - key lifecycle state machine (Enabled/Disabled/PendingDeletion) gating crypto ops;
//   - automatic key rotation (Vault Transit rotate) with old ciphertext still decryptable;
//   - aliases; ScheduleKeyDeletion with a 7–30 day window and CancelKeyDeletion; crypto-erase on expiry.
//
// Deliberate carve-outs, refused honestly rather than faked (never a silent divergence):
//   - asymmetric CMKs (RSA/ECC), HMAC keys, and Sign/Verify/GetPublicKey — v1 is SYMMETRIC_DEFAULT only;
//   - key policies / grants (KMS's own resource-policy language) — authorization is the shim's one
//     policy world (RBAC + Cedar), not a second KMS-native policy engine;
//   - multi-Region keys, custom key stores, imported key material, and tags.
//
// See docs/aws-shim.md for the full divergence list.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type kmsHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	transit *vaultTransit // nil => Vault not configured (honest 501)
	store   *kmsStore     // nil => data layer not configured (honest 501)
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger
}

func newKMSHandler(cs kubernetes.Interface, authzNS, account, region string, transit *vaultTransit, store *kmsStore, logger *slog.Logger) *kmsHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &kmsHandler{cs: cs, authzNS: authzNS, account: account, region: region, transit: transit, store: store, logger: logger}
}

// --- error dialect (AWS JSON 1.1). KMS surfaces the bare exception name in __type. ---

func writeKMSError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeKMSJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *kmsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	// AWS surfaces a SigV4 mismatch as InvalidSignatureException before the service sees it.
	writeKMSError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForKMSOp maps a KMS operation to the coarse RBAC verb its SubjectAccessReview checks. Decrypt is a
// "get" (a read/use) while Encrypt is a "create" (a write/use): a principal allowed to encrypt-but-not-
// decrypt (or the reverse) is a real, deliberate KMS configuration, and the fine-grained Cedar action
// (kms:Encrypt vs kms:Decrypt) enforces the exact separation at key granularity.
func verbForKMSOp(op string) (string, bool) {
	switch op {
	case "DescribeKey", "ListKeys", "ListAliases", "GetKeyRotationStatus", "Decrypt":
		return "get", true
	case "CreateKey", "CreateAlias", "UpdateAlias", "Encrypt", "GenerateDataKey",
		"GenerateDataKeyWithoutPlaintext", "ReEncrypt", "EnableKey", "DisableKey",
		"EnableKeyRotation", "DisableKeyRotation", "CancelKeyDeletion":
		return "create", true
	case "DeleteAlias", "ScheduleKeyDeletion":
		return "delete", true
	}
	return "", false
}

func (h *kmsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeKMSError(w, http.StatusBadRequest, "MissingActionException", requestID,
			"No operation named in the X-Amz-Target header (expected TrentService.<Op>).")
		return
	}
	verb, known := verbForKMSOp(op)
	if !known {
		writeKMSError(w, http.StatusBadRequest, "InvalidActionException", requestID,
			"KMS "+op+" is not implemented by the open-infra shim.")
		return
	}
	body := readJSONBody(r)

	// The key this op scopes to (for authz + policy), resolved to a canonical key id — accepting a raw id,
	// a key ARN, an alias name, or an alias ARN. Ops without a key (CreateKey, ListKeys, ListAliases) have
	// none. A key ref that does not resolve is reported as NotFound in the handler; here a miss just leaves
	// the scope empty (the coarse gate still applies).
	keyRef := firstString(body, "KeyId", "TargetKeyId")
	// Decrypt and ReEncrypt do not carry the key in KeyId — Decrypt's key is embedded in the ciphertext
	// blob, and ReEncrypt's write target is DestinationKeyId. Resolve those so the fine-grained Cedar scope
	// is correct: this is what makes kms:Decrypt independently deniable from kms:Encrypt on the same key.
	scopeRef := keyRef
	if scopeRef == "" {
		switch op {
		case "Decrypt":
			if blob, _ := body["CiphertextBlob"].(string); blob != "" {
				if id, _, err := decodeBlob(blob); err == nil {
					scopeRef = id
				}
			}
		case "ReEncrypt":
			scopeRef = firstString(body, "DestinationKeyId")
		}
	}
	scopeKeyID := ""
	if scopeRef != "" {
		if id, ok, _ := h.resolveKeyID(r.Context(), scopeRef); ok {
			scopeKeyID = id
		}
	}

	// One policy world: the coarse impersonated SubjectAccessReview (resource-agnostic, as every front door in v1).
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, scopeKeyID); !allowed {
		writeKMSError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	// Fine-grained Cedar dataPlane — additive, can only tighten. Scoped to the key when we have one; this
	// is where kms:Encrypt is separable from kms:Decrypt for the same principal on the same key.
	if scopeKeyID != "" {
		if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "kms:"+op, "Key", scopeKeyID, r); denied {
			writeKMSError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}
	if h.transit == nil {
		writeKMSError(w, http.StatusNotImplemented, "KMSInternalException", requestID,
			"the KMS crypto backend (Vault Transit) is not configured on this shim (set VAULT_ADDR)")
		return
	}
	if h.store == nil {
		writeKMSError(w, http.StatusNotImplemented, "KMSInternalException", requestID,
			"the KMS metadata store is not configured on this shim (set SQS_PG_URI)")
		return
	}

	ctx := r.Context()
	switch op {
	case "CreateKey":
		h.createKey(ctx, w, requestID, body)
	case "DescribeKey":
		h.describeKey(ctx, w, requestID, keyRef)
	case "ListKeys":
		h.listKeys(ctx, w, requestID, body)
	case "CreateAlias":
		h.createAlias(ctx, w, requestID, body)
	case "UpdateAlias":
		h.updateAlias(ctx, w, requestID, body)
	case "DeleteAlias":
		h.deleteAlias(ctx, w, requestID, body)
	case "ListAliases":
		h.listAliases(ctx, w, requestID, body)
	case "Encrypt":
		h.encrypt(ctx, w, requestID, body)
	case "Decrypt":
		h.decrypt(ctx, w, requestID, body)
	case "GenerateDataKey":
		h.generateDataKey(ctx, w, requestID, body, true)
	case "GenerateDataKeyWithoutPlaintext":
		h.generateDataKey(ctx, w, requestID, body, false)
	case "ReEncrypt":
		h.reEncrypt(ctx, w, requestID, body)
	case "EnableKey":
		h.setKeyEnabled(ctx, w, requestID, keyRef, true)
	case "DisableKey":
		h.setKeyEnabled(ctx, w, requestID, keyRef, false)
	case "EnableKeyRotation":
		h.setRotation(ctx, w, requestID, keyRef, true)
	case "DisableKeyRotation":
		h.setRotation(ctx, w, requestID, keyRef, false)
	case "GetKeyRotationStatus":
		h.getKeyRotationStatus(ctx, w, requestID, keyRef)
	case "ScheduleKeyDeletion":
		h.scheduleKeyDeletion(ctx, w, requestID, body)
	case "CancelKeyDeletion":
		h.cancelKeyDeletion(ctx, w, requestID, keyRef)
	default:
		writeKMSError(w, http.StatusBadRequest, "InvalidActionException", requestID,
			"KMS "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// --- key lifecycle ---

func (h *kmsHandler) createKey(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	usage, _ := body["KeyUsage"].(string)
	if usage != "" && usage != "ENCRYPT_DECRYPT" {
		writeKMSError(w, http.StatusBadRequest, "UnsupportedOperationException", requestID,
			"the open-infra shim supports only KeyUsage=ENCRYPT_DECRYPT (symmetric) keys.")
		return
	}
	spec, _ := body["KeySpec"].(string)
	if spec == "" {
		spec, _ = body["CustomerMasterKeySpec"].(string)
	}
	if spec != "" && spec != "SYMMETRIC_DEFAULT" {
		writeKMSError(w, http.StatusBadRequest, "UnsupportedOperationException", requestID,
			"the open-infra shim supports only KeySpec=SYMMETRIC_DEFAULT keys.")
		return
	}
	desc, _ := body["Description"].(string)

	keyID := uuidLike()
	if err := h.transit.createKey(ctx, keyID); err != nil {
		h.internal(w, requestID, err)
		return
	}
	m := keyMeta{
		KeyID:       keyID,
		Arn:         h.keyARN(keyID),
		Description: desc,
		KeyUsage:    "ENCRYPT_DECRYPT",
		KeySpec:     "SYMMETRIC_DEFAULT",
		State:       "Enabled",
		Created:     time.Now(),
	}
	if err := h.store.createKey(ctx, m); err != nil {
		// Roll back the Vault key so a metadata failure does not orphan crypto material.
		_ = h.transit.destroy(ctx, keyID)
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateKey", keyID, "")
	writeKMSJSON(w, requestID, map[string]any{"KeyMetadata": h.keyMetadataJSON(m)})
}

func (h *kmsHandler) describeKey(ctx context.Context, w http.ResponseWriter, requestID, keyRef string) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	writeKMSJSON(w, requestID, map[string]any{"KeyMetadata": h.keyMetadataJSON(m)})
}

func (h *kmsHandler) listKeys(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	limit := toInt(body["Limit"])
	keys, err := h.store.listKeys(ctx, limit)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(keys))
	for _, m := range keys {
		out = append(out, map[string]any{"KeyId": m.KeyID, "KeyArn": m.Arn})
	}
	writeKMSJSON(w, requestID, map[string]any{"Keys": out, "Truncated": false})
}

func (h *kmsHandler) setKeyEnabled(ctx context.Context, w http.ResponseWriter, requestID, keyRef string, enabled bool) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	if m.State == "PendingDeletion" {
		h.invalidState(w, requestID, m.KeyID, "is pending deletion")
		return
	}
	state := "Disabled"
	if enabled {
		state = "Enabled"
	}
	if _, err := h.store.setState(ctx, m.KeyID, state, nil); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, map[bool]string{true: "EnableKey", false: "DisableKey"}[enabled], m.KeyID, "")
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) setRotation(ctx context.Context, w http.ResponseWriter, requestID, keyRef string, on bool) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	if m.State != "Enabled" {
		h.invalidState(w, requestID, m.KeyID, "is not enabled")
		return
	}
	// Enabling rotation rotates once immediately (Vault has no scheduled rotation); the flag records that
	// automatic rotation is on. This is honestly weaker than AWS's yearly cadence — documented as such.
	if on {
		if err := h.transit.rotate(ctx, m.KeyID); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	if _, err := h.store.setRotation(ctx, m.KeyID, on); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, map[bool]string{true: "EnableKeyRotation", false: "DisableKeyRotation"}[on], m.KeyID, "")
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) getKeyRotationStatus(ctx context.Context, w http.ResponseWriter, requestID, keyRef string) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	writeKMSJSON(w, requestID, map[string]any{"KeyRotationEnabled": m.Rotation})
}

func (h *kmsHandler) scheduleKeyDeletion(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	m, ok := h.mustKey(ctx, w, requestID, firstString(body, "KeyId"))
	if !ok {
		return
	}
	if m.State == "PendingDeletion" {
		h.invalidState(w, requestID, m.KeyID, "is already pending deletion")
		return
	}
	window := 30
	if v, ok := body["PendingWindowInDays"]; ok {
		window = toInt(v)
	}
	if window < 7 || window > 30 {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID,
			"PendingWindowInDays must be between 7 and 30.")
		return
	}
	deletionDate := time.Now().Add(time.Duration(window) * 24 * time.Hour)
	if _, err := h.store.setState(ctx, m.KeyID, "PendingDeletion", &deletionDate); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "ScheduleKeyDeletion", m.KeyID, "")
	writeKMSJSON(w, requestID, map[string]any{
		"KeyId":               m.KeyID,
		"DeletionDate":        epoch(deletionDate),
		"KeyState":            "PendingDeletion",
		"PendingWindowInDays": window,
	})
}

func (h *kmsHandler) cancelKeyDeletion(ctx context.Context, w http.ResponseWriter, requestID, keyRef string) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	if m.State != "PendingDeletion" {
		h.invalidState(w, requestID, m.KeyID, "is not pending deletion")
		return
	}
	// Cancelling deletion restores the key Disabled (AWS's post-cancel state).
	if _, err := h.store.setState(ctx, m.KeyID, "Disabled", nil); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CancelKeyDeletion", m.KeyID, "")
	writeKMSJSON(w, requestID, map[string]any{"KeyId": m.KeyID, "KeyState": "Disabled"})
}

// --- aliases ---

func (h *kmsHandler) createAlias(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["AliasName"].(string)
	if !strings.HasPrefix(name, "alias/") {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, "AliasName must begin with \"alias/\".")
		return
	}
	target := firstString(body, "TargetKeyId")
	m, ok := h.mustKey(ctx, w, requestID, target)
	if !ok {
		return
	}
	if err := h.store.createAlias(ctx, name, m.KeyID); err == errAliasExists {
		writeKMSError(w, http.StatusBadRequest, "AlreadyExistsException", requestID, "An alias with this name already exists.")
		return
	} else if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateAlias", m.KeyID, name)
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) updateAlias(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["AliasName"].(string)
	target := firstString(body, "TargetKeyId")
	m, ok := h.mustKey(ctx, w, requestID, target)
	if !ok {
		return
	}
	updated, err := h.store.updateAlias(ctx, name, m.KeyID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !updated {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID, "The specified alias does not exist.")
		return
	}
	h.audit(ctx, "UpdateAlias", m.KeyID, name)
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) deleteAlias(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["AliasName"].(string)
	ok, err := h.store.deleteAlias(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID, "The specified alias does not exist.")
		return
	}
	h.audit(ctx, "DeleteAlias", "", name)
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) listAliases(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	filter := ""
	if ref := firstString(body, "KeyId"); ref != "" {
		if id, ok, _ := h.resolveKeyID(ctx, ref); ok {
			filter = id
		}
	}
	aliases, err := h.store.listAliases(ctx, filter)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, map[string]any{
			"AliasName":       a.Name,
			"AliasArn":        h.aliasARN(a.Name),
			"TargetKeyId":     a.KeyID,
			"CreationDate":    epoch(a.Created),
			"LastUpdatedDate": epoch(a.Updated),
		})
	}
	writeKMSJSON(w, requestID, map[string]any{"Aliases": out, "Truncated": false})
}

// --- cryptography (Vault Transit) ---

func (h *kmsHandler) encrypt(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	m, ok := h.mustUsableKey(ctx, w, requestID, firstString(body, "KeyId"))
	if !ok {
		return
	}
	plaintext, _ := body["Plaintext"].(string) // JSON blob == base64 already
	if plaintext == "" {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, "Plaintext must not be empty.")
		return
	}
	aad, err := encryptionContextAAD(body["EncryptionContext"])
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
		return
	}
	ct, err := h.transit.encrypt(ctx, m.KeyID, plaintext, aad)
	if err != nil {
		h.cryptoErr(w, requestID, err)
		return
	}
	h.audit(ctx, "Encrypt", m.KeyID, "")
	writeKMSJSON(w, requestID, map[string]any{
		"CiphertextBlob":      encodeBlob(m.KeyID, ct),
		"KeyId":               m.Arn,
		"EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
	})
}

func (h *kmsHandler) decrypt(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	blob, _ := body["CiphertextBlob"].(string)
	keyID, ct, err := decodeBlob(blob)
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "InvalidCiphertextException", requestID,
			"The ciphertext refers to a ciphertext blob that is not valid.")
		return
	}
	// A caller MAY pin KeyId on Decrypt; if they do, it must match the blob's key (AWS behavior).
	if pin := firstString(body, "KeyId"); pin != "" {
		if id, ok, _ := h.resolveKeyID(ctx, pin); ok && id != keyID {
			writeKMSError(w, http.StatusBadRequest, "IncorrectKeyException", requestID,
				"The key ID in the request does not identify a CMK that can perform this operation.")
			return
		}
	}
	m, ok := h.mustUsableKey(ctx, w, requestID, keyID)
	if !ok {
		return
	}
	aad, err := encryptionContextAAD(body["EncryptionContext"])
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
		return
	}
	plaintext, err := h.transit.decrypt(ctx, m.KeyID, ct, aad)
	if err != nil {
		// A wrong/absent EncryptionContext or tampered ciphertext fails the AEAD tag check in Vault (400).
		if isVaultBadRequest(err) {
			writeKMSError(w, http.StatusBadRequest, "InvalidCiphertextException", requestID,
				"The ciphertext refers to a ciphertext blob that is not valid, or the EncryptionContext does not match.")
			return
		}
		h.cryptoErr(w, requestID, err)
		return
	}
	h.audit(ctx, "Decrypt", m.KeyID, "")
	writeKMSJSON(w, requestID, map[string]any{
		"Plaintext":           plaintext, // Vault returns base64; JSON blob == base64
		"KeyId":               m.Arn,
		"EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
	})
}

func (h *kmsHandler) generateDataKey(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, withPlaintext bool) {
	m, ok := h.mustUsableKey(ctx, w, requestID, firstString(body, "KeyId"))
	if !ok {
		return
	}
	n := 32 // AES_256 default
	if spec, _ := body["KeySpec"].(string); spec == "AES_128" {
		n = 16
	}
	if v, ok := body["NumberOfBytes"]; ok {
		n = toInt(v)
		if n < 1 || n > 1024 {
			writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, "NumberOfBytes must be between 1 and 1024.")
			return
		}
	}
	dk := make([]byte, n)
	if _, err := rand.Read(dk); err != nil {
		h.internal(w, requestID, err)
		return
	}
	plaintextB64 := base64.StdEncoding.EncodeToString(dk)
	aad, err := encryptionContextAAD(body["EncryptionContext"])
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
		return
	}
	ct, err := h.transit.encrypt(ctx, m.KeyID, plaintextB64, aad)
	if err != nil {
		h.cryptoErr(w, requestID, err)
		return
	}
	out := map[string]any{"CiphertextBlob": encodeBlob(m.KeyID, ct), "KeyId": m.Arn}
	if withPlaintext {
		out["Plaintext"] = plaintextB64 // JSON blob == base64
	}
	h.audit(ctx, "GenerateDataKey", m.KeyID, "")
	writeKMSJSON(w, requestID, out)
}

func (h *kmsHandler) reEncrypt(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	blob, _ := body["CiphertextBlob"].(string)
	srcKeyID, srcCT, err := decodeBlob(blob)
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "InvalidCiphertextException", requestID,
			"The ciphertext refers to a ciphertext blob that is not valid.")
		return
	}
	srcM, ok := h.mustUsableKey(ctx, w, requestID, srcKeyID)
	if !ok {
		return
	}
	srcAAD, err := encryptionContextAAD(body["SourceEncryptionContext"])
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
		return
	}
	plaintext, err := h.transit.decrypt(ctx, srcM.KeyID, srcCT, srcAAD)
	if err != nil {
		if isVaultBadRequest(err) {
			writeKMSError(w, http.StatusBadRequest, "InvalidCiphertextException", requestID,
				"The source ciphertext is not valid, or the SourceEncryptionContext does not match.")
			return
		}
		h.cryptoErr(w, requestID, err)
		return
	}
	destM, ok := h.mustUsableKey(ctx, w, requestID, firstString(body, "DestinationKeyId"))
	if !ok {
		return
	}
	destAAD, err := encryptionContextAAD(body["DestinationEncryptionContext"])
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
		return
	}
	newCT, err := h.transit.encrypt(ctx, destM.KeyID, plaintext, destAAD)
	if err != nil {
		h.cryptoErr(w, requestID, err)
		return
	}
	h.audit(ctx, "ReEncrypt", destM.KeyID, "from:"+srcM.KeyID)
	writeKMSJSON(w, requestID, map[string]any{
		"CiphertextBlob":                 encodeBlob(destM.KeyID, newCT),
		"SourceKeyId":                    srcM.Arn,
		"KeyId":                          destM.Arn,
		"SourceEncryptionAlgorithm":      "SYMMETRIC_DEFAULT",
		"DestinationEncryptionAlgorithm": "SYMMETRIC_DEFAULT",
	})
}

// --- helpers ---

// mustKey resolves a key ref to its metadata, writing NotFoundException and returning ok=false on a miss.
func (h *kmsHandler) mustKey(ctx context.Context, w http.ResponseWriter, requestID, keyRef string) (keyMeta, bool) {
	if keyRef == "" {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, "A key identifier is required.")
		return keyMeta{}, false
	}
	keyID, ok, err := h.resolveKeyID(ctx, keyRef)
	if err != nil {
		h.internal(w, requestID, err)
		return keyMeta{}, false
	}
	if !ok {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID,
			"Key '"+keyRef+"' does not exist.")
		return keyMeta{}, false
	}
	m, found, err := h.store.getKey(ctx, keyID)
	if err != nil {
		h.internal(w, requestID, err)
		return keyMeta{}, false
	}
	if !found {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID, "Key '"+keyRef+"' does not exist.")
		return keyMeta{}, false
	}
	return m, true
}

// mustUsableKey is mustKey plus the crypto state gate: the key must be Enabled to Encrypt/Decrypt/etc.
func (h *kmsHandler) mustUsableKey(ctx context.Context, w http.ResponseWriter, requestID, keyRef string) (keyMeta, bool) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return keyMeta{}, false
	}
	switch m.State {
	case "Enabled":
		return m, true
	case "Disabled":
		writeKMSError(w, http.StatusBadRequest, "DisabledException", requestID,
			m.Arn+" is disabled.")
		return keyMeta{}, false
	case "PendingDeletion":
		h.invalidState(w, requestID, m.KeyID, "is pending deletion and cannot be used for cryptographic operations")
		return keyMeta{}, false
	}
	h.invalidState(w, requestID, m.KeyID, "is not in a usable state")
	return keyMeta{}, false
}

// resolveKeyID accepts a raw key id, a key ARN, an alias name ("alias/x"), or an alias ARN, and returns
// the canonical key id. A bare id is only accepted if a metadata row exists for it (so a made-up id is a miss).
func (h *kmsHandler) resolveKeyID(ctx context.Context, ref string) (string, bool, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false, nil
	}
	// key ARN: arn:aws:kms:region:account:key/<id>
	if i := strings.Index(ref, ":key/"); i >= 0 {
		ref = ref[i+len(":key/"):]
	}
	// alias ARN: arn:aws:kms:region:account:alias/<name>  ->  alias/<name>
	if i := strings.Index(ref, ":alias/"); i >= 0 {
		ref = "alias/" + ref[i+len(":alias/"):]
	}
	if strings.HasPrefix(ref, "alias/") {
		return h.store.aliasTarget(ctx, ref)
	}
	// bare id — accept only if a key row exists
	if _, found, err := h.store.getKey(ctx, ref); err != nil {
		return "", false, err
	} else if found {
		return ref, true, nil
	}
	return "", false, nil
}

func (h *kmsHandler) keyMetadataJSON(m keyMeta) map[string]any {
	md := map[string]any{
		"AWSAccountId":          h.account,
		"KeyId":                 m.KeyID,
		"Arn":                   m.Arn,
		"CreationDate":          epoch(m.Created),
		"Enabled":               m.State == "Enabled",
		"Description":           m.Description,
		"KeyUsage":              m.KeyUsage,
		"KeyState":              m.State,
		"Origin":                "AWS_KMS",
		"KeyManager":            "CUSTOMER",
		"KeySpec":               m.KeySpec,
		"CustomerMasterKeySpec": m.KeySpec,
		"EncryptionAlgorithms":  []string{"SYMMETRIC_DEFAULT"},
		"MultiRegion":           false,
	}
	if m.DeletionDate.Valid {
		md["DeletionDate"] = epoch(m.DeletionDate.Time)
	}
	return md
}

func (h *kmsHandler) keyARN(keyID string) string {
	return "arn:aws:kms:" + h.region + ":" + h.account + ":key/" + keyID
}

func (h *kmsHandler) aliasARN(name string) string {
	return "arn:aws:kms:" + h.region + ":" + h.account + ":" + name
}

func (h *kmsHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("kms backend error", "error", err.Error())
	writeKMSError(w, http.StatusInternalServerError, "KMSInternalException", requestID, "The server encountered an internal error.")
}

// cryptoErr maps an unexpected Vault crypto error. A 404 from Vault means the CMK material is gone
// (crypto-erased) even though metadata may linger — surface that as NotFound, never a false success.
func (h *kmsHandler) cryptoErr(w http.ResponseWriter, requestID string, err error) {
	var ve *vaultAPIError
	if errors.As(err, &ve) && ve.status == http.StatusNotFound {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID,
			"The key material for this CMK no longer exists.")
		return
	}
	h.internal(w, requestID, err)
}

func (h *kmsHandler) invalidState(w http.ResponseWriter, requestID, keyID, why string) {
	writeKMSError(w, http.StatusBadRequest, "KMSInvalidStateException", requestID,
		h.keyARN(keyID)+" "+why+".")
}

// audit emits a structured audit line for a KMS mutation/crypto op (AC-2/AU-2). The scrubbed fields —
// key id, op, and (for aliases) alias name — never include plaintext or ciphertext.
func (h *kmsHandler) audit(ctx context.Context, op, keyID, extra string) {
	args := []any{"service", "kms", "op", op}
	if keyID != "" {
		args = append(args, "keyId", keyID)
	}
	if extra != "" {
		args = append(args, "detail", extra)
	}
	h.logger.InfoContext(ctx, "kms audit", args...)
}

// reapDeleted crypto-erases keys whose deletion window has elapsed: destroy the Vault Transit key (after
// which no ciphertext can ever be decrypted again), then drop the metadata row. Idempotent.
func (h *kmsHandler) reapDeleted(ctx context.Context) error {
	if h.store == nil || h.transit == nil {
		return nil
	}
	due, err := h.store.dueForDeletion(ctx, time.Now())
	if err != nil {
		return err
	}
	for _, id := range due {
		if err := h.transit.destroy(ctx, id); err != nil {
			h.logger.Warn("kms crypto-erase failed", "keyId", id, "error", err.Error())
			continue
		}
		if err := h.store.deleteKeyRow(ctx, id); err != nil {
			h.logger.Warn("kms metadata delete failed after crypto-erase", "keyId", id, "error", err.Error())
			continue
		}
		h.audit(ctx, "CryptoErase", id, "deletion window elapsed")
	}
	return nil
}

// --- pure helpers ---

// encodeBlob wraps a Vault ciphertext + its key id into the opaque CiphertextBlob the SDK carries.
func encodeBlob(keyID, vaultCT string) string {
	b, _ := json.Marshal(map[string]any{"v": 1, "k": keyID, "c": vaultCT})
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBlob(blob string) (keyID, vaultCT string, err error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob))
	if err != nil {
		return "", "", err
	}
	var env struct {
		V int    `json:"v"`
		K string `json:"k"`
		C string `json:"c"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", "", err
	}
	if env.K == "" || env.C == "" {
		return "", "", errBadBlob
	}
	return env.K, env.C, nil
}

var errBadBlob = &blobError{}

type blobError struct{}

func (*blobError) Error() string { return "invalid ciphertext blob" }

// encryptionContextAAD canonicalizes a KMS EncryptionContext (a string->string map) into the base64 AEAD
// associated-data that binds it at the cipher layer. encoding/json marshals map keys in sorted order, so
// the same context always yields the same AAD. Empty/absent context => "" (no AAD).
func encryptionContextAAD(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return "", nil
	}
	ctx := make(map[string]string, len(m))
	for k, val := range m {
		s, ok := val.(string)
		if !ok {
			return "", errBadContext
		}
		ctx[k] = s
	}
	b, err := json.Marshal(ctx)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

var errBadContext = &contextError{}

type contextError struct{}

func (*contextError) Error() string { return "EncryptionContext values must be strings" }

// isVaultBadRequest reports whether err is a Vault 400 (an AEAD/ciphertext validation failure).
func isVaultBadRequest(err error) bool {
	var ve *vaultAPIError
	return errors.As(err, &ve) && ve.status == http.StatusBadRequest
}

// firstString returns the first present non-empty string value among the given body keys.
func firstString(body map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := body[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// epoch renders a time as KMS's numeric epoch-seconds (the JSON protocol carries timestamps as numbers).
func epoch(t time.Time) float64 { return float64(t.Unix()) }
