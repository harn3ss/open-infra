// KMS front door for the aws-shim.
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
// Key policies: authorization is still the shim's ONE policy world (RBAC + Cedar) — there
// is NO second KMS-native policy engine. But a supplied AWS key-policy JSON (CreateKey's Policy param,
// PutKeyPolicy) is now TRANSLATED into the equivalent kind: Policy spec.dataPlane grants (one CR per
// statement, Allow/Deny kms:<action> on Key::<keyId>, appliesTo the statement's principals) instead of
// being refused, and GetKeyPolicy/ListKeyPolicies round-trip it. The translation is fail-closed (a
// Condition, a non-user/role principal, a foreign Resource, or a non-kms action refuses the whole policy),
// and the default root statement is skipped (it delegates to identity policies). See kms_keypolicy.go.
//
// Deliberate carve-outs, refused honestly rather than faked (never a silent divergence):
//   - asymmetric CMKs (RSA/ECC), HMAC keys, and Sign/Verify/GetPublicKey — v1 is SYMMETRIC_DEFAULT only;
//   - KMS grants (CreateGrant — the grant token API) — use a kind: Policy / key policy instead;
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
	"sort"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// KMS keeps each account's keys apart: a key belongs to the account that made it, and its ARN names that
// account. Key ids are UUIDs, unique across accounts, so a key keeps its id, its Transit key (kms-<keyId>)
// and its row whatever its account, and the account it belongs to is the one its ARN names (keyAccount).
// An alias name is unique within an account: a member account's is kept under its account's key
// (accountKey). An imported key policy's kind: Policy objects live in the key's account's namespace
// (accountNamespace), where they govern that account's principals alone.
func init() { accountScopedServices["kms"] = true }

type kmsHandler struct {
	cs         kubernetes.Interface
	dyn        dynamic.Interface // for key-policy import (materializes kind: Policy CRs); nil => import off
	policiesNS string            // namespace the imported kind: Policy CRs live in (the data plane loads cluster-wide)
	authzNS    string
	account    string
	region     string
	transit    *vaultTransit // nil => Vault not configured (honest 501)
	store      *kmsStore     // nil => data layer not configured (honest 501)
	authz      *dataplaneauthz.Checker
	logger     *slog.Logger
}

func newKMSHandler(cs kubernetes.Interface, dyn dynamic.Interface, policiesNS, authzNS, account, region string, transit *vaultTransit, store *kmsStore, logger *slog.Logger) *kmsHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &kmsHandler{cs: cs, dyn: dyn, policiesNS: policiesNS, authzNS: authzNS, account: account, region: region, transit: transit, store: store, logger: logger}
}

// --- error dialect (AWS JSON 1.1). KMS surfaces the bare exception name in __type. ---

func writeKMSError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
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
	case "DescribeKey", "ListKeys", "ListAliases", "GetKeyRotationStatus", "Decrypt", "GenerateRandom",
		"GetKeyPolicy", "ListKeyPolicies":
		return "get", true
	case "CreateKey", "CreateAlias", "UpdateAlias", "Encrypt", "GenerateDataKey",
		"GenerateDataKeyWithoutPlaintext", "ReEncrypt", "EnableKey", "DisableKey",
		"EnableKeyRotation", "DisableKeyRotation", "CancelKeyDeletion", "PutKeyPolicy":
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

	// The key ref most ops act on (KeyId, or TargetKeyId for CreateAlias): a raw id, a key ARN, an alias
	// name or an alias ARN. A ref that does not resolve is reported as NotFound in the handler.
	keyRef := firstString(body, "KeyId", "TargetKeyId")

	// Carry the resolved open-infra principal on the context so every audit record — allowed OR denied —
	// records *who*, not just the access-key id (AU-2/AU-9, the compliance stake of this doorway).
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// Every key the request reads through or writes to is authorized, as on AWS, in the one policy world:
	// the coarse impersonated SubjectAccessReview, then the fine-grained Cedar dataPlane at key granularity
	// (additive for a User; closed for an assumed role, which is checked on Key::* for an op naming no key).
	// This is where kms:Encrypt is separable from kms:Decrypt for one principal on one key.
	for _, c := range h.kmsKeyChecks(r.Context(), op, verb, body) {
		if ok, reason := decide(ctx, r, h.authz, claims, c.action, "Key", c.keyID,
			coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, c.verb, "openinfra.dev", "applications", h.authzNS, c.keyID,
				c.action, "Key", c.keyID)); !ok {
			h.auditDeny(ctx, op, c.keyID, reason)
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
	case "GenerateRandom":
		h.generateRandom(ctx, w, requestID, body)
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
	case "PutKeyPolicy":
		h.putKeyPolicy(ctx, w, requestID, body)
	case "GetKeyPolicy":
		h.getKeyPolicy(ctx, w, requestID, body)
	case "ListKeyPolicies":
		h.listKeyPolicies(ctx, w, requestID, body)
	default:
		writeKMSError(w, http.StatusBadRequest, "InvalidActionException", requestID,
			"KMS "+op+" is recognized but not implemented by the open-infra shim.")
	}
}

// kmsKeyCheck is one authorization a KMS request needs: an AWS action on a key, with its coarse verb.
type kmsKeyCheck struct{ action, verb, keyID string }

// kmsKeyChecks lists the keys an op touches, each with the action AWS authorizes on it. Most ops name one
// key. Decrypt's key is the one its ciphertext names. ReEncrypt reads through the ciphertext's key
// (kms:ReEncryptFrom) and writes under DestinationKeyId (kms:ReEncryptTo), so a key the caller may not
// use cannot be re-encrypted out of. UpdateAlias moves an alias from one key to another and needs
// kms:UpdateAlias on both; DeleteAlias needs kms:DeleteAlias on the key the alias names. A ref that does
// not resolve leaves that check's key empty (the coarse gate still applies; the handler reports NotFound).
func (h *kmsHandler) kmsKeyChecks(ctx context.Context, op, verb string, body map[string]any) []kmsKeyCheck {
	resolve := func(ref string) string {
		if ref == "" || h.store == nil {
			return ""
		}
		if id, ok, _ := h.resolveKeyID(ctx, ref); ok {
			return id
		}
		return ""
	}
	blobKey := func() string {
		if blob, _ := body["CiphertextBlob"].(string); blob != "" {
			if id, _, err := decodeBlob(blob); err == nil {
				return resolve(id)
			}
		}
		return ""
	}
	alias, _ := body["AliasName"].(string)
	switch op {
	case "Decrypt":
		return []kmsKeyCheck{{"kms:Decrypt", verb, blobKey()}}
	case "ReEncrypt":
		return []kmsKeyCheck{
			{"kms:ReEncryptFrom", "get", blobKey()},
			{"kms:ReEncryptTo", verb, resolve(firstString(body, "DestinationKeyId"))},
		}
	case "UpdateAlias":
		checks := []kmsKeyCheck{{"kms:UpdateAlias", verb, resolve(firstString(body, "TargetKeyId"))}}
		if cur := resolve(alias); cur != "" {
			checks = append(checks, kmsKeyCheck{"kms:UpdateAlias", verb, cur})
		}
		return checks
	case "DeleteAlias":
		return []kmsKeyCheck{{"kms:DeleteAlias", verb, resolve(alias)}}
	}
	return []kmsKeyCheck{{"kms:" + op, verb, resolve(firstString(body, "KeyId", "TargetKeyId"))}}
}

// --- accounts ---

// acct is the account the request acts in, as its responses name it: the management account's own
// (h.account, exactly as before) or the member account the request acts in.
func (h *kmsHandler) acct(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// keyAccount is the account a key belongs to: the member account its ARN names, or "" for the management
// account's (its ARN names the management account, or no account at all).
func (h *kmsHandler) keyAccount(m keyMeta) string {
	a := awsidentity.AccountOfARN(m.Arn)
	if a == "" || a == h.account || awsidentity.Current().IsManagement(a) {
		return ""
	}
	return a
}

// ownsKey reports whether a key is the caller's account's. A member account never reaches the management
// account's key, nor another member's, and the management account never a member's: AWS reaches another
// account's key only by its full ARN under that key's key policy, which this door does not serve, so
// another account's key is not found.
func (h *kmsHandler) ownsKey(ctx context.Context, m keyMeta) bool {
	if !isMemberRequest(ctx) {
		return h.keyAccount(m) == ""
	}
	return h.keyAccount(m) == callerAccount(ctx)
}

// aliasKey is the store key of an alias name in the caller's account, and whether the name can be one of
// its aliases at all (a name spelled as a member account's key is none of the management account's).
func (h *kmsHandler) aliasKey(ctx context.Context, name string) (string, bool) {
	k := accountKey(ctx, name)
	_, ok := nameOfAccountKey(ctx, k)
	return k, ok
}

// foreignRef reports whether a member account's request names a key or an alias by the ARN of another
// account (which it does not reach: see ownsKey).
func (h *kmsHandler) foreignRef(ctx context.Context, ref string) bool {
	return isMemberRequest(ctx) && strings.HasPrefix(ref, "arn:") && awsidentity.AccountOfARN(ref) != callerAccount(ctx)
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

	// An optional AWS key-policy JSON (CreateKey's Policy param) is translated to kind: Policy CRs. Validate
	// it BEFORE creating any crypto material, so a malformed policy fails the whole CreateKey (AWS behavior)
	// with nothing orphaned.
	policyDoc, _ := body["Policy"].(string)
	var translatedPolicy []kmsTranslatedPolicy
	if strings.TrimSpace(policyDoc) != "" {
		if h.dyn == nil {
			writeKMSError(w, http.StatusNotImplemented, "KMSInternalException", requestID,
				"key-policy import is not configured on this shim (no cluster client)")
			return
		}
		tp, err := h.translateKeyPolicyIn(ctx, policyDoc, keyID)
		if err != nil {
			writeKMSError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", requestID, err.Error())
			return
		}
		translatedPolicy = tp
	}

	if err := h.transit.createKey(ctx, keyID); err != nil {
		h.internal(w, requestID, err)
		return
	}
	m := keyMeta{
		KeyID:       keyID,
		Arn:         h.keyARNIn(ctx, keyID),
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
	// Materialize an optional key policy. On failure, roll the whole CreateKey back (crypto + metadata +
	// any partially-created CRs) so a key never exists with a policy that didn't fully apply.
	if translatedPolicy != nil {
		if err := h.materializeKeyPolicy(ctx, keyID, translatedPolicy); err != nil {
			_ = h.deleteKeyPolicyCRs(ctx, keyID)
			_ = h.store.deleteKeyRow(ctx, keyID)
			_ = h.transit.destroy(ctx, keyID)
			h.internal(w, requestID, err)
			return
		}
		if err := h.store.putKeyPolicyDoc(ctx, keyID, policyDoc); err != nil {
			_ = h.deleteKeyPolicyCRs(ctx, keyID)
			_ = h.store.deleteKeyRow(ctx, keyID)
			_ = h.transit.destroy(ctx, keyID)
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "CreateKey", keyID)
	writeKMSJSON(w, requestID, map[string]any{"KeyMetadata": h.keyMetadataJSON(ctx, m)})
}

func (h *kmsHandler) describeKey(ctx context.Context, w http.ResponseWriter, requestID, keyRef string) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	writeKMSJSON(w, requestID, map[string]any{"KeyMetadata": h.keyMetadataJSON(ctx, m)})
}

func (h *kmsHandler) listKeys(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	limit := toInt(body["Limit"])
	keys, err := h.store.listKeys(ctx, limit, func(m keyMeta) bool { return h.ownsKey(ctx, m) })
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
		h.invalidState(ctx, w, requestID, m.KeyID, "is pending deletion")
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
	h.audit(ctx, map[bool]string{true: "EnableKey", false: "DisableKey"}[enabled], m.KeyID)
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) setRotation(ctx context.Context, w http.ResponseWriter, requestID, keyRef string, on bool) {
	m, ok := h.mustKey(ctx, w, requestID, keyRef)
	if !ok {
		return
	}
	if m.State != "Enabled" {
		h.invalidState(ctx, w, requestID, m.KeyID, "is not enabled")
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
	h.audit(ctx, map[bool]string{true: "EnableKeyRotation", false: "DisableKeyRotation"}[on], m.KeyID)
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
		h.invalidState(ctx, w, requestID, m.KeyID, "is already pending deletion")
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
	h.audit(ctx, "ScheduleKeyDeletion", m.KeyID)
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
		h.invalidState(ctx, w, requestID, m.KeyID, "is not pending deletion")
		return
	}
	// Cancelling deletion restores the key Disabled (AWS's post-cancel state).
	if _, err := h.store.setState(ctx, m.KeyID, "Disabled", nil); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CancelKeyDeletion", m.KeyID)
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
	key, _ := h.aliasKey(ctx, name) // a name beginning "alias/" is always the caller's account's own
	if err := h.store.createAlias(ctx, key, m.KeyID); err == errAliasExists {
		writeKMSError(w, http.StatusBadRequest, "AlreadyExistsException", requestID, "An alias with this name already exists.")
		return
	} else if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateAlias", m.KeyID, "alias", name)
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) updateAlias(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["AliasName"].(string)
	target := firstString(body, "TargetKeyId")
	m, ok := h.mustKey(ctx, w, requestID, target)
	if !ok {
		return
	}
	updated := false
	if key, own := h.aliasKey(ctx, name); own {
		var err error
		if updated, err = h.store.updateAlias(ctx, key, m.KeyID); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	if !updated {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID, "The specified alias does not exist.")
		return
	}
	h.audit(ctx, "UpdateAlias", m.KeyID, "alias", name)
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) deleteAlias(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["AliasName"].(string)
	ok := false
	if key, own := h.aliasKey(ctx, name); own {
		var err error
		if ok, err = h.store.deleteAlias(ctx, key); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	if !ok {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID, "The specified alias does not exist.")
		return
	}
	h.audit(ctx, "DeleteAlias", "", "alias", name)
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
		name, own := nameOfAccountKey(ctx, a.Name)
		if !own {
			continue // another account's alias
		}
		// An alias naming another account's key is none of this account's to show (it resolves to nothing).
		if m, found, err := h.store.getKey(ctx, a.KeyID); err == nil && found && !h.ownsKey(ctx, m) {
			continue
		}
		out = append(out, map[string]any{
			"AliasName":       name,
			"AliasArn":        h.aliasARNIn(ctx, name),
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
	// AWS caps direct Encrypt at 4 KB of plaintext — the practical reason envelope encryption (GenerateDataKey)
	// exists. Enforce it so an app hitting the limit gets the real error, never a silent truncation.
	if raw, derr := base64.StdEncoding.DecodeString(plaintext); derr != nil {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID, "Plaintext must be valid base64.")
		return
	} else if len(raw) > 4096 {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID,
			"1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length less than or equal to 4096.")
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
	h.audit(ctx, "Encrypt", m.KeyID, "encryptionContext", contextKeys(body["EncryptionContext"]))
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
	h.audit(ctx, "Decrypt", m.KeyID, "encryptionContext", contextKeys(body["EncryptionContext"]))
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
	h.audit(ctx, "GenerateDataKey", m.KeyID, "encryptionContext", contextKeys(body["EncryptionContext"]))
	writeKMSJSON(w, requestID, out)
}

// generateRandom returns cryptographically-random bytes. It needs no CMK (no key material is involved),
// so it does not touch Vault Transit — the shim's own crypto/rand is the source, exactly as KMS's own
// GenerateRandom is unrelated to any key.
func (h *kmsHandler) generateRandom(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	n := toInt(body["NumberOfBytes"])
	if n < 1 || n > 1024 {
		writeKMSError(w, http.StatusBadRequest, "ValidationException", requestID,
			"NumberOfBytes must be between 1 and 1024.")
		return
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "GenerateRandom", "", "bytes", n)
	writeKMSJSON(w, requestID, map[string]any{"Plaintext": base64.StdEncoding.EncodeToString(b)})
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
	h.audit(ctx, "ReEncrypt", destM.KeyID, "from", srcM.KeyID)
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
	if !found || !h.ownsKey(ctx, m) {
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
		h.invalidState(ctx, w, requestID, m.KeyID, "is pending deletion and cannot be used for cryptographic operations")
		return keyMeta{}, false
	}
	h.invalidState(ctx, w, requestID, m.KeyID, "is not in a usable state")
	return keyMeta{}, false
}

// resolveKeyID accepts a raw key id, a key ARN, an alias name ("alias/x"), or an alias ARN, and returns
// the canonical key id. A bare id is only accepted if a metadata row exists for it (so a made-up id is a miss).
// Only the caller's account's keys and aliases resolve (ownsKey): another account's is a miss.
func (h *kmsHandler) resolveKeyID(ctx context.Context, ref string) (string, bool, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || h.foreignRef(ctx, ref) {
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
		key, _ := h.aliasKey(ctx, ref)
		id, ok, err := h.store.aliasTarget(ctx, key)
		if err != nil || !ok {
			return "", false, err
		}
		// An alias names a key of its own account: one naming another account's key resolves to nothing.
		if m, found, err := h.store.getKey(ctx, id); err != nil {
			return "", false, err
		} else if found && !h.ownsKey(ctx, m) {
			return "", false, nil
		}
		return id, true, nil
	}
	// bare id — accept only if a key row exists, and it is the caller's account's
	if m, found, err := h.store.getKey(ctx, ref); err != nil {
		return "", false, err
	} else if found && h.ownsKey(ctx, m) {
		return ref, true, nil
	}
	return "", false, nil
}

func (h *kmsHandler) keyMetadataJSON(ctx context.Context, m keyMeta) map[string]any {
	md := map[string]any{
		"AWSAccountId":          h.acct(ctx), // the key is the caller's account's (ownsKey)
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

// keyARN is the ARN of a management-account key (a stack's key whose spec names no ARN of its own).
func (h *kmsHandler) keyARN(keyID string) string {
	return "arn:aws:kms:" + h.region + ":" + h.account + ":key/" + keyID
}

// keyARNIn is the ARN of a key of the account the request acts in.
func (h *kmsHandler) keyARNIn(ctx context.Context, keyID string) string {
	return "arn:aws:kms:" + h.region + ":" + h.acct(ctx) + ":key/" + keyID
}

// aliasARNIn is the ARN of an alias of the account the request acts in.
func (h *kmsHandler) aliasARNIn(ctx context.Context, name string) string {
	return "arn:aws:kms:" + h.region + ":" + h.acct(ctx) + ":" + name
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

func (h *kmsHandler) invalidState(ctx context.Context, w http.ResponseWriter, requestID, keyID, why string) {
	writeKMSError(w, http.StatusBadRequest, "KMSInvalidStateException", requestID,
		h.keyARNIn(ctx, keyID)+" "+why+".")
}

// audit emits a structured audit record for a KMS operation (AC-2/AU-2/AU-9): who (the resolved
// open-infra principal), which op, which key, the decision, and any op-specific fields (kv pairs) — never
// plaintext or ciphertext. EncryptionContext is safe to log (KMS itself forbids secrets in it) and is
// what an auditor correlates on. This is the record a compliance reviewer reads to evidence SC-12.
func (h *kmsHandler) audit(ctx context.Context, op, keyID string, kv ...any) {
	args := []any{"service", "kms", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if keyID != "" {
		args = append(args, "keyId", keyID)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "kms audit", args...)
}

// auditDeny records a denied KMS operation (the other half of "allowed or denied").
func (h *kmsHandler) auditDeny(ctx context.Context, op, keyID, reason string) {
	args := []any{"service", "kms", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if keyID != "" {
		args = append(args, "keyId", keyID)
	}
	h.logger.InfoContext(ctx, "kms audit", args...)
}

// reapDeleted crypto-erases keys whose deletion window has elapsed: destroy the Vault Transit key (after
// which no ciphertext can ever be decrypted again), then drop the metadata row. Idempotent. It reaps every
// account's keys, each key's imported policy torn down in its own account's namespace.
func (h *kmsHandler) reapDeleted(ctx context.Context) error {
	if h.store == nil || h.transit == nil {
		return nil
	}
	due, err := h.store.dueForDeletion(ctx, time.Now())
	if err != nil {
		return err
	}
	for _, id := range due {
		// Where the key's policy objects live: the management account's namespace for its keys; for a
		// member account's key (whose home this pass, run without a request, does not know), wherever
		// the label naming this one key puts them — its id is unique across accounts.
		policyNS := h.policiesNS
		if m, found, err := h.store.getKey(ctx, id); err == nil && found && h.keyAccount(m) != "" {
			policyNS = metav1.NamespaceAll
		}
		if err := h.transit.destroy(ctx, id); err != nil {
			h.logger.Warn("kms crypto-erase failed", "keyId", id, "error", err.Error())
			continue
		}
		if err := h.store.deleteKeyRow(ctx, id); err != nil {
			h.logger.Warn("kms metadata delete failed after crypto-erase", "keyId", id, "error", err.Error())
			continue
		}
		// Tear down the imported key-policy CRs + the stored raw doc (the grants are moot once the key is
		// gone). Best-effort: a stale grant on a destroyed Key::<id> can authorize nothing. Cleanup runs at
		// crypto-erase (true deletion), not ScheduleKeyDeletion, so the policy survives a CancelKeyDeletion.
		if h.dyn != nil {
			if err := h.deleteKeyPolicyCRsIn(ctx, policyNS, id); err != nil {
				h.logger.Warn("kms key-policy CR cleanup failed after crypto-erase", "keyId", id, "error", err.Error())
			}
		}
		if err := h.store.deleteKeyPolicyDoc(ctx, id); err != nil {
			h.logger.Warn("kms key-policy doc delete failed after crypto-erase", "keyId", id, "error", err.Error())
		}
		h.audit(ctx, "CryptoErase", id, "reason", "deletion window elapsed")
	}
	return nil
}

// --- principal on context (for the audit "who") ---

type principalCtxKey struct{}

func withPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, principal)
}

func principalFromCtx(ctx context.Context) string {
	if p, ok := ctx.Value(principalCtxKey{}).(string); ok && p != "" {
		return p
	}
	return "unknown"
}

// contextKeys returns the sorted key names of an EncryptionContext for the audit line (keys, not values,
// keep the record compact while still letting an auditor see the binding was present). "" when absent.
func contextKeys(v any) string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
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
