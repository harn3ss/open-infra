// KMS key-policy import for the aws-shim (follow-on to #267).
//
// AWS governs who may use a CMK with a resource-based KEY POLICY attached to the key. open-infra has no
// second resource-attached policy engine — authorization is the one policy world (RBAC + Cedar data
// plane). #267 established the equivalence: a key-policy statement "Principal P may kms:X on this key" ==
// a kind: Policy { dataPlane.appliesTo: [P], Allow kms:X on Key::<keyId> }, enforced at key granularity.
//
// This file closes the import-convenience gap: the KMS doorway accepts a supplied AWS key-policy JSON
// (CreateKey's Policy param, PutKeyPolicy) and TRANSLATES it into the equivalent kind: Policy CR set —
// one CR per statement, labeled by key id so PutKeyPolicy replaces the whole set — rather than refusing
// it and forcing the policy to be re-authored by hand. GetKeyPolicy round-trips the raw JSON verbatim;
// ListKeyPolicies reports the single "default" policy name KMS exposes.
//
// FAIL-CLOSED like the IAM doorway's translateOrRefuse: anything the data plane can't honor faithfully
// (a Condition, a non-user/role principal, a Resource that isn't this key, a non-kms action) refuses the
// WHOLE policy — never a looser or silently-narrowed grant. The default root statement (Principal root/
// account, kms:*, Resource *) is SKIPPED: it is AWS's "delegate to IAM" default, which open-infra already
// provides through identity-based authorization, so translating it would grant everyone everything.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// kmsKeyPolicyLabel tags every kind: Policy CR materialized from a key policy with its key id, so the
// whole set for a key can be listed (replace) and deleted (crypto-erase) without name guessing.
const kmsKeyPolicyLabel = "openinfra.dev/kms-key"

// kmsTranslatedPolicy is one key-policy statement translated to the kind: Policy spec.dataPlane shape.
type kmsTranslatedPolicy struct {
	appliesTo  []string // the statement's principals, as Role::x / User::y / * (data-plane principals)
	statements []any    // spec.dataPlane.statements — one grant (effect, kms actions, Key::<id> resource)
}

// translateKeyPolicy parses an AWS KMS key-policy document into the per-statement grants to materialize.
// Pure + side-effect-free so the translation fidelity is unit-tested. keyID scopes every grant's resource.
func translateKeyPolicy(doc, keyID string) ([]kmsTranslatedPolicy, error) {
	if strings.TrimSpace(doc) == "" {
		return nil, errors.New("key policy document is empty")
	}
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, errors.New("key policy is not valid JSON")
	}
	stmts, err := rawStatements(d.Statement)
	if err != nil {
		return nil, err
	}
	if len(stmts) == 0 {
		return nil, errors.New("key policy has no statements")
	}
	var out []kmsTranslatedPolicy
	for i, st := range stmts {
		// A Condition (kms:ViaService, kms:EncryptionContext, aws:SourceArn, …) is not populated as a
		// request key on this doorway, so honoring it would change the grant — refuse the whole policy.
		if _, has := st["Condition"]; has {
			return nil, fmt.Errorf("statement %d has a Condition the data plane can't honor (kms:ViaService/kms:EncryptionContext/…); author the grant natively", i)
		}
		eff, _ := st["Effect"].(string)
		if eff != "Allow" && eff != "Deny" {
			return nil, fmt.Errorf("statement %d: Effect must be \"Allow\" or \"Deny\"", i)
		}
		actions, err := kmsActions(st["Action"])
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		principals := principalARNs(st["Principal"])
		if len(principals) == 0 {
			return nil, fmt.Errorf("statement %d: a key-policy statement needs an AWS principal (Service/Federated/CanonicalUser principals aren't supported)", i)
		}
		if err := checkKeyResource(st["Resource"], keyID); err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		// Map principals to data-plane form; a root/account principal is the IAM-delegation default and is
		// skipped. If a statement names ONLY root/account principals, the whole statement is the default → skip.
		var appliesTo []string
		for _, p := range principals {
			if p == "*" {
				appliesTo = append(appliesTo, "*")
				continue
			}
			if isRootOrAccountArn(p) {
				continue // identity policies govern the account root — not a second engine
			}
			t, id := principalFromArn(p)
			if t == "" {
				return nil, fmt.Errorf("statement %d: principal %q is not a user or role ARN the data plane can map", i, p)
			}
			appliesTo = append(appliesTo, t+"::"+id)
		}
		if len(appliesTo) == 0 {
			continue // root/account-only statement → the delegate-to-IAM default, skipped
		}
		stmt := map[string]any{
			"effect":    eff,
			"actions":   toAny(actions),
			"resources": []any{"Key::" + keyID},
		}
		out = append(out, kmsTranslatedPolicy{appliesTo: dedupeSortedStrings(appliesTo), statements: []any{stmt}})
	}
	return out, nil
}

// rawStatements normalizes a policy's Statement (a single object OR an array) into a slice of maps.
func rawStatements(raw json.RawMessage) ([]map[string]any, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("key policy has no Statement")
	}
	if trimmed[0] == '{' {
		var one map[string]any
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, errors.New("malformed Statement")
		}
		return []map[string]any{one}, nil
	}
	var many []map[string]any
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("malformed Statement")
	}
	return many, nil
}

// kmsActions normalizes a key-policy statement's Action (string or list) to the kms:<op> action strings the
// data plane matches (Cedar `like`, so "kms:*" is a real wildcard). A key policy governs only KMS, so a
// bare "*" means all KMS actions ("kms:*"); any non-kms action refuses the policy.
func kmsActions(v any) ([]string, error) {
	var raw []string
	switch a := v.(type) {
	case string:
		raw = []string{a}
	case []any:
		for _, e := range a {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("statement has no Action")
	}
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		switch {
		case a == "*":
			out = append(out, "kms:*")
		case strings.HasPrefix(a, "kms:"):
			out = append(out, a)
		default:
			return nil, fmt.Errorf("action %q is not a kms: action (a key policy governs only KMS)", a)
		}
	}
	return out, nil
}

// checkKeyResource verifies the statement's Resource names THIS key: "*" (the key-policy convention for
// "this CMK"), or a key ARN whose id is keyID. Anything else refuses (a key policy over another resource
// would change what the grant covers).
func checkKeyResource(v any, keyID string) error {
	var res []string
	switch r := v.(type) {
	case nil:
		return nil // absent Resource == "*" (this key) in a key policy
	case string:
		res = []string{r}
	case []any:
		for _, e := range r {
			if s, ok := e.(string); ok {
				res = append(res, s)
			}
		}
	}
	for _, r := range res {
		if r == "*" {
			continue
		}
		if i := strings.Index(r, ":key/"); i >= 0 {
			if r[i+len(":key/"):] == keyID {
				continue
			}
		}
		return fmt.Errorf("Resource %q must be \"*\" or this key's ARN", r)
	}
	return nil
}

// dedupeSortedStrings returns the unique values of ss, sorted (stable CR content across re-imports).
func dedupeSortedStrings(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// defaultKeyPolicyJSON synthesizes the AWS default key policy (root full access) returned by GetKeyPolicy
// when no policy was ever set — exactly what AWS returns for a key created without an explicit Policy.
func defaultKeyPolicyJSON(account string) string {
	return `{"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User Permissions",` +
		`"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + account + `:root"},"Action":"kms:*","Resource":"*"}]}`
}

// --- handlers ---

func (h *kmsHandler) putKeyPolicy(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if h.dyn == nil {
		writeKMSError(w, http.StatusNotImplemented, "KMSInternalException", requestID,
			"key-policy import is not configured on this shim (no cluster client)")
		return
	}
	m, ok := h.mustKey(ctx, w, requestID, firstString(body, "KeyId"))
	if !ok {
		return
	}
	if name := firstString(body, "PolicyName"); name != "" && name != "default" {
		writeKMSError(w, http.StatusBadRequest, "UnsupportedOperationException", requestID,
			"KMS supports only the \"default\" key policy.")
		return
	}
	doc, _ := body["Policy"].(string)
	if strings.TrimSpace(doc) == "" {
		writeKMSError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", requestID, "Policy is required.")
		return
	}
	translated, err := translateKeyPolicy(doc, m.KeyID)
	if err != nil {
		writeKMSError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", requestID, err.Error())
		return
	}
	if err := h.materializeKeyPolicy(ctx, m.KeyID, translated); err != nil {
		h.internal(w, requestID, err)
		return
	}
	if err := h.store.putKeyPolicyDoc(ctx, m.KeyID, doc); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutKeyPolicy", m.KeyID, "grants", len(translated))
	writeKMSJSON(w, requestID, map[string]any{})
}

func (h *kmsHandler) getKeyPolicy(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	m, ok := h.mustKey(ctx, w, requestID, firstString(body, "KeyId"))
	if !ok {
		return
	}
	if name := firstString(body, "PolicyName"); name != "" && name != "default" {
		writeKMSError(w, http.StatusBadRequest, "NotFoundException", requestID, "No key policy named \""+name+"\".")
		return
	}
	if doc, found, err := h.store.getKeyPolicyDoc(ctx, m.KeyID); err != nil {
		h.internal(w, requestID, err)
		return
	} else if found {
		writeKMSJSON(w, requestID, map[string]any{"Policy": doc})
		return
	}
	// No explicit policy was ever set — return the AWS default (root full access), as KMS does.
	writeKMSJSON(w, requestID, map[string]any{"Policy": defaultKeyPolicyJSON(h.account)})
}

func (h *kmsHandler) listKeyPolicies(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if _, ok := h.mustKey(ctx, w, requestID, firstString(body, "KeyId")); !ok {
		return
	}
	// KMS exposes exactly one key policy per key, always named "default".
	writeKMSJSON(w, requestID, map[string]any{"PolicyNames": []any{"default"}, "Truncated": false})
}

// --- CR materialization ---

// materializeKeyPolicy replaces the whole kind: Policy CR set for a key with the translated grants (one CR
// per statement, labeled by key id). Replace = delete the existing labeled set, then create the new one —
// so PutKeyPolicy is a full replace, like AWS (a key has exactly one policy document).
func (h *kmsHandler) materializeKeyPolicy(ctx context.Context, keyID string, policies []kmsTranslatedPolicy) error {
	if err := h.deleteKeyPolicyCRs(ctx, keyID); err != nil {
		return err
	}
	for i, p := range policies {
		name := fmt.Sprintf("kmskey-%s-%d", keyID, i+1)
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Policy",
			"metadata": map[string]any{
				"name":      name,
				"namespace": h.policiesNS,
				"labels":    map[string]any{kmsKeyPolicyLabel: keyID},
			},
			"spec": map[string]any{
				"description": "KMS key policy for Key::" + keyID + " (imported by the aws-shim KMS doorway, #298)",
				"statements":  []any{}, // control-plane statements: none (this is a data-plane grant)
				"dataPlane":   map[string]any{"appliesTo": toAny(p.appliesTo), "statements": p.statements},
			},
		}}
		if _, err := h.dyn.Resource(gvrPolicies).Namespace(h.policiesNS).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

// deleteKeyPolicyCRs removes every kind: Policy CR materialized for a key (by its label). Idempotent.
func (h *kmsHandler) deleteKeyPolicyCRs(ctx context.Context, keyID string) error {
	list, err := h.dyn.Resource(gvrPolicies).Namespace(h.policiesNS).List(ctx, metav1.ListOptions{
		LabelSelector: kmsKeyPolicyLabel + "=" + keyID,
	})
	if err != nil {
		return err
	}
	for _, it := range list.Items {
		if err := h.dyn.Resource(gvrPolicies).Namespace(h.policiesNS).Delete(ctx, it.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
