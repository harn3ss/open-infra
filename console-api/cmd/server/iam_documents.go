package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

// IAM policy documents in the console: the AWS JSON a policy, an inline policy or a permission
// boundary is written as, and the IAM actions changing an identity's attachments amounts to.

// inlinePolicy is an identity's inline policy (AWS PutUserPolicy/PutGroupPolicy/PutRolePolicy): its name
// and its AWS JSON document, stored as written.
type inlinePolicy struct {
	Name     string `json:"name"`
	Document string `json:"document"`
}

// inlinePolicyCR reads an inline policy whose document is stored either as JSON text or as an object.
type inlinePolicyCR struct {
	Name     string          `json:"name"`
	Document json.RawMessage `json:"document"`
}

// documentString renders a stored document (JSON text, or an object) as JSON text; "" when absent.
func documentString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// inlineViews is the stored inline policies as the SPA reads them (always an array).
func inlineViews(in []inlinePolicyCR) []inlinePolicy {
	out := make([]inlinePolicy, 0, len(in))
	for _, p := range in {
		out = append(out, inlinePolicy{Name: p.Name, Document: documentString(p.Document)})
	}
	return out
}

// checkDocument validates an AWS JSON policy document the way IAM does before storing it: it must parse
// and every statement must be one the evaluator can read. warnings lists statements the evaluator
// narrows (an Allow with a condition key it does not support is dropped; a Deny with one applies
// unconditionally) — accepted, as IAM accepts any well-formed document, but said so the author knows.
// msg is "" when valid.
func checkDocument(doc string) (warnings []string, msg string) {
	if strings.TrimSpace(doc) == "" {
		return nil, "MalformedPolicyDocument: the policy document is empty"
	}
	stmts, report, err := iamauthz.CompileDocument(doc)
	if err != nil {
		return nil, "MalformedPolicyDocument: " + err.Error()
	}
	if len(stmts) == 0 && len(report) == 0 {
		return nil, "MalformedPolicyDocument: the policy document has no statements"
	}
	return report, ""
}

// checkInline validates inline policies: each needs a unique name and a valid document.
func checkInline(in []inlinePolicy) (warnings []string, msg string) {
	seen := map[string]bool{}
	for _, p := range in {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			return nil, "an inline policy needs a name"
		}
		if seen[name] {
			return nil, "two inline policies are named " + name
		}
		seen[name] = true
		w, m := checkDocument(p.Document)
		if m != "" {
			return nil, "inline policy " + name + ": " + m
		}
		for _, x := range w {
			warnings = append(warnings, "inline policy "+name+": "+x)
		}
	}
	return warnings, ""
}

// iamManagementAccount is the account the console's IAM home (and every policy without an ARN of its
// own) belongs to.
const iamManagementAccount = iam.ManagementAccount

// policyErr is a policy validation failure in AWS's shape: MalformedPolicyDocument for a document IAM
// would refuse, else a validation error.
func policyErr(msg string) map[string]string {
	if rest, ok := strings.CutPrefix(msg, "MalformedPolicyDocument: "); ok {
		return map[string]string{"error": rest, "errorCode": "MalformedPolicyDocument"}
	}
	return map[string]string{"error": msg}
}

// nonNil is ss, or [] for nil (so a JSON answer carries an array, never null).
func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// inlineSpec is inline policies as stored (document as written).
func inlineSpec(in []inlinePolicy) []any {
	out := make([]any, 0, len(in))
	for _, p := range in {
		out = append(out, map[string]any{"name": strings.TrimSpace(p.Name), "document": p.Document})
	}
	return out
}

// setDiff is what changes between a stored set and a new one.
func setDiff(old, new []string) (added, removed []string) {
	for _, n := range new {
		if !slices.Contains(old, n) {
			added = append(added, n)
		}
	}
	for _, o := range old {
		if !slices.Contains(new, o) {
			removed = append(removed, o)
		}
	}
	return added, removed
}

// inlineDiff is the inline policies put (new or changed) and deleted.
func inlineDiff(old []inlinePolicyCR, new []inlinePolicy) (put, deleted bool) {
	byName := map[string]string{}
	for _, p := range old {
		byName[p.Name] = documentString(p.Document)
	}
	names := map[string]bool{}
	for _, p := range new {
		names[p.Name] = true
		if d, ok := byName[p.Name]; !ok || d != p.Document {
			put = true
		}
	}
	for n := range byName {
		if !names[n] {
			deleted = true
		}
	}
	return put, deleted
}

// attachmentChange is one identity's attachment edit as IAM actions: the policies attached and detached,
// group membership added and removed, the boundary set or cleared, inline policies put or deleted.
type attachmentChange struct {
	kind string // user, group, role (the IAM entity, for action names and the ARN)
	name string

	policiesAdded, policiesRemoved bool
	groupsAdded, groupsRemoved     []string
	boundarySet, boundaryDeleted   bool
	inlinePut, inlineDeleted       bool
	trustChanged                   bool
}

// iamEntityTitle is the entity's name in IAM action names (User, Group, Role).
func iamEntityTitle(kind string) string {
	switch kind {
	case "group":
		return "Group"
	case "role":
		return "Role"
	}
	return "User"
}

// requireChange asks for every IAM action an attachment edit amounts to (AWS's own: AttachUserPolicy on
// the user, AddUserToGroup on the group, PutUserPermissionsBoundary …), writing the first denial. Legacy
// and shadow pass (the handler's own checks decide; shadow logs); enforce decides.
func requireChange(w http.ResponseWriter, r *http.Request, c attachmentChange) bool {
	z := consoleIAM
	if z == nil {
		return true
	}
	acct := callerAccount(r)
	self := iamEntityARN(c.kind, acct, c.name)
	t := iamEntityTitle(c.kind)
	type q struct{ action, arn string }
	var qs []q
	if c.policiesAdded {
		qs = append(qs, q{"iam:Attach" + t + "Policy", self})
	}
	if c.policiesRemoved {
		qs = append(qs, q{"iam:Detach" + t + "Policy", self})
	}
	for _, g := range c.groupsAdded {
		qs = append(qs, q{"iam:AddUserToGroup", iamEntityARN("group", acct, g)})
	}
	for _, g := range c.groupsRemoved {
		qs = append(qs, q{"iam:RemoveUserFromGroup", iamEntityARN("group", acct, g)})
	}
	if c.boundarySet {
		qs = append(qs, q{"iam:Put" + t + "PermissionsBoundary", self})
	}
	if c.boundaryDeleted {
		qs = append(qs, q{"iam:Delete" + t + "PermissionsBoundary", self})
	}
	if c.inlinePut {
		qs = append(qs, q{"iam:Put" + t + "Policy", self})
	}
	if c.inlineDeleted {
		qs = append(qs, q{"iam:Delete" + t + "Policy", self})
	}
	if c.trustChanged {
		qs = append(qs, q{"iam:UpdateAssumeRolePolicy", self})
	}
	for _, x := range qs {
		if !z.require(w, r, x.action, x.arn) {
			return false
		}
	}
	return true
}
