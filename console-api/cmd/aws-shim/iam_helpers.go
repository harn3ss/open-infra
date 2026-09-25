// Pure helpers for the IAM management doorway (polyhedron#168/#174): trust-policy parsing, ARN mapping,
// AWS-statement→CR rendering, and query-protocol list extraction. Kept side-effect-free so the parts the
// translation fidelity depends on are unit-tested.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/policyengine"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func isAlreadyExists(err error) bool { return err != nil && apierrors.IsAlreadyExists(err) }

func toAny(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// statementsToSpecAny renders translated Cedar statements into the kind: Policy spec.dataPlane.statements
// shape (mirrors cfn/translate.go's statementsToSpec).
func statementsToSpecAny(stmts []policyengine.Statement) []any {
	out := make([]any, 0, len(stmts))
	for _, s := range stmts {
		m := map[string]any{"effect": string(s.Effect), "actions": toAny(s.Actions)}
		if len(s.Resources) > 0 {
			m["resources"] = toAny(s.Resources)
		}
		if len(s.Condition) > 0 {
			c := map[string]any{}
			for k, v := range s.Condition {
				c[k] = v
			}
			m["condition"] = c
		}
		if len(s.IPConditions) > 0 {
			ips := make([]any, 0, len(s.IPConditions))
			for _, ip := range s.IPConditions {
				ips = append(ips, map[string]any{"key": ip.Key, "cidr": ip.CIDR, "negate": ip.Negate})
			}
			m["ipConditions"] = ips
		}
		out = append(out, m)
	}
	return out
}

// parseTrustPolicy extracts the principals a role may be assumed by from an AWS AssumeRolePolicyDocument,
// returning the kind: Role spec.trust list (User names, or "*"). Only the sts:AssumeRole Allow statements
// are considered; a Principal of "*" or an account/root ARN maps to "*" (any authenticated principal).
func parseTrustPolicy(doc string) ([]string, error) {
	if strings.TrimSpace(doc) == "" {
		return nil, errors.New("empty trust policy")
	}
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, errors.New("not valid JSON")
	}
	var stmts []map[string]any
	// Statement may be a single object or an array.
	if len(d.Statement) > 0 && d.Statement[0] == '{' {
		var one map[string]any
		if err := json.Unmarshal(d.Statement, &one); err != nil {
			return nil, errors.New("malformed Statement")
		}
		stmts = []map[string]any{one}
	} else if err := json.Unmarshal(d.Statement, &stmts); err != nil {
		return nil, errors.New("malformed Statement")
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, st := range stmts {
		if eff, _ := st["Effect"].(string); eff != "Allow" {
			continue
		}
		// Action must include sts:AssumeRole (string or list).
		if !actionAllowsAssume(st["Action"]) {
			continue
		}
		prin := st["Principal"]
		for _, p := range principalARNs(prin) {
			if p == "*" {
				add("*")
				continue
			}
			if n := userFromArn(p); n != "" {
				add(n)
			} else if isRootOrAccountArn(p) {
				add("*")
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no sts:AssumeRole Allow principal found")
	}
	return out, nil
}

func actionAllowsAssume(v any) bool {
	switch a := v.(type) {
	case string:
		return a == "sts:AssumeRole" || a == "*"
	case []any:
		for _, e := range a {
			if s, _ := e.(string); s == "sts:AssumeRole" || s == "*" {
				return true
			}
		}
	}
	return false
}

// principalARNs extracts the principal ARN strings from a trust statement's Principal (which may be "*", a
// {"AWS": ...} map with a string or list, or {"Service": ...} which we ignore).
func principalARNs(v any) []string {
	switch p := v.(type) {
	case string:
		if p == "*" {
			return []string{"*"}
		}
	case map[string]any:
		aws := p["AWS"]
		switch a := aws.(type) {
		case string:
			return []string{a}
		case []any:
			var out []string
			for _, e := range a {
				if s, _ := e.(string); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}

func userFromArn(arn string) string {
	if i := strings.Index(arn, ":user/"); i >= 0 {
		return arn[i+len(":user/"):]
	}
	return ""
}

func isRootOrAccountArn(arn string) bool {
	return strings.HasSuffix(arn, ":root") || (strings.HasPrefix(arn, "arn:aws:iam::") && !strings.Contains(arn, "/"))
}

// hasNotActionOrResource reports whether the policy JSON uses NotAction/NotResource, which policyengine
// .ImportAWS drops SILENTLY (a fidelity hole) — so the IAM doorway refuses such a policy explicitly.
func hasNotActionOrResource(doc string) bool {
	var raw any
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return false // let ImportAWS report the parse error
	}
	return jsonHasKey(raw, "NotAction") || jsonHasKey(raw, "NotResource")
}

func jsonHasKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t[key]; ok {
			return true
		}
		for _, e := range t {
			if jsonHasKey(e, key) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if jsonHasKey(e, key) {
				return true
			}
		}
	}
	return false
}

func policyNameFromArn(arn string) string {
	if i := strings.Index(arn, ":policy/"); i >= 0 {
		return arn[i+len(":policy/"):]
	}
	return arn
}

// principalFromArn maps a PolicySourceArn to a data-plane principal (Type, ID). role → ("Role", name),
// user → ("User", name).
func principalFromArn(arn string) (string, string) {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		return "Role", arn[i+len(":role/"):]
	}
	if i := strings.Index(arn, ":user/"); i >= 0 {
		return "User", arn[i+len(":user/"):]
	}
	return "", ""
}

// arnToResourceShim maps an AWS resource ARN to the shim's (resType, resID) for a SimulatePrincipalPolicy
// query. Mirrors policyengine's S3/DynamoDB/Lambda mapping; "*" → ("*",""). A bucket key suffix is dropped
// (authz is at the bucket).
func arnToResourceShim(arn string) (string, string) {
	if arn == "*" || arn == "" {
		return "*", "*"
	}
	switch {
	case strings.HasPrefix(arn, "arn:aws:s3:::"):
		rest := strings.TrimPrefix(arn, "arn:aws:s3:::")
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		}
		return "Bucket", rest
	case strings.Contains(arn, ":table/"):
		return "Table", arn[strings.Index(arn, ":table/")+len(":table/"):]
	case strings.Contains(arn, ":function:"):
		return "Function", arn[strings.Index(arn, ":function:")+len(":function:"):]
	}
	return "*", arn
}

// queryList extracts an AWS query-protocol list ("<name>.member.1", ".2", …) from the form.
func queryList(r *http.Request, name string) []string {
	var out []string
	for i := 1; i < 256; i++ {
		v := r.PostFormValue(name + ".member." + strconv.Itoa(i))
		if v == "" {
			// AWS lists are 1-indexed and contiguous; stop at the first gap.
			if i == 1 {
				// some SDKs use <name>.1 (no .member); try that form once
				if alt := r.PostFormValue(name + "." + strconv.Itoa(i)); alt != "" {
					out = append(out, alt)
					for j := 2; j < 256; j++ {
						a := r.PostFormValue(name + "." + strconv.Itoa(j))
						if a == "" {
							break
						}
						out = append(out, a)
					}
				}
			}
			break
		}
		out = append(out, v)
	}
	return out
}

// roleID returns a stable AWS-shaped unique id (AROA-prefixed, uppercase alphanumerics) derived from the
// entity name — opaque and stable, which is all clients rely on.
func roleID(name string) string {
	sum := sha256.Sum256([]byte(name))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	// map hex to a 17-char base32-ish tail
	var sb strings.Builder
	for i := 0; i < 17 && i < len(h); i++ {
		sb.WriteByte(alnum[int(h[i])%len(alnum)])
	}
	return "AROA" + sb.String()
}
