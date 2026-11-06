// Pure helpers for the IAM management doorway: trust-policy parsing, ARN mapping,
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
		m := map[string]any{"effect": string(s.Effect)}
		if len(s.Actions) > 0 {
			m["actions"] = toAny(s.Actions)
		}
		if len(s.NotActions) > 0 {
			m["notActions"] = toAny(s.NotActions)
		}
		if len(s.Resources) > 0 {
			m["resources"] = toAny(s.Resources)
		}
		if len(s.NotResources) > 0 {
			m["notResources"] = toAny(s.NotResources)
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
		if len(s.LikeConditions) > 0 {
			likes := make([]any, 0, len(s.LikeConditions))
			for _, lk := range s.LikeConditions {
				likes = append(likes, map[string]any{"key": lk.Key, "pattern": lk.Pattern, "negate": lk.Negate})
			}
			m["likeConditions"] = likes
		}
		if len(s.TimeConditions) > 0 {
			times := make([]any, 0, len(s.TimeConditions))
			for _, tc := range s.TimeConditions {
				times = append(times, map[string]any{"key": tc.Key, "op": tc.Op, "target": tc.Target})
			}
			m["timeConditions"] = times
		}
		out = append(out, m)
	}
	return out
}

// parseTrustPolicy extracts the principals a role of account may be assumed by from an AWS
// AssumeRolePolicyDocument, returning the kind: Role spec.trust list. Only the sts:AssumeRole Allow
// statements count. As AWS reads a trust policy:
//   - Principal "*" (or {"AWS":"*"}) is "*": any principal, of any account;
//   - a user or role of the role's own account is that User ("<name>") or that role's sessions
//     ("Role::<name>");
//   - an account's root, and any user or role of another account, stay the ARN they are: the account's
//     principals, or that one principal, matched by the caller's account (sts.go trustedARN) — never "*";
//   - a service principal is recorded as "Service::<service>" (EC2's as "vm", the instance principal the
//     instance-credentials path honours); a service assumes the role only where its front door does so.
func parseTrustPolicy(doc, account string) ([]string, error) {
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
			switch {
			case p == "*":
				add("*")
			case !strings.HasPrefix(p, "arn:"):
				// A bare account id is that account's root, as AWS reads it.
				if accountIDRe.MatchString(p) {
					add("arn:aws:iam::" + p + ":root")
				}
			case arnAccountField(p) != account || isRootOrAccountArn(p):
				add(p) // another account's principal, or an account's root: matched by account
			case userFromArn(p) != "":
				add(lastSegment(userFromArn(p)))
			case strings.Contains(p, ":role/"):
				add("Role::" + lastSegment(p[strings.Index(p, ":role/")+len(":role/"):])) // a role's sessions (role chaining)
			}
		}
		for _, svc := range servicePrincipals(prin) {
			if svc == "ec2.amazonaws.com" {
				add("vm")
				continue
			}
			add("Service::" + svc)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no sts:AssumeRole Allow principal found")
	}
	return out, nil
}

// arnAccountField is an ARN's account field, as written ("" when it has none).
func arnAccountField(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// servicePrincipals extracts a trust statement's {"Service": ...} principals (a string or a list).
func servicePrincipals(v any) []string {
	p, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	switch s := p["Service"].(type) {
	case string:
		return []string{s}
	case []any:
		var out []string
		for _, e := range s {
			if v, _ := e.(string); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}

// trustsService reports whether a role's trust names a service principal (Service::<service>).
func trustsService(trust []string, service string) bool {
	for _, t := range trust {
		if t == "Service::"+service {
			return true
		}
	}
	return false
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

// principalARNs extracts the AWS principals from a trust statement's Principal: "*", or a {"AWS": ...}
// map with a string or list (servicePrincipals reads its {"Service": ...}).
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
// query. Mirrors policyengine's S3/DynamoDB/Lambda mapping; "*" → ("*",""). An S3 object ARN keeps its key
// (arn:aws:s3:::b/k → Bucket b/k), the resource the S3 front door checks an object action on, so a
// simulation answers what a real request would get.
func arnToResourceShim(arn string) (string, string) {
	if arn == "*" || arn == "" {
		return "*", "*"
	}
	switch {
	case strings.HasPrefix(arn, "arn:aws:s3:::"):
		return "Bucket", strings.TrimPrefix(arn, "arn:aws:s3:::")
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
