// The IAM front door's instance-profile reads: GetInstanceProfile, ListInstanceProfiles and
// ListInstanceProfilesForRole.
//
// An instance profile provisions nothing on open-infra: a stack's AWS::IAM::InstanceProfile only carries
// an instance's IamInstanceProfile through to its role, which binds directly on the VM (kind:
// VirtualMachine spec.instanceRole). So a profile is read from its stack's recorded template, as the
// stack resolved it (cfn.TemplateResourcesOf), while the stack holds it: its name is its Ref (the id the
// stack's DescribeStackResources lists it by), its path and tags the template's, its ARN
// arn:aws:iam::<account>:instance-profile<path><name> (the stack's Fn::GetAtt Arn), its id an AIPA… id
// derived from the stack and logical id, its create date the stack's, and its roles each in-stack
// AWS::IAM::Role it names as the stack resolved that role (its Ref, path, Fn::GetAtt Arn and RoleId, its
// trust policy).
//
// Authorization, as AWS evaluates it: iam:GetInstanceProfile on the profile's ARN (with its path), iam:
// ListInstanceProfiles on arn:aws:iam::<account>:instance-profile<PathPrefix>*, iam:
// ListInstanceProfilesForRole on the role. In legacy the IAM front door's coarse RBAC check (get on its
// roles) comes first, and a profile is read only by a caller that may read its stack, as
// DescribeStackResources needs (a profile belongs to its stack and to nothing else); a list leaves out the
// profiles of stacks the caller may not read. In enforce IAM policy alone decides.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cfnInstanceProfileType = "AWS::IAM::InstanceProfile"
	cfnIAMRoleType         = "AWS::IAM::Role"
)

// iamInstanceProfileOp reports whether op is one of the instance-profile reads (authorized here, not by
// serve's per-entity gate: their resource is the profile, or the role a profile lists).
func iamInstanceProfileOp(op string) bool {
	switch op {
	case "GetInstanceProfile", "ListInstanceProfiles", "ListInstanceProfilesForRole":
		return true
	}
	return false
}

// iamInstanceProfile is a stack's instance profile.
type iamInstanceProfile struct {
	rec         *cfn.StackRecord
	logicalID   string
	name, path  string
	arn, id     string
	created     string
	tags        map[string]string
	roles       []iamProfileRole
	roleNameSet map[string]bool // lower-cased: IAM names are unique without regard to case
}

// iamProfileRole is a role a profile lists, as IAM describes a role.
type iamProfileRole struct{ name, path, arn, id, created, trust string }

// iamPathOf is an IAM path as IAM writes one: "/" when unset, always ending in "/".
func iamPathOf(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// instanceProfileID is a profile's unique id: AIPA and 17 upper-case characters derived from its stack and
// logical id (the shape the engine gives a role's RoleId, AROA…).
func instanceProfileID(stack, logicalID string) string {
	sum := sha256.Sum256([]byte(stack + "/" + logicalID + "/"))
	return "AIPA" + strings.ToUpper(hex.EncodeToString(sum[:])[:17])
}

// iamTime is a record time in IAM's form (RFC 3339, UTC, seconds); the first that parses.
func iamTime(ts ...string) string {
	for _, s := range ts {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return time.Unix(0, 0).UTC().Format(time.RFC3339)
}

// instanceProfiles are the instance profiles of the caller's account's stacks that hold them, by name.
func (h *iamHandler) instanceProfiles(ctx context.Context) ([]iamInstanceProfile, error) {
	if h.cfn == nil || h.cfn.shimDyn == nil {
		return nil, nil // no CloudFormation front door: no stack has made a profile
	}
	recs, err := accountStacks(ctx, h.cfn)
	if err != nil {
		return nil, err
	}
	acct := callerAccount(ctx)
	var out []iamInstanceProfile
	for _, rec := range recs {
		if !stackHolds(rec) || !strings.Contains(rec.Template, cfnInstanceProfileType) {
			continue
		}
		trs := templateResources(rec, recs, cfnInstanceProfileType, cfnIAMRoleType)
		roles := map[string]cfn.TemplateResource{}
		for _, tr := range trs {
			if tr.Type == cfnIAMRoleType && tr.Ref != "" {
				roles[tr.Ref] = tr
			}
		}
		created := iamTime(rec.CreatedAt)
		for _, tr := range trs {
			if tr.Type != cfnInstanceProfileType || tr.Ref == "" {
				continue
			}
			p := iamInstanceProfile{rec: rec, logicalID: tr.LogicalID, name: tr.Ref, path: iamPathOf(fnStr(tr.Properties["Path"])),
				id: instanceProfileID(rec.Name, tr.LogicalID), created: created, tags: templateTags(tr), roleNameSet: map[string]bool{}}
			p.arn = "arn:aws:iam::" + acct + ":instance-profile" + p.path + p.name
			for _, name := range cfStrings(tr.Properties["Roles"]) {
				role := iamProfileRole{name: name, path: "/", id: roleID(name), created: created}
				if rt, ok := roles[name]; ok {
					role.path = iamPathOf(fnStr(rt.Properties["Path"]))
					role.id = cfOrDefault(rt.Attrs["RoleId"], role.id)
					if doc, err := json.Marshal(rt.Properties["AssumeRolePolicyDocument"]); err == nil && rt.Properties["AssumeRolePolicyDocument"] != nil {
						role.trust = string(doc)
					}
				}
				role.arn = "arn:aws:iam::" + acct + ":role" + role.path + role.name
				p.roles = append(p.roles, role)
				p.roleNameSet[strings.ToLower(name)] = true
			}
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// inAccountOpts names the resource's account for a member account's request (its IAM entities are its own).
func (h *iamHandler) inAccountOpts(ctx context.Context) []iamauthz.RequestOption {
	if sc := h.scope(ctx); sc.ns != h.usersNS {
		return []iamauthz.RequestOption{iamauthz.WithResourceAccount(sc.account)}
	}
	return nil
}

func (h *iamHandler) serveInstanceProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string, claims iam.Claims) {
	switch op {
	case "GetInstanceProfile":
		h.getInstanceProfile(ctx, w, r, requestID, claims)
	case "ListInstanceProfiles", "ListInstanceProfilesForRole":
		h.listInstanceProfiles(ctx, w, r, op, requestID, claims)
	}
}

func (h *iamHandler) getInstanceProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name := r.PostFormValue("InstanceProfileName")
	if name == "" {
		h.fail(w, requestID, validationErr("1 validation error detected: Value null at 'instanceProfileName' failed to satisfy constraint: Member must not be null"))
		return
	}
	// The profile is found before it is authorized only for its path: AWS authorizes on the profile's ARN,
	// which carries it. A caller not allowed the action is denied whether or not the profile exists.
	profiles, lerr := h.instanceProfiles(ctx)
	var p *iamInstanceProfile
	for i := range profiles {
		if strings.EqualFold(profiles[i].name, name) {
			p = &profiles[i]
			break
		}
	}
	arn := "arn:aws:iam::" + callerAccount(ctx) + ":instance-profile/" + name
	if p != nil {
		arn = p.arn
	}
	if ok, reason := decide(ctx, r, h.authz, claims, "iam:GetInstanceProfile", arnType, arn, func() (bool, string) {
		if ok, why := coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, "get", "iam.openinfra.dev", "roles", h.usersNS, "",
			"iam:GetInstanceProfile", arnType, arn)(); !ok {
			return false, why
		}
		if p != nil {
			return h.cfn.canDo(ctx, claims, "get", p.rec.Name)
		}
		return true, ""
	}, h.inAccountOpts(ctx)...); !ok {
		h.audit(ctx, "GetInstanceProfile", name, "deny", reason)
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, iamXMLNamespace)
		return
	}
	if lerr != nil {
		h.internal(w, requestID, lerr)
		return
	}
	if p == nil {
		h.noSuchEntity(w, requestID, "Instance Profile "+name+" cannot be found.")
		return
	}
	h.writeResult(w, requestID, "GetInstanceProfile", "<InstanceProfile>"+instanceProfileXML(*p, true)+"</InstanceProfile>")
}

// listInstanceProfiles answers ListInstanceProfiles (the account's, under PathPrefix) and
// ListInstanceProfilesForRole (those listing RoleName), by name, paged by Marker (the last name answered)
// and MaxItems (default 100, at most 1000).
func (h *iamHandler) listInstanceProfiles(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string, claims iam.Claims) {
	role := r.PostFormValue("RoleName")
	prefix := iamPathOf(r.PostFormValue("PathPrefix"))
	resType, resID := arnType, "arn:aws:iam::"+callerAccount(ctx)+":instance-profile"+prefix+"*"
	if op == "ListInstanceProfilesForRole" {
		if role == "" {
			h.fail(w, requestID, validationErr("1 validation error detected: Value null at 'roleName' failed to satisfy constraint: Member must not be null"))
			return
		}
		resType, resID = "Role", role
	}
	if ok, reason := decide(ctx, r, h.authz, claims, "iam:"+op, resType, resID,
		coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, "get", "iam.openinfra.dev", "roles", h.usersNS, "", "iam:"+op, resType, resID),
		h.inAccountOpts(ctx)...); !ok {
		h.audit(ctx, op, role, "deny", reason)
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, iamXMLNamespace)
		return
	}
	max := 100
	if s := r.PostFormValue("MaxItems"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000 {
			h.fail(w, requestID, validationErr("1 validation error detected: Value '"+s+"' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000"))
			return
		}
		max = n
	}
	marker := r.PostFormValue("Marker")
	profiles, err := h.instanceProfiles(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if op == "ListInstanceProfilesForRole" && !h.roleExists(ctx, role, profiles) {
		h.noSuchEntity(w, requestID, "The role with name "+role+" cannot be found.")
		return
	}
	enforce := enforcing(ctx, h.authz, claims)
	readable := map[string]bool{}
	var items []string
	last, truncated := "", false
	for _, p := range profiles {
		if p.name <= marker {
			continue
		}
		if op == "ListInstanceProfilesForRole" && !p.roleNameSet[strings.ToLower(role)] {
			continue
		}
		if op == "ListInstanceProfiles" && !strings.HasPrefix(p.path, prefix) {
			continue
		}
		if !enforce {
			ok, seen := readable[p.rec.Name]
			if !seen {
				ok, _ = h.cfn.canDo(ctx, claims, "get", p.rec.Name)
				readable[p.rec.Name] = ok
			}
			if !ok {
				continue
			}
		}
		if len(items) == max {
			truncated = true
			break
		}
		items = append(items, "<member>"+instanceProfileXML(p, false)+"</member>")
		last = p.name
	}
	body := "<InstanceProfiles>" + strings.Join(items, "") + "</InstanceProfiles><IsTruncated>" + strconv.FormatBool(truncated) + "</IsTruncated>"
	if truncated {
		body += "<Marker>" + xmlEscape(last) + "</Marker>"
	}
	h.writeResult(w, requestID, op, body)
}

// roleExists reports whether the caller's account has the role: one a stack's profile lists, or a kind:
// Role in its IAM home.
func (h *iamHandler) roleExists(ctx context.Context, role string, profiles []iamInstanceProfile) bool {
	for _, p := range profiles {
		if p.roleNameSet[strings.ToLower(role)] {
			return true
		}
	}
	_, err := h.dyn.Resource(gvrRoles).Namespace(h.scope(ctx).ns).Get(ctx, role, metav1.GetOptions{})
	return err == nil
}

// instanceProfileXML is an InstanceProfile's fields (with its tags for GetInstanceProfile: a list omits
// them, as IAM's does).
func instanceProfileXML(p iamInstanceProfile, withTags bool) string {
	var b strings.Builder
	b.WriteString("<Path>" + xmlEscape(p.path) + "</Path><InstanceProfileName>" + xmlEscape(p.name) + "</InstanceProfileName>" +
		"<InstanceProfileId>" + xmlEscape(p.id) + "</InstanceProfileId><Arn>" + xmlEscape(p.arn) + "</Arn>" +
		"<CreateDate>" + xmlEscape(p.created) + "</CreateDate><Roles>")
	for _, role := range p.roles {
		b.WriteString("<member><Path>" + xmlEscape(role.path) + "</Path><RoleName>" + xmlEscape(role.name) + "</RoleName><RoleId>" +
			xmlEscape(role.id) + "</RoleId><Arn>" + xmlEscape(role.arn) + "</Arn><CreateDate>" + xmlEscape(role.created) + "</CreateDate>")
		if role.trust != "" {
			b.WriteString("<AssumeRolePolicyDocument>" + xmlEscape(encodeDocument(role.trust)) + "</AssumeRolePolicyDocument>")
		}
		b.WriteString("</member>")
	}
	b.WriteString("</Roles>")
	if withTags && len(p.tags) > 0 {
		keys := make([]string, 0, len(p.tags))
		for k := range p.tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("<Tags>")
		for _, k := range keys {
			b.WriteString("<member><Key>" + xmlEscape(k) + "</Key><Value>" + xmlEscape(p.tags[k]) + "</Value></member>")
		}
		b.WriteString("</Tags>")
	}
	return b.String()
}
