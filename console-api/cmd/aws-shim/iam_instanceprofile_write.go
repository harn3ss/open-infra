// The IAM front door's instance-profile writes: CreateInstanceProfile, DeleteInstanceProfile,
// AddRoleToInstanceProfile and RemoveRoleFromInstanceProfile, on the profiles the IAM API makes
// (iam_instanceprofile_store.go). A profile a stack holds is changed only through its stack.
package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/mfa"
)

// instanceProfileNameRe is IAM's InstanceProfileName pattern (1 to 128 characters).
var instanceProfileNameRe = regexp.MustCompile(`^[\w+=,.@-]+$`)

// findInstanceProfile is the caller's account's profile named name (in any case), nil for none.
func (h *iamHandler) findInstanceProfile(ctx context.Context, name string) (*iamInstanceProfile, error) {
	profiles, err := h.instanceProfiles(ctx)
	if err != nil {
		return nil, err
	}
	for i := range profiles {
		if strings.EqualFold(profiles[i].name, name) {
			return &profiles[i], nil
		}
	}
	return nil, nil
}

// authorizeProfile decides iam:<op> on a profile's ARN, writing AWS's AccessDenied when it is refused: in
// legacy the coarse RBAC check (verb on the IAM front door's roles) first, in enforce IAM policy alone.
func (h *iamHandler) authorizeProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, op, verb, arn, entity string) bool {
	ok, reason := decide(ctx, r, h.authz, claims, "iam:"+op, arnType, arn,
		coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "iam.openinfra.dev", "roles", h.usersNS, "", "iam:"+op, arnType, arn),
		h.inAccountOpts(ctx)...)
	if !ok {
		h.audit(ctx, op, entity, "deny", reason)
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, iamXMLNamespace)
	}
	return ok
}

// profileARN is the ARN a request naming profile name is authorized on: the profile's own (with its path),
// else the one it would have under the root path. A caller not allowed the action is refused whether or not
// the profile exists.
func (h *iamHandler) profileARN(ctx context.Context, p *iamInstanceProfile, name string) string {
	if p != nil {
		return p.arn
	}
	return "arn:aws:iam::" + callerAccount(ctx) + ":instance-profile/" + name
}

// stackOwned refuses a change to a profile a stack holds, which changes only through its stack.
func stackOwned(w http.ResponseWriter, requestID string, p *iamInstanceProfile) bool {
	if p == nil || p.rec == nil {
		return false
	}
	writeQueryError(w, http.StatusBadRequest, "UnmodifiableEntity", requestID, "Instance Profile "+p.name+
		" belongs to CloudFormation stack "+p.rec.Name+" and is changed only through that stack.", iamXMLNamespace)
	return true
}

// noProfileStore answers a write when the shim keeps no profiles (its Postgres is not configured).
func noProfileStore(w http.ResponseWriter, requestID string) {
	writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID,
		"the instance-profile store is not configured on this shim.", iamXMLNamespace)
}

// createInstanceProfile makes a profile of the caller's account (CreateInstanceProfile): its name, its path
// (/ when none is given) and its tags, with no role yet.
func (h *iamHandler) createInstanceProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name, path := r.PostFormValue("InstanceProfileName"), r.PostFormValue("Path")
	if path == "" {
		path = "/"
	}
	switch {
	case name == "":
		h.validation(w, requestID, "1 validation error detected: Value null at 'instanceProfileName' failed to satisfy constraint: Member must not be null")
		return
	case len(name) > 128:
		h.validation(w, requestID, "1 validation error detected: Value '"+name+"' at 'instanceProfileName' failed to satisfy constraint: Member must have length less than or equal to 128")
		return
	case !instanceProfileNameRe.MatchString(name):
		h.validation(w, requestID, "1 validation error detected: Value '"+name+"' at 'instanceProfileName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]+")
		return
	case !mfa.ValidPath(path):
		h.validation(w, requestID, "1 validation error detected: Value '"+path+"' at 'path' failed to satisfy constraint: Member must satisfy regular expression pattern: (\\u002F)|(\\u002F[\\u0021-\\u007E]+\\u002F)")
		return
	}
	tags, why := mfaTagsFromForm(r)
	if why != "" {
		h.fail(w, requestID, invalidInputErr(why))
		return
	}
	tagMap := map[string]string{}
	for _, t := range tags {
		if _, dup := tagMap[t.Key]; dup {
			h.fail(w, requestID, invalidInputErr("Duplicate tag keys found."))
			return
		}
		tagMap[t.Key] = t.Value
	}
	arn := "arn:aws:iam::" + callerAccount(ctx) + ":instance-profile" + path + name
	if !h.authorizeProfile(ctx, w, r, requestID, claims, "CreateInstanceProfile", "create", arn, name) {
		return
	}
	// Tags given on create tag the new profile, which AWS authorizes as well.
	if len(tags) > 0 && !h.authorizeProfile(ctx, w, r, requestID, claims, "TagInstanceProfile", "create", arn, name) {
		return
	}
	if h.profiles == nil {
		noProfileStore(w, requestID)
		return
	}
	// A name is the account's once: a stack's profile has it as surely as one made here.
	stack, err := h.stackInstanceProfiles(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	for _, p := range stack {
		if strings.EqualFold(p.name, name) {
			h.conflict(w, requestID, "EntityAlreadyExists", "Instance Profile "+name+" already exists.")
			return
		}
	}
	sp, err := h.profiles.create(ctx, h.profileAccount(ctx), storedInstanceProfile{Name: name, Path: path, ID: newInstanceProfileID(), Tags: tagMap})
	switch {
	case errors.Is(err, errProfileExists):
		h.conflict(w, requestID, "EntityAlreadyExists", "Instance Profile "+name+" already exists.")
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateInstanceProfile", name, "allow", "")
	h.writeResult(w, requestID, "CreateInstanceProfile", "<InstanceProfile>"+instanceProfileXML(h.apiInstanceProfile(ctx, sp), true)+"</InstanceProfile>")
}

// deleteInstanceProfile deletes a profile of the caller's account (DeleteInstanceProfile), refused while it
// still has its role, as AWS refuses it.
func (h *iamHandler) deleteInstanceProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	vals, err := required(r, "InstanceProfileName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	name := vals[0]
	p, lerr := h.findInstanceProfile(ctx, name)
	if !h.authorizeProfile(ctx, w, r, requestID, claims, "DeleteInstanceProfile", "delete", h.profileARN(ctx, p, name), name) {
		return
	}
	switch {
	case lerr != nil:
		h.internal(w, requestID, lerr)
		return
	case p == nil:
		h.noSuchEntity(w, requestID, "Instance Profile "+name+" cannot be found.")
		return
	case stackOwned(w, requestID, p):
		return
	case h.profiles == nil:
		noProfileStore(w, requestID)
		return
	}
	switch err := h.profiles.delete(ctx, h.profileAccount(ctx), p.name); {
	case errors.Is(err, errProfileHasRole):
		h.conflict(w, requestID, "DeleteConflict", "Cannot delete entity, must remove roles from instance profile first.")
		return
	case errors.Is(err, errNoProfile):
		h.noSuchEntity(w, requestID, "Instance Profile "+name+" cannot be found.")
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteInstanceProfile", p.name, "allow", "")
	h.writeResult(w, requestID, "DeleteInstanceProfile", "")
}

// instanceProfileRole serves AddRoleToInstanceProfile and RemoveRoleFromInstanceProfile. A profile holds one
// role (a second is LimitExceeded, as on AWS), and adding one needs iam:PassRole on it as well: the profile
// hands it to the instances launched with it.
func (h *iamHandler) instanceProfileRole(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string, claims iam.Claims) {
	vals, err := required(r, "InstanceProfileName", "RoleName")
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	name, roleName := vals[0], vals[1]
	p, lerr := h.findInstanceProfile(ctx, name)
	if !h.authorizeProfile(ctx, w, r, requestID, claims, op, "create", h.profileARN(ctx, p, name), name) {
		return
	}
	add := op == "AddRoleToInstanceProfile"
	if add {
		// The role's object is its AWS name lower-cased; the passrole grant is on that object.
		if ok, reason := callerMayPassRole(ctx, h.cs, h.authz, claims, h.scope(ctx).ns, strings.ToLower(roleName), instanceProfileService, r,
			h.inAccountOpts(ctx)...); !ok {
			h.audit(ctx, op, name, "deny", reason)
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, iamXMLNamespace)
			return
		}
	}
	switch {
	case lerr != nil:
		h.internal(w, requestID, lerr)
		return
	case p == nil:
		h.noSuchEntity(w, requestID, "Instance Profile "+name+" cannot be found.")
		return
	case stackOwned(w, requestID, p):
		return
	case h.profiles == nil:
		noProfileStore(w, requestID)
		return
	}
	acct := h.profileAccount(ctx)
	if !add {
		switch err := h.profiles.removeRole(ctx, acct, p.name, roleName); {
		case errors.Is(err, errNoProfile):
			h.noSuchEntity(w, requestID, "Instance Profile "+name+" cannot be found.")
			return
		case errors.Is(err, errRoleNotInProfile):
			h.noSuchEntity(w, requestID, "The role with name "+roleName+" cannot be found.")
			return
		case err != nil:
			h.internal(w, requestID, err)
			return
		}
		h.audit(ctx, op, p.name, "allow", "role="+roleName)
		h.writeResult(w, requestID, op, "")
		return
	}
	role, ok := h.accountRole(ctx, roleName)
	if !ok {
		h.noSuchEntity(w, requestID, "The role with name "+roleName+" cannot be found.")
		return
	}
	switch err := h.profiles.addRole(ctx, acct, p.name, role.GetName()); {
	case errors.Is(err, errProfileHasRole):
		h.conflict(w, requestID, "LimitExceeded", "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1")
		return
	case errors.Is(err, errNoProfile):
		h.noSuchEntity(w, requestID, "Instance Profile "+name+" cannot be found.")
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, op, p.name, "allow", "role="+role.GetName())
	h.writeResult(w, requestID, op, "")
}

// roleInAProfile reports whether one of the caller's account's profiles made with the IAM API has role:
// DeleteRole refuses such a role, as AWS does, until it is removed from the profile.
func (h *iamHandler) roleInAProfile(ctx context.Context, role string) (bool, error) {
	if h.profiles == nil {
		return false, nil
	}
	return h.profiles.roleInUse(ctx, h.profileAccount(ctx), role)
}
