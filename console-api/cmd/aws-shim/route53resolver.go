// Route 53 Resolver front door for the aws-shim: DNS Firewall (domain lists, rule groups and rules, their
// VPC associations, each VPC's firewall configuration) and Resolver query logging (configurations whose
// destination is a CloudWatch Logs log group, associated with VPCs).
//
// Speaks AWS JSON 1.1 (X-Amz-Target: Route53Resolver.<Op>, signing name route53resolver). Backed by
// Postgres (route53resolver_store.go). What it stores is applied by the VPC resolver (vpcresolver.go), the
// DNS server Lambda functions in a VPC use: their queries are filtered by the VPC's rule groups and logged
// to the VPC's query log destinations. An association applies as soon as it is stored, so it is answered
// COMPLETE (a query log association ACTIVE).
//
// Not served, and refused as such: DNS Firewall Advanced rules (DnsThreatProtection, FirewallRuleType),
// AWS managed domain lists, importing domains from Amazon S3, query log destinations other than a
// CloudWatch Logs log group, and the rest of Route 53 Resolver (endpoints, forwarding rules, DNSSEC,
// Profiles).
//
// Authorization is the one policy world: route53resolver:<Op> on the resource it names — FirewallDomainList,
// FirewallRuleGroup, FirewallRuleGroupAssociation, FirewallConfig or ResolverQueryLogConfig::<id> (Type::*
// for an operation that names none). A rule's create and update are decided on its rule group and on the
// domain list it uses, as AWS does.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// Route 53 Resolver keeps each account's resources apart: a member account's domain lists, rule groups,
// associations, firewall configurations and query log configurations are its own (owner: its account id),
// and its associations name its own VPCs alone.
func init() { accountScopedServices["route53resolver"] = true }

// vpcLister lists the caller's account's VPC ids (kind: Vpc claims); denied when the caller may not read them.
type vpcLister func(ctx context.Context, claims iam.Claims) (ids []string, denied bool, err error)

type r53rHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *r53rStore
	authz   *dataplaneauthz.Checker
	vpcs    vpcLister // nil: the account's VPCs cannot be read here (an operation naming one answers so)
	logger  *slog.Logger
}

func newR53RHandler(cs kubernetes.Interface, authzNS, account, region string, store *r53rStore, logger *slog.Logger) *r53rHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &r53rHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, logger: logger}
}

const (
	r53rContentType  = "application/x-amz-json-1.1"
	r53rTargetPrefix = "Route53Resolver." // X-Amz-Target: Route53Resolver.<Op>
)

func writeR53RError(w http.ResponseWriter, status int, code, requestID, message string) {
	writeR53RErr(w, status, requestID, &r53rError{Code: code, Message: message})
}

// writeR53RErr writes AWS's JSON error: __type, Message and, where AWS names them, ResourceType and FieldName.
func writeR53RErr(w http.ResponseWriter, status int, requestID string, e *r53rError) {
	body := map[string]string{"__type": e.Code, "Message": awserr.Clean(e.Message)}
	if e.ResourceType != "" {
		body["ResourceType"] = e.ResourceType
	}
	if e.FieldName != "" {
		body["FieldName"] = e.FieldName
	}
	w.Header().Set("Content-Type", r53rContentType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeR53RJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", r53rContentType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *r53rHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeR53RError(w, http.StatusForbidden, authCode(r, "InvalidSignatureException"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."))
}

// fail answers err: a Route 53 Resolver error as itself (400, as AWS answers each), anything else as an
// internal error.
func (h *r53rHandler) fail(w http.ResponseWriter, requestID string, err error) {
	if e, ok := err.(*r53rError); ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	h.logger.Error("route53resolver backend error", "error", err.Error())
	writeR53RError(w, http.StatusBadRequest, "InternalServiceErrorException", requestID,
		"We encountered an unknown error. Try again in a few minutes.")
}

// verbForR53ROp is the coarse verb of an operation's legacy check.
func verbForR53ROp(op string) (string, bool) {
	switch op {
	case "GetFirewallDomainList", "ListFirewallDomainLists", "ListFirewallDomains", "GetFirewallRuleGroup",
		"ListFirewallRuleGroups", "ListFirewallRules", "GetFirewallRuleGroupAssociation", "ListFirewallRuleGroupAssociations",
		"GetFirewallConfig", "ListFirewallConfigs", "GetResolverQueryLogConfig", "ListResolverQueryLogConfigs",
		"GetResolverQueryLogConfigAssociation", "ListResolverQueryLogConfigAssociations", "ListTagsForResource":
		return "get", true
	case "CreateFirewallDomainList", "UpdateFirewallDomains", "CreateFirewallRuleGroup", "CreateFirewallRule",
		"UpdateFirewallRule", "AssociateFirewallRuleGroup", "UpdateFirewallRuleGroupAssociation", "UpdateFirewallConfig",
		"CreateResolverQueryLogConfig", "AssociateResolverQueryLogConfig", "TagResource":
		return "create", true
	case "DeleteFirewallDomainList", "DeleteFirewallRuleGroup", "DeleteFirewallRule", "DisassociateFirewallRuleGroup",
		"DeleteResolverQueryLogConfig", "DisassociateResolverQueryLogConfig", "UntagResource":
		return "delete", true
	}
	return "", false
}

func (h *r53rHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	switch op {
	case "":
		writeR53RError(w, http.StatusBadRequest, "InvalidAction", requestID, "no X-Amz-Target (expected Route53Resolver.<Op>).")
		return
	case "ImportFirewallDomains":
		writeR53RError(w, http.StatusBadRequest, "ValidationException", requestID,
			"Importing domains from Amazon S3 is not supported here: add them with UpdateFirewallDomains.")
		return
	case "ListFirewallRuleTypes":
		writeR53RError(w, http.StatusBadRequest, "ValidationException", requestID,
			"DNS Firewall Advanced rule types are not supported here: a rule matches a domain list (FirewallDomainListId).")
		return
	}
	verb, known := verbForR53ROp(op)
	if !known {
		writeR53RError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"Route 53 Resolver "+op+" is not supported here (DNS Firewall and query logging are).")
		return
	}
	if h.store == nil {
		writeR53RError(w, http.StatusServiceUnavailable, "InternalServiceErrorException", requestID,
			"the Route 53 Resolver data layer is not configured on this endpoint")
		return
	}
	body := readJSONBody(r)
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	resType, resID := r53rResourceOf(ctx, op, body)

	// route53resolver:<Op> on the resource (decide): in legacy the coarse SubjectAccessReview, then the
	// data-plane refinement (an assumed role is checked on every operation, a list on <Type>::*).
	if ok, reason := decide(ctx, r, h.authz, claims, "route53resolver:"+op, resType, resID,
		coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "openinfra.dev", "applications", h.authzNS, resID,
			"route53resolver:"+op, resType, resID)); !ok {
		h.auditDeny(ctx, op, resType, resID, reason)
		writeR53RError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
		return
	}
	// A rule is decided on the domain list it uses too.
	if op == "CreateFirewallRule" || op == "UpdateFirewallRule" {
		if list := r53rStr(body, "FirewallDomainListId"); list != "" {
			if ok, reason := decide(ctx, r, h.authz, claims, "route53resolver:"+op, "FirewallDomainList", list,
				dataPlaneOnly(ctx, r, h.authz, claims, "route53resolver:"+op, "FirewallDomainList", list)); !ok {
				h.auditDeny(ctx, op, "FirewallDomainList", list, reason)
				writeR53RError(w, http.StatusBadRequest, "AccessDeniedException", requestID, reason)
				return
			}
		}
	}

	if lim, isList := r53rListLimits[op]; isList {
		queryLog := strings.Contains(op, "QueryLog") || op == "ListTagsForResource"
		if e := checkMaxResults(body, lim[0], lim[1], queryLog); e != nil {
			writeR53RErr(w, http.StatusBadRequest, requestID, e)
			return
		}
	}

	switch op {
	case "CreateFirewallDomainList":
		h.createDomainList(ctx, w, requestID, body)
	case "GetFirewallDomainList":
		h.getDomainList(ctx, w, requestID, body)
	case "ListFirewallDomainLists":
		h.listDomainLists(ctx, w, requestID, body)
	case "DeleteFirewallDomainList":
		h.deleteDomainList(ctx, w, requestID, body)
	case "UpdateFirewallDomains":
		h.updateDomains(ctx, w, requestID, body)
	case "ListFirewallDomains":
		h.listDomains(ctx, w, requestID, body)
	case "CreateFirewallRuleGroup":
		h.createRuleGroup(ctx, w, requestID, body)
	case "GetFirewallRuleGroup":
		h.getRuleGroup(ctx, w, requestID, body)
	case "ListFirewallRuleGroups":
		h.listRuleGroups(ctx, w, requestID, body)
	case "DeleteFirewallRuleGroup":
		h.deleteRuleGroup(ctx, w, requestID, body)
	case "CreateFirewallRule":
		h.createRule(ctx, w, requestID, body)
	case "UpdateFirewallRule":
		h.updateRule(ctx, w, requestID, body)
	case "DeleteFirewallRule":
		h.deleteRule(ctx, w, requestID, body)
	case "ListFirewallRules":
		h.listRules(ctx, w, requestID, body)
	case "AssociateFirewallRuleGroup":
		h.associate(ctx, w, requestID, claims, body)
	case "DisassociateFirewallRuleGroup":
		h.disassociate(ctx, w, requestID, body)
	case "GetFirewallRuleGroupAssociation":
		h.getAssociation(ctx, w, requestID, body)
	case "UpdateFirewallRuleGroupAssociation":
		h.updateAssociation(ctx, w, requestID, body)
	case "ListFirewallRuleGroupAssociations":
		h.listAssociations(ctx, w, requestID, body)
	case "GetFirewallConfig":
		h.getFirewallConfig(ctx, w, requestID, claims, body)
	case "UpdateFirewallConfig":
		h.updateFirewallConfig(ctx, w, requestID, claims, body)
	case "ListFirewallConfigs":
		h.listFirewallConfigs(ctx, w, requestID, claims, body)
	case "CreateResolverQueryLogConfig":
		h.createQueryLogConfig(ctx, w, requestID, body)
	case "GetResolverQueryLogConfig":
		h.getQueryLogConfig(ctx, w, requestID, body)
	case "ListResolverQueryLogConfigs":
		h.listQueryLogConfigs(ctx, w, requestID, body)
	case "DeleteResolverQueryLogConfig":
		h.deleteQueryLogConfig(ctx, w, requestID, body)
	case "AssociateResolverQueryLogConfig":
		h.associateQueryLog(ctx, w, requestID, claims, body)
	case "DisassociateResolverQueryLogConfig":
		h.disassociateQueryLog(ctx, w, requestID, body)
	case "GetResolverQueryLogConfigAssociation":
		h.getQueryLogAssociation(ctx, w, requestID, body)
	case "ListResolverQueryLogConfigAssociations":
		h.listQueryLogAssociations(ctx, w, requestID, body)
	case "TagResource":
		h.tagResource(ctx, w, requestID, body)
	case "UntagResource":
		h.untagResource(ctx, w, requestID, body)
	case "ListTagsForResource":
		h.listTags(ctx, w, requestID, body)
	}
}

// r53rResourceOf is the resource an operation is authorized on: its type and id ("" for an operation that
// names none: AWS's Resource "*").
func r53rResourceOf(ctx context.Context, op string, body map[string]any) (string, string) {
	switch op {
	case "CreateFirewallDomainList", "ListFirewallDomainLists":
		return "FirewallDomainList", ""
	case "GetFirewallDomainList", "DeleteFirewallDomainList", "UpdateFirewallDomains", "ListFirewallDomains":
		return "FirewallDomainList", r53rStr(body, "FirewallDomainListId")
	case "CreateFirewallRuleGroup", "ListFirewallRuleGroups":
		return "FirewallRuleGroup", ""
	case "GetFirewallRuleGroup", "DeleteFirewallRuleGroup", "CreateFirewallRule", "UpdateFirewallRule", "DeleteFirewallRule",
		"ListFirewallRules", "AssociateFirewallRuleGroup":
		return "FirewallRuleGroup", r53rStr(body, "FirewallRuleGroupId")
	case "DisassociateFirewallRuleGroup", "GetFirewallRuleGroupAssociation", "UpdateFirewallRuleGroupAssociation":
		return "FirewallRuleGroupAssociation", r53rStr(body, "FirewallRuleGroupAssociationId")
	case "ListFirewallRuleGroupAssociations":
		return "FirewallRuleGroupAssociation", ""
	case "GetFirewallConfig", "UpdateFirewallConfig":
		if vpc := r53rStr(body, "ResourceId"); vpc != "" {
			return "FirewallConfig", firewallConfigID(r53rOwner(ctx), vpc)
		}
		return "FirewallConfig", ""
	case "ListFirewallConfigs":
		return "FirewallConfig", ""
	case "CreateResolverQueryLogConfig", "ListResolverQueryLogConfigs", "GetResolverQueryLogConfigAssociation",
		"ListResolverQueryLogConfigAssociations":
		return "ResolverQueryLogConfig", ""
	case "GetResolverQueryLogConfig", "DeleteResolverQueryLogConfig", "AssociateResolverQueryLogConfig",
		"DisassociateResolverQueryLogConfig":
		return "ResolverQueryLogConfig", r53rStr(body, "ResolverQueryLogConfigId")
	case "TagResource", "UntagResource", "ListTagsForResource":
		if typ, id, ok := r53rResourceOfARN(r53rStr(body, "ResourceArn")); ok {
			return typ, id
		}
	}
	return "", ""
}

// r53rARNTypes are the ARN resource types (arn:aws:route53resolver:<region>:<account>:<type>/<id>) of the
// resources served here, and the resource type each is authorized as.
var r53rARNTypes = map[string]string{
	"firewall-domain-list":            "FirewallDomainList",
	"firewall-rule-group":             "FirewallRuleGroup",
	"firewall-rule-group-association": "FirewallRuleGroupAssociation",
	"firewall-config":                 "FirewallConfig",
	"resolver-query-log-config":       "ResolverQueryLogConfig",
}

// r53rResourceOfARN is the resource type and id a Route 53 Resolver ARN names.
func r53rResourceOfARN(arn string) (string, string, bool) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[2] != "route53resolver" {
		return "", "", false
	}
	typ, id, ok := strings.Cut(p[5], "/")
	if !ok || id == "" || strings.Contains(id, "/") || r53rARNTypes[typ] == "" {
		return "", "", false
	}
	return r53rARNTypes[typ], id, true
}

// r53rOwner is the store owner of the caller's account's resources (r53rOwnerOf).
func r53rOwner(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return ""
	}
	return callerAccount(ctx)
}

// accountOf is the account the caller's resources belong to: the account their ARNs and OwnerId name.
func (h *r53rHandler) accountOf(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

func (h *r53rHandler) arn(ctx context.Context, typ, id string) string {
	return "arn:aws:route53resolver:" + h.region + ":" + h.accountOf(ctx) + ":" + typ + "/" + id
}

// firewallConfigID is the id of a VPC's firewall configuration (rslvr-fc-…): one per VPC, stable.
func firewallConfigID(owner, vpcID string) string {
	return shortHashID("rslvr-fc-", "firewall-config/"+owner+"/"+vpcID, 17)
}

// r53rNewID is a new resource id: prefix and n random hex digits, AWS's shape (rslvr-fdl-…, rqlc-…).
func r53rNewID(prefix string, n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)[:n]
}

// r53rTime is a Route 53 Resolver timestamp: ISO 8601 in UTC, to the millisecond.
func r53rTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func r53rStr(body map[string]any, k string) string { s, _ := body[k].(string); return s }

// r53rInt is a numeric member, and whether the request carries one.
func r53rInt(body map[string]any, k string) (int, bool) {
	switch v := body[k].(type) {
	case float64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil
	}
	return 0, false
}

// r53rNameRe is AWS's name pattern, (?!^[0-9]+$)([a-zA-Z0-9\-_' ']+), at most 64 characters.
var r53rNameRe = regexp.MustCompile(`^[a-zA-Z0-9\-_' ]+$`)
var r53rDigitsRe = regexp.MustCompile(`^[0-9]+$`)

func validR53RName(s string) bool {
	return s != "" && len(s) <= 64 && r53rNameRe.MatchString(s) && !r53rDigitsRe.MatchString(s)
}

// enumError is AWS's validation message for a value outside an enum.
func enumError(member, value string, allowed ...string) *r53rError {
	return r53rValidation(fmt.Sprintf("1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: "+
		"Member must satisfy enum value set: [%s]", value, member, strings.Join(allowed, ", ")))
}

func requiredError(member string) *r53rError {
	return r53rValidation("1 validation error detected: Value null at '" + member + "' failed to satisfy constraint: Member must not be null")
}

func nameError(member, value string) *r53rError {
	return r53rValidation(fmt.Sprintf("1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: "+
		"Member must satisfy regular expression pattern: (?!^[0-9]+$)([a-zA-Z0-9\\-_' ']+) and have length less than or equal to 64",
		value, member))
}

// r53rTags reads a request's Tags ([{Key, Value}], at most 200).
func r53rTags(body map[string]any) (map[string]string, *r53rError) {
	list := sliceOf(body["Tags"])
	if len(list) > 200 {
		return nil, r53rValidation("A resource takes at most 200 tags.")
	}
	out := map[string]string{}
	for _, t := range list {
		m := mapOf(t)
		k, _ := m["Key"].(string)
		v, _ := m["Value"].(string)
		if k == "" || len(k) > 128 || len(v) > 256 {
			return nil, &r53rError{Code: "InvalidTagException", Message: "A tag's Key is 1 to 128 characters and its Value at most 256."}
		}
		out[k] = v
	}
	return out, nil
}

// creatorRequestID is the request's idempotency token; the SDKs fill one in, a request without one is
// given its own.
func creatorRequestID(body map[string]any) (string, *r53rError) {
	id := r53rStr(body, "CreatorRequestId")
	if len(id) > 255 {
		return "", r53rValidation("CreatorRequestId is at most 255 characters.")
	}
	if id == "" {
		id = r53rNewID("", 32)
	}
	return id, nil
}

// r53rPage is the window of n items a list request asks for: MaxResults (def when absent, at most max) from
// its NextToken, and the token of the next window ("" at the end). queryLog picks the query-logging
// operations' error codes.
func r53rPage(n int, body map[string]any, min, def, max int, queryLog bool) (lo, hi int, next string, e *r53rError) {
	size := def
	if e := checkMaxResults(body, min, max, queryLog); e != nil {
		return 0, 0, "", e
	}
	if v, ok := r53rInt(body, "MaxResults"); ok {
		size = v
	}
	if tok := r53rStr(body, "NextToken"); tok != "" {
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		off, perr := strconv.Atoi(strings.TrimPrefix(string(raw), "rslvr-page:"))
		if err != nil || perr != nil || !strings.HasPrefix(string(raw), "rslvr-page:") || off < 0 || off > n {
			code := "ValidationException"
			if queryLog {
				code = "InvalidNextTokenException"
			}
			return 0, 0, "", &r53rError{Code: code, Message: "The NextToken is not valid."}
		}
		lo = off
	}
	hi = lo + size
	if hi >= n {
		return lo, n, "", nil
	}
	return lo, hi, base64.RawURLEncoding.EncodeToString([]byte("rslvr-page:" + strconv.Itoa(hi))), nil
}

// checkMaxResults checks a list request's MaxResults (from min to max), before anything is read.
func checkMaxResults(body map[string]any, min, max int, queryLog bool) *r53rError {
	if v, ok := r53rInt(body, "MaxResults"); ok && (v < min || v > max) {
		code := "ValidationException"
		if queryLog {
			code = "InvalidParameterException"
		}
		return &r53rError{Code: code, FieldName: "MaxResults", Message: fmt.Sprintf("MaxResults must be from %d to %d.", min, max)}
	}
	return nil
}

// r53rListLimits are each list operation's MaxResults range, AWS's.
var r53rListLimits = map[string][2]int{
	"ListFirewallDomainLists": {1, 100}, "ListFirewallDomains": {1, 5000}, "ListFirewallRuleGroups": {1, 100},
	"ListFirewallRules": {1, 100}, "ListFirewallRuleGroupAssociations": {1, 100}, "ListFirewallConfigs": {5, 10},
	"ListResolverQueryLogConfigs": {1, 100}, "ListResolverQueryLogConfigAssociations": {1, 100}, "ListTagsForResource": {1, 100},
}

func withNextToken(m map[string]any, next string) map[string]any {
	if next != "" {
		m["NextToken"] = next
	}
	return m
}

// callerVPC checks that vpcID is one of the caller's account's VPCs.
func (h *r53rHandler) callerVPC(ctx context.Context, claims iam.Claims, vpcID string) *r53rError {
	if h.vpcs == nil {
		return &r53rError{Code: "InternalServiceErrorException", Message: "The account's VPCs cannot be read on this endpoint."}
	}
	ids, denied, err := h.vpcs(ctx, claims)
	if denied {
		return &r53rError{Code: "AccessDeniedException", Message: "You are not authorized to read the VPC " + vpcID + "."}
	}
	if err != nil {
		h.logger.Warn("route53resolver: the account's VPCs could not be read", "error", err.Error())
		return &r53rError{Code: "InternalServiceErrorException", Message: "The account's VPCs could not be read. Try again in a few minutes."}
	}
	for _, id := range ids {
		if id == vpcID {
			return nil
		}
	}
	return r53rNotFound("VPC", "The VPC '"+vpcID+"' does not exist.")
}

// --- domain lists ---

func (h *r53rHandler) domainListJSON(ctx context.Context, l r53rDomainList, status, msg string) map[string]any {
	m := map[string]any{"Id": l.ID, "Arn": h.arn(ctx, "firewall-domain-list", l.ID), "Name": l.Name, "DomainCount": l.DomainCount,
		"Status": status, "CreatorRequestId": l.CreatorRequestID, "CreationTime": r53rTime(l.Created),
		"ModificationTime": r53rTime(l.Modified)}
	if msg != "" {
		m["StatusMessage"] = msg
	}
	return m
}

func (h *r53rHandler) createDomainList(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := r53rStr(body, "Name")
	if !validR53RName(name) {
		writeR53RErr(w, http.StatusBadRequest, requestID, nameError("name", name))
		return
	}
	crid, e := creatorRequestID(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	tags, e := r53rTags(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	l, created, err := h.store.createDomainList(ctx, r53rDomainList{ID: r53rNewID("rslvr-fdl-", 17), Owner: r53rOwner(ctx),
		Name: name, CreatorRequestID: crid}, tags)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if created {
		h.audit(ctx, "CreateFirewallDomainList", l.ID)
	}
	writeR53RJSON(w, requestID, map[string]any{"FirewallDomainList": h.domainListJSON(ctx, l, "COMPLETE", "Created Firewall Domain List")})
}

// mustDomainList is the caller's domain list a request names.
func (h *r53rHandler) mustDomainList(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) (r53rDomainList, bool) {
	id := r53rStr(body, "FirewallDomainListId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallDomainListId"))
		return r53rDomainList{}, false
	}
	l, ok, err := h.store.getDomainList(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return r53rDomainList{}, false
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("FIREWALL_DOMAIN_LIST", "The domain list '"+id+"' does not exist."))
		return r53rDomainList{}, false
	}
	return l, true
}

func (h *r53rHandler) getDomainList(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if l, ok := h.mustDomainList(ctx, w, requestID, body); ok {
		writeR53RJSON(w, requestID, map[string]any{"FirewallDomainList": h.domainListJSON(ctx, l, "COMPLETE", "")})
	}
}

func (h *r53rHandler) listDomainLists(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	lists, err := h.store.listDomainLists(ctx, r53rOwner(ctx))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	lo, hi, next, e := r53rPage(len(lists), body, 1, 100, 100, false)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, l := range lists[lo:hi] {
		out = append(out, map[string]any{"Id": l.ID, "Arn": h.arn(ctx, "firewall-domain-list", l.ID), "Name": l.Name,
			"CreatorRequestId": l.CreatorRequestID})
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"FirewallDomainLists": out}, next))
}

func (h *r53rHandler) deleteDomainList(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallDomainListId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallDomainListId"))
		return
	}
	l, err := h.store.deleteDomainList(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteFirewallDomainList", id)
	writeR53RJSON(w, requestID, map[string]any{"FirewallDomainList": h.domainListJSON(ctx, l, "DELETING", "Deleting the Firewall Domain List")})
}

// r53rDomainRe is AWS's domain specification: an optional leading "*", then letters, digits, hyphens and
// the dots between labels.
var r53rDomainRe = regexp.MustCompile(`^\*?[A-Za-z0-9.-]*$`)

// normalizeR53RDomain checks a domain specification (1-255 characters) and gives the form it is stored and
// matched in: lower case, no trailing dot (DNS names compare case-insensitively, with or without it).
func normalizeR53RDomain(d string) (string, bool) {
	if len(d) < 1 || len(d) > 255 || !r53rDomainRe.MatchString(d) {
		return "", false
	}
	d = strings.ToLower(d)
	if d != "*." {
		d = strings.TrimSuffix(d, ".")
	} else {
		d = "*"
	}
	if d == "" {
		return "", false
	}
	return d, true
}

func (h *r53rHandler) updateDomains(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallDomainListId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallDomainListId"))
		return
	}
	op := r53rStr(body, "Operation")
	switch op {
	case "ADD", "REMOVE", "REPLACE":
	case "":
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("operation"))
		return
	default:
		writeR53RErr(w, http.StatusBadRequest, requestID, enumError("operation", op, "ADD", "REMOVE", "REPLACE"))
		return
	}
	raw, present := body["Domains"].([]any)
	if !present {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("domains"))
		return
	}
	if len(raw) > 1000 {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rValidation("An UpdateFirewallDomains request takes at most 1000 domains."))
		return
	}
	seen := map[string]bool{}
	domains := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		d, ok := normalizeR53RDomain(s)
		if !ok {
			writeR53RErr(w, http.StatusBadRequest, requestID, r53rValidation("The domain '"+s+"' is not valid: a domain may start "+
				"with '*' and otherwise holds only A-Z, a-z, 0-9, '-' and '.', 1 to 255 characters."))
			return
		}
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	l, err := h.store.updateDomains(ctx, r53rOwner(ctx), id, op, domains)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "UpdateFirewallDomains", id, "operation", op, "domains", len(domains))
	writeR53RJSON(w, requestID, map[string]any{"Id": l.ID, "Name": l.Name, "Status": "COMPLETE",
		"StatusMessage": "Finished domain list update"})
}

func (h *r53rHandler) listDomains(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallDomainListId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallDomainListId"))
		return
	}
	domains, ok, err := h.store.listDomains(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("FIREWALL_DOMAIN_LIST", "The domain list '"+id+"' does not exist."))
		return
	}
	lo, hi, next, e := r53rPage(len(domains), body, 1, 100, 5000, false)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"Domains": domains[lo:hi]}, next))
}

// --- rule groups ---

func (h *r53rHandler) ruleGroupJSON(ctx context.Context, g r53rRuleGroup, status, msg string) map[string]any {
	m := map[string]any{"Id": g.ID, "Arn": h.arn(ctx, "firewall-rule-group", g.ID), "Name": g.Name, "RuleCount": g.RuleCount,
		"Status": status, "OwnerId": h.accountOf(ctx), "ShareStatus": "NOT_SHARED", "CreatorRequestId": g.CreatorRequestID,
		"CreationTime": r53rTime(g.Created), "ModificationTime": r53rTime(g.Modified)}
	if msg != "" {
		m["StatusMessage"] = msg
	}
	return m
}

func (h *r53rHandler) createRuleGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := r53rStr(body, "Name")
	if !validR53RName(name) {
		writeR53RErr(w, http.StatusBadRequest, requestID, nameError("name", name))
		return
	}
	crid, e := creatorRequestID(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	tags, e := r53rTags(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	g, created, err := h.store.createRuleGroup(ctx, r53rRuleGroup{ID: r53rNewID("rslvr-frg-", 17), Owner: r53rOwner(ctx),
		Name: name, CreatorRequestID: crid}, tags)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if created {
		h.audit(ctx, "CreateFirewallRuleGroup", g.ID)
	}
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroup": h.ruleGroupJSON(ctx, g, "COMPLETE", "Created Firewall Rule Group")})
}

func (h *r53rHandler) getRuleGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallRuleGroupId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupId"))
		return
	}
	g, ok, err := h.store.getRuleGroup(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("FIREWALL_RULE_GROUP", "The rule group '"+id+"' does not exist."))
		return
	}
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroup": h.ruleGroupJSON(ctx, g, "COMPLETE", "")})
}

func (h *r53rHandler) listRuleGroups(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	groups, err := h.store.listRuleGroups(ctx, r53rOwner(ctx))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	lo, hi, next, e := r53rPage(len(groups), body, 1, 100, 100, false)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, g := range groups[lo:hi] {
		out = append(out, map[string]any{"Id": g.ID, "Arn": h.arn(ctx, "firewall-rule-group", g.ID), "Name": g.Name,
			"OwnerId": h.accountOf(ctx), "ShareStatus": "NOT_SHARED", "CreatorRequestId": g.CreatorRequestID})
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"FirewallRuleGroups": out}, next))
}

func (h *r53rHandler) deleteRuleGroup(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallRuleGroupId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupId"))
		return
	}
	g, err := h.store.deleteRuleGroup(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteFirewallRuleGroup", id)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroup": h.ruleGroupJSON(ctx, g, "DELETING", "Deleting the Firewall Rule Group")})
}

// --- rules ---

func ruleJSON(r r53rRule) map[string]any {
	m := map[string]any{"FirewallRuleGroupId": r.GroupID, "FirewallDomainListId": r.DomainListID, "Name": r.Name,
		"Priority": r.Priority, "Action": r.Action, "FirewallDomainRedirectionAction": r.Redirection,
		"CreatorRequestId": r.CreatorRequestID, "CreationTime": r53rTime(r.Created), "ModificationTime": r53rTime(r.Modified)}
	if r.BlockResponse != "" {
		m["BlockResponse"] = r.BlockResponse
	}
	if r.BlockOverrideDomain != "" {
		m["BlockOverrideDomain"] = r.BlockOverrideDomain
	}
	if r.BlockOverrideDNSType != "" {
		m["BlockOverrideDnsType"] = r.BlockOverrideDNSType
	}
	if r.BlockOverrideTTL != nil {
		m["BlockOverrideTtl"] = *r.BlockOverrideTTL
	}
	if r.Qtype != "" {
		m["Qtype"] = r.Qtype
	}
	return m
}

// r53rAdvanced are the DNS Firewall Advanced members of a rule, which are not served.
var r53rAdvanced = []string{"DnsThreatProtection", "ConfidenceThreshold", "FirewallRuleType", "FirewallThreatProtectionId"}

func refuseAdvanced(body map[string]any) *r53rError {
	for _, k := range r53rAdvanced {
		if v, ok := body[k]; ok && v != nil {
			return r53rValidation("DNS Firewall Advanced rules (" + k + ") are not supported here: a rule matches a domain " +
				"list of your own (FirewallDomainListId).")
		}
	}
	return nil
}

// r53rQtypeNames are the query types a rule's Qtype names (and TYPE<n> for any other).
var r53rQtypeNames = map[string]uint16{"A": 1, "AAAA": 28, "CAA": 257, "CNAME": 5, "DS": 43, "MX": 15, "NAPTR": 35,
	"NS": 2, "PTR": 12, "SOA": 6, "SPF": 99, "SRV": 33, "TXT": 16}

// qtypeNumber is the DNS type number a rule's Qtype names: A, AAAA, …, or TYPE<1-65534>.
func qtypeNumber(q string) (uint16, bool) {
	q = strings.ToUpper(q)
	if n, ok := r53rQtypeNames[q]; ok {
		return n, true
	}
	if rest, ok := strings.CutPrefix(q, "TYPE"); ok {
		if n, err := strconv.Atoi(rest); err == nil && n >= 1 && n <= 65534 && strconv.Itoa(n) == rest {
			return uint16(n), true
		}
	}
	return 0, false
}

// validR53RRule checks a rule as AWS does and fills in its defaults: an action; BLOCK's block response;
// OVERRIDE's domain, CNAME type and TTL; the redirection action; the query type.
func validR53RRule(r *r53rRule) *r53rError {
	if !validR53RName(r.Name) {
		return nameError("name", r.Name)
	}
	if r.Redirection == "" {
		r.Redirection = "INSPECT_REDIRECTION_DOMAIN"
	}
	if r.Redirection != "INSPECT_REDIRECTION_DOMAIN" && r.Redirection != "TRUST_REDIRECTION_DOMAIN" {
		return enumError("firewallDomainRedirectionAction", r.Redirection, "INSPECT_REDIRECTION_DOMAIN", "TRUST_REDIRECTION_DOMAIN")
	}
	if r.Qtype != "" {
		if _, ok := qtypeNumber(r.Qtype); !ok {
			return r53rValidation("The Qtype '" + r.Qtype + "' is not valid: use a DNS record type (A, AAAA, CNAME, MX, TXT, …) or TYPE<1-65534>.")
		}
		r.Qtype = strings.ToUpper(r.Qtype)
	}
	override := r.BlockOverrideDomain != "" || r.BlockOverrideDNSType != "" || r.BlockOverrideTTL != nil
	switch r.Action {
	case "ALLOW", "ALERT":
		if r.BlockResponse != "" || override {
			return r53rValidation("BlockResponse and the BlockOverride settings apply only to a rule whose Action is BLOCK.")
		}
	case "BLOCK":
		switch r.BlockResponse {
		case "NODATA", "NXDOMAIN":
			if override {
				return r53rValidation("BlockOverrideDomain, BlockOverrideDnsType and BlockOverrideTtl apply only to BlockResponse OVERRIDE.")
			}
		case "OVERRIDE":
			if r.BlockOverrideDomain == "" || r.BlockOverrideDNSType == "" || r.BlockOverrideTTL == nil {
				return r53rValidation("BlockResponse OVERRIDE requires BlockOverrideDomain, BlockOverrideDnsType and BlockOverrideTtl.")
			}
			if len(r.BlockOverrideDomain) > 255 {
				return r53rValidation("BlockOverrideDomain is 1 to 255 characters.")
			}
			if r.BlockOverrideDNSType != "CNAME" {
				return enumError("blockOverrideDnsType", r.BlockOverrideDNSType, "CNAME")
			}
			if *r.BlockOverrideTTL < 0 || *r.BlockOverrideTTL > 604800 {
				return r53rValidation("BlockOverrideTtl is from 0 to 604800 seconds.")
			}
		case "":
			return r53rValidation("A rule whose Action is BLOCK requires a BlockResponse (NODATA, NXDOMAIN or OVERRIDE).")
		default:
			return enumError("blockResponse", r.BlockResponse, "NODATA", "NXDOMAIN", "OVERRIDE")
		}
	case "":
		return requiredError("action")
	default:
		return enumError("action", r.Action, "ALLOW", "BLOCK", "ALERT")
	}
	return nil
}

func (h *r53rHandler) createRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if e := refuseAdvanced(body); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	r := r53rRule{GroupID: r53rStr(body, "FirewallRuleGroupId"), DomainListID: r53rStr(body, "FirewallDomainListId"),
		Name: r53rStr(body, "Name"), Action: r53rStr(body, "Action"), BlockResponse: r53rStr(body, "BlockResponse"),
		BlockOverrideDomain: r53rStr(body, "BlockOverrideDomain"), BlockOverrideDNSType: r53rStr(body, "BlockOverrideDnsType"),
		Redirection: r53rStr(body, "FirewallDomainRedirectionAction"), Qtype: r53rStr(body, "Qtype")}
	for member, v := range map[string]string{"firewallRuleGroupId": r.GroupID, "firewallDomainListId": r.DomainListID} {
		if v == "" {
			writeR53RErr(w, http.StatusBadRequest, requestID, requiredError(member))
			return
		}
	}
	p, ok := r53rInt(body, "Priority")
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("priority"))
		return
	}
	r.Priority = p
	if ttl, ok := r53rInt(body, "BlockOverrideTtl"); ok {
		r.BlockOverrideTTL = &ttl
	}
	crid, e := creatorRequestID(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	r.CreatorRequestID = crid
	if e := validR53RRule(&r); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	got, err := h.store.createRule(ctx, r53rOwner(ctx), r)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateFirewallRule", r.GroupID, "domainList", r.DomainListID, "action", r.Action, "priority", r.Priority)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRule": ruleJSON(got)})
}

func (h *r53rHandler) updateRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if e := refuseAdvanced(body); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	group, list := r53rStr(body, "FirewallRuleGroupId"), r53rStr(body, "FirewallDomainListId")
	if group == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupId"))
		return
	}
	if list == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallDomainListId"))
		return
	}
	qtype, qtypeGiven := body["Qtype"].(string)
	got, err := h.store.updateRule(ctx, r53rOwner(ctx), group, list, qtype, qtypeGiven, func(r *r53rRule) *r53rError {
		set := func(member string, dst *string) {
			if v, ok := body[member].(string); ok {
				*dst = v
			}
		}
		set("Name", &r.Name)
		set("Action", &r.Action)
		set("FirewallDomainRedirectionAction", &r.Redirection)
		set("Qtype", &r.Qtype)
		if p, ok := r53rInt(body, "Priority"); ok {
			r.Priority = p
		}
		_, blockGiven := body["BlockResponse"]
		if r.Action != "BLOCK" && !blockGiven {
			// A rule that stops blocking drops its block settings.
			r.BlockResponse, r.BlockOverrideDomain, r.BlockOverrideDNSType, r.BlockOverrideTTL = "", "", "", nil
		}
		set("BlockResponse", &r.BlockResponse)
		set("BlockOverrideDomain", &r.BlockOverrideDomain)
		set("BlockOverrideDnsType", &r.BlockOverrideDNSType)
		if ttl, ok := r53rInt(body, "BlockOverrideTtl"); ok {
			r.BlockOverrideTTL = &ttl
		}
		if r.BlockResponse != "OVERRIDE" && !hasAny(body, "BlockOverrideDomain", "BlockOverrideDnsType", "BlockOverrideTtl") {
			r.BlockOverrideDomain, r.BlockOverrideDNSType, r.BlockOverrideTTL = "", "", nil
		}
		return nil
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "UpdateFirewallRule", group, "domainList", list, "action", got.Action, "priority", got.Priority)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRule": ruleJSON(got)})
}

func (h *r53rHandler) deleteRule(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if v, ok := body["FirewallThreatProtectionId"]; ok && v != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, refuseAdvanced(body))
		return
	}
	group, list := r53rStr(body, "FirewallRuleGroupId"), r53rStr(body, "FirewallDomainListId")
	if group == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupId"))
		return
	}
	if list == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallDomainListId"))
		return
	}
	qtype, qtypeGiven := body["Qtype"].(string)
	r, err := h.store.deleteRule(ctx, r53rOwner(ctx), group, list, qtype, qtypeGiven)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteFirewallRule", group, "domainList", list)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRule": ruleJSON(r)})
}

func (h *r53rHandler) listRules(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	group := r53rStr(body, "FirewallRuleGroupId")
	if group == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupId"))
		return
	}
	rules, ok, err := h.store.listRules(ctx, r53rOwner(ctx), group)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("FIREWALL_RULE_GROUP", "The rule group '"+group+"' does not exist."))
		return
	}
	action := r53rStr(body, "Action")
	prio, byPrio := r53rInt(body, "Priority")
	var kept []r53rRule
	for _, r := range rules {
		if (action == "" || r.Action == action) && (!byPrio || r.Priority == prio) {
			kept = append(kept, r)
		}
	}
	lo, hi, next, e := r53rPage(len(kept), body, 1, 100, 100, false)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, r := range kept[lo:hi] {
		out = append(out, ruleJSON(r))
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"FirewallRules": out}, next))
}

// --- rule group associations ---

func (h *r53rHandler) associationJSON(ctx context.Context, a r53rAssociation, status, msg string) map[string]any {
	m := map[string]any{"Id": a.ID, "Arn": h.arn(ctx, "firewall-rule-group-association", a.ID), "FirewallRuleGroupId": a.GroupID,
		"VpcId": a.VpcID, "Name": a.Name, "Priority": a.Priority, "MutationProtection": a.MutationProtection, "Status": status,
		"CreatorRequestId": a.CreatorRequestID, "CreationTime": r53rTime(a.Created), "ModificationTime": r53rTime(a.Modified)}
	if msg != "" {
		m["StatusMessage"] = msg
	}
	return m
}

// validAssociationPriority is AWS's range for a rule group association's priority: between 100 and 9900.
func validAssociationPriority(p int) bool { return p > 100 && p < 9900 }

func (h *r53rHandler) associate(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	a := r53rAssociation{ID: r53rNewID("rslvr-frgassoc-", 17), Owner: r53rOwner(ctx), GroupID: r53rStr(body, "FirewallRuleGroupId"),
		VpcID: r53rStr(body, "VpcId"), Name: r53rStr(body, "Name"), MutationProtection: r53rStr(body, "MutationProtection")}
	if a.GroupID == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupId"))
		return
	}
	if a.VpcID == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("vpcId"))
		return
	}
	if !validR53RName(a.Name) {
		writeR53RErr(w, http.StatusBadRequest, requestID, nameError("name", a.Name))
		return
	}
	p, ok := r53rInt(body, "Priority")
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("priority"))
		return
	}
	if !validAssociationPriority(p) {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rValidation("The priority of a rule group association is between 100 and 9900."))
		return
	}
	a.Priority = p
	switch a.MutationProtection {
	case "":
		a.MutationProtection = "DISABLED"
	case "ENABLED", "DISABLED":
	default:
		writeR53RErr(w, http.StatusBadRequest, requestID, enumError("mutationProtection", a.MutationProtection, "ENABLED", "DISABLED"))
		return
	}
	crid, e := creatorRequestID(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	a.CreatorRequestID = crid
	tags, e := r53rTags(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	if e := h.callerVPC(ctx, claims, a.VpcID); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	got, err := h.store.associate(ctx, a, tags)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "AssociateFirewallRuleGroup", got.GroupID, "vpc", got.VpcID, "priority", got.Priority, "association", got.ID)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroupAssociation": h.associationJSON(ctx, got, "COMPLETE", "")})
}

func (h *r53rHandler) disassociate(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallRuleGroupAssociationId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupAssociationId"))
		return
	}
	a, err := h.store.disassociate(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DisassociateFirewallRuleGroup", a.GroupID, "vpc", a.VpcID, "association", id)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroupAssociation": h.associationJSON(ctx, a, "DELETING",
		"Deleting the Firewall Rule Group Association")})
}

func (h *r53rHandler) getAssociation(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallRuleGroupAssociationId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupAssociationId"))
		return
	}
	a, ok, err := h.store.getAssociation(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("FIREWALL_RULE_GROUP_ASSOCIATION",
			"The rule group association '"+id+"' does not exist."))
		return
	}
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroupAssociation": h.associationJSON(ctx, a, "COMPLETE", "")})
}

func (h *r53rHandler) updateAssociation(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "FirewallRuleGroupAssociationId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallRuleGroupAssociationId"))
		return
	}
	a, err := h.store.updateAssociation(ctx, r53rOwner(ctx), id, func(a *r53rAssociation) *r53rError {
		// Protected: mutation protection is on, and this request does not turn it off.
		wasOn := a.MutationProtection == "ENABLED"
		if v, ok := body["MutationProtection"].(string); ok {
			if v != "ENABLED" && v != "DISABLED" {
				return enumError("mutationProtection", v, "ENABLED", "DISABLED")
			}
			a.MutationProtection = v
		}
		protected := wasOn && a.MutationProtection == "ENABLED"
		if v, ok := body["Name"].(string); ok {
			if !validR53RName(v) {
				return nameError("name", v)
			}
			if protected && v != a.Name {
				return r53rValidation("The rule group association " + id + " has mutation protection enabled: disable it first.")
			}
			a.Name = v
		}
		if p, ok := r53rInt(body, "Priority"); ok {
			if !validAssociationPriority(p) {
				return r53rValidation("The priority of a rule group association is between 100 and 9900.")
			}
			if protected && p != a.Priority {
				return r53rValidation("The rule group association " + id + " has mutation protection enabled: disable it first.")
			}
			a.Priority = p
		}
		return nil
	})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "UpdateFirewallRuleGroupAssociation", a.GroupID, "vpc", a.VpcID, "association", id)
	writeR53RJSON(w, requestID, map[string]any{"FirewallRuleGroupAssociation": h.associationJSON(ctx, a, "COMPLETE", "")})
}

func (h *r53rHandler) listAssociations(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	all, err := h.store.listAssociations(ctx, r53rOwner(ctx))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	group, vpc, status := r53rStr(body, "FirewallRuleGroupId"), r53rStr(body, "VpcId"), r53rStr(body, "Status")
	switch status {
	case "", "COMPLETE", "DELETING", "UPDATING":
	default:
		writeR53RErr(w, http.StatusBadRequest, requestID, enumError("status", status, "COMPLETE", "DELETING", "UPDATING"))
		return
	}
	prio, byPrio := r53rInt(body, "Priority")
	var kept []r53rAssociation
	for _, a := range all {
		if (group == "" || a.GroupID == group) && (vpc == "" || a.VpcID == vpc) && (!byPrio || a.Priority == prio) &&
			(status == "" || status == "COMPLETE") {
			kept = append(kept, a)
		}
	}
	lo, hi, next, e := r53rPage(len(kept), body, 1, 100, 100, false)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, a := range kept[lo:hi] {
		out = append(out, h.associationJSON(ctx, a, "COMPLETE", ""))
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"FirewallRuleGroupAssociations": out}, next))
}

// --- firewall configs ---

func (h *r53rHandler) firewallConfigJSON(ctx context.Context, vpcID, failOpen string) map[string]any {
	return map[string]any{"Id": firewallConfigID(r53rOwner(ctx), vpcID), "OwnerId": h.accountOf(ctx), "ResourceId": vpcID,
		"FirewallFailOpen": failOpen}
}

func (h *r53rHandler) getFirewallConfig(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	vpc := r53rStr(body, "ResourceId")
	if vpc == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("resourceId"))
		return
	}
	if e := h.callerVPC(ctx, claims, vpc); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	v, err := h.store.failOpen(ctx, r53rOwner(ctx), vpc)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	writeR53RJSON(w, requestID, map[string]any{"FirewallConfig": h.firewallConfigJSON(ctx, vpc, v)})
}

func (h *r53rHandler) updateFirewallConfig(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	vpc, v := r53rStr(body, "ResourceId"), r53rStr(body, "FirewallFailOpen")
	if vpc == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("resourceId"))
		return
	}
	switch v {
	case "ENABLED", "DISABLED", "USE_LOCAL_RESOURCE_SETTING":
	case "":
		writeR53RErr(w, http.StatusBadRequest, requestID, requiredError("firewallFailOpen"))
		return
	default:
		writeR53RErr(w, http.StatusBadRequest, requestID, enumError("firewallFailOpen", v, "ENABLED", "DISABLED", "USE_LOCAL_RESOURCE_SETTING"))
		return
	}
	if e := h.callerVPC(ctx, claims, vpc); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	if err := h.store.setFailOpen(ctx, r53rOwner(ctx), vpc, v); err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "UpdateFirewallConfig", vpc, "failOpen", v)
	writeR53RJSON(w, requestID, map[string]any{"FirewallConfig": h.firewallConfigJSON(ctx, vpc, v)})
}

// listFirewallConfigs answers a configuration for each of the account's VPCs (the default for one never
// updated), as AWS keeps one per VPC; when the VPCs cannot be read, the configurations updated here.
func (h *r53rHandler) listFirewallConfigs(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	stored, err := h.store.failOpens(ctx, r53rOwner(ctx))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	var vpcs []string
	if h.vpcs != nil {
		if ids, denied, verr := h.vpcs(ctx, claims); verr == nil && !denied {
			vpcs = ids
		}
	}
	if vpcs == nil {
		for v := range stored {
			vpcs = append(vpcs, v)
		}
	}
	sort.Strings(vpcs)
	lo, hi, next, e := r53rPage(len(vpcs), body, 5, 10, 10, false)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, v := range vpcs[lo:hi] {
		fo := stored[v]
		if fo == "" {
			fo = r53rDefaultFailOpen
		}
		out = append(out, h.firewallConfigJSON(ctx, v, fo))
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"FirewallConfigs": out}, next))
}

// --- query logging ---

func (h *r53rHandler) queryLogConfigJSON(ctx context.Context, c r53rQueryLogConfig, status string) map[string]any {
	return map[string]any{"Id": c.ID, "Arn": h.arn(ctx, "resolver-query-log-config", c.ID), "Name": c.Name,
		"DestinationArn": c.DestinationARN, "AssociationCount": c.AssociationCount, "OwnerId": h.accountOf(ctx),
		"ShareStatus": "NOT_SHARED", "Status": status, "CreatorRequestId": c.CreatorRequestID, "CreationTime": r53rTime(c.Created)}
}

// checkQueryLogDestination checks a DestinationArn: a CloudWatch Logs log group of the caller's account in
// this region. Amazon S3 and Amazon Data Firehose destinations are refused.
func (h *r53rHandler) checkQueryLogDestination(ctx context.Context, arn string) *r53rError {
	bad := func(msg string) *r53rError {
		return &r53rError{Code: "InvalidParameterException", FieldName: "DestinationArn", Message: msg}
	}
	if arn == "" {
		return bad("DestinationArn is required.")
	}
	if len(arn) > 600 {
		return bad("DestinationArn is at most 600 characters.")
	}
	p := strings.SplitN(arn, ":", 6)
	if len(p) == 6 && p[0] == "arn" && p[2] != "logs" {
		return bad("Query logs are delivered to a CloudWatch Logs log group here (arn:aws:logs:<region>:<account>:log-group:<name>); " +
			"Amazon S3 and Amazon Data Firehose destinations are not supported.")
	}
	acct, _, ok := logGroupOfARN(arn)
	if !ok {
		return bad("The DestinationArn '" + arn + "' is not a CloudWatch Logs log group ARN (arn:aws:logs:<region>:<account>:log-group:<name>).")
	}
	if p[3] != h.region {
		return bad("The log group must be in " + h.region + ", the Region of the query logging configuration.")
	}
	if acct != h.accountOf(ctx) {
		return bad("The log group must be in your own account (" + h.accountOf(ctx) + ").")
	}
	return nil
}

func (h *r53rHandler) createQueryLogConfig(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := r53rStr(body, "Name")
	if !validR53RName(name) {
		writeR53RErr(w, http.StatusBadRequest, requestID, &r53rError{Code: "InvalidParameterException", FieldName: "Name",
			Message: "Name is 1 to 64 letters, digits, spaces, hyphens, underscores and apostrophes, and not only digits."})
		return
	}
	dest := r53rStr(body, "DestinationArn")
	if e := h.checkQueryLogDestination(ctx, dest); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	crid, e := creatorRequestID(body)
	if e != nil {
		e.Code = "InvalidParameterException"
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	tags, e := r53rTags(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	c, created, err := h.store.createQueryLogConfig(ctx, r53rQueryLogConfig{ID: r53rNewID("rqlc-", 16), Owner: r53rOwner(ctx),
		Name: name, DestinationARN: dest, CreatorRequestID: crid}, tags)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if created {
		h.audit(ctx, "CreateResolverQueryLogConfig", c.ID, "destination", dest)
	}
	writeR53RJSON(w, requestID, map[string]any{"ResolverQueryLogConfig": h.queryLogConfigJSON(ctx, c, "CREATED")})
}

func (h *r53rHandler) getQueryLogConfig(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "ResolverQueryLogConfigId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, &r53rError{Code: "InvalidParameterException", FieldName: "ResolverQueryLogConfigId",
			Message: "ResolverQueryLogConfigId is required."})
		return
	}
	c, ok, err := h.store.getQueryLogConfig(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("RESOLVER_QUERY_LOG_CONFIG", "The query logging configuration '"+id+"' does not exist."))
		return
	}
	writeR53RJSON(w, requestID, map[string]any{"ResolverQueryLogConfig": h.queryLogConfigJSON(ctx, c, "CREATED")})
}

// r53rFilter is a list request's filters ([{Name, Values}]): each kept item matches every filter.
type r53rFilter map[string][]string

func r53rFilters(body map[string]any, allowed ...string) (r53rFilter, *r53rError) {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	out := r53rFilter{}
	for _, f := range sliceOf(body["Filters"]) {
		m := mapOf(f)
		name, _ := m["Name"].(string)
		if !ok[name] {
			return nil, &r53rError{Code: "InvalidParameterException", FieldName: "Filters",
				Message: "The filter '" + name + "' is not valid: use one of " + strings.Join(allowed, ", ") + "."}
		}
		switch v := m["Values"].(type) {
		case string:
			out[name] = append(out[name], v)
		case []any:
			for _, x := range v {
				if s, isStr := x.(string); isStr {
					out[name] = append(out[name], s)
				}
			}
		}
	}
	return out, nil
}

func (f r53rFilter) keep(fields map[string]string) bool {
	for name, values := range f {
		match := false
		for _, v := range values {
			if fields[name] == v {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// r53rSort orders items by a SortBy field (SortOrder ASCENDING, the default, or DESCENDING).
func r53rSort(body map[string]any, fields []map[string]string, allowed ...string) ([]int, *r53rError) {
	idx := make([]int, len(fields))
	for i := range idx {
		idx[i] = i
	}
	by, order := r53rStr(body, "SortBy"), r53rStr(body, "SortOrder")
	if order != "" && order != "ASCENDING" && order != "DESCENDING" {
		return nil, &r53rError{Code: "InvalidParameterException", FieldName: "SortOrder", Message: "SortOrder is ASCENDING or DESCENDING."}
	}
	if by == "" {
		return idx, nil
	}
	valid := false
	for _, a := range allowed {
		valid = valid || a == by
	}
	if !valid {
		return nil, &r53rError{Code: "InvalidParameterException", FieldName: "SortBy",
			Message: "SortBy is one of " + strings.Join(allowed, ", ") + "."}
	}
	sort.SliceStable(idx, func(i, j int) bool {
		a, b := fields[idx[i]][by], fields[idx[j]][by]
		if order == "DESCENDING" {
			return a > b
		}
		return a < b
	})
	return idx, nil
}

var r53rQLCFields = []string{"Arn", "AssociationCount", "CreationTime", "CreatorRequestId", "DestinationArn", "Id", "Name",
	"OwnerId", "ShareStatus", "Status"}

func (h *r53rHandler) listQueryLogConfigs(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	all, err := h.store.listQueryLogConfigs(ctx, r53rOwner(ctx))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	filters, e := r53rFilters(body, r53rQLCFields...)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	var kept []r53rQueryLogConfig
	var fields []map[string]string
	for _, c := range all {
		f := map[string]string{"Arn": h.arn(ctx, "resolver-query-log-config", c.ID), "AssociationCount": fmt.Sprintf("%010d", c.AssociationCount),
			"CreationTime": r53rTime(c.Created), "CreatorRequestId": c.CreatorRequestID, "DestinationArn": c.DestinationARN,
			"Id": c.ID, "Name": c.Name, "OwnerId": h.accountOf(ctx), "ShareStatus": "NOT_SHARED", "Status": "CREATED"}
		probe := map[string]string{}
		for k, v := range f {
			probe[k] = v
		}
		probe["AssociationCount"] = strconv.Itoa(c.AssociationCount)
		if filters.keep(probe) {
			kept, fields = append(kept, c), append(fields, f)
		}
	}
	order, e := r53rSort(body, fields, r53rQLCFields...)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	lo, hi, next, e := r53rPage(len(kept), body, 1, 100, 100, true)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, i := range order[lo:hi] {
		out = append(out, h.queryLogConfigJSON(ctx, kept[i], "CREATED"))
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"ResolverQueryLogConfigs": out, "TotalCount": len(all),
		"TotalFilteredCount": len(kept)}, next))
}

func (h *r53rHandler) deleteQueryLogConfig(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "ResolverQueryLogConfigId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, &r53rError{Code: "InvalidParameterException", FieldName: "ResolverQueryLogConfigId",
			Message: "ResolverQueryLogConfigId is required."})
		return
	}
	c, err := h.store.deleteQueryLogConfig(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteResolverQueryLogConfig", id)
	writeR53RJSON(w, requestID, map[string]any{"ResolverQueryLogConfig": h.queryLogConfigJSON(ctx, c, "DELETING")})
}

func queryLogAssociationJSON(a r53rQueryLogAssociation, status string) map[string]any {
	return map[string]any{"Id": a.ID, "ResolverQueryLogConfigId": a.ConfigID, "ResourceId": a.VpcID, "Status": status,
		"Error": "NONE", "ErrorMessage": "", "CreationTime": r53rTime(a.Created)}
}

func (h *r53rHandler) queryLogIDs(w http.ResponseWriter, requestID string, body map[string]any) (string, string, bool) {
	cfg, vpc := r53rStr(body, "ResolverQueryLogConfigId"), r53rStr(body, "ResourceId")
	for member, v := range map[string]string{"ResolverQueryLogConfigId": cfg, "ResourceId": vpc} {
		if v == "" {
			writeR53RErr(w, http.StatusBadRequest, requestID, &r53rError{Code: "InvalidParameterException", FieldName: member,
				Message: member + " is required."})
			return "", "", false
		}
	}
	return cfg, vpc, true
}

func (h *r53rHandler) associateQueryLog(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims, body map[string]any) {
	cfg, vpc, ok := h.queryLogIDs(w, requestID, body)
	if !ok {
		return
	}
	if e := h.callerVPC(ctx, claims, vpc); e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	a, err := h.store.associateQueryLog(ctx, r53rQueryLogAssociation{ID: r53rNewID("rqlcassoc-", 16), Owner: r53rOwner(ctx),
		ConfigID: cfg, VpcID: vpc})
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "AssociateResolverQueryLogConfig", cfg, "vpc", vpc, "association", a.ID)
	writeR53RJSON(w, requestID, map[string]any{"ResolverQueryLogConfigAssociation": queryLogAssociationJSON(a, "ACTIVE")})
}

func (h *r53rHandler) disassociateQueryLog(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	cfg, vpc, ok := h.queryLogIDs(w, requestID, body)
	if !ok {
		return
	}
	a, err := h.store.disassociateQueryLog(ctx, r53rOwner(ctx), cfg, vpc)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	h.audit(ctx, "DisassociateResolverQueryLogConfig", cfg, "vpc", vpc, "association", a.ID)
	writeR53RJSON(w, requestID, map[string]any{"ResolverQueryLogConfigAssociation": queryLogAssociationJSON(a, "DELETING")})
}

func (h *r53rHandler) getQueryLogAssociation(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id := r53rStr(body, "ResolverQueryLogConfigAssociationId")
	if id == "" {
		writeR53RErr(w, http.StatusBadRequest, requestID, &r53rError{Code: "InvalidParameterException",
			FieldName: "ResolverQueryLogConfigAssociationId", Message: "ResolverQueryLogConfigAssociationId is required."})
		return
	}
	a, ok, err := h.store.getQueryLogAssociation(ctx, r53rOwner(ctx), id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !ok {
		writeR53RErr(w, http.StatusBadRequest, requestID, r53rNotFound("RESOLVER_QUERY_LOG_CONFIG_ASSOCIATION",
			"The query logging configuration association '"+id+"' does not exist."))
		return
	}
	writeR53RJSON(w, requestID, map[string]any{"ResolverQueryLogConfigAssociation": queryLogAssociationJSON(a, "ACTIVE")})
}

var r53rQLAFields = []string{"CreationTime", "Error", "Id", "ResolverQueryLogConfigId", "ResourceId", "Status"}

func (h *r53rHandler) listQueryLogAssociations(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	all, err := h.store.listQueryLogAssociations(ctx, r53rOwner(ctx))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	filters, e := r53rFilters(body, r53rQLAFields...)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	var kept []r53rQueryLogAssociation
	var fields []map[string]string
	for _, a := range all {
		f := map[string]string{"CreationTime": r53rTime(a.Created), "Error": "NONE", "Id": a.ID, "ResolverQueryLogConfigId": a.ConfigID,
			"ResourceId": a.VpcID, "Status": "ACTIVE"}
		if filters.keep(f) {
			kept, fields = append(kept, a), append(fields, f)
		}
	}
	order, e := r53rSort(body, fields, r53rQLAFields...)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	lo, hi, next, e := r53rPage(len(kept), body, 1, 100, 100, true)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, i := range order[lo:hi] {
		out = append(out, queryLogAssociationJSON(kept[i], "ACTIVE"))
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"ResolverQueryLogConfigAssociations": out, "TotalCount": len(all),
		"TotalFilteredCount": len(kept)}, next))
}

// --- tags ---

// taggedResource is the caller's resource a tagging request's ResourceArn names (its id), or the error AWS
// answers for it.
func (h *r53rHandler) taggedResource(ctx context.Context, arn string) (string, *r53rError, error) {
	typ, id, ok := r53rResourceOfARN(arn)
	p := strings.SplitN(arn, ":", 6)
	if !ok || typ == "FirewallConfig" {
		return "", &r53rError{Code: "InvalidParameterException", FieldName: "ResourceArn",
			Message: "The ResourceArn '" + arn + "' does not name a domain list, rule group, rule group association or query logging configuration."}, nil
	}
	notFound := r53rNotFound(typ, "The resource '"+arn+"' does not exist.")
	if p[3] != h.region || p[4] != h.accountOf(ctx) {
		return "", notFound, nil
	}
	owner := r53rOwner(ctx)
	var found bool
	var err error
	switch typ {
	case "FirewallDomainList":
		_, found, err = h.store.getDomainList(ctx, owner, id)
	case "FirewallRuleGroup":
		_, found, err = h.store.getRuleGroup(ctx, owner, id)
	case "FirewallRuleGroupAssociation":
		_, found, err = h.store.getAssociation(ctx, owner, id)
	case "ResolverQueryLogConfig":
		_, found, err = h.store.getQueryLogConfig(ctx, owner, id)
	}
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", notFound, nil
	}
	return id, nil, nil
}

func (h *r53rHandler) tagResource(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id, e, err := h.taggedResource(ctx, r53rStr(body, "ResourceArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	tags, e := r53rTags(body)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	if err := h.store.setTags(ctx, id, tags); err != nil {
		h.fail(w, requestID, err)
		return
	}
	writeR53RJSON(w, requestID, map[string]any{})
}

func (h *r53rHandler) untagResource(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id, e, err := h.taggedResource(ctx, r53rStr(body, "ResourceArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	if err := h.store.untag(ctx, id, stringSlice(body["TagKeys"])); err != nil {
		h.fail(w, requestID, err)
		return
	}
	writeR53RJSON(w, requestID, map[string]any{})
}

func (h *r53rHandler) listTags(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	id, e, err := h.taggedResource(ctx, r53rStr(body, "ResourceArn"))
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	tags, err := h.store.tags(ctx, id)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lo, hi, next, e := r53rPage(len(keys), body, 1, 100, 100, true)
	if e != nil {
		writeR53RErr(w, http.StatusBadRequest, requestID, e)
		return
	}
	out := []any{}
	for _, k := range keys[lo:hi] {
		out = append(out, map[string]string{"Key": k, "Value": tags[k]})
	}
	writeR53RJSON(w, requestID, withNextToken(map[string]any{"Tags": out}, next))
}

// --- audit ---

func (h *r53rHandler) audit(ctx context.Context, op, resource string, kv ...any) {
	args := []any{"service", "route53resolver", "op", op, "decision", "allow", "principal", principalFromCtx(ctx), "resource", resource}
	h.logger.InfoContext(ctx, "route53resolver audit", append(args, kv...)...)
}

func (h *r53rHandler) auditDeny(ctx context.Context, op, resType, resID, reason string) {
	h.logger.InfoContext(ctx, "route53resolver audit", "service", "route53resolver", "op", op, "decision", "deny",
		"principal", principalFromCtx(ctx), "resource", typedResource(resType, resID), "reason", reason)
}

// ec2VPCLister lists the caller's account's VPCs through the EC2 front door's reads: the kind: Vpc claims
// of the account's namespace, read as the caller in legacy and by the shim when IAM policy decides.
func ec2VPCLister(ec2 *ec2Handler) vpcLister {
	return func(ctx context.Context, claims iam.Claims) ([]string, bool, error) {
		items, denied, err := ec2.listForCaller(ctx, claims, vpcGVR)
		if err != nil || denied {
			return nil, denied, err
		}
		ids := make([]string, 0, len(items))
		for i := range items {
			if items[i].GetDeletionTimestamp() == nil {
				ids = append(ids, items[i].GetName())
			}
		}
		return ids, false, nil
	}
}
