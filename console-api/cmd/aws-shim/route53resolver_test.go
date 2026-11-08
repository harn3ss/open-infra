package main

// Route 53 Resolver's front door without a store: what it refuses before reading one, its validation of
// domains, rules, priorities and pages, and the order the VPC resolver evaluates rules in. The store-backed
// lifecycle is route53resolver_pg_test.go's.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// r53rTestHandler is the front door over a store that cannot be reached: an authorized call ends in
// InternalServiceErrorException, never in the access-denied code.
func r53rTestHandler(t *testing.T, a *dataplaneauthz.Checker) *r53rHandler {
	h := newR53RHandler(csWithSAR(true), "default", "open-infra", "us-east-1", &r53rStore{db: unreachableDB(t)}, discardLogger())
	h.authz = a
	return h
}

func r53rCall(t *testing.T, h *r53rHandler, claims iam.Claims, op, body string) (int, map[string]any) {
	t.Helper()
	w := serveWith(h, jsonOp(r53rTargetPrefix+op, body), claims)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestR53R_IsAccountScoped(t *testing.T) {
	if !accountScopedServices["route53resolver"] {
		t.Fatal("route53resolver keeps each account's resources apart: it must be in accountScopedServices")
	}
}

// What is not served is refused as such, after authorization and before any store read.
func TestR53R_RefusesWhatIsNotServed(t *testing.T) {
	h := r53rTestHandler(t, nil)
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers"}}
	for _, c := range []struct{ op, body, code, says string }{
		{"ImportFirewallDomains", `{"FirewallDomainListId":"rslvr-fdl-1","Operation":"REPLACE","DomainFileUrl":"s3://b/k"}`, "ValidationException", "Amazon S3"},
		{"ListFirewallRuleTypes", `{}`, "ValidationException", "Advanced"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","DnsThreatProtection":"DGA","ConfidenceThreshold":"HIGH","Priority":1,"Action":"BLOCK","BlockResponse":"NODATA","Name":"dga"}`,
			"ValidationException", "DNS Firewall Advanced"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallRuleType":{"FirewallAdvancedThreatCategory":{"Category":"PHISHING"}},"Priority":1,"Action":"BLOCK","BlockResponse":"NODATA","Name":"p"}`,
			"ValidationException", "DNS Firewall Advanced"},
		{"CreateResolverQueryLogConfig", `{"Name":"dns","DestinationArn":"arn:aws:s3:::example-bucket/dns/"}`, "InvalidParameterException", "Amazon S3"},
		{"CreateResolverQueryLogConfig", `{"Name":"dns","DestinationArn":"arn:aws:firehose:us-east-1:open-infra:deliverystream/dns"}`, "InvalidParameterException", "Firehose"},
		{"CreateResolverQueryLogConfig", `{"Name":"dns","DestinationArn":"arn:aws:logs:us-east-1:111122223333:log-group:dns"}`, "InvalidParameterException", "your own account"},
		{"CreateResolverQueryLogConfig", `{"Name":"dns","DestinationArn":"arn:aws:logs:eu-west-1:open-infra:log-group:dns"}`, "InvalidParameterException", "us-east-1"},
		{"CreateResolverEndpoint", `{}`, "InvalidAction", "not supported"},
	} {
		code, out := r53rCall(t, h, user, c.op, c.body)
		msg, _ := out["Message"].(string)
		if code != 400 || jsonErrType(out) != c.code || !strings.Contains(msg, c.says) {
			t.Errorf("%s %s = %d %v, want %s saying %q", c.op, c.body, code, out, c.code, c.says)
		}
	}
}

// A request's members are checked as AWS checks them, before the store is read.
func TestR53R_ValidatesBeforeTheStore(t *testing.T) {
	h := r53rTestHandler(t, nil)
	user := iam.Claims{Sub: "tester"}
	for _, c := range []struct{ op, body, code string }{
		{"CreateFirewallDomainList", `{"Name":"12345"}`, "ValidationException"},
		{"CreateFirewallDomainList", `{"Name":"bad/name"}`, "ValidationException"},
		{"UpdateFirewallDomains", `{"FirewallDomainListId":"rslvr-fdl-1","Operation":"MERGE","Domains":["example.com"]}`, "ValidationException"},
		{"UpdateFirewallDomains", `{"FirewallDomainListId":"rslvr-fdl-1","Operation":"ADD","Domains":["ex_ample.com"]}`, "ValidationException"},
		{"UpdateFirewallDomains", `{"FirewallDomainListId":"rslvr-fdl-1","Operation":"ADD","Domains":["a.*.example.com"]}`, "ValidationException"},
		{"UpdateFirewallDomains", `{"FirewallDomainListId":"rslvr-fdl-1","Operation":"ADD"}`, "ValidationException"},
		{"UpdateFirewallDomains", `{"FirewallDomainListId":"rslvr-fdl-1","Operation":"ADD","Domains":[` + strings.Repeat(`"a.example.com",`, 1000) + `"b.example.com"]}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"BLOCK","Name":"b"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"BLOCK","BlockResponse":"OVERRIDE","Name":"b"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"BLOCK","BlockResponse":"OVERRIDE","BlockOverrideDomain":"sink.example.com","BlockOverrideDnsType":"A","BlockOverrideTtl":60,"Name":"b"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"ALLOW","BlockResponse":"NODATA","Name":"b"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"DENY","Name":"b"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Action":"ALLOW","Name":"b"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"ALLOW","Name":"b","Qtype":"TYPE0"}`, "ValidationException"},
		{"CreateFirewallRule", `{"FirewallRuleGroupId":"rslvr-frg-1","FirewallDomainListId":"rslvr-fdl-1","Priority":1,"Action":"ALLOW","Name":"b","FirewallDomainRedirectionAction":"FOLLOW"}`, "ValidationException"},
		{"AssociateFirewallRuleGroup", `{"FirewallRuleGroupId":"rslvr-frg-1","VpcId":"vpc-1","Priority":100,"Name":"a"}`, "ValidationException"},
		{"AssociateFirewallRuleGroup", `{"FirewallRuleGroupId":"rslvr-frg-1","VpcId":"vpc-1","Priority":9900,"Name":"a"}`, "ValidationException"},
		{"AssociateFirewallRuleGroup", `{"FirewallRuleGroupId":"rslvr-frg-1","VpcId":"vpc-1","Priority":200,"Name":"a","MutationProtection":"ON"}`, "ValidationException"},
		{"UpdateFirewallConfig", `{"ResourceId":"vpc-1","FirewallFailOpen":"MAYBE"}`, "ValidationException"},
		{"ListFirewallDomainLists", `{"MaxResults":101}`, "ValidationException"},
		{"ListTagsForResource", `{"ResourceArn":"arn:aws:route53resolver:us-east-1:open-infra:resolver-endpoint/rslvr-in-1"}`, "InvalidParameterException"},
	} {
		if code, out := r53rCall(t, h, user, c.op, c.body); code != 400 || jsonErrType(out) != c.code {
			t.Errorf("%s %.120s = %d %v, want %s", c.op, c.body, code, out, c.code)
		}
	}
}

// An association names a VPC of the caller's account: one it cannot see is ResourceNotFoundException, and
// listing the account's VPCs refused is AccessDeniedException.
func TestR53R_AssociationNamesTheCallersVPC(t *testing.T) {
	h := r53rTestHandler(t, nil)
	h.vpcs = func(context.Context, iam.Claims) ([]string, bool, error) { return []string{"vpc-0a1b2c3d"}, false, nil }
	user := iam.Claims{Sub: "tester"}
	body := `{"FirewallRuleGroupId":"rslvr-frg-1","VpcId":"vpc-0ffffff","Priority":101,"Name":"egress"}`
	if code, out := r53rCall(t, h, user, "AssociateFirewallRuleGroup", body); code != 400 || jsonErrType(out) != "ResourceNotFoundException" {
		t.Errorf("another VPC = %d %v, want ResourceNotFoundException", code, out)
	}
	if code, out := r53rCall(t, h, user, "AssociateResolverQueryLogConfig", `{"ResolverQueryLogConfigId":"rqlc-1","ResourceId":"vpc-0ffffff"}`); code != 400 ||
		jsonErrType(out) != "ResourceNotFoundException" {
		t.Errorf("query log association with another VPC = %d %v, want ResourceNotFoundException", code, out)
	}
	if code, out := r53rCall(t, h, user, "GetFirewallConfig", `{"ResourceId":"vpc-0ffffff"}`); code != 400 || jsonErrType(out) != "ResourceNotFoundException" {
		t.Errorf("GetFirewallConfig of another VPC = %d %v, want ResourceNotFoundException", code, out)
	}
	h.vpcs = func(context.Context, iam.Claims) ([]string, bool, error) { return nil, true, nil }
	if code, out := r53rCall(t, h, user, "AssociateFirewallRuleGroup", body); code != 400 || jsonErrType(out) != "AccessDeniedException" {
		t.Errorf("VPCs not readable = %d %v, want AccessDeniedException", code, out)
	}
	// The caller's own VPC passes the check and reaches the store.
	h.vpcs = func(context.Context, iam.Claims) ([]string, bool, error) { return []string{"vpc-0ffffff"}, false, nil }
	if code, out := r53rCall(t, h, user, "AssociateFirewallRuleGroup", body); jsonErrType(out) != "InternalServiceErrorException" {
		t.Errorf("own VPC = %d %v, want the unreachable store's InternalServiceErrorException", code, out)
	}
}

// A rule's create and update are decided on its domain list too: a grant on the rule group alone is not
// enough, as on AWS.
func TestR53R_RuleIsDecidedOnItsDomainListToo(t *testing.T) {
	group, list := "rslvr-frg-0123456789abcdef0", "rslvr-fdl-0123456789abcdef0"
	body := `{"FirewallRuleGroupId":"` + group + `","FirewallDomainListId":"` + list + `","Priority":100,"Action":"ALLOW","Name":"ok","CreatorRequestId":"r"}`
	role := ecrRoleClaims()
	only := roleChecker(dpAllow([]string{"route53resolver:CreateFirewallRule"}, "FirewallRuleGroup::"+group))
	if _, out := r53rCall(t, r53rTestHandler(t, only), role, "CreateFirewallRule", body); jsonErrType(out) != "AccessDeniedException" {
		t.Errorf("rule group grant alone = %v, want AccessDeniedException on the domain list", out)
	}
	both := roleChecker(dpAllow([]string{"route53resolver:CreateFirewallRule"}, "FirewallRuleGroup::"+group, "FirewallDomainList::"+list))
	if _, out := r53rCall(t, r53rTestHandler(t, both), role, "CreateFirewallRule", body); jsonErrType(out) == "AccessDeniedException" {
		t.Errorf("rule group and domain list grant = %v, want it past authorization", out)
	}
}

func TestR53R_DomainSpecifications(t *testing.T) {
	for in, want := range map[string]string{"Example.COM": "example.com", "example.com.": "example.com", "*": "*", "*.": "*",
		"*.Example.com": "*.example.com", "*example.com": "*example.com", "xn--bcher-kva.example": "xn--bcher-kva.example"} {
		if got, ok := normalizeR53RDomain(in); !ok || got != want {
			t.Errorf("normalize(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", ".", "ex ample.com", "a*.example.com", "example.com/x", "ex_ample.com", strings.Repeat("a", 256)} {
		if got, ok := normalizeR53RDomain(bad); ok {
			t.Errorf("normalize(%q) = %q, want refused", bad, got)
		}
	}
}

func TestR53R_RuleValidationFillsDefaults(t *testing.T) {
	ttl := 300
	r := r53rRule{Name: "sinkhole", Action: "BLOCK", BlockResponse: "OVERRIDE", BlockOverrideDomain: "sink.example.com",
		BlockOverrideDNSType: "CNAME", BlockOverrideTTL: &ttl, Qtype: "aaaa"}
	if e := validR53RRule(&r); e != nil {
		t.Fatal(e)
	}
	if r.Redirection != "INSPECT_REDIRECTION_DOMAIN" || r.Qtype != "AAAA" {
		t.Errorf("defaults: %+v", r)
	}
	for q, want := range map[string]uint16{"A": 1, "aaaa": 28, "TYPE28": 28, "TYPE65534": 65534, "MX": 15, "CAA": 257} {
		if n, ok := qtypeNumber(q); !ok || n != want {
			t.Errorf("qtypeNumber(%s) = %d %v", q, n, ok)
		}
	}
	for _, q := range []string{"TYPE0", "TYPE65535", "TYPE028", "BOGUS", ""} {
		if _, ok := qtypeNumber(q); ok {
			t.Errorf("qtypeNumber(%q) accepted", q)
		}
	}
}

// A rule is named by its domain list and query type, as DeleteFirewallRule names it.
func TestR53R_LocateRule(t *testing.T) {
	rules := []r53rRule{{DomainListID: "l1"}, {DomainListID: "l2", Qtype: "A"}, {DomainListID: "l2", Qtype: "AAAA"}, {DomainListID: "l3", Qtype: "MX"}}
	for _, c := range []struct {
		list, qtype   string
		given, update bool
		want          int
		code          string
	}{
		{"l1", "", false, false, 0, ""},
		{"l2", "AAAA", true, false, 2, ""},
		{"l2", "", false, false, -1, "ValidationException"}, // several: name the Qtype
		{"l3", "", false, false, 3, ""},                     // the list's only rule
		{"l3", "A", true, false, -1, "ResourceNotFoundException"},
		{"l3", "A", true, true, 3, ""}, // an update may give the rule a new query type
		{"l9", "", false, false, -1, "ResourceNotFoundException"},
	} {
		i, e := locateRule(rules, "g", c.list, c.qtype, c.given, c.update)
		code := ""
		if e != nil {
			code = e.Code
		}
		if i != c.want || code != c.code {
			t.Errorf("locate(%s, %q, given=%v, update=%v) = %d %s, want %d %s", c.list, c.qtype, c.given, c.update, i, code, c.want, c.code)
		}
	}
	if e := checkNewRule(rules, r53rRule{GroupID: "g", DomainListID: "l1", Priority: 5}, -1); e == nil {
		t.Error("a second rule for the same domain list and query type must be refused")
	}
	if e := checkNewRule([]r53rRule{{DomainListID: "l1", Priority: 5}}, r53rRule{GroupID: "g", DomainListID: "l2", Priority: 5}, -1); e == nil {
		t.Error("a second rule at the same priority must be refused")
	}
	if e := checkNewRule([]r53rRule{{DomainListID: "l1", Priority: 5}}, r53rRule{GroupID: "g", DomainListID: "l1", Priority: 6}, 0); e != nil {
		t.Errorf("a rule replacing itself is not a duplicate: %v", e)
	}
}

func TestR53R_Pages(t *testing.T) {
	lo, hi, next, e := r53rPage(250, map[string]any{}, 1, 100, 100, false)
	if e != nil || lo != 0 || hi != 100 || next == "" {
		t.Fatalf("first page = %d..%d %q %v", lo, hi, next, e)
	}
	lo, hi, next2, e := r53rPage(250, map[string]any{"NextToken": next}, 1, 100, 100, false)
	if e != nil || lo != 100 || hi != 200 || next2 == "" {
		t.Fatalf("second page = %d..%d %q %v", lo, hi, next2, e)
	}
	lo, hi, last, e := r53rPage(250, map[string]any{"NextToken": next2}, 1, 100, 100, false)
	if e != nil || lo != 200 || hi != 250 || last != "" {
		t.Fatalf("last page = %d..%d %q %v", lo, hi, last, e)
	}
	if _, _, _, e := r53rPage(10, map[string]any{"NextToken": "garbage"}, 1, 100, 100, true); e == nil || e.Code != "InvalidNextTokenException" {
		t.Errorf("a bad token = %v", e)
	}
	if _, _, _, e := r53rPage(10, map[string]any{"MaxResults": float64(4)}, 5, 10, 10, false); e == nil {
		t.Error("ListFirewallConfigs takes MaxResults 5 to 10")
	}
}

func TestR53R_ResourceOfARN(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:route53resolver:us-east-1:111122223333:firewall-domain-list/rslvr-fdl-1":                 "FirewallDomainList::rslvr-fdl-1",
		"arn:aws:route53resolver:us-east-1:111122223333:firewall-rule-group/rslvr-frg-1":                  "FirewallRuleGroup::rslvr-frg-1",
		"arn:aws:route53resolver:us-east-1:111122223333:firewall-rule-group-association/rslvr-frgassoc-1": "FirewallRuleGroupAssociation::rslvr-frgassoc-1",
		"arn:aws:route53resolver:us-east-1:111122223333:resolver-query-log-config/rqlc-1":                 "ResolverQueryLogConfig::rqlc-1",
		"arn:aws:route53resolver:us-east-1:111122223333:firewall-config/rslvr-fc-1":                       "FirewallConfig::rslvr-fc-1",
	} {
		typ, id, ok := r53rResourceOfARN(arn)
		if !ok || typ+"::"+id != want {
			t.Errorf("%s -> %s::%s %v, want %s", arn, typ, id, ok, want)
		}
	}
	for _, bad := range []string{"arn:aws:route53resolver:us-east-1:111122223333:resolver-rule/rslvr-rr-1",
		"arn:aws:route53:::hostedzone/Z1", "arn:aws:route53resolver:us-east-1:111122223333:firewall-rule-group/a/b", "rslvr-frg-1"} {
		if _, _, ok := r53rResourceOfARN(bad); ok {
			t.Errorf("%s mapped", bad)
		}
	}
}

// The VPC resolver evaluates rule groups by association priority, then each group's rules by rule
// priority, the lowest first, whatever order the store reads them in.
func TestR53R_ResolverConfigOrder(t *testing.T) {
	rules := []resolverRule{
		{GroupID: "late", AssociationPriority: 300, Priority: 1, Action: "BLOCK", DomainListID: "all"},
		{GroupID: "early", AssociationPriority: 101, Priority: 200, Action: "BLOCK", DomainListID: "all"},
		{GroupID: "early", AssociationPriority: 101, Priority: 100, Action: "ALLOW", DomainListID: "ok"},
		{GroupID: "mid", AssociationPriority: 200, Priority: 5, Action: "ALERT", DomainListID: "watch"},
	}
	cfg := buildResolverConfig("", rules, map[string][]string{"all": {"*"}, "ok": {"example.com"}}, nil)
	var got []string
	for _, r := range cfg.Rules {
		got = append(got, r.GroupID+"/"+r.Action)
	}
	if strings.Join(got, ",") != "early/ALLOW,early/BLOCK,mid/ALERT,late/BLOCK" {
		t.Errorf("order = %v", got)
	}
	if cfg.FailOpen != "DISABLED" || cfg.Rules[0].Redirection != "INSPECT_REDIRECTION_DOMAIN" || len(cfg.Rules[1].Domains) != 1 {
		t.Errorf("defaults: %+v", cfg)
	}
}

// Every response the door writes is AWS JSON 1.1 with the request id.
func TestR53R_ErrorShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeR53RErr(w, 400, "rid", r53rNotFound("FIREWALL_RULE_GROUP", "The rule group 'x' does not exist."))
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Header().Get("Content-Type") != "application/x-amz-json-1.1" || w.Header().Get("x-amzn-RequestId") != "rid" ||
		out["__type"] != "ResourceNotFoundException" || out["Message"] == "" || out["ResourceType"] != "FIREWALL_RULE_GROUP" {
		t.Errorf("error = %v %v", w.Header(), out)
	}
}
