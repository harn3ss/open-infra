package main

// Route 53 Resolver against a real Postgres store (OPENINFRA_TEST_PG_URI; skipped without it, see
// cfn_services_pg_test.go): DNS Firewall's domain lists, rule groups, rules and associations, a VPC's
// firewall configuration, query logging, tags, and each account keeping its own — and the configuration
// the VPC resolver reads for a VPC.

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const (
	r53rVPC      = "vpc-0a1b2c3d4e5f60718"
	r53rOtherVPC = "vpc-0b1c2d3e4f5a60718"
	r53rMemberVP = "vpc-0c1d2e3f4a5b60718"
)

func r53rPGHandler(t *testing.T) (*r53rHandler, *r53rStore) {
	t.Helper()
	st := &r53rStore{db: freshPGDB(t)}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatalf("the schema is created idempotently: %v", err)
	}
	h := newR53RHandler(csWithSAR(true), "authz", testMgmt, "us-east-1", st, discardLogger())
	h.authz = doorAccountsAuthz(t)
	h.vpcs = func(_ context.Context, c iam.Claims) ([]string, bool, error) {
		if c.Account == testMember {
			return []string{r53rMemberVP}, false, nil
		}
		return []string{r53rVPC, r53rOtherVPC}, false, nil
	}
	return h, st
}

func r53r(t *testing.T, h *r53rHandler, c doorCaller, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return c.call(t, h.serve, r53rTargetPrefix+op, body)
}

// r53rOK calls op and fails the test unless it succeeds.
func r53rOK(t *testing.T, h *r53rHandler, c doorCaller, op string, body map[string]any) map[string]any {
	t.Helper()
	code, out := r53r(t, h, c, op, body)
	if code != 200 {
		t.Fatalf("%s %v = %d %v", op, body, code, out)
	}
	return out
}

// r53rErr calls op and fails the test unless it answers the error code.
func r53rErr(t *testing.T, h *r53rHandler, c doorCaller, op string, body map[string]any, code string) {
	t.Helper()
	if status, out := r53r(t, h, c, op, body); status != 400 || jsonErrType(out) != code {
		t.Errorf("%s %v = %d %v, want %s", op, body, status, out, code)
	}
}

func r53rField(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }

func r53rStrings(v any) []string {
	var out []string
	for _, x := range sliceOf(v) {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func TestR53RPG_DNSFirewallLifecycle(t *testing.T) {
	ctx := context.Background()
	h, st := r53rPGHandler(t)
	mgmt := mgmtDoorCaller()

	// A domain list, made once for a retried request (its CreatorRequestId).
	out := r53rOK(t, h, mgmt, "CreateFirewallDomainList", map[string]any{"Name": "allowed", "CreatorRequestId": "c-allowed",
		"Tags": []any{map[string]any{"Key": "team", "Value": "payments"}}})
	fdl := r53rField(out, "FirewallDomainList")
	allowed, _ := fdl["Id"].(string)
	if fdl["Arn"] != "arn:aws:route53resolver:us-east-1:"+testMgmt+":firewall-domain-list/"+allowed || fdl["Status"] != "COMPLETE" ||
		len(allowed) != len("rslvr-fdl-")+17 {
		t.Fatalf("CreateFirewallDomainList = %v", out)
	}
	again := r53rOK(t, h, mgmt, "CreateFirewallDomainList", map[string]any{"Name": "allowed", "CreatorRequestId": "c-allowed"})
	if r53rField(again, "FirewallDomainList")["Id"] != allowed {
		t.Errorf("a retried request makes nothing new: %v", again)
	}

	gen := st.generation()
	r53rOK(t, h, mgmt, "UpdateFirewallDomains", map[string]any{"FirewallDomainListId": allowed, "Operation": "ADD",
		"Domains": []any{"Example.com", "*.example.org", "example.com."}})
	if st.generation() == gen {
		t.Error("a write changes the store's generation (the VPC resolver drops what it cached)")
	}
	if got := r53rStrings(r53rOK(t, h, mgmt, "ListFirewallDomains", map[string]any{"FirewallDomainListId": allowed})["Domains"]); len(got) != 2 ||
		got[0] != "*.example.org" || got[1] != "example.com" {
		t.Errorf("after ADD: %v", got)
	}
	r53rOK(t, h, mgmt, "UpdateFirewallDomains", map[string]any{"FirewallDomainListId": allowed, "Operation": "REMOVE", "Domains": []any{"EXAMPLE.com"}})
	r53rOK(t, h, mgmt, "UpdateFirewallDomains", map[string]any{"FirewallDomainListId": allowed, "Operation": "ADD", "Domains": []any{"api.example.com"}})
	if got := r53rStrings(r53rOK(t, h, mgmt, "ListFirewallDomains", map[string]any{"FirewallDomainListId": allowed})["Domains"]); len(got) != 2 ||
		got[0] != "*.example.org" || got[1] != "api.example.com" {
		t.Errorf("after REMOVE and ADD: %v", got)
	}
	r53rOK(t, h, mgmt, "UpdateFirewallDomains", map[string]any{"FirewallDomainListId": allowed, "Operation": "REPLACE",
		"Domains": []any{"api.example.com", "*.example.net"}})
	if d := r53rField(r53rOK(t, h, mgmt, "GetFirewallDomainList", map[string]any{"FirewallDomainListId": allowed}), "FirewallDomainList"); d["DomainCount"] != float64(2) {
		t.Errorf("after REPLACE: %v", d)
	}
	everything, _ := r53rField(r53rOK(t, h, mgmt, "CreateFirewallDomainList", map[string]any{"Name": "everything", "CreatorRequestId": "c-all"}),
		"FirewallDomainList")["Id"].(string)
	r53rOK(t, h, mgmt, "UpdateFirewallDomains", map[string]any{"FirewallDomainListId": everything, "Operation": "ADD", "Domains": []any{"*"}})
	if lists := sliceOf(r53rOK(t, h, mgmt, "ListFirewallDomainLists", map[string]any{})["FirewallDomainLists"]); len(lists) != 2 {
		t.Errorf("ListFirewallDomainLists = %v", lists)
	}

	// A rule group: a walled garden — the allowed names, then everything else blocked.
	frg := r53rField(r53rOK(t, h, mgmt, "CreateFirewallRuleGroup", map[string]any{"Name": "walled-garden", "CreatorRequestId": "c-frg"}), "FirewallRuleGroup")
	group, _ := frg["Id"].(string)
	if frg["OwnerId"] != testMgmt || frg["ShareStatus"] != "NOT_SHARED" || frg["RuleCount"] != float64(0) {
		t.Errorf("CreateFirewallRuleGroup = %v", frg)
	}
	rule := func(list string, prio int, action string, extra map[string]any) map[string]any {
		b := map[string]any{"FirewallRuleGroupId": group, "FirewallDomainListId": list, "Priority": prio, "Action": action,
			"Name": "r" + action, "CreatorRequestId": list + action}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}
	allow := r53rField(r53rOK(t, h, mgmt, "CreateFirewallRule", rule(allowed, 100, "ALLOW", nil)), "FirewallRule")
	if allow["FirewallDomainRedirectionAction"] != "INSPECT_REDIRECTION_DOMAIN" || allow["Priority"] != float64(100) {
		t.Errorf("CreateFirewallRule = %v", allow)
	}
	r53rOK(t, h, mgmt, "CreateFirewallRule", rule(everything, 200, "BLOCK", map[string]any{"BlockResponse": "NXDOMAIN"}))
	r53rErr(t, h, mgmt, "CreateFirewallRule", rule(everything, 100, "BLOCK", map[string]any{"BlockResponse": "NODATA", "Qtype": "AAAA",
		"CreatorRequestId": "dup-prio"}), "ValidationException")
	r53rErr(t, h, mgmt, "CreateFirewallRule", rule(everything, 300, "ALERT", map[string]any{"CreatorRequestId": "dup-list"}), "ValidationException")
	r53rErr(t, h, mgmt, "CreateFirewallRule", rule("rslvr-fdl-00000000000000000", 400, "ALERT", nil), "ResourceNotFoundException")
	// The same domain list again, for one query type.
	r53rOK(t, h, mgmt, "CreateFirewallRule", rule(everything, 150, "ALERT", map[string]any{"Qtype": "TXT", "CreatorRequestId": "txt"}))
	rules := sliceOf(r53rOK(t, h, mgmt, "ListFirewallRules", map[string]any{"FirewallRuleGroupId": group})["FirewallRules"])
	if len(rules) != 3 || mapOf(rules[0])["Priority"] != float64(100) || mapOf(rules[2])["Action"] != "BLOCK" {
		t.Errorf("ListFirewallRules = %v", rules)
	}
	if blocks := sliceOf(r53rOK(t, h, mgmt, "ListFirewallRules", map[string]any{"FirewallRuleGroupId": group, "Action": "BLOCK"})["FirewallRules"]); len(blocks) != 1 {
		t.Errorf("ListFirewallRules Action BLOCK = %v", blocks)
	}

	// Associations: a VPC of the account, one per rule group and VPC, one per priority in a VPC.
	assocBody := map[string]any{"FirewallRuleGroupId": group, "VpcId": r53rVPC, "Priority": 101, "Name": "egress", "CreatorRequestId": "c-a1"}
	fa := r53rField(r53rOK(t, h, mgmt, "AssociateFirewallRuleGroup", assocBody), "FirewallRuleGroupAssociation")
	assoc, _ := fa["Id"].(string)
	if fa["Status"] != "COMPLETE" || fa["VpcId"] != r53rVPC || fa["MutationProtection"] != "DISABLED" ||
		fa["Arn"] != "arn:aws:route53resolver:us-east-1:"+testMgmt+":firewall-rule-group-association/"+assoc {
		t.Errorf("AssociateFirewallRuleGroup = %v", fa)
	}
	if again := r53rField(r53rOK(t, h, mgmt, "AssociateFirewallRuleGroup", assocBody), "FirewallRuleGroupAssociation"); again["Id"] != assoc {
		t.Errorf("a retried association makes nothing new: %v", again)
	}
	r53rErr(t, h, mgmt, "AssociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": group, "VpcId": r53rVPC, "Priority": 300,
		"Name": "twice", "CreatorRequestId": "c-a2"}, "ConflictException")
	other := r53rField(r53rOK(t, h, mgmt, "CreateFirewallRuleGroup", map[string]any{"Name": "monitor", "CreatorRequestId": "c-frg2"}), "FirewallRuleGroup")["Id"]
	r53rErr(t, h, mgmt, "AssociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": other, "VpcId": r53rVPC, "Priority": 101,
		"Name": "same-prio", "CreatorRequestId": "c-a3"}, "ConflictException")
	r53rErr(t, h, mgmt, "AssociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": "rslvr-frg-00000000000000000", "VpcId": r53rVPC,
		"Priority": 500, "Name": "nogroup", "CreatorRequestId": "c-a4"}, "ResourceNotFoundException")
	if list := sliceOf(r53rOK(t, h, mgmt, "ListFirewallRuleGroupAssociations", map[string]any{"VpcId": r53rVPC})["FirewallRuleGroupAssociations"]); len(list) != 1 {
		t.Errorf("ListFirewallRuleGroupAssociations = %v", list)
	}

	// What the VPC resolver reads: the walled garden's rules in priority order, with their domains.
	cfg, err := st.resolverConfig(ctx, testMgmt, r53rVPC)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOpen != "DISABLED" || len(cfg.Rules) != 3 || cfg.Rules[0].Action != "ALLOW" || len(cfg.Rules[0].Domains) != 2 ||
		cfg.Rules[1].Qtype != "TXT" || cfg.Rules[2].BlockResponse != "NXDOMAIN" || cfg.Rules[2].Domains[0] != "*" || cfg.Rules[0].AssociationPriority != 101 {
		t.Errorf("resolverConfig = %+v", cfg)
	}
	if none, err := st.resolverConfig(ctx, testMgmt, r53rOtherVPC); err != nil || len(none.Rules) != 0 {
		t.Errorf("another VPC has no rules: %+v %v", none, err)
	}

	// What is in use is not deleted.
	r53rErr(t, h, mgmt, "DeleteFirewallDomainList", map[string]any{"FirewallDomainListId": allowed}, "ConflictException")
	r53rErr(t, h, mgmt, "DeleteFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": group}, "ConflictException")

	// A rule changed: BLOCK's response becomes an OVERRIDE; a rule that stops blocking drops its block settings.
	upd := r53rField(r53rOK(t, h, mgmt, "UpdateFirewallRule", map[string]any{"FirewallRuleGroupId": group, "FirewallDomainListId": everything,
		"Qtype": "", "BlockResponse": "OVERRIDE", "BlockOverrideDomain": "sinkhole.example.com", "BlockOverrideDnsType": "CNAME", "BlockOverrideTtl": 60}), "FirewallRule")
	if upd["BlockResponse"] != "OVERRIDE" || upd["BlockOverrideDomain"] != "sinkhole.example.com" || upd["BlockOverrideTtl"] != float64(60) {
		t.Errorf("UpdateFirewallRule = %v", upd)
	}
	// Without a Qtype, the list's rule that has none.
	if same := r53rField(r53rOK(t, h, mgmt, "UpdateFirewallRule", map[string]any{"FirewallRuleGroupId": group, "FirewallDomainListId": everything}),
		"FirewallRule"); same["Action"] != "BLOCK" || same["BlockResponse"] != "OVERRIDE" {
		t.Errorf("UpdateFirewallRule without Qtype = %v", same)
	}
	alert := r53rField(r53rOK(t, h, mgmt, "UpdateFirewallRule", map[string]any{"FirewallRuleGroupId": group, "FirewallDomainListId": everything,
		"Qtype": "TXT", "Priority": 160}), "FirewallRule")
	if alert["Priority"] != float64(160) || alert["Action"] != "ALERT" {
		t.Errorf("UpdateFirewallRule by Qtype = %v", alert)
	}
	r53rErr(t, h, mgmt, "UpdateFirewallRule", map[string]any{"FirewallRuleGroupId": group, "FirewallDomainListId": allowed, "Priority": 160}, "ValidationException")

	// The VPC's firewall configuration: AWS's default fails closed; one per VPC of the account.
	fc := r53rField(r53rOK(t, h, mgmt, "GetFirewallConfig", map[string]any{"ResourceId": r53rVPC}), "FirewallConfig")
	if fc["FirewallFailOpen"] != "DISABLED" || fc["ResourceId"] != r53rVPC || fc["OwnerId"] != testMgmt || fc["Id"] != firewallConfigID("", r53rVPC) {
		t.Errorf("GetFirewallConfig = %v", fc)
	}
	r53rOK(t, h, mgmt, "UpdateFirewallConfig", map[string]any{"ResourceId": r53rVPC, "FirewallFailOpen": "ENABLED"})
	if cfg, _ := st.resolverConfig(ctx, testMgmt, r53rVPC); cfg.FailOpen != "ENABLED" {
		t.Errorf("fail open after UpdateFirewallConfig: %+v", cfg)
	}
	configs := sliceOf(r53rOK(t, h, mgmt, "ListFirewallConfigs", map[string]any{})["FirewallConfigs"])
	if len(configs) != 2 || mapOf(configs[0])["ResourceId"] != r53rVPC || mapOf(configs[0])["FirewallFailOpen"] != "ENABLED" ||
		mapOf(configs[1])["FirewallFailOpen"] != "DISABLED" {
		t.Errorf("ListFirewallConfigs = %v", configs)
	}
	r53rErr(t, h, mgmt, "UpdateFirewallConfig", map[string]any{"ResourceId": r53rMemberVP, "FirewallFailOpen": "ENABLED"}, "ResourceNotFoundException")

	// Tags.
	frgARN := "arn:aws:route53resolver:us-east-1:" + testMgmt + ":firewall-rule-group/" + group
	r53rOK(t, h, mgmt, "TagResource", map[string]any{"ResourceArn": frgARN, "Tags": []any{map[string]any{"Key": "env", "Value": "prod"},
		map[string]any{"Key": "owner", "Value": "netops"}}})
	r53rOK(t, h, mgmt, "UntagResource", map[string]any{"ResourceArn": frgARN, "TagKeys": []any{"owner"}})
	if tags := sliceOf(r53rOK(t, h, mgmt, "ListTagsForResource", map[string]any{"ResourceArn": frgARN})["Tags"]); len(tags) != 1 ||
		mapOf(tags[0])["Key"] != "env" {
		t.Errorf("tags = %v", tags)
	}
	if tags := sliceOf(r53rOK(t, h, mgmt, "ListTagsForResource", map[string]any{"ResourceArn": "arn:aws:route53resolver:us-east-1:" + testMgmt +
		":firewall-domain-list/" + allowed})["Tags"]); len(tags) != 1 || mapOf(tags[0])["Value"] != "payments" {
		t.Errorf("tags given at creation = %v", tags)
	}
	r53rErr(t, h, mgmt, "ListTagsForResource", map[string]any{"ResourceArn": "arn:aws:route53resolver:us-east-1:" + testMgmt +
		":firewall-rule-group/rslvr-frg-00000000000000000"}, "ResourceNotFoundException")

	// Mutation protection holds an association until it is turned off.
	r53rOK(t, h, mgmt, "UpdateFirewallRuleGroupAssociation", map[string]any{"FirewallRuleGroupAssociationId": assoc, "MutationProtection": "ENABLED"})
	r53rErr(t, h, mgmt, "DisassociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupAssociationId": assoc}, "ValidationException")
	r53rErr(t, h, mgmt, "UpdateFirewallRuleGroupAssociation", map[string]any{"FirewallRuleGroupAssociationId": assoc, "Priority": 500}, "ValidationException")
	r53rOK(t, h, mgmt, "UpdateFirewallRuleGroupAssociation", map[string]any{"FirewallRuleGroupAssociationId": assoc, "MutationProtection": "DISABLED", "Priority": 500})
	if a := r53rField(r53rOK(t, h, mgmt, "GetFirewallRuleGroupAssociation", map[string]any{"FirewallRuleGroupAssociationId": assoc}),
		"FirewallRuleGroupAssociation"); a["Priority"] != float64(500) || a["MutationProtection"] != "DISABLED" {
		t.Errorf("updated association = %v", a)
	}
	gone := r53rField(r53rOK(t, h, mgmt, "DisassociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupAssociationId": assoc}), "FirewallRuleGroupAssociation")
	if gone["Status"] != "DELETING" {
		t.Errorf("DisassociateFirewallRuleGroup = %v", gone)
	}
	r53rErr(t, h, mgmt, "GetFirewallRuleGroupAssociation", map[string]any{"FirewallRuleGroupAssociationId": assoc}, "ResourceNotFoundException")
	if cfg, _ := st.resolverConfig(ctx, testMgmt, r53rVPC); len(cfg.Rules) != 0 {
		t.Errorf("a disassociated rule group no longer applies: %+v", cfg)
	}

	// A rule group with rules is not deleted; without them it is, and so is its domain list.
	r53rErr(t, h, mgmt, "DeleteFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": group}, "ConflictException")
	for _, del := range []map[string]any{{"FirewallDomainListId": allowed}, {"FirewallDomainListId": everything, "Qtype": "TXT"},
		{"FirewallDomainListId": everything}} {
		del["FirewallRuleGroupId"] = group
		r53rOK(t, h, mgmt, "DeleteFirewallRule", del)
	}
	r53rErr(t, h, mgmt, "DeleteFirewallRule", map[string]any{"FirewallRuleGroupId": group, "FirewallDomainListId": allowed}, "ResourceNotFoundException")
	if d := r53rField(r53rOK(t, h, mgmt, "DeleteFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": group}), "FirewallRuleGroup"); d["Status"] != "DELETING" {
		t.Errorf("DeleteFirewallRuleGroup = %v", d)
	}
	r53rOK(t, h, mgmt, "DeleteFirewallDomainList", map[string]any{"FirewallDomainListId": allowed})
	r53rErr(t, h, mgmt, "GetFirewallDomainList", map[string]any{"FirewallDomainListId": allowed}, "ResourceNotFoundException")
	r53rErr(t, h, mgmt, "ListTagsForResource", map[string]any{"ResourceArn": frgARN}, "ResourceNotFoundException")
}

func TestR53RPG_QueryLogging(t *testing.T) {
	ctx := context.Background()
	h, st := r53rPGHandler(t)
	mgmt := mgmtDoorCaller()
	dest := "arn:aws:logs:us-east-1:" + testMgmt + ":log-group:/vpc/dns-queries:*"
	c := r53rField(r53rOK(t, h, mgmt, "CreateResolverQueryLogConfig", map[string]any{"Name": "dns-queries", "DestinationArn": dest, "CreatorRequestId": "q1"}),
		"ResolverQueryLogConfig")
	id, _ := c["Id"].(string)
	if c["Status"] != "CREATED" || c["DestinationArn"] != dest || c["AssociationCount"] != float64(0) || len(id) != len("rqlc-")+16 ||
		c["Arn"] != "arn:aws:route53resolver:us-east-1:"+testMgmt+":resolver-query-log-config/"+id {
		t.Fatalf("CreateResolverQueryLogConfig = %v", c)
	}
	a := r53rField(r53rOK(t, h, mgmt, "AssociateResolverQueryLogConfig", map[string]any{"ResolverQueryLogConfigId": id, "ResourceId": r53rVPC}),
		"ResolverQueryLogConfigAssociation")
	if a["Status"] != "ACTIVE" || a["Error"] != "NONE" || a["ResourceId"] != r53rVPC {
		t.Errorf("AssociateResolverQueryLogConfig = %v", a)
	}
	r53rErr(t, h, mgmt, "AssociateResolverQueryLogConfig", map[string]any{"ResolverQueryLogConfigId": id, "ResourceId": r53rVPC}, "ResourceExistsException")
	r53rErr(t, h, mgmt, "DeleteResolverQueryLogConfig", map[string]any{"ResolverQueryLogConfigId": id}, "InvalidRequestException")
	cfg, err := st.resolverConfig(ctx, testMgmt, r53rVPC)
	if err != nil || len(cfg.QueryLogs) != 1 || cfg.QueryLogs[0].ConfigID != id || cfg.QueryLogs[0].LogGroupARN != dest {
		t.Errorf("resolverConfig query logs = %+v %v", cfg, err)
	}
	r53rOK(t, h, mgmt, "CreateResolverQueryLogConfig", map[string]any{"Name": "second", "DestinationArn": "arn:aws:logs:us-east-1:" + testMgmt +
		":log-group:other", "CreatorRequestId": "q2"})
	list := r53rOK(t, h, mgmt, "ListResolverQueryLogConfigs", map[string]any{"Filters": []any{map[string]any{"Name": "Name", "Values": []any{"dns-queries"}}}})
	if got := sliceOf(list["ResolverQueryLogConfigs"]); len(got) != 1 || mapOf(got[0])["AssociationCount"] != float64(1) ||
		list["TotalCount"] != float64(2) || list["TotalFilteredCount"] != float64(1) {
		t.Errorf("ListResolverQueryLogConfigs = %v", list)
	}
	sorted := sliceOf(r53rOK(t, h, mgmt, "ListResolverQueryLogConfigs", map[string]any{"SortBy": "Name", "SortOrder": "DESCENDING"})["ResolverQueryLogConfigs"])
	if len(sorted) != 2 || mapOf(sorted[0])["Name"] != "second" {
		t.Errorf("sorted = %v", sorted)
	}
	r53rErr(t, h, mgmt, "ListResolverQueryLogConfigs", map[string]any{"Filters": []any{map[string]any{"Name": "Color", "Values": []any{"x"}}}}, "InvalidParameterException")
	assocs := sliceOf(r53rOK(t, h, mgmt, "ListResolverQueryLogConfigAssociations", map[string]any{"Filters": []any{
		map[string]any{"Name": "ResourceId", "Values": []any{r53rVPC}}}})["ResolverQueryLogConfigAssociations"])
	if len(assocs) != 1 {
		t.Fatalf("ListResolverQueryLogConfigAssociations = %v", assocs)
	}
	aid, _ := mapOf(assocs[0])["Id"].(string)
	if got := r53rField(r53rOK(t, h, mgmt, "GetResolverQueryLogConfigAssociation", map[string]any{"ResolverQueryLogConfigAssociationId": aid}),
		"ResolverQueryLogConfigAssociation"); got["ResolverQueryLogConfigId"] != id {
		t.Errorf("GetResolverQueryLogConfigAssociation = %v", got)
	}
	d := r53rField(r53rOK(t, h, mgmt, "DisassociateResolverQueryLogConfig", map[string]any{"ResolverQueryLogConfigId": id, "ResourceId": r53rVPC}),
		"ResolverQueryLogConfigAssociation")
	if d["Status"] != "DELETING" {
		t.Errorf("DisassociateResolverQueryLogConfig = %v", d)
	}
	if del := r53rField(r53rOK(t, h, mgmt, "DeleteResolverQueryLogConfig", map[string]any{"ResolverQueryLogConfigId": id}), "ResolverQueryLogConfig"); del["Status"] != "DELETING" {
		t.Errorf("DeleteResolverQueryLogConfig = %v", del)
	}
	r53rErr(t, h, mgmt, "GetResolverQueryLogConfig", map[string]any{"ResolverQueryLogConfigId": id}, "ResourceNotFoundException")
}

// Each account's DNS Firewall and query logging are its own: a member account's resources carry its id in
// their ARNs, neither account reads, lists, changes or associates the other's, and the VPC resolver reads
// each VPC's configuration in its own account.
func TestR53RPG_EachAccountKeepsItsOwn(t *testing.T) {
	ctx := context.Background()
	h, st := r53rPGHandler(t)
	mgmt, mem := mgmtDoorCaller(), memberDoorCaller()
	mg := r53rField(r53rOK(t, h, mgmt, "CreateFirewallRuleGroup", map[string]any{"Name": "mgmt", "CreatorRequestId": "same"}), "FirewallRuleGroup")
	mm := r53rField(r53rOK(t, h, mem, "CreateFirewallRuleGroup", map[string]any{"Name": "member", "CreatorRequestId": "same"}), "FirewallRuleGroup")
	if mg["Id"] == mm["Id"] {
		t.Fatal("the same CreatorRequestId in two accounts makes two rule groups")
	}
	if mm["OwnerId"] != testMember || mm["Arn"] != "arn:aws:route53resolver:us-east-1:"+testMember+":firewall-rule-group/"+mm["Id"].(string) {
		t.Errorf("member rule group = %v", mm)
	}
	r53rErr(t, h, mgmt, "GetFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": mm["Id"]}, "ResourceNotFoundException")
	r53rErr(t, h, mem, "GetFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": mg["Id"]}, "ResourceNotFoundException")
	for _, c := range []struct {
		who  doorCaller
		want any
	}{{mgmt, mg["Id"]}, {mem, mm["Id"]}} {
		groups := sliceOf(r53rOK(t, h, c.who, "ListFirewallRuleGroups", map[string]any{})["FirewallRuleGroups"])
		if len(groups) != 1 || mapOf(groups[0])["Id"] != c.want {
			t.Errorf("ListFirewallRuleGroups = %v, want only %v", groups, c.want)
		}
	}
	// The member account associates only its own rule group, with only its own VPC.
	r53rErr(t, h, mem, "AssociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": mg["Id"], "VpcId": r53rMemberVP, "Priority": 101,
		"Name": "theirs", "CreatorRequestId": "x1"}, "ResourceNotFoundException")
	r53rErr(t, h, mem, "AssociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": mm["Id"], "VpcId": r53rVPC, "Priority": 101,
		"Name": "theirvpc", "CreatorRequestId": "x2"}, "ResourceNotFoundException")
	list := r53rField(r53rOK(t, h, mem, "CreateFirewallDomainList", map[string]any{"Name": "all", "CreatorRequestId": "l"}), "FirewallDomainList")["Id"]
	r53rOK(t, h, mem, "UpdateFirewallDomains", map[string]any{"FirewallDomainListId": list, "Operation": "ADD", "Domains": []any{"*"}})
	r53rOK(t, h, mem, "CreateFirewallRule", map[string]any{"FirewallRuleGroupId": mm["Id"], "FirewallDomainListId": list, "Priority": 1,
		"Action": "BLOCK", "BlockResponse": "NODATA", "Name": "all", "CreatorRequestId": "r"})
	r53rOK(t, h, mem, "AssociateFirewallRuleGroup", map[string]any{"FirewallRuleGroupId": mm["Id"], "VpcId": r53rMemberVP, "Priority": 101,
		"Name": "mine", "CreatorRequestId": "x3"})
	r53rErr(t, h, mgmt, "ListFirewallDomains", map[string]any{"FirewallDomainListId": list}, "ResourceNotFoundException")
	r53rErr(t, h, mgmt, "CreateFirewallRule", map[string]any{"FirewallRuleGroupId": mg["Id"], "FirewallDomainListId": list, "Priority": 1,
		"Action": "ALLOW", "Name": "theirlist", "CreatorRequestId": "r"}, "ResourceNotFoundException")
	if cfg, err := st.resolverConfig(ctx, testMember, r53rMemberVP); err != nil || len(cfg.Rules) != 1 || cfg.Rules[0].Action != "BLOCK" {
		t.Errorf("the member account's VPC = %+v %v", cfg, err)
	}
	if cfg, err := st.resolverConfig(ctx, testMgmt, r53rMemberVP); err != nil || len(cfg.Rules) != 0 {
		t.Errorf("the same VPC id in the management account has none of the member's rules: %+v %v", cfg, err)
	}
	// A member account's query logs go to its own log groups.
	r53rErr(t, h, mem, "CreateResolverQueryLogConfig", map[string]any{"Name": "q", "DestinationArn": "arn:aws:logs:us-east-1:" + testMgmt + ":log-group:g"},
		"InvalidParameterException")
	r53rOK(t, h, mem, "CreateResolverQueryLogConfig", map[string]any{"Name": "q", "DestinationArn": "arn:aws:logs:us-east-1:" + testMember + ":log-group:g"})
	if got := sliceOf(r53rOK(t, h, mgmt, "ListResolverQueryLogConfigs", map[string]any{})["ResolverQueryLogConfigs"]); len(got) != 0 {
		t.Errorf("the management account lists the member's query log configs: %v", got)
	}
}
