package render

import (
	"testing"
)

// A function in a VPC reaches the platform's AWS front door by AWS's own hostnames (#335), on the aws-shim's
// AWS-names listener: Service port 443, the shim's pod port 8443. An egress rule that admits HTTPS to anywhere
// (as a function reaches AWS's endpoints through a NAT) or to the aws-shim admits that listener; nothing else
// does, and a group outside a VPC is unchanged.
func sgEgressCtx(vpc string, egress ...any) map[string]any {
	spec := map[string]any{"egress": egress}
	if vpc != "" {
		spec["vpc"] = vpc
	}
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec, "metadata": map[string]any{"labels": map[string]any{
			"crossplane.io/claim-name": "fn-sg", "crossplane.io/claim-namespace": "team-a"}},
	}}}}
}

func sgAdmitsAWSNames(t *testing.T, out string) bool {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, d := range docs {
		m := mget(d, "spec", "forProvider", "manifest")
		if mstr(m, "kind") != "NetworkPolicy" {
			continue
		}
		rules, _ := mget(m, "spec", "egress").([]any)
		for _, r := range rules {
			ports, _ := mget(r, "ports").([]any)
			for _, p := range ports {
				if mstr(p, "port") == "8443" && mstr(p, "protocol") == "TCP" {
					to, _ := mget(r, "to").([]any)
					return len(to) == 1 && mstr(to[0], "podSelector", "matchLabels", "app") == "aws-shim"
				}
			}
		}
	}
	return false
}

func TestSecurityGroup_HTTPSAdmitsThePlatformsAWSNames(t *testing.T) {
	tmpl := extractInlineTemplate(t, sgCompositionPath)
	rule := func(proto string, ports []any, to map[string]any) map[string]any {
		r := map[string]any{"protocol": proto, "to": []any{to}}
		if ports != nil {
			r["ports"] = ports
		}
		return r
	}
	anywhere := map[string]any{"cidr": "0.0.0.0/0"}
	shim := map[string]any{"namespace": "open-infra-aws-shim"}
	for what, c := range map[string]struct {
		vpc  string
		rule map[string]any
		want bool
	}{
		"HTTPS to anywhere":             {"vpc-1", rule("TCP", []any{443.0}, anywhere), true},
		"HTTPS to the aws-shim":         {"vpc-1", rule("TCP", []any{443.0}, shim), true},
		"all TCP to anywhere":           {"vpc-1", rule("TCP", nil, anywhere), true},
		"all traffic to anywhere":       {"vpc-1", rule("ALL", nil, anywhere), true},
		"the shim's own port only":      {"vpc-1", rule("TCP", []any{4566.0}, shim), false},
		"HTTPS to one address":          {"vpc-1", rule("TCP", []any{443.0}, map[string]any{"cidr": "192.0.2.10/32"}), false},
		"UDP to anywhere":               {"vpc-1", rule("UDP", []any{443.0}, anywhere), false},
		"HTTPS to anywhere, not in VPC": {"", rule("TCP", []any{443.0}, anywhere), false},
	} {
		out := render(t, tmpl, sgEgressCtx(c.vpc, c.rule))
		if got := sgAdmitsAWSNames(t, out); got != c.want {
			t.Errorf("%s: admits the AWS-names listener = %v, want %v\n%s", what, got, c.want, grepCtx(out, "egress:"))
		}
	}
}
