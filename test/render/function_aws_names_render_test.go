package render

import (
	"strings"
	"testing"
)

// AWS's own hostnames reach the platform from a function (#335): with the function resolver named
// (openinfra-function-dns) and the AWS endpoints CA published (openinfra-platform-ca), a function's pod resolves
// through the function resolver (in a VPC, through its VPC resolver) and trusts the AWS endpoints CA, so an SDK
// client built with no endpoint (aws-sdk v2 reads none of the endpoint variables) reaches the platform's AWS
// front door. Without both, nothing changes.

const testAWSEndpointsCA = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"

// awsNamesExtra is the extra resources with the function resolver and the published CA (each optional).
func awsNamesExtra(resolver, ca string, base map[string]any) map[string]any {
	extra := map[string]any{}
	for k, v := range base {
		extra[k] = v
	}
	if resolver != "" {
		extra["function-dns"] = map[string]any{"items": []any{map[string]any{"resource": map[string]any{
			"data": map[string]any{"resolver": resolver}}}}}
	}
	if ca != "" {
		extra["platform-ca"] = map[string]any{"items": []any{map[string]any{"resource": map[string]any{
			"data": map[string]any{"awsEndpointsCA": ca, "platformRootCA": "root"}}}}}
	}
	return extra
}

func podSpecOf(t *testing.T, out, name string) map[string]any {
	t.Helper()
	ps, _ := mget(ksvcOf(t, out, name), "spec", "template", "spec").(map[string]any)
	if ps == nil {
		t.Fatalf("no pod spec rendered for %s", name)
	}
	return ps
}

func TestFunction_AWSNamesReachThePlatform(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	for what, spec := range map[string]map[string]any{
		"code":  {"code": map[string]any{"runtime": "nodejs16", "handler": "index.handler", "source": map[string]any{"configMap": "orders-code"}}},
		"image": {"image": "registry.example/orders:1"},
		"role":  pkgSpec("orders-reader"),
	} {
		t.Run(what, func(t *testing.T) {
			base := map[string]any{}
			if _, ok := spec["role"]; ok {
				base = fnRoleExtra("111122223333", "us-east-1")
			}
			out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, awsNamesExtra("10.43.0.54", testAWSEndpointsCA, base)))
			ps := podSpecOf(t, out, "orders")
			if ps["dnsPolicy"] != "None" {
				t.Errorf("dnsPolicy = %v, want None: the function resolver is the only DNS", ps["dnsPolicy"])
			}
			ns, _ := mget(ps, "dnsConfig", "nameservers").([]any)
			if len(ns) != 1 || ns[0] != "10.43.0.54" {
				t.Errorf("nameservers = %v, want only the function resolver", ns)
			}
			if s, _ := mget(ps, "dnsConfig", "searches").([]any); len(s) != 3 || s[0] != "team-a.svc.cluster.local" {
				t.Errorf("searches = %v, want the cluster's search path", s)
			}
			env := envOf(ksvcOf(t, out, "orders"))
			for k, v := range map[string]string{"NODE_EXTRA_CA_CERTS": "/etc/openinfra/aws-endpoints-ca/ca.crt",
				"OPENINFRA_AWS_ENDPOINTS_CA": "/etc/openinfra/aws-endpoints-ca/ca.crt"} {
				if env[k] != v {
					t.Errorf("env %s = %q, want %q", k, env[k], v)
				}
			}
			cs, _ := ps["containers"].([]any)
			mounts, _ := mget(cs[0], "volumeMounts").([]any)
			mounted := false
			for _, m := range mounts {
				if mstr(m, "name") == "openinfra-aws-endpoints-ca" && mstr(m, "mountPath") == "/etc/openinfra/aws-endpoints-ca" && mget(m, "readOnly") == "true" {
					mounted = true
				}
			}
			if !mounted {
				t.Errorf("the AWS endpoints CA must be mounted read-only: %v", mounts)
			}
			vols, _ := ps["volumes"].([]any)
			found := false
			for _, v := range vols {
				if mstr(v, "name") == "openinfra-aws-endpoints-ca" && mstr(v, "configMap", "name") == "orders-aws-endpoints-ca" {
					found = true
				}
			}
			if !found {
				t.Errorf("the CA volume must be the function's ConfigMap: %v", vols)
			}
			docs, _ := parseYAMLDocs(out)
			cm := objectFor(docs, "ConfigMap", "orders-aws-endpoints-ca")
			if cm == nil {
				t.Fatalf("no CA ConfigMap rendered")
			}
			m := mget(cm, "spec", "forProvider", "manifest")
			if mstr(m, "metadata", "namespace") != "team-a" || mstr(m, "data", "ca.crt") != testAWSEndpointsCA {
				t.Errorf("the ConfigMap must carry the published CA in the function's namespace: %v", m)
			}
		})
	}
}

// In a VPC the VPC resolver stays the function's DNS (it answers AWS's names itself); the CA is trusted.
func TestFunction_AWSNamesInAVPCKeepTheVPCResolver(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	spec := map[string]any{"image": "registry.example/orders:1",
		"vpcConfig": map[string]any{"vpcId": "vpc-1", "subnetIds": []any{"subnet-a"}, "securityGroupIds": []any{"sg-1"}}}
	out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, awsNamesExtra("10.43.0.54", testAWSEndpointsCA, nil)))
	ps := podSpecOf(t, out, "orders")
	if ns, _ := mget(ps, "dnsConfig", "nameservers").([]any); len(ns) != 1 || ns[0] != "10.43.0.2" {
		t.Errorf("a VPC function's only DNS is its VPC resolver, got %v", ns)
	}
	if envOf(ksvcOf(t, out, "orders"))["NODE_EXTRA_CA_CERTS"] == "" {
		t.Error("a VPC function trusts the AWS endpoints CA too")
	}
}

// Both the function resolver and the published CA, or nothing: a function that resolved AWS's names to the
// platform without trusting its certificate would fail every call, and one that trusted it without the
// resolver gains nothing.
func TestFunction_AWSNamesNeedBothTheResolverAndTheCA(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	spec := map[string]any{"image": "registry.example/orders:1"}
	plain := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
	for what, extra := range map[string]map[string]any{
		"the resolver alone": awsNamesExtra("10.43.0.54", "", nil),
		"the CA alone":       awsNamesExtra("", testAWSEndpointsCA, nil),
	} {
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, extra))
		if out != plain {
			t.Errorf("%s changed the render", what)
		}
		for _, s := range []string{"dnsPolicy: None", "NODE_EXTRA_CA_CERTS", "aws-endpoints-ca"} {
			if strings.Contains(out, s) {
				t.Errorf("%s rendered %q", what, s)
			}
		}
	}
}
