package render

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Lambda VPC's settings agree everywhere they are written (docs/lambda-vpc.md): the VPC resolver's
// address (its Service, the EnvironmentConfig, the subnet ACL that lets DNS reach only it, the composition's
// default), the subnet's name (the subnet, the EnvironmentConfig, the shim's LAMBDA_VPC_SUBNET, the
// composition's default), and the Lambda service port (the shim's listener, its Service, the
// EnvironmentConfig, the composition's default, the security group's allow).
func TestLambdaVPC_SettingsAgree(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	vpc := read("../../platform/aws-shim/lambda-vpc.yaml")
	subnet := read("../../platform/networking/kube-ovn/lambda-vpc-subnet.yaml")
	shim := read("../../platform/aws-shim/aws-shim.yaml")
	comp := read("../../platform/abstraction/function-composition.yaml")
	sg := read("../../platform/abstraction/securitygroup-composition.yaml")
	find := func(src, re string) string {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("no match for %s", re)
		}
		return m[1]
	}

	resolver := find(vpc, `clusterIP: (\S+)`)
	for name, got := range map[string]string{
		"EnvironmentConfig resolver": find(vpc, `\n  resolver: (\S+)`),
		"subnet ACL":                 find(subnet, `ip4\.dst != (\d+\.\d+\.\d+\.\d+)`),
		"composition default":        find(comp, `\$lvResolver := "([^"]+)"`),
	} {
		if got != resolver {
			t.Errorf("%s is %s, the vpc-resolver Service is %s", name, got, resolver)
		}
	}
	if !strings.Contains(vpc, "targetPort: 5353") || !strings.Contains(shim, `VPC_RESOLVER_LISTEN, value: ":5353"`) {
		t.Error("the resolver Service must target the shim's VPC_RESOLVER_LISTEN port 5353")
	}

	name := find(subnet, `\n  name: (\S+)`)
	for what, got := range map[string]string{
		"EnvironmentConfig subnet": find(vpc, `\n  subnet: (\S+)`),
		"shim LAMBDA_VPC_SUBNET":   find(shim, `LAMBDA_VPC_SUBNET, value: "([^"]+)"`),
		"composition default":      find(comp, `\$lvSubnet := "([^"]+)"`),
	} {
		if got != name {
			t.Errorf("%s is %s, the subnet is %s", what, got, name)
		}
	}

	svc := find(vpc, `lambdaService: (\S+)`)
	if want := "http://" + find(vpc, `name: lambda-service\n(?:.*\n)*?  clusterIP: (\S+)`) + ":4568"; svc != want {
		t.Errorf("the EnvironmentConfig's Lambda service %s is not the lambda-service Service's address %s", svc, want)
	}
	if def := find(comp, `\$lvService := "([^"]+)"`); def != svc {
		t.Errorf("the composition's Lambda service default %s is not the EnvironmentConfig's %s", def, svc)
	}
	if !strings.HasSuffix(svc, ":4568") || !strings.Contains(shim, `LAMBDA_SERVICE_LISTEN, value: ":4568"`) ||
		!regexp.MustCompile(`name: lambda-service\n\s+port: 4568`).MatchString(shim) ||
		!strings.Contains(sg, `"port" 4568`) || !strings.Contains(sg, `"port" 5353`) {
		t.Error("the Lambda service port 4568 and the resolver port 5353 must agree across the shim, its Service and the security group's allow")
	}
}
