package render

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// platform/aws-shim/guest-aws-endpoints.yaml: inside VM guests, AWS's names of the services the aws-shim
// serves resolve to the platform, served with a certificate from a CA only guests trust.

const guestAWSPath = "../../platform/aws-shim/guest-aws-endpoints.yaml"

// guestAWSCAPath holds the AWS endpoints CA and its CA-type issuer, apart so that install.sh can exclude them
// once the platform's CAs are in OpenBao (openbao.platformCAs).
const guestAWSCAPath = "../../platform/aws-shim/guest-aws-endpoints-ca.yaml"

const (
	shimTarget     = "aws-shim.open-infra-aws-shim.svc.cluster.local."
	registryTarget = "ecr-registry-aws.open-infra-ecr.svc.cluster.local."
)

// The amazonaws.com hostnames ({r} = a region) of each service the aws-shim registers (main.go). A
// service registered without an entry here fails TestGuestAWSEndpoints_EveryServedServiceResolvesAndVerifies:
// decide its names, then cover them in the resolver and the shim's certificate.
var servedHostForms = map[string][]string{
	"s3":              {"s3.{r}", "examplebucket.s3.{r}", "s3", "examplebucket.s3"},
	"sts":             {"sts.{r}", "sts"},
	"lambda":          {"lambda.{r}"},
	"appsync":         {"appsync.{r}", "abcdefghijklmnopqrstuvwxyz.appsync-api.{r}"},
	"dynamodb":        {"dynamodb.{r}"},
	"dynamodbstreams": {"streams.dynamodb.{r}"},
	"sqs":             {"sqs.{r}", "{r}.queue", "queue"},
	"sns":             {"sns.{r}"},
	"kms":             {"kms.{r}"},
	"secretsmanager":  {"secretsmanager.{r}"},
	"events":          {"events.{r}"},
	"rds":             {"rds.{r}"},
	"logs":            {"logs.{r}"},
	"ssm":             {"ssm.{r}"},
	"apigateway":      {"apigateway.{r}", "a1b2c3d4e5.execute-api.{r}"},
	"monitoring":      {"monitoring.{r}"},
	"kinesis":         {"kinesis.{r}"},
	"iam":             {"iam"},
	"ses":             {"email.{r}"},
	"email":           {"email.{r}"},
	"cognito-idp":     {"cognito-idp.{r}"},
	"states":          {"states.{r}", "sync-states.{r}"},
	"cloudformation":  {"cloudformation.{r}"},
	"cloudfront":      {"cloudfront"},
	"acm":             {"acm.{r}"},
	"ecs":             {"ecs.{r}"},
	"ecr":             {"api.ecr.{r}", "ecr.{r}"},
	"glue":            {"glue.{r}"},
	"athena":          {"athena.{r}"},
	"eks":             {"eks.{r}"},
	"ec2":             {"ec2.{r}"},
	"organizations":   {"organizations.{r}"},
	"servicequotas":   {"servicequotas.{r}"},
	"route53resolver": {"route53resolver.{r}"},
}

type rewriteRule struct {
	re     *regexp.Regexp
	target string
}

func guestAWSDocs(t *testing.T) (raw string, byName map[string]map[string]any) {
	t.Helper()
	raw = mustRead(t, guestAWSPath) + "\n---\n" + mustRead(t, guestAWSCAPath)
	docs, err := parseYAMLDocs(raw)
	if err != nil {
		t.Fatal(err)
	}
	byName = map[string]map[string]any{}
	for _, d := range docs {
		md, _ := d["metadata"].(map[string]any)
		byName[fmt.Sprintf("%v/%v", d["kind"], md["name"])] = d
	}
	return raw, byName
}

func mustDoc(t *testing.T, docs map[string]map[string]any, key string) map[string]any {
	t.Helper()
	d, ok := docs[key]
	if !ok {
		keys := make([]string, 0, len(docs))
		for k := range docs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("%s has no %s (has %v)", guestAWSPath, key, keys)
	}
	return d
}

func strList(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func guestCorefile(t *testing.T, docs map[string]map[string]any) (rules []rewriteRule, corefile string) {
	t.Helper()
	cm := mustDoc(t, docs, "ConfigMap/openinfra-guest-dns")
	corefile = cm["data"].(map[string]any)["Corefile"].(string)
	for _, ln := range strings.Split(corefile, "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 || f[0] != "rewrite" {
			continue
		}
		// rewrite stop name regex <re> <target> answer auto
		if len(f) != 8 || f[1] != "stop" || f[2] != "name" || f[3] != "regex" || f[6] != "answer" || f[7] != "auto" {
			t.Fatalf("every rule must be `rewrite stop name regex <re> <target> answer auto` (first match wins, answered under the asked name): %q", ln)
		}
		rules = append(rules, rewriteRule{re: regexp.MustCompile(f[4]), target: f[5]})
	}
	if len(rules) == 0 {
		t.Fatal("the guest resolver has no rewrite rules")
	}
	return rules, corefile
}

// resolveVia is the target of the first rule matching name (CoreDNS rewrite: Go regexp on the FQDN).
func resolveVia(rules []rewriteRule, name string) string {
	fq := name + "."
	for _, r := range rules {
		if r.re.MatchString(fq) {
			return r.target
		}
	}
	return ""
}

// covers reports whether a certificate's dnsNames cover host (a wildcard covers exactly one label).
func covers(sans []string, host string) bool {
	for _, s := range sans {
		if s == host {
			return true
		}
		if rest, ok := strings.CutPrefix(s, "*."); ok {
			if label, tail, ok := strings.Cut(host, "."); ok && label != "" && tail == rest {
				return true
			}
		}
	}
	return false
}

var regionLabel = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$`)

func certSANs(t *testing.T, docs map[string]map[string]any, key string) []string {
	t.Helper()
	return strList(mustDoc(t, docs, key)["spec"].(map[string]any)["dnsNames"])
}

// The services main.go registers with the shim's router.
func registeredShimServices(t *testing.T) []string {
	t.Helper()
	src := mustRead(t, "../../console-api/cmd/aws-shim/main.go")
	seen := map[string]bool{}
	i := strings.Index(src, "services := map[string]awsService{")
	if i < 0 {
		t.Fatal("main.go: the services map literal moved; update this test")
	}
	block := src[i:]
	block = block[:strings.Index(block, "\n\t}\n")]
	for _, m := range regexp.MustCompile(`(?m)^\s+"([a-z0-9-]+)":`).FindAllStringSubmatch(block, -1) {
		seen[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`services\["([a-z0-9-]+)"\]\s*=`).FindAllStringSubmatch(src, -1) {
		seen[m[1]] = true
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) < 20 {
		t.Fatalf("found only %d registered services in main.go (%v); the parse is broken", len(out), out)
	}
	return out
}

// Every service the shim serves: each of its AWS names, in every region the certificate lists, is
// answered with the shim's address and covered by the shim's AWS-names certificate; an image name is
// answered with the guest registry's and covered by its certificate; the shim's own name, virtual-hosted,
// is answered with the shim and covered by its internal certificate.
func TestGuestAWSEndpoints_EveryServedServiceResolvesAndVerifies(t *testing.T) {
	_, docs := guestAWSDocs(t)
	rules, _ := guestCorefile(t, docs)
	shimSANs := certSANs(t, docs, "Certificate/aws-shim-aws-endpoints-tls")
	regSANs := certSANs(t, docs, "Certificate/ecr-registry-aws-endpoints-tls")

	var regions []string
	for _, s := range shimSANs {
		if r, ok := strings.CutSuffix(strings.TrimPrefix(s, "*."), ".amazonaws.com"); ok && regionLabel.MatchString(r) {
			regions = append(regions, r)
		}
	}
	if len(regions) < 30 || !covers(shimSANs, "sqs.us-east-1.amazonaws.com") {
		t.Fatalf("the shim's certificate must list the AWS regions (found %d: %v)", len(regions), regions)
	}

	for _, svc := range registeredShimServices(t) {
		forms, ok := servedHostForms[svc]
		if !ok {
			t.Errorf("main.go registers %q, which servedHostForms does not name: decide its amazonaws.com names, cover them in %s (resolver + certificate), and add them here", svc, guestAWSPath)
			continue
		}
		for _, f := range forms {
			for _, r := range regions {
				host := strings.ReplaceAll(f, "{r}", r) + ".amazonaws.com"
				if got := resolveVia(rules, host); got != shimTarget {
					t.Errorf("%s (%s): the guest resolver answers %q, want the shim (%s)", host, svc, got, shimTarget)
				}
				if !covers(shimSANs, host) {
					t.Errorf("%s (%s): not covered by aws-shim-aws-endpoints-tls", host, svc)
				}
				if !strings.Contains(f, "{r}") {
					break // a global name: once
				}
			}
		}
	}

	for _, r := range regions {
		host := "123456789012.dkr.ecr." + r + ".amazonaws.com"
		if got := resolveVia(rules, host); got != registryTarget {
			t.Errorf("%s: answered %q, want the guest registry (%s)", host, got, registryTarget)
		}
		if !covers(regSANs, host) {
			t.Errorf("%s: not covered by ecr-registry-aws-endpoints-tls", host)
		}
	}

	internal := mustRead(t, "../../platform/aws-shim/aws-shim.yaml")
	for _, host := range []string{"examplebucket.aws-shim.open-infra-aws-shim.svc.cluster.local", "examplebucket.aws-shim.open-infra-aws-shim.svc"} {
		if got := resolveVia(rules, host); got != shimTarget {
			t.Errorf("%s: answered %q, want the shim", host, got)
		}
		wild := `"*.` + strings.SplitN(host, ".", 2)[1] + `"`
		if !strings.Contains(internal, "- "+wild) {
			t.Errorf("the shim's internal certificate must cover %s (dnsName %s)", host, wild)
		}
	}
	if !strings.Contains(internal, `S3_INTERNAL_VHOST_SUFFIXES, value: "aws-shim.open-infra-aws-shim.svc.cluster.local,aws-shim.open-infra-aws-shim.svc"`) {
		t.Error("the shim must take <bucket>.<its own name> as virtual-hosted S3 (S3_INTERNAL_VHOST_SUFFIXES)")
	}
}

// Every name the shim does not serve resolves as it always did (forwarded, unchanged): another AWS
// service, the AWS CLI's download host, S3's website and dualstack names, other partitions, other
// namespaces' services, any other domain.
func TestGuestAWSEndpoints_OtherNamesAreForwarded(t *testing.T) {
	_, docs := guestAWSDocs(t)
	rules, corefile := guestCorefile(t, docs)
	for _, host := range []string{
		"awscli.amazonaws.com", "ssmmessages.us-east-1.amazonaws.com",
		"ec2messages.us-east-1.amazonaws.com", "elasticloadbalancing.us-east-1.amazonaws.com",
		"examplebucket.s3-website-us-east-1.amazonaws.com", "s3.dualstack.us-east-1.amazonaws.com",
		"sqs.cn-north-1.amazonaws.com.cn", "notsqs.us-east-1.amazonaws.com", "sqs.us-east-1.amazonaws.com.example.com",
		"examplebucket.aws-shim.other-ns.svc.cluster.local", "aws-shim.open-infra-aws-shim.svc.cluster.local",
		"kubernetes.default.svc.cluster.local", "example.com",
	} {
		if got := resolveVia(rules, host); got != "" {
			t.Errorf("%s must be forwarded unchanged, but the resolver answers it with %s", host, got)
		}
	}
	for _, want := range []string{"forward . /etc/resolv.conf", "loop"} {
		if !strings.Contains(corefile, want) {
			t.Errorf("the guest resolver must forward everything else to the cluster DNS (%q)", want)
		}
	}
	dep := mustDoc(t, docs, "Deployment/openinfra-guest-dns")
	if got := dep["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["dnsPolicy"]; got != "ClusterFirst" {
		t.Errorf("the resolver's own resolv.conf must be the cluster DNS (dnsPolicy ClusterFirst), got %v", got)
	}
}

// The resolver guests are pointed at is the one this file runs: the EnvironmentConfig names the Service's
// fixed address. It runs in kube-system on port 53, which a security group's egress always allows, from
// a digest-pinned image.
func TestGuestAWSEndpoints_ResolverAddress(t *testing.T) {
	raw, docs := guestAWSDocs(t)
	svc := mustDoc(t, docs, "Service/openinfra-guest-dns")
	ec := mustDoc(t, docs, "EnvironmentConfig/openinfra-guest-dns")
	ip := svc["spec"].(map[string]any)["clusterIP"]
	if ns := ec["data"].(map[string]any)["guestNameserver"]; ip == nil || ns != ip {
		t.Fatalf("the EnvironmentConfig's guestNameserver (%v) must be the Service's clusterIP (%v)", ns, ip)
	}
	if svc["metadata"].(map[string]any)["namespace"] != "kube-system" {
		t.Error("the resolver must be in kube-system: a security group's egress rules allow DNS there only")
	}
	for _, want := range []string{"{ name: dns, port: 53, targetPort: 53, protocol: UDP }", "{ name: dns-tcp, port: 53, targetPort: 53, protocol: TCP }",
		"{ name: dns, containerPort: 53, protocol: UDP }", "{ name: dns-tcp, containerPort: 53, protocol: TCP }"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the resolver must serve DNS on port 53, UDP and TCP (%s)", want)
		}
	}
	for _, m := range regexp.MustCompile(`(?m)^\s+image: (\S+)`).FindAllStringSubmatch(raw, -1) {
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(m[1]) {
			t.Errorf("image %s must be pinned by digest", m[1])
		}
	}
}

// The AWS endpoints CA vouches for AWS's names only, and signs only in the aws-shim's and the
// registry's namespaces; the platform root (which LAN clients trust) never signs an AWS name.
func TestGuestAWSEndpoints_CAIsGuestOnlyAndConstrained(t *testing.T) {
	raw, docs := guestAWSDocs(t)
	ca := mustDoc(t, docs, "Certificate/openinfra-aws-endpoints-ca")
	spec := ca["spec"].(map[string]any)
	nc := spec["nameConstraints"].(map[string]any)
	if spec["isCA"] != "true" || nc["critical"] != "true" {
		t.Fatalf("the AWS endpoints CA must be a CA with critical name constraints: %v", spec)
	}
	if got := strList(nc["permitted"].(map[string]any)["dnsDomains"]); len(got) != 1 || got[0] != "amazonaws.com" {
		t.Fatalf("the AWS endpoints CA must be constrained to amazonaws.com, got %v", got)
	}
	iss := mustDoc(t, docs, "ClusterIssuer/openinfra-aws-endpoints")
	if iss["spec"].(map[string]any)["ca"].(map[string]any)["secretName"] != spec["secretName"] {
		t.Error("the ClusterIssuer must sign with the CA's own Secret")
	}
	for _, c := range []string{"Certificate/aws-shim-aws-endpoints-tls", "Certificate/ecr-registry-aws-endpoints-tls"} {
		ref := mustDoc(t, docs, c)["spec"].(map[string]any)["issuerRef"].(map[string]any)
		if ref["name"] != "openinfra-aws-endpoints" || ref["kind"] != "ClusterIssuer" {
			t.Errorf("%s must be issued by the openinfra-aws-endpoints ClusterIssuer, got %v", c, ref)
		}
	}
	for _, want := range []string{"values: [open-infra-aws-shim, open-infra-ecr]", "object.spec.issuerRef.name == 'openinfra-aws-endpoints'",
		"object.spec.signerName != 'clusterissuers.cert-manager.io/openinfra-aws-endpoints'"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the admission policy must confine the issuer to the shim's and the registry's namespaces (%q)", want)
		}
	}
	// Nothing the platform root issues names an AWS host.
	for _, path := range []string{"../../platform/aws-shim/aws-shim.yaml", "../../platform/aws-shim/ecr-registry.yaml", "../../platform/networking/cluster-ca.yaml"} {
		if strings.Contains(mustRead(t, path), "amazonaws.com\"") {
			t.Errorf("%s must not put an amazonaws.com name on a platform-root certificate", path)
		}
	}
}

// The shim serves the AWS names on its own listener (Service 443 -> 8443) with the guest-only
// certificate; the guest registry serves TLS itself, its token realm the shim's in-cluster TLS port.
func TestGuestAWSEndpoints_ShimAndRegistryServeTheNames(t *testing.T) {
	shim := mustRead(t, "../../platform/aws-shim/aws-shim.yaml")
	for _, want := range []string{
		"- name: https-aws\n      port: 443\n      targetPort: 8443",
		`TLS_LISTEN_ADDR, value: ":8443"`, "TLS_CERT_FILE, value: /tls-aws/tls.crt", "TLS_KEY_FILE, value: /tls-aws/tls.key",
		"secret: { secretName: aws-shim-aws-endpoints-tls, optional: true }",
	} {
		if !strings.Contains(shim, want) {
			t.Errorf("aws-shim.yaml must serve the AWS names on its AWS-names listener (missing %q)", want)
		}
	}
	raw, docs := guestAWSDocs(t)
	svc := mustDoc(t, docs, "Service/ecr-registry-aws")
	if svc["metadata"].(map[string]any)["namespace"] != "open-infra-ecr" || !strings.Contains(raw, "{ name: https, port: 443, targetPort: https }") {
		t.Error("the guest registry must be ecr-registry-aws in open-infra-ecr, on port 443")
	}
	for _, want := range []string{"REGISTRY_HTTP_TLS_CERTIFICATE, value: /tls/tls.crt", "REGISTRY_HTTP_TLS_KEY, value: /tls/tls.key",
		`REGISTRY_AUTH_TOKEN_REALM, value: "https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567/ecr/token"`,
		"secret: { secretName: ecr-registry-aws-endpoints-tls }", "httpGet: { path: /, port: https, scheme: HTTPS }"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the guest registry must serve TLS with its AWS-names certificate (missing %q)", want)
		}
	}
	install := mustRead(t, "../../install.sh")
	for _, want := range []string{`if [ "$(yget networking.guestAwsEndpoints)" = "false" ]; then`, `EXCLUDES="${EXCLUDES},aws-shim/guest-aws-endpoints.yaml,aws-shim/guest-aws-endpoints-ca.yaml"`} {
		if !strings.Contains(install, want) {
			t.Errorf("install.sh must exclude the guest AWS endpoints under networking.guestAwsEndpoints: false (missing %q)", want)
		}
	}
}

func withGuestEnv(ctx map[string]any, env map[string]any) map[string]any {
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": env}
	return ctx
}

// renderedVMISpec is the rendered VirtualMachine's spec.template.spec (the VMI spec).
func renderedVMISpec(t *testing.T, out string) map[string]any {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		m, _ := d["spec"].(map[string]any)
		fp, _ := m["forProvider"].(map[string]any)
		man, _ := fp["manifest"].(map[string]any)
		if man["kind"] != "VirtualMachine" {
			continue
		}
		return man["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	}
	t.Fatal("no VirtualMachine rendered")
	return nil
}

func vmiSpecBlock(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "kind: VirtualMachine\n")
	if i < 0 {
		t.Fatalf("no VirtualMachine rendered")
	}
	return out[i:]
}

// A Linux guest uses the guest resolver when the platform has one (its VMI's dnsConfig, under the usual
// search domains), and trusts the AWS endpoints CA as a second anchor; without them, nothing changes.
// Windows guests run no agent and keep the cluster DNS.
func TestVM_GuestResolverAndAWSEndpointsCA(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	env := map[string]any{"platformRootCA": testRootPEM, "awsEndpointsCA": testRootPEM, "guestNameserver": "10.43.0.53"}
	with := render(t, tmpl, withGuestEnv(vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"}), env))
	vmiSpec := renderedVMISpec(t, with)
	if vmiSpec["dnsPolicy"] != "None" {
		t.Errorf("with a guest resolver the VMI's dnsPolicy must be None, got %v:\n%s", vmiSpec["dnsPolicy"], grepCtx(vmiSpecBlock(t, with), "dns"))
	}
	dc, _ := vmiSpec["dnsConfig"].(map[string]any)
	if dc == nil || fmt.Sprint(dc["nameservers"]) != "[10.43.0.53]" ||
		fmt.Sprint(dc["searches"]) != "[default.svc.cluster.local svc.cluster.local cluster.local]" ||
		!strings.Contains(fmt.Sprint(dc["options"]), "name:ndots") {
		t.Errorf("the VMI's dnsConfig must name the guest resolver under the usual search domains, got %v", dc)
	}
	if got := vmWriteFileScalar(t, with, "/etc/openinfra/aws-endpoints-ca.pem"); got != testRootPEM {
		t.Errorf("the cloud-init must write the AWS endpoints CA from the environment; got %q", got)
	}
	if cfg := vmAgentConfig(t, with); cfg["awsEndpointsCaFile"] != "/etc/openinfra/aws-endpoints-ca.pem" {
		t.Errorf("agent awsEndpointsCaFile = %#v", cfg["awsEndpointsCaFile"])
	}

	without := render(t, tmpl, withPlatformCA(vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"})))
	if strings.Contains(without, "dnsPolicy") || strings.Contains(without, "aws-endpoints-ca.pem\n") ||
		strings.Contains(without, "- path: /etc/openinfra/aws-endpoints-ca.pem") {
		t.Errorf("without a guest resolver or CA nothing changes:\n%s", grepCtx(without, "dnsPolicy"))
	}

	win := render(t, tmpl, withGuestEnv(vmCtx("windows-server-2022", ""), env))
	if strings.Contains(win, "dnsPolicy") {
		t.Errorf("Windows guests keep the cluster DNS:\n%s", grepCtx(win, "dnsPolicy"))
	}

	raw := mustRead(t, vmComposition)
	if !strings.Contains(raw, "name: openinfra-guest-dns") {
		t.Error("vm-composition.yaml must read the openinfra-guest-dns EnvironmentConfig (Optional environment step)")
	}
}
