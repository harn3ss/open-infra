package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	elbTestShimNS = "shim-ns"
	elbGameID     = "i-0aaaaaaaaaaaaaaa1"
	elbIdleID     = "i-0bbbbbbbbbbbbbbb2"
)

// elbVMI is instance name's VirtualMachineInstance in the member's home: running at ip on node (phase
// Running), or stopped (ip "").
func elbVMI(name, ip, node string) *unstructured.Unstructured {
	st := map[string]any{"phase": "Succeeded"}
	if ip != "" {
		st = map[string]any{"phase": "Running", "nodeName": node, "interfaces": []any{map[string]any{"name": "default", "ipAddress": ip}}}
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
		"metadata": map[string]any{"name": name, "namespace": memberHome}, "status": st}}
}

// elbFixture: a member account whose default VPC has no internet gateway and, with public, a public subnet
// (172.31.240.0/24); its instances game (running at 172.31.16.7 on node-b) and idle (stopped), both in its
// default subnet. IAM policy decides (enforce): bob may do anything, carol (no policy) nothing, and docs add
// more principals.
func elbFixture(t *testing.T, public bool, docs ...dataplaneauthz.PolicyDoc) (*elbHandler, *fake.Clientset) {
	t.Helper()
	sub := kubeovnSubnet("default-vpc-"+testMember, "172.31.16.0/20", 4090)
	sub.Object["spec"].(map[string]any)["natOutgoing"] = false
	dv := map[string]any{"subnetCidr": "172.31.16.0/20", "internetGateway": false}
	if public {
		dv["publicSubnet"] = map[string]any{"subnetCidr": "172.31.240.0/24"}
	}
	acct := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account",
		"metadata": map[string]any{"name": testMember}, "spec": map[string]any{"defaultVpc": dv}}}
	objs := []runtime.Object{sub, acct,
		inNS(ec2Obj("VirtualMachine", "game", map[string]any{"os": "ubuntu-24.04", "subnet": "default-vpc-" + testMember},
			map[string]any{"instanceId": elbGameID, "ip": "172.31.16.7", "powerState": "Running"}, nil), memberHome),
		inNS(ec2Obj("VirtualMachine", "idle", map[string]any{"os": "ubuntu-24.04", "subnet": "default-vpc-" + testMember, "running": false},
			map[string]any{"instanceId": elbIdleID, "powerState": "Stopped"}, nil), memberHome),
		elbVMI("game", "172.31.16.7", "node-b"),
	}
	ec2H, _ := ec2Fixture(t, objs...)
	all := []policyengine.Statement{dpAllow([]string{"*"}, "*")}
	docs = append(docs, dataplaneauthz.PolicyDoc{Name: "bob-all", AppliesTo: []string{"User::" + memberHome + "/bob"}, Statements: all},
		dataplaneauthz.PolicyDoc{Name: "alice-all", AppliesTo: []string{"User::alice"}, Statements: all})
	ec2H.door.authz = checkerInMode(t, "enforce", docs...)
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: memberHome}})
	return newELBHandler(ec2H, cs, elbTestShimNS, "lb-pool", slog.New(slog.NewTextHandler(io.Discard, nil))), cs
}

var elbCarol = iam.Claims{Sub: "carol", Account: testMember}

// elbDo serves one ELB request as claims, in ctx's account (member: memberCtx).
func elbDo(h *elbHandler, ctx context.Context, claims iam.Claims, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(form.Encode())).WithContext(inAccountScope(ctx))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	return w
}

func elbOK(t *testing.T, what string, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", what, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func elbRefused(t *testing.T, what string, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "<Code>"+code+"</Code>") {
		t.Errorf("%s: want %s, got %d %s", what, code, w.Code, w.Body.String())
	}
}

func xmlField(body, tag string) string {
	m := regexp.MustCompile("<" + tag + ">([^<]*)</" + tag + ">").FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// An internet-facing network load balancer in the public subnet forwards its UDP listener's traffic to the
// instance registered in its target group: a Service in the shim's namespace, taking its address from the
// load-balancer pool, keeping the client's address and opening no node ports, and an EndpointSlice carrying
// the instance's address and node. It is active once it has its address; the target is healthy while its
// instance runs, and drops out of the endpoints when it stops. Deleting the listener and the load balancer
// removes their objects.
func TestELB_NetworkLoadBalancerForwardsToItsTargets(t *testing.T) {
	h, cs := elbFixture(t, true)
	ctx, d := memberCtx(), &defaultVPC{account: testMember}
	bg := context.Background()

	b := elbOK(t, "CreateTargetGroup", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"CreateTargetGroup"}, "Name": {"game"},
		"Protocol": {"UDP"}, "Port": {"27015"}, "VpcId": {d.vpcID()}, "TargetType": {"instance"}}))
	tg := xmlField(b, "TargetGroupArn")
	if !regexp.MustCompile(`^arn:aws:elasticloadbalancing:us-east-1:` + testMember + `:targetgroup/game/[0-9a-f]{16}$`).MatchString(tg) {
		t.Fatalf("a target group ARN as AWS writes it: %q", tg)
	}
	mustHave(t, "the target group", b, []string{"<Protocol>UDP</Protocol>", "<Port>27015</Port>", "<HealthCheckProtocol>TCP</HealthCheckProtocol>",
		"<HealthCheckPort>traffic-port</HealthCheckPort>", "<TargetType>instance</TargetType>", "<LoadBalancerArns/>"}, nil)
	// Idempotent: the same name and settings return the same group.
	if b2 := elbOK(t, "CreateTargetGroup again", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"CreateTargetGroup"}, "Name": {"game"},
		"Protocol": {"UDP"}, "Port": {"27015"}, "VpcId": {d.vpcID()}})); xmlField(b2, "TargetGroupArn") != tg {
		t.Errorf("CreateTargetGroup is idempotent: %s", b2)
	}
	elbOK(t, "RegisterTargets", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"RegisterTargets"}, "TargetGroupArn": {tg},
		"Targets.member.1.Id": {elbGameID}}))

	b = elbOK(t, "CreateLoadBalancer", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"CreateLoadBalancer"}, "Name": {"game-nlb"},
		"Type": {"network"}, "Scheme": {"internet-facing"}, "Subnets.member.1": {d.publicSubnetID()}}))
	lbArn := xmlField(b, "LoadBalancerArn")
	m := regexp.MustCompile(`^arn:aws:elasticloadbalancing:us-east-1:` + testMember + `:loadbalancer/net/game-nlb/([0-9a-f]{16})$`).FindStringSubmatch(lbArn)
	if m == nil {
		t.Fatalf("a load balancer ARN as AWS writes it: %q", lbArn)
	}
	lbID := m[1]
	mustHave(t, "the new load balancer", b, []string{"<Code>provisioning</Code>", "<Type>network</Type>", "<Scheme>internet-facing</Scheme>",
		"<VpcId>" + d.vpcID() + "</VpcId>", "<SubnetId>" + d.publicSubnetID() + "</SubnetId>", "<DNSName>game-nlb-" + lbID + ".elb.us-east-1.amazonaws.com</DNSName>",
		"<CanonicalHostedZoneId>Z26RNL4JYFTOTI</CanonicalHostedZoneId>"}, nil)

	b = elbOK(t, "CreateListener", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"CreateListener"}, "LoadBalancerArn": {lbArn},
		"Protocol": {"UDP"}, "Port": {"27015"}, "DefaultActions.member.1.Type": {"forward"}, "DefaultActions.member.1.TargetGroupArn": {tg}}))
	listener := xmlField(b, "ListenerArn")
	if !strings.HasPrefix(listener, "arn:aws:elasticloadbalancing:us-east-1:"+testMember+":listener/net/game-nlb/"+lbID+"/") {
		t.Fatalf("a listener ARN as AWS writes it: %q", listener)
	}

	svcName := elbServiceName(testMember, lbID)
	svc, err := cs.CoreV1().Services(elbTestShimNS).Get(bg, svcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the load balancer's Service: %v", err)
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer || svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal ||
		svc.Spec.AllocateLoadBalancerNodePorts == nil || *svc.Spec.AllocateLoadBalancerNodePorts || len(svc.Spec.Selector) != 0 ||
		svc.Annotations[elbPoolAnnotation] != "lb-pool" {
		t.Errorf("a LoadBalancer Service keeping the client's address, no node ports, no selector, from the pool: %+v %v", svc.Spec, svc.Annotations)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Protocol != corev1.ProtocolUDP || svc.Spec.Ports[0].Port != 27015 || svc.Spec.Ports[0].Name != "udp-27015" {
		t.Errorf("its listener's port: %+v", svc.Spec.Ports)
	}
	slice, err := cs.DiscoveryV1().EndpointSlices(elbTestShimNS).Get(bg, elbSliceName(svcName, "UDP", 27015, 27015), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the listener's EndpointSlice: %v", err)
	}
	if slice.Labels["kubernetes.io/service-name"] != svcName || len(slice.Endpoints) != 1 || slice.Endpoints[0].Addresses[0] != "172.31.16.7" ||
		slice.Endpoints[0].NodeName == nil || *slice.Endpoints[0].NodeName != "node-b" || !*slice.Endpoints[0].Conditions.Ready ||
		*slice.Ports[0].Port != 27015 || *slice.Ports[0].Protocol != corev1.ProtocolUDP {
		t.Errorf("the instance's address and node, on the target port: %+v", slice)
	}

	// Active once it has its address, which DescribeLoadBalancers reports.
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "198.51.100.40"}}
	if _, err := cs.CoreV1().Services(elbTestShimNS).UpdateStatus(bg, svc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	b = elbOK(t, "DescribeLoadBalancers", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeLoadBalancers"}, "Names.member.1": {"game-nlb"}}))
	mustHave(t, "the active load balancer", b, []string{"<Code>active</Code>", "<IpAddress>198.51.100.40</IpAddress>"}, nil)

	b = elbOK(t, "DescribeTargetHealth", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTargetHealth"}, "TargetGroupArn": {tg}}))
	mustHave(t, "the running target", b, []string{"<Id>" + elbGameID + "</Id>", "<Port>27015</Port>", "<State>healthy</State>", "<HealthCheckPort>27015</HealthCheckPort>"}, nil)
	b = elbOK(t, "DescribeListeners", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeListeners"}, "LoadBalancerArn": {lbArn}}))
	mustHave(t, "its listener", b, []string{"<ListenerArn>" + listener + "</ListenerArn>", "<Protocol>UDP</Protocol>", "<TargetGroupArn>" + tg + "</TargetGroupArn>"}, nil)
	b = elbOK(t, "DescribeTargetGroups by load balancer", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTargetGroups"}, "LoadBalancerArn": {lbArn}}))
	mustHave(t, "its target group", b, []string{"<TargetGroupArn>" + tg + "</TargetGroupArn>", "<LoadBalancerArns><member>" + lbArn + "</member></LoadBalancerArns>"}, nil)

	// A stopped instance is not a target the load balancer forwards to.
	elbOK(t, "RegisterTargets idle", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"RegisterTargets"}, "TargetGroupArn": {tg}, "Targets.member.1.Id": {elbIdleID}}))
	b = elbOK(t, "DescribeTargetHealth idle", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTargetHealth"}, "TargetGroupArn": {tg},
		"Targets.member.1.Id": {elbIdleID}}))
	mustHave(t, "the stopped target", b, []string{"<State>unused</State>", "<Reason>Target.InvalidState</Reason>"}, []string{elbGameID})
	if s, _ := cs.DiscoveryV1().EndpointSlices(elbTestShimNS).Get(bg, elbSliceName(svcName, "UDP", 27015, 27015), metav1.GetOptions{}); len(s.Endpoints) != 1 {
		t.Errorf("only the running instance is an endpoint: %+v", s.Endpoints)
	}
	// When the running one stops too, the pass takes it out.
	if err := h.ec2.door.shimDyn.Resource(vmiGVR).Namespace(memberHome).Delete(bg, "game", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	h.syncAll(bg)
	if s, _ := cs.DiscoveryV1().EndpointSlices(elbTestShimNS).Get(bg, elbSliceName(svcName, "UDP", 27015, 27015), metav1.GetOptions{}); len(s.Endpoints) != 0 {
		t.Errorf("a target with no running instance is no endpoint: %+v", s.Endpoints)
	}

	elbRefused(t, "DeleteTargetGroup in use", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DeleteTargetGroup"}, "TargetGroupArn": {tg}}), "ResourceInUse")
	elbOK(t, "DeleteListener", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DeleteListener"}, "ListenerArn": {listener}}))
	if l, _ := cs.DiscoveryV1().EndpointSlices(elbTestShimNS).List(bg, metav1.ListOptions{}); len(l.Items) != 0 {
		t.Errorf("a deleted listener's endpoints go: %d left", len(l.Items))
	}
	elbOK(t, "DeleteLoadBalancer", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DeleteLoadBalancer"}, "LoadBalancerArn": {lbArn}}))
	if _, err := cs.CoreV1().Services(elbTestShimNS).Get(bg, svcName, metav1.GetOptions{}); err == nil {
		t.Error("a deleted load balancer's Service goes")
	}
	elbOK(t, "DeleteLoadBalancer again (already gone)", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DeleteLoadBalancer"}, "LoadBalancerArn": {lbArn}}))
	elbOK(t, "DeleteTargetGroup", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DeleteTargetGroup"}, "TargetGroupArn": {tg}}))
	b = elbOK(t, "DescribeTargetGroups", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTargetGroups"}}))
	if strings.Contains(b, tg) {
		t.Errorf("a deleted target group is gone: %s", b)
	}
}

// What the platform does not serve is refused in ELB's words, saying so, and what AWS refuses is refused
// as AWS does.
func TestELB_RefusesWhatItDoesNotServe(t *testing.T) {
	h, _ := elbFixture(t, true)
	ctx, d := memberCtx(), &defaultVPC{account: testMember}
	lb := func(extra url.Values) *httptest.ResponseRecorder {
		f := url.Values{"Action": {"CreateLoadBalancer"}, "Name": {"edge"}, "Type": {"network"}, "Subnets.member.1": {d.publicSubnetID()}}
		for k, v := range extra {
			if len(v) == 1 && v[0] == "" {
				delete(f, k) // an empty override leaves the parameter out
				continue
			}
			f[k] = v
		}
		return elbDo(h, ctx, ec2Bob, f)
	}
	elbRefused(t, "no Type (an application load balancer)", lb(url.Values{"Type": {""}}), "ValidationError")
	elbRefused(t, "an internal load balancer", lb(url.Values{"Scheme": {"internal"}}), "ValidationError")
	elbRefused(t, "a load balancer's own security groups", lb(url.Values{"SecurityGroups.member.1": {"sg-1"}}), "ValidationError")
	elbRefused(t, "the default subnet, with no route to the gateway", lb(url.Values{"Subnets.member.1": {d.subnetID()}}), "InvalidSubnet")
	elbRefused(t, "a subnet that is not the account's", lb(url.Values{"Subnets.member.1": {"subnet-0123456789abcdef0"}}), "SubnetNotFound")
	elbRefused(t, "a bad name", lb(url.Values{"Name": {"-edge"}}), "ValidationError")
	elbRefused(t, "an Elastic IP on its subnet mapping", lb(url.Values{"Subnets.member.1": {""}, "SubnetMappings.member.1.SubnetId": {d.publicSubnetID()},
		"SubnetMappings.member.1.AllocationId": {"eipalloc-0123456789abcdef0"}}), "ValidationError")
	b := elbOK(t, "CreateLoadBalancer", lb(nil))
	lbArn := xmlField(b, "LoadBalancerArn")
	elbRefused(t, "the same name, other settings", lb(url.Values{"Subnets.member.1": {""}, "SubnetMappings.member.1.SubnetId": {d.subnetID()}}), "InvalidSubnet")

	tgf := func(extra url.Values) *httptest.ResponseRecorder {
		f := url.Values{"Action": {"CreateTargetGroup"}, "Name": {"tcp"}, "Protocol": {"TCP"}, "Port": {"80"}, "VpcId": {d.vpcID()}}
		for k, v := range extra {
			f[k] = v
		}
		return elbDo(h, ctx, ec2Bob, f)
	}
	elbRefused(t, "a TLS target group", tgf(url.Values{"Protocol": {"TLS"}}), "UnsupportedProtocol")
	elbRefused(t, "an HTTP target group", tgf(url.Values{"Protocol": {"HTTP"}}), "UnsupportedProtocol")
	elbRefused(t, "IP targets", tgf(url.Values{"TargetType": {"ip"}}), "ValidationError")
	elbRefused(t, "another VPC", tgf(url.Values{"VpcId": {"vpc-0123456789abcdef0"}}), "ValidationError")
	elbRefused(t, "a port out of range", tgf(url.Values{"Port": {"70000"}}), "ValidationError")
	tcp := xmlField(elbOK(t, "CreateTargetGroup tcp", tgf(nil)), "TargetGroupArn")
	elbRefused(t, "the same name, other settings", tgf(url.Values{"Port": {"81"}}), "DuplicateTargetGroupName")
	elbRefused(t, "an instance that is not the account's", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"RegisterTargets"}, "TargetGroupArn": {tcp},
		"Targets.member.1.Id": {"i-0ccccccccccccccc3"}}), "InvalidTarget")

	listen := func(proto, port, tg string) *httptest.ResponseRecorder {
		return elbDo(h, ctx, ec2Bob, url.Values{"Action": {"CreateListener"}, "LoadBalancerArn": {lbArn}, "Protocol": {proto}, "Port": {port},
			"DefaultActions.member.1.Type": {"forward"}, "DefaultActions.member.1.TargetGroupArn": {tg}})
	}
	elbRefused(t, "a UDP listener to a TCP target group", listen("UDP", "80", tcp), "IncompatibleProtocols")
	elbRefused(t, "a TLS listener", listen("TLS", "443", tcp), "UnsupportedProtocol")
	first := xmlField(elbOK(t, "CreateListener", listen("TCP", "80", tcp)), "ListenerArn")
	if again := xmlField(elbOK(t, "CreateListener again", listen("TCP", "80", tcp)), "ListenerArn"); again != first {
		t.Errorf("CreateListener is idempotent: %s vs %s", again, first)
	}
	other := xmlField(elbOK(t, "another target group", tgf(url.Values{"Name": {"tcp2"}})), "TargetGroupArn")
	elbRefused(t, "a second listener on the port", listen("TCP", "80", other), "DuplicateListener")
	elbRefused(t, "a fixed-response action", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"CreateListener"}, "LoadBalancerArn": {lbArn},
		"Protocol": {"TCP"}, "Port": {"81"}, "DefaultActions.member.1.Type": {"fixed-response"}}), "ValidationError")
	elbRefused(t, "an operation it does not serve", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"ModifyListener"}}), "InvalidAction")
	elbRefused(t, "an unknown load balancer", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeLoadBalancers"},
		"LoadBalancerArns.member.1": {strings.Replace(lbArn, "/edge/", "/gone/", 1)}}), "LoadBalancerNotFound")

	// Tags: added, described, removed.
	elbOK(t, "AddTags", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"AddTags"}, "ResourceArns.member.1": {lbArn},
		"Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"games"}}))
	b = elbOK(t, "DescribeTags", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTags"}, "ResourceArns.member.1": {lbArn}}))
	mustHave(t, "its tags", b, []string{"<ResourceArn>" + lbArn + "</ResourceArn>", "<Key>team</Key><Value>games</Value>"}, nil)
	elbOK(t, "RemoveTags", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"RemoveTags"}, "ResourceArns.member.1": {lbArn}, "TagKeys.member.1": {"team"}}))
	if b = elbOK(t, "DescribeTags", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTags"}, "ResourceArns.member.1": {lbArn}})); strings.Contains(b, "team") {
		t.Errorf("a removed tag is gone: %s", b)
	}
	b = elbOK(t, "DescribeLoadBalancerAttributes", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeLoadBalancerAttributes"}, "LoadBalancerArn": {lbArn}}))
	mustHave(t, "its attributes", b, []string{"<Key>deletion_protection.enabled</Key><Value>false</Value>"}, nil)
	b = elbOK(t, "DescribeTargetGroupAttributes", elbDo(h, ctx, ec2Bob, url.Values{"Action": {"DescribeTargetGroupAttributes"}, "TargetGroupArn": {tcp}}))
	mustHave(t, "the client's address kept", b, []string{"<Key>preserve_client_ip.enabled</Key><Value>true</Value>"}, nil)
}

// A default VPC with no internet gateway at all has nowhere to put an internet-facing load balancer, as on
// AWS.
func TestELB_NoInternetGatewayNoInternetFacingLoadBalancer(t *testing.T) {
	h, _ := elbFixture(t, false)
	d := &defaultVPC{account: testMember}
	w := elbDo(h, memberCtx(), ec2Bob, url.Values{"Action": {"CreateLoadBalancer"}, "Name": {"edge"}, "Type": {"network"},
		"Subnets.member.1": {d.subnetID()}})
	elbRefused(t, "a VPC without an internet gateway", w, "InvalidSubnet")
	if !strings.Contains(w.Body.String(), "has no internet gateway") {
		t.Errorf("as AWS says it: %s", w.Body.String())
	}
}

// IAM policy decides, on the ARN as AWS writes it: a principal with no policy is refused with AccessDenied;
// a policy allowing CreateLoadBalancer on loadbalancer/net/game-* allows that name and no other; tags given at
// creation need AddTags too; a Describe needs its action on "*". Each account sees its own load balancers.
func TestELB_IAMDecidesOnTheARN(t *testing.T) {
	prefix := "arn:aws:elasticloadbalancing:us-east-1:" + testMember + ":"
	dave := dataplaneauthz.PolicyDoc{Name: "dave-game", AppliesTo: []string{"User::" + memberHome + "/dave"}, Statements: []policyengine.Statement{
		dpAllow([]string{"elasticloadbalancing:CreateLoadBalancer"}, "ARN::"+prefix+"loadbalancer/net/game-*/*"),
		dpAllow([]string{"elasticloadbalancing:Describe*"}, "*")}}
	h, _ := elbFixture(t, true, dave)
	ctx, d := memberCtx(), &defaultVPC{account: testMember}
	daveC := iam.Claims{Sub: "dave", Account: testMember}
	create := func(c iam.Claims, name string, extra url.Values) *httptest.ResponseRecorder {
		f := url.Values{"Action": {"CreateLoadBalancer"}, "Name": {name}, "Type": {"network"}, "Subnets.member.1": {d.publicSubnetID()}}
		for k, v := range extra {
			f[k] = v
		}
		return elbDo(h, ctx, c, f)
	}

	w := create(elbCarol, "game-1", nil)
	elbRefused(t, "a principal with no policy", w, "AccessDenied")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "elasticloadbalancing:CreateLoadBalancer on resource: "+prefix+"loadbalancer/net/game-1/") {
		t.Errorf("AWS's access-denied, naming the action and the ARN: %d %s", w.Code, w.Body.String())
	}
	elbRefused(t, "a Describe with no policy", elbDo(h, ctx, elbCarol, url.Values{"Action": {"DescribeLoadBalancers"}}), "AccessDenied")

	elbOK(t, "a name the policy's ARN allows", create(daveC, "game-1", nil))
	elbRefused(t, "a name it does not", create(daveC, "other-1", nil), "AccessDenied")
	elbRefused(t, "tags at creation without AddTags", create(daveC, "game-2", url.Values{"Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"x"}}), "AccessDenied")
	b := elbOK(t, "DescribeLoadBalancers", elbDo(h, ctx, daveC, url.Values{"Action": {"DescribeLoadBalancers"}}))
	mustHave(t, "the member's load balancer", b, []string{"<LoadBalancerName>game-1</LoadBalancerName>"}, []string{"other-1", "game-2"})
	elbRefused(t, "deleting without DeleteLoadBalancer", elbDo(h, ctx, daveC, url.Values{"Action": {"DeleteLoadBalancer"},
		"LoadBalancerArn": {xmlField(b, "LoadBalancerArn")}}), "AccessDenied")

	// The management account's are its own: it sees none of the member's.
	b = elbOK(t, "management DescribeLoadBalancers", elbDo(h, context.Background(), ec2Alice, url.Values{"Action": {"DescribeLoadBalancers"}}))
	if strings.Contains(b, "game-1") {
		t.Errorf("another account's load balancer is not the management account's: %s", b)
	}
}
