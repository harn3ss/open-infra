package main

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func defaultSubnetObj(name, cidr, account string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kubeovn.io/v1", "kind": "Subnet",
		"metadata": map[string]any{"name": name}, "spec": map[string]any{"cidrBlock": cidr}}}
	labels := map[string]string{"openinfra.dev/default-vpc": "true"}
	if account != "" {
		labels["openinfra.dev/account-id"] = account
	}
	u.SetLabels(labels)
	return u
}

// A query from an address in an account's default subnet is that account's, in its default VPC: the
// management account's default-vpc, a member's default-vpc-<account>; any other address is no default VPC's.
func TestDefaultVPCSenders_NameTheAccountsDefaultVPC(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{kubeovnSubnetGVR: "SubnetList"},
		defaultSubnetObj("default-vpc", "172.31.0.0/20", ""), defaultSubnetObj("default-vpc-111122223333", "172.31.16.0/20", "111122223333"))
	d := newDefaultVPCSenders(dyn)
	now := time.Now()
	in, ok := d.At("172.31.16.9", now)
	member := &defaultVPC{account: "111122223333"}
	if !ok || in.Account != "111122223333" || in.VpcID != member.vpcID() || in.SubnetID != member.subnetID() {
		t.Fatalf("a member's default-subnet address = %+v %v", in, ok)
	}
	if in, ok := d.At("172.31.0.7", now); !ok || in.Account != d.mgmt {
		t.Fatalf("the management account's default-subnet address = %+v %v", in, ok)
	}
	if _, ok := d.At("10.16.0.5", now); ok {
		t.Fatal("a pod-network address is no default VPC's")
	}
	// A Lambda VPC interface still comes first.
	both := eitherClients{fakeClients{ready: true, by: map[string]vpcInterface{"172.31.16.9": {Account: "x", Function: "fn"}}}, d}
	if in, _ := both.At("172.31.16.9", now); in.Function != "fn" {
		t.Fatalf("the first source to know a sender names it: %+v", in)
	}
}

// A task in a default VPC gets the DNS Firewall associated with that VPC: an allowed name resolves, any
// other is answered NXDOMAIN and never forwarded.
func TestVPCResolver_DefaultVPCFirewall(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{kubeovnSubnetGVR: "SubnetList"},
		defaultSubnetObj("default-vpc-111122223333", "172.31.16.0/20", "111122223333"))
	f := newResolverFixture(t, vpcResolverConfig{})
	vpc := (&defaultVPC{account: "111122223333"}).vpcID()
	f.configs.mu.Lock()
	f.configs.cfgs["111122223333/"+vpc] = firewallOf("", fwRule("platform", 101, 100, "ALLOW", "*.cluster.local"), fwRule("platform", 101, 200, "BLOCK", "*"))
	f.configs.mu.Unlock()
	f.res.clients = eitherClients{f.res.clients, newDefaultVPCSenders(dyn)}
	task := "172.31.16.4"
	if m := f.ask(t, task, "aws-shim.open-infra-aws-shim.svc.cluster.local.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("a platform name = %+v", m.Header)
	}
	if m := f.ask(t, task, "example.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeNameError || f.up.asked("example.com.") != 0 {
		t.Errorf("an outside name must be NXDOMAIN and never forwarded: %+v (asked %d)", m.Header, f.up.asked("example.com."))
	}
	if m := f.ask(t, "10.99.0.1", "example.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeRefused {
		t.Errorf("an address in no VPC is refused: %+v", m.Header)
	}
}

// An amazonaws.com name the platform does not serve, such as awscli.amazonaws.com (where the AWS CLI is
// downloaded from): a default VPC with its internet gateway resolves it upstream as any public name, as AWS's
// resolver does; one without its gateway is answered NXDOMAIN at once and the name is never forwarded. The names
// of the services the platform serves are the platform's for both.
func TestVPCResolver_DefaultVPCAWSNamesFollowTheInternetGateway(t *testing.T) {
	withGateway := defaultSubnetObj("default-vpc-111122223333", "172.31.16.0/20", "111122223333")
	withGateway.Object["spec"].(map[string]any)["natOutgoing"] = true
	withoutGateway := defaultSubnetObj("default-vpc-444455556666", "172.31.32.0/20", "444455556666")
	withoutGateway.Object["spec"].(map[string]any)["natOutgoing"] = false
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{kubeovnSubnetGVR: "SubnetList"}, withGateway, withoutGateway)
	f := newResolverFixture(t, vpcResolverConfig{})
	f.res.awsNames = true
	f.res.clients = eitherClients{f.res.clients, newDefaultVPCSenders(dyn)}
	open, closed := "172.31.16.4", "172.31.32.4"

	if m := f.ask(t, closed, "awscli.amazonaws.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeNameError ||
		f.up.asked("awscli.amazonaws.com.") != 0 {
		t.Errorf("without an internet gateway: %v, forwarded %d times; want NXDOMAIN, never forwarded",
			m.Header.RCode, f.up.asked("awscli.amazonaws.com."))
	}
	if m := f.ask(t, open, "awscli.amazonaws.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeSuccess ||
		f.up.asked("awscli.amazonaws.com.") != 1 {
		t.Errorf("with an internet gateway: %v, forwarded %d times; want the public answer",
			m.Header.RCode, f.up.asked("awscli.amazonaws.com."))
	}
	for _, src := range []string{open, closed} {
		if got := aRecordsOf(f.ask(t, src, "sqs.us-east-1.amazonaws.com.", dnsmessage.TypeA, "UDP")); len(got) != 1 ||
			got[0] != "sqs.us-east-1.amazonaws.com.=192.0.2.1" {
			t.Errorf("%s: a served name answered %v, want the platform's address", src, got)
		}
	}
	if n := f.up.asked("sqs.us-east-1.amazonaws.com."); n != 0 {
		t.Errorf("a served name was forwarded %d times", n)
	}
}
