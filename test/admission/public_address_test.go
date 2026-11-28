package admission

import (
	"strings"
	"testing"
)

// openinfra-public-address-needs-internet-gateway: an instance in a default VPC without its internet gateway
// gets no public address (spec.expose, spec.ports, spec.elasticIp), as EC2 refuses an Elastic IP there
// (Gateway.NotAttached). The namespace's openinfra.dev/internet-gateway label says which VPC it is in.

const (
	addrPolicyPath = "../../platform/abstraction/account-composition.yaml"
	addrPolicyName = "openinfra-public-address-needs-internet-gateway"
	addrAccount    = "111122223333"
	addrNS         = "team-a"
)

func addrNamespace(igw string) map[string]any {
	labels := map[string]any{"openinfra.dev/account-id": addrAccount}
	if igw != "" {
		labels["openinfra.dev/internet-gateway"] = igw
	}
	return map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": addrNS, "labels": labels}}
}

func instance(spec map[string]any) map[string]any {
	s := map[string]any{"os": "ubuntu-24.04", "expose": false}
	for k, v := range spec {
		s[k] = v
	}
	return map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "VirtualMachine",
		"metadata": map[string]any{"name": "web", "namespace": addrNS}, "spec": s}
}

func addrAdmit(t *testing.T, r Request) Verdict {
	t.Helper()
	p, err := Load(addrPolicyPath, addrPolicyName)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Admit(r)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPublicAddress_RefusedAtLaunchWithoutAnInternetGateway(t *testing.T) {
	for name, spec := range map[string]map[string]any{
		"exposed":                        {"expose": true},
		"with ports":                     {"ports": []any{map[string]any{"port": int64(80)}}},
		"with an Elastic IP":             {"expose": true, "elasticIp": map[string]any{"allocationId": "eipalloc-0123456789abcdef0"}},
		"in the default subnet, exposed": {"expose": true, "subnet": "default-vpc-" + addrAccount},
	} {
		r := create(addrNS, "alice", instance(spec))
		r.NamespaceObject = addrNamespace("false")
		v := addrAdmit(t, r)
		if v.Allowed() {
			t.Errorf("%s: launched with a public address in a VPC without an internet gateway", name)
			continue
		}
		for _, want := range []string{"Gateway.NotAttached", "account " + addrAccount, "instance web", "network load balancer"} {
			if !strings.Contains(v.Denied, want) {
				t.Errorf("%s: refusal %q does not say %q", name, v.Denied, want)
			}
		}
	}
}

func TestPublicAddress_UpdateThatAddsOneIsRefused(t *testing.T) {
	r := update(addrNS, "alice", instance(nil), instance(map[string]any{"expose": true}))
	r.NamespaceObject = addrNamespace("false")
	if addrAdmit(t, r).Allowed() {
		t.Error("an update gave an instance a public address in a VPC without an internet gateway")
	}
}

func TestPublicAddress_WhatIsAllowed(t *testing.T) {
	cases := map[string]Request{}

	r := create(addrNS, "alice", instance(nil))
	r.NamespaceObject = addrNamespace("false")
	cases["an instance with no public address"] = r

	r = create(addrNS, "alice", instance(map[string]any{"expose": true}))
	r.NamespaceObject = addrNamespace("true")
	cases["a public address in a VPC with its internet gateway"] = r

	r = create(addrNS, "alice", instance(map[string]any{"expose": true}))
	r.NamespaceObject = addrNamespace("")
	cases["a namespace that says nothing of its VPC (the management account's)"] = r

	r = create(addrNS, "alice", instance(map[string]any{"expose": true, "subnet": "stack-vpc-public-a"}))
	r.NamespaceObject = addrNamespace("false")
	cases["an instance in a stack's own VPC"] = r

	old := instance(map[string]any{"ports": []any{map[string]any{"port": int64(80)}}})
	r = update(addrNS, "crossplane", old, instance(map[string]any{"ports": []any{map[string]any{"port": int64(80)}}, "cpu": int64(4)}))
	r.NamespaceObject = addrNamespace("false")
	cases["an instance that already had one keeps it"] = r

	for name, r := range cases {
		if v := addrAdmit(t, r); !v.Allowed() {
			t.Errorf("%s: refused: %s", name, v.Denied)
		}
	}
}

// An instance in a default VPC's private subnet gets no public address whatever the VPC has: the subnet's
// route table sends only its NAT gateway routes out. Another account's private subnet is not this one's, and
// an instance that already has an address keeps it.
func TestPublicAddress_RefusedInThePrivateSubnet(t *testing.T) {
	for _, igw := range []string{"true", "false", ""} {
		r := create(addrNS, "alice", instance(map[string]any{"expose": true, "subnet": "default-vpc-" + addrAccount + "-private"}))
		r.NamespaceObject = addrNamespace(igw)
		v := addrAdmit(t, r)
		if v.Allowed() {
			t.Errorf("internet gateway %q: launched with a public address in the private subnet", igw)
			continue
		}
		if !strings.Contains(v.Denied, "Gateway.NotAttached") || !strings.Contains(v.Denied, "routes nothing to an internet gateway") {
			t.Errorf("internet gateway %q: refusal %q", igw, v.Denied)
		}
	}
	r := create(addrNS, "alice", instance(map[string]any{"subnet": "default-vpc-" + addrAccount + "-private"}))
	r.NamespaceObject = addrNamespace("true")
	if v := addrAdmit(t, r); !v.Allowed() {
		t.Errorf("an instance with no public address is refused in the private subnet: %s", v.Denied)
	}
	r = create(addrNS, "alice", instance(map[string]any{"expose": true, "subnet": "default-vpc-999988887777-private"}))
	r.NamespaceObject = addrNamespace("true")
	if v := addrAdmit(t, r); !v.Allowed() {
		t.Errorf("another account's subnet name is refused as this one's: %s", v.Denied)
	}
}
