package main

// The VPC resolver answers tasks in an account's default VPC too, as Route 53 Resolver (AmazonProvidedDNS)
// serves every VPC: a query from an address in an account's default subnet (ec2_default_vpc.go) is that
// account's, in its default VPC, so the DNS Firewall rule groups associated with that VPC apply to it and its
// queries are logged to that VPC's query log configurations. A task in a default subnet sends its DNS here
// (the Application composition's dnsConfig); in a default VPC without its internet gateway, the subnet's
// network ACL drops DNS to anywhere else, so the firewall cannot be gone around. A default VPC that keeps its
// internet gateway (the subnet's natOutgoing) is one whose senders reach the internet: an amazonaws.com name the
// platform does not serve resolves for them as any other public name (vpcresolver.go).

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

const defaultVPCSendersRefresh = 30 * time.Second

// defaultVPCSenders names a query's sender in an account's default VPC by the default subnet that holds its
// address. The default subnets are read with the shim's client and refreshed every half minute.
type defaultVPCSenders struct {
	dyn  dynamic.Interface
	mgmt string // the install's account: the default subnet named default-vpc is its

	mu   sync.Mutex
	nets []defaultNet
	read time.Time
}

type defaultNet struct {
	ipnet    *net.IPNet
	account  string
	internet bool // the subnet has its internet gateway (natOutgoing)
}

func newDefaultVPCSenders(dyn dynamic.Interface) *defaultVPCSenders {
	return &defaultVPCSenders{dyn: dyn, mgmt: awsidentity.Current().AccountID}
}

// At is the default-VPC interface that held ip: its account, VPC and subnet.
func (d *defaultVPCSenders) At(ip string, t time.Time) (vpcInterface, bool) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return vpcInterface{}, false
	}
	for _, n := range d.subnets(t) {
		if n.ipnet.Contains(addr) {
			v := &defaultVPC{account: n.account}
			return vpcInterface{IP: ip, Account: n.account, VpcID: v.vpcID(), SubnetID: v.subnetID(),
				SubnetIDs: []string{v.subnetID()}, Internet: n.internet}, true
		}
	}
	return vpcInterface{}, false
}

// Ready: the default subnets are read on demand, so a sender is never waited for.
func (d *defaultVPCSenders) Ready() bool { return true }

func (d *defaultVPCSenders) subnets(t time.Time) []defaultNet {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.read.IsZero() && t.Sub(d.read) < defaultVPCSendersRefresh {
		return d.nets
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := d.dyn.Resource(kubeovnSubnetGVR).List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/default-vpc=true"})
	if err != nil {
		return d.nets // keep the last known until the next read
	}
	d.nets = defaultNetsOf(list.Items, d.mgmt)
	d.read = t
	return d.nets
}

// defaultNetsOf are the default subnets among items, each with its account: a member account's subnet carries
// openinfra.dev/account-id; the one named default-vpc is the management account's.
func defaultNetsOf(items []unstructured.Unstructured, mgmt string) []defaultNet {
	var out []defaultNet
	for i := range items {
		u := &items[i]
		cidr, _, _ := unstructured.NestedString(u.Object, "spec", "cidrBlock")
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		account := u.GetLabels()["openinfra.dev/account-id"]
		if u.GetName() == "default-vpc" {
			account = mgmt
		}
		if account == "" {
			continue
		}
		internet, _, _ := unstructured.NestedBool(u.Object, "spec", "natOutgoing")
		out = append(out, defaultNet{ipnet: ipnet, account: account, internet: internet})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ipnet.String() < out[j].ipnet.String() })
	return out
}

// eitherClients names a sender by the first of its sources that knows it: a Lambda VPC function's interface,
// else a default VPC's address.
type eitherClients []vpcClients

func (e eitherClients) At(ip string, t time.Time) (vpcInterface, bool) {
	for _, c := range e {
		if c == nil {
			continue
		}
		if in, ok := c.At(ip, t); ok {
			return in, true
		}
	}
	return vpcInterface{}, false
}

func (e eitherClients) Ready() bool {
	for _, c := range e {
		if c != nil && !c.Ready() {
			return false
		}
	}
	return true
}
