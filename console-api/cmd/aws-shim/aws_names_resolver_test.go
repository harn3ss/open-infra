package main

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A function in a VPC resolves AWS's own hostnames as the platform serves them (#335): through its VPC's Route
// 53 Resolver, after the VPC's DNS Firewall.

func aRecordsOf(m dnsmessage.Message) []string {
	var out []string
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			out = append(out, a.Header.Name.String()+"="+net.IP(r.A[:]).String())
		}
	}
	return out
}

func TestVPCResolver_AWSNamesReachThePlatform(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	f.res.awsNames = true
	for _, name := range []string{"dynamodb.us-east-1.amazonaws.com.", "states.eu-west-1.amazonaws.com.",
		"my-bucket.s3.amazonaws.com.", "my-bucket.s3.us-east-1.amazonaws.com.", "sts.amazonaws.com.", "DynamoDB.US-East-1.amazonaws.com."} {
		m := f.query(t, name)
		if m.Header.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("%s: %v", name, m.Header.RCode)
		}
		if got := aRecordsOf(m); len(got) != 1 || got[0] != name+"=192.0.2.1" {
			t.Errorf("%s answered %v, want the platform's address under the asked name", name, got)
		}
		if n := f.up.asked(name); n != 0 {
			t.Errorf("%s was sent upstream %d times: an AWS name the platform serves never leaves it", name, n)
		}
	}
	if f.up.asked(awsShimTarget) == 0 {
		t.Error("the platform's AWS front door was never resolved")
	}
	if got := len(f.sink.got); got != 0 {
		t.Logf("%d deliveries buffered", got)
	}
}

func TestVPCResolver_AWSNamesOfServicesThePlatformDoesNotServeFailFast(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	f.res.awsNames = true
	for _, name := range []string{"comprehend.us-east-1.amazonaws.com.", "ssmmessages.us-east-1.amazonaws.com.", "amazonaws.com."} {
		if m := f.query(t, name); m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Errorf("%s: %v %v, want NXDOMAIN", name, m.Header.RCode, m.Answers)
		}
		if n := f.up.asked(name); n != 0 {
			t.Errorf("%s was sent upstream: a sinkholed name never leaves the platform", name)
		}
	}
	// Not AWS's names: as before.
	if m := f.query(t, "example.com."); m.Header.RCode != dnsmessage.RCodeSuccess || f.up.asked("example.com.") != 1 {
		t.Errorf("example.com: %v", m.Header.RCode)
	}
	if m := f.query(t, "dynamodb.us-east-1.amazonaws.com.svc.cluster.local."); m.Header.RCode != dnsmessage.RCodeSuccess ||
		f.up.asked("dynamodb.us-east-1.amazonaws.com.svc.cluster.local.") != 1 {
		t.Error("a search-path name under cluster.local is the cluster's, not AWS's")
	}
}

// The DNS Firewall comes first, as on AWS: a walled garden that blocks everything blocks AWS's names too; one that
// allows them gets the platform's answer.
func TestVPCResolver_AWSNamesAfterTheFirewall(t *testing.T) {
	blocked := newResolverFixture(t, firewallOf("", fwRule("g", 101, 1, "ALLOW", "*.cluster.local"), fwRule("g", 101, 2, "BLOCK", "*")))
	blocked.res.awsNames = true
	if m := blocked.query(t, "dynamodb.us-east-1.amazonaws.com."); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("a walled garden that does not allow AWS's names blocks them: %v", m.Header.RCode)
	}
	allowed := newResolverFixture(t, firewallOf("", fwRule("g", 101, 1, "ALLOW", "*.amazonaws.com"), fwRule("g", 101, 2, "BLOCK", "*")))
	allowed.res.awsNames = true
	if got := aRecordsOf(allowed.query(t, "dynamodb.us-east-1.amazonaws.com.")); len(got) != 1 {
		t.Errorf("a walled garden that allows *.amazonaws.com gets the platform's answer, got %v", got)
	}
	if m := allowed.query(t, "comprehend.us-east-1.amazonaws.com."); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("an allowed name of a service the platform does not serve is still NXDOMAIN: %v", m.Header.RCode)
	}
}

// Off (the default), AWS's names resolve as any other name.
func TestVPCResolver_AWSNamesOffByDefault(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	if f.res.awsNames {
		t.Fatal("AWS names must be off unless VPC_RESOLVER_AWS_NAMES=on")
	}
	f.query(t, "dynamodb.us-east-1.amazonaws.com.")
	if f.up.asked("dynamodb.us-east-1.amazonaws.com.") != 1 {
		t.Error("off, an AWS name is forwarded as before")
	}
}

// One list in three places: the Go rules here and the guest and function resolvers' Corefiles.
func TestAWSNameRules_SameAsTheResolvers(t *testing.T) {
	for _, path := range []string{"../../../platform/aws-shim/guest-aws-endpoints.yaml", "../../../platform/aws-shim/function-aws-endpoints.yaml"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, ln := range strings.Split(string(raw), "\n") {
			f := strings.Fields(strings.TrimSpace(ln))
			if len(f) == 8 && f[0] == "rewrite" && f[1] == "stop" && f[2] == "name" && f[3] == "regex" {
				got = append(got, f[4]+" "+f[5])
			}
		}
		var want []string
		for _, r := range awsNameRules {
			want = append(want, r.re.String()+" "+r.target)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s's rules differ from awsNameRules:\n got:  %q\n want: %q", path, got, want)
		}
	}
}
