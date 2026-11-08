package main

// The VPC resolver from its own side: DNS Firewall's matching and order, each block response, ALERT, CNAME
// inspection, fail open and closed, the sender's identity, query logs, and UDP/TCP serving. The upstream is
// a stub resolver that counts every name it is asked, so a blocked name never reaching it is observed, not
// assumed.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	testVPC      = "vpc-0a1b2c3d4e5f60718"
	testClientIP = "198.51.100.7"
)

// stubUpstream is a resolver on 127.0.0.1 (one port, UDP and TCP) that counts the names it is asked.
type stubUpstream struct {
	addr   string
	mu     sync.Mutex
	counts map[string]int
}

func (u *stubUpstream) asked(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.counts[strings.ToLower(name)]
}

func (u *stubUpstream) total() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, c := range u.counts {
		n += c
	}
	return n
}

func mustName(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func aRecord(name string, ip [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: mustName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
		Body: &dnsmessage.AResource{A: ip}}
}

// answerFor is the stub's zone: nx.* does not exist; cdn.example.com is a CNAME to edge.example.net;
// big.example.com is too big for UDP; every other name has an A (and AAAA, TXT) record.
func (u *stubUpstream) answerFor(q dnsmessage.Question, tcp bool) dnsmessage.Message {
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
	name := strings.ToLower(q.Name.String())
	switch {
	case strings.HasPrefix(name, "nx."):
		m.Header.RCode = dnsmessage.RCodeNameError
	case name == "cdn.example.com.":
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30},
			Body: &dnsmessage.CNAMEResource{CNAME: mustName("edge.example.net.")}}, aRecord("edge.example.net.", [4]byte{192, 0, 2, 20})}
	case name == "big.example.com." && !tcp:
		m.Header.Truncated = true
	case name == "big.example.com.":
		for i := 0; i < 40; i++ {
			m.Answers = append(m.Answers, aRecord(name, [4]byte{192, 0, 2, byte(i + 1)}))
		}
	case q.Type == dnsmessage.TypeAAAA:
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 30},
			Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}}}}
	case q.Type == dnsmessage.TypeTXT:
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 30},
			Body: &dnsmessage.TXTResource{TXT: []string{"v=spf1 -all"}}}}
	default:
		m.Answers = []dnsmessage.Resource{aRecord(q.Name.String(), [4]byte{192, 0, 2, 1})}
	}
	return m
}

func (u *stubUpstream) reply(raw []byte, tcp bool) []byte {
	var q dnsmessage.Message
	if q.Unpack(raw) != nil || len(q.Questions) != 1 {
		return nil
	}
	u.mu.Lock()
	u.counts[strings.ToLower(q.Questions[0].Name.String())]++
	u.mu.Unlock()
	m := u.answerFor(q.Questions[0], tcp)
	m.Header.ID = q.Header.ID
	b, _ := m.Pack()
	return b
}

func newStubUpstream(t *testing.T) *stubUpstream {
	t.Helper()
	pc, ln := listenUDPAndTCP(t)
	u := &stubUpstream{addr: pc.LocalAddr().String(), counts: map[string]int{}}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if b := u.reply(buf[:n], false); b != nil {
				_, _ = pc.WriteTo(b, from)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					msg, err := readTCPMessage(c)
					if err != nil {
						return
					}
					if b := u.reply(msg, true); b != nil {
						_ = writeTCPMessage(c, b)
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); _ = ln.Close() })
	return u
}

// listenUDPAndTCP listens on one free 127.0.0.1 port for both UDP and TCP.
func listenUDPAndTCP(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln
		}
		_ = pc.Close()
	}
	t.Fatal("no free port for both UDP and TCP")
	return nil, nil
}

type fakeConfigs struct {
	mu    sync.Mutex
	cfgs  map[string]vpcResolverConfig
	err   error
	gen   int64
	reads int
}

func (f *fakeConfigs) resolverConfig(_ context.Context, account, vpcID string) (vpcResolverConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return vpcResolverConfig{}, f.err
	}
	return f.cfgs[account+"/"+vpcID], nil
}

func (f *fakeConfigs) generation() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gen
}

func (f *fakeConfigs) set(cfg vpcResolverConfig, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfgs[testMgmt+"/"+testVPC], f.err = cfg, err
}

type fakeClients struct {
	ready bool
	by    map[string]vpcInterface
}

func (c fakeClients) At(ip string, _ time.Time) (vpcInterface, bool) {
	in, ok := c.by[ip]
	return in, ok
}
func (c fakeClients) Ready() bool { return c.ready }

type resolverDelivery struct {
	account, region, group, stream string
	events                         []putEvent
}

type fakeSink struct {
	mu  sync.Mutex
	got []resolverDelivery
}

func (s *fakeSink) deliver(_ context.Context, account, region, group, stream string, events []putEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, resolverDelivery{account, region, group, stream, events})
	return nil
}

func fwRule(group string, assocPrio, prio int, action string, domains ...string) resolverRule {
	r := resolverRule{GroupID: group, DomainListID: "rslvr-fdl-" + group + action, AssociationPriority: assocPrio, Priority: prio,
		Action: action, Domains: domains}
	if action == "BLOCK" {
		r.BlockResponse = "NXDOMAIN"
	}
	return r
}

// firewallOf is a VPC's configuration as the store builds it (rules ordered as DNS Firewall evaluates them).
func firewallOf(failOpen string, rules ...resolverRule) vpcResolverConfig {
	domains := map[string][]string{}
	for _, r := range rules {
		domains[r.DomainListID] = r.Domains
	}
	return buildResolverConfig(failOpen, rules, domains, nil)
}

type resolverFixture struct {
	res     *vpcResolver
	up      *stubUpstream
	configs *fakeConfigs
	sink    *fakeSink
	now     time.Time
}

func newResolverFixture(t *testing.T, cfg vpcResolverConfig) *resolverFixture {
	t.Helper()
	f := &resolverFixture{up: newStubUpstream(t), configs: &fakeConfigs{cfgs: map[string]vpcResolverConfig{}}, sink: &fakeSink{},
		now: time.Date(2026, 11, 8, 17, 51, 55, 0, time.UTC)}
	f.configs.set(cfg, nil)
	clients := fakeClients{ready: true, by: map[string]vpcInterface{
		testClientIP: {IP: testClientIP, Account: testMgmt, Function: "orders", VpcID: testVPC, ENI: "eni-0123456789abcdef0"},
		"127.0.0.1":  {IP: "127.0.0.1", Account: testMgmt, Function: "orders", VpcID: testVPC}}}
	f.res = newVPCResolver(f.configs, clients, f.up.addr, f.sink, "us-east-1", discardLogger())
	f.res.clientWait = 0
	f.res.now = func() time.Time { return f.now }
	return f
}

func dnsQuery(t *testing.T, name string, qt dnsmessage.Type, edns uint16) []byte {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x4a4a, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: mustName(name), Type: qt, Class: dnsmessage.ClassINET}}}
	if edns > 0 {
		m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: mustName("."), Type: dnsmessage.TypeOPT,
			Class: dnsmessage.Class(edns)}, Body: &dnsmessage.OPTResource{}}}
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ask is one query from src over transport, and the resolver's answer.
func (f *resolverFixture) ask(t *testing.T, src, name string, qt dnsmessage.Type, transport string) dnsmessage.Message {
	t.Helper()
	raw := f.res.answer(context.Background(), dnsQuery(t, name, qt, 0), src, 53001, transport)
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("%s %s: no answer (%v)", name, dnsTypeName(qt), err)
	}
	if m.Header.ID != 0x4a4a || !m.Header.Response {
		t.Fatalf("%s: the answer must carry the client's query id: %+v", name, m.Header)
	}
	return m
}

func (f *resolverFixture) query(t *testing.T, name string) dnsmessage.Message {
	t.Helper()
	return f.ask(t, testClientIP, name, dnsmessage.TypeA, "UDP")
}

func TestVPCResolver_DomainMatching(t *testing.T) {
	for _, c := range []struct {
		spec, name string
		want       bool
	}{
		{"example.com", "example.com.", true}, {"example.com", "EXAMPLE.Com", true}, {"example.com", "www.example.com.", false},
		{"example.com", "badexample.com.", false}, {"example.com.", "example.com", true},
		{"*.example.com", "www.example.com.", true}, {"*.example.com", "a.b.example.com.", true}, {"*.example.com", "example.com.", false},
		{"*.example.com", "wwwexample.com.", false}, {"*", "anything.example.org.", true}, {"*", ".", true},
		{"*example.com", "badexample.com.", true}, {"*example.com", "example.com.", true}, {"*example.com", "example.org.", false},
	} {
		cfg := compileVPC(vpcResolverConfig{Rules: []resolverRule{{Action: "BLOCK", Domains: []string{c.spec}}}})
		if got := cfg.rules[0].matches(c.name); got != c.want {
			t.Errorf("%q matches %q = %v, want %v", c.spec, c.name, got, c.want)
		}
	}
}

// A walled garden: the allowed names resolve; everything else is answered by the resolver itself and
// never reaches the upstream resolver.
func TestVPCResolver_BlockedNameIsNeverForwarded(t *testing.T) {
	f := newResolverFixture(t, firewallOf("", fwRule("garden", 101, 100, "ALLOW", "allowed.example.com", "*.example.net"),
		fwRule("garden", 101, 200, "BLOCK", "*")))
	if m := f.query(t, "allowed.example.com."); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Errorf("an allowed name = %+v", m)
	}
	if m := f.query(t, "api.example.net."); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Errorf("an allowed subdomain = %+v", m)
	}
	for _, blocked := range []string{"blocked.example.org.", "exfil.attacker.example.", "example.net."} {
		if m := f.query(t, blocked); m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Errorf("%s = %+v, want NXDOMAIN", blocked, m.Header)
		}
		if n := f.up.asked(blocked); n != 0 {
			t.Errorf("%s was sent upstream %d time(s): a blocked query must never be forwarded", blocked, n)
		}
	}
	if f.up.asked("allowed.example.com.") != 1 || f.up.total() != 2 {
		t.Errorf("upstream saw %v, want only the two allowed names", f.up.counts)
	}
}

func TestVPCResolver_BlockResponses(t *testing.T) {
	ttl := 60
	override := resolverRule{GroupID: "g", DomainListID: "l", AssociationPriority: 101, Priority: 1, Action: "BLOCK", BlockResponse: "OVERRIDE",
		BlockOverrideDomain: "sinkhole.example.com", BlockOverrideDNSType: "CNAME", BlockOverrideTTL: ttl, Domains: []string{"*.blocked.example"}}
	nodata := fwRule("g", 101, 2, "BLOCK", "nodata.example")
	nodata.BlockResponse, nodata.DomainListID = "NODATA", "rslvr-fdl-nodata"
	nx := fwRule("g", 101, 3, "BLOCK", "nxdomain.example")
	nx.DomainListID = "rslvr-fdl-nxdomain"
	f := newResolverFixture(t, firewallOf("", override, nodata, nx))

	m := f.query(t, "nodata.example.")
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("NODATA = %+v", m)
	}
	if m := f.query(t, "nxdomain.example."); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("NXDOMAIN = %+v", m.Header)
	}
	m = f.query(t, "www.blocked.example.")
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 2 {
		t.Fatalf("OVERRIDE = %+v", m)
	}
	c, ok := m.Answers[0].Body.(*dnsmessage.CNAMEResource)
	if !ok || m.Answers[0].Header.Name.String() != "www.blocked.example." || c.CNAME.String() != "sinkhole.example.com." || m.Answers[0].Header.TTL != 60 {
		t.Errorf("OVERRIDE's CNAME = %+v", m.Answers[0])
	}
	if a, ok := m.Answers[1].Body.(*dnsmessage.AResource); !ok || a.A != [4]byte{192, 0, 2, 1} {
		t.Errorf("OVERRIDE's target resolved = %+v", m.Answers[1])
	}
	for _, blocked := range []string{"nodata.example.", "nxdomain.example.", "www.blocked.example."} {
		if f.up.asked(blocked) != 0 {
			t.Errorf("%s was forwarded", blocked)
		}
	}
	if f.up.asked("sinkhole.example.com.") != 1 {
		t.Error("the override domain (the operator's, not the blocked name) is resolved")
	}
	// A CNAME query is answered with the CNAME alone.
	if m := f.ask(t, testClientIP, "x.blocked.example.", dnsmessage.TypeCNAME, "UDP"); len(m.Answers) != 1 {
		t.Errorf("OVERRIDE for a CNAME query = %+v", m.Answers)
	}
}

// Rule groups are evaluated by association priority, then rule priority: the first ALLOW or BLOCK that
// matches decides.
func TestVPCResolver_RuleOrderAcrossGroups(t *testing.T) {
	block := fwRule("strict", 101, 500, "BLOCK", "example.com")
	allow := fwRule("open", 200, 1, "ALLOW", "example.com")
	f := newResolverFixture(t, firewallOf("", allow, block))
	if m := f.query(t, "example.com."); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("the rule group at priority 101 decides first, whatever its rules' priorities: %+v", m.Header)
	}
	block.AssociationPriority, allow.AssociationPriority = 300, 200
	f.configs.set(firewallOf("", block, allow), nil)
	f.configs.gen++
	if m := f.query(t, "example.com."); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Errorf("with the ALLOW group first: %+v", m)
	}
	// Within a group, rule priority.
	f.configs.set(firewallOf("", fwRule("g", 101, 20, "ALLOW", "example.com"), fwRule("g", 101, 10, "BLOCK", "*")), nil)
	f.configs.gen++
	if m := f.query(t, "example.com."); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("the rule at priority 10 decides before the one at 20: %+v", m.Header)
	}
}

// ALERT logs and evaluation continues: to the next rule, or to resolution when none decides.
func TestVPCResolver_AlertContinues(t *testing.T) {
	cfg := firewallOf("", fwRule("watch", 101, 1, "ALERT", "*.example.com"), fwRule("watch", 101, 2, "BLOCK", "bad.example.com"))
	cfg.QueryLogs = []resolverQueryLog{{ConfigID: "rqlc-1", LogGroupARN: "arn:aws:logs:us-east-1:" + testMgmt + ":log-group:dns"}}
	f := newResolverFixture(t, cfg)
	if m := f.query(t, "ok.example.com."); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || f.up.asked("ok.example.com.") != 1 {
		t.Errorf("an ALERT alone resolves: %+v", m)
	}
	if m := f.query(t, "bad.example.com."); m.Header.RCode != dnsmessage.RCodeNameError || f.up.asked("bad.example.com.") != 0 {
		t.Errorf("an ALERT then a BLOCK blocks: %+v", m.Header)
	}
	recs := drainRecords(t, f.res)
	if len(recs) != 2 || recs[0].FirewallRuleAction != "ALERT" || recs[0].FirewallRuleGroupID != "watch" ||
		recs[1].FirewallRuleAction != "BLOCK" || recs[1].FirewallDomainListID != "rslvr-fdl-watchBLOCK" || recs[1].Rcode != "NXDOMAIN" {
		t.Errorf("records = %+v", recs)
	}
}

func TestVPCResolver_QtypeFilter(t *testing.T) {
	r := fwRule("g", 101, 1, "BLOCK", "example.com")
	r.Qtype = "AAAA"
	f := newResolverFixture(t, firewallOf("", r))
	if m := f.ask(t, testClientIP, "example.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Errorf("an A query passes an AAAA rule: %+v", m)
	}
	if m := f.ask(t, testClientIP, "example.com.", dnsmessage.TypeAAAA, "UDP"); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("an AAAA query is blocked: %+v", m.Header)
	}
	r.Qtype = "TYPE16" // TXT, by number
	f.configs.set(firewallOf("", r), nil)
	f.configs.gen++
	if m := f.ask(t, testClientIP, "example.com.", dnsmessage.TypeTXT, "UDP"); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("TYPE16 blocks TXT: %+v", m.Header)
	}
}

// A sender that is no VPC function's interface is refused, and nothing it asks is forwarded.
func TestVPCResolver_RefusesUnknownSender(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	if m := f.ask(t, "203.0.113.50", "example.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeRefused || len(m.Answers) != 0 {
		t.Errorf("an unknown sender = %+v", m)
	}
	if f.up.total() != 0 {
		t.Errorf("an unknown sender's query was forwarded: %v", f.up.counts)
	}
	// Whatever it sends: a NOTIFY from an unknown sender is refused too; from a VPC function, not implemented.
	notify := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, OpCode: 4},
		Questions: []dnsmessage.Question{{Name: mustName("example.com."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}}}
	raw, _ := notify.Pack()
	for src, want := range map[string]dnsmessage.RCode{"203.0.113.50": dnsmessage.RCodeRefused, testClientIP: dnsmessage.RCodeNotImplemented} {
		var m dnsmessage.Message
		if m.Unpack(f.res.answer(context.Background(), raw, src, 1, "UDP")) != nil || m.Header.RCode != want {
			t.Errorf("NOTIFY from %s = %+v, want %v", src, m.Header, want)
		}
	}
	f.res.clients = fakeClients{ready: false}
	if m := f.ask(t, testClientIP, "example.com.", dnsmessage.TypeA, "UDP"); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("before the interfaces are listed = %+v, want SERVFAIL (ask again)", m.Header)
	}
	if f.up.total() != 0 {
		t.Error("nothing is forwarded before the sender is known")
	}
}

// Each name a CNAME redirects to is evaluated too, unless the ALLOW rule trusts redirection.
func TestVPCResolver_CNAMEInspection(t *testing.T) {
	allow := fwRule("garden", 101, 1, "ALLOW", "cdn.example.com")
	f := newResolverFixture(t, firewallOf("", allow, fwRule("garden", 101, 2, "BLOCK", "*")))
	if m := f.query(t, "cdn.example.com."); m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
		t.Errorf("INSPECT_REDIRECTION_DOMAIN: a CNAME to a blocked name is blocked: %+v", m)
	}
	allow.Redirection = "TRUST_REDIRECTION_DOMAIN"
	f.configs.set(firewallOf("", allow, fwRule("garden", 101, 2, "BLOCK", "*")), nil)
	f.configs.gen++
	if m := f.query(t, "cdn.example.com."); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 2 {
		t.Errorf("TRUST_REDIRECTION_DOMAIN: the chain is not inspected: %+v", m)
	}
	allow.Redirection = ""
	allow.Domains = []string{"cdn.example.com", "edge.example.net"}
	f.configs.set(firewallOf("", allow, fwRule("garden", 101, 2, "BLOCK", "*")), nil)
	f.configs.gen++
	if m := f.query(t, "cdn.example.com."); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 2 {
		t.Errorf("a chain whose every name is allowed resolves: %+v", m)
	}
	// With no rule matching the name itself, its chain is still inspected.
	f.configs.set(firewallOf("", fwRule("deny", 101, 1, "BLOCK", "edge.example.net")), nil)
	f.configs.gen++
	if m := f.query(t, "cdn.example.com."); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("a CNAME to a blocked name, no rule on the name: %+v", m.Header)
	}
}

// A VPC whose configuration cannot be read: FirewallFailOpen ENABLED resolves without the firewall,
// anything else (and no configuration ever read) fails closed.
func TestVPCResolver_FailOpenAndClosed(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	f.configs.set(vpcResolverConfig{}, errors.New("the store is down"))
	if m := f.query(t, "example.com."); m.Header.RCode != dnsmessage.RCodeServerFailure || f.up.total() != 0 {
		t.Errorf("never read = %+v (upstream %v), want SERVFAIL", m.Header, f.up.counts)
	}

	walled := []resolverRule{fwRule("g", 101, 1, "BLOCK", "*")}
	for _, c := range []struct {
		failOpen string
		want     dnsmessage.RCode
	}{{"ENABLED", dnsmessage.RCodeSuccess}, {"DISABLED", dnsmessage.RCodeServerFailure}, {"USE_LOCAL_RESOURCE_SETTING", dnsmessage.RCodeServerFailure}} {
		f := newResolverFixture(t, firewallOf(c.failOpen, walled...))
		if m := f.query(t, "example.com."); m.Header.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("%s: read: %+v", c.failOpen, m.Header)
		}
		f.configs.set(vpcResolverConfig{}, errors.New("the store is down"))
		f.now = f.now.Add(time.Minute) // past the cache
		m := f.query(t, "example.com.")
		if m.Header.RCode != c.want {
			t.Errorf("%s, unreadable: %v, want %v", c.failOpen, m.Header.RCode, c.want)
		}
		if forwarded := f.up.asked("example.com.") == 1; forwarded != (c.want == dnsmessage.RCodeSuccess) {
			t.Errorf("%s: forwarded=%v", c.failOpen, forwarded)
		}
	}
}

// A VPC's configuration is cached for a few seconds and read again as soon as this process changes one.
func TestVPCResolver_CachesUntilAWrite(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	f.query(t, "a.example.com.")
	f.query(t, "b.example.com.")
	if f.configs.reads != 1 {
		t.Errorf("reads = %d, want 1 (cached)", f.configs.reads)
	}
	f.configs.set(firewallOf("", fwRule("g", 101, 1, "BLOCK", "c.example.com")), nil)
	f.configs.gen++
	if m := f.query(t, "c.example.com."); m.Header.RCode != dnsmessage.RCodeNameError || f.configs.reads != 2 {
		t.Errorf("after a write: %+v reads=%d", m.Header, f.configs.reads)
	}
	f.now = f.now.Add(vpcResolverConfigTTL)
	f.query(t, "d.example.com.")
	if f.configs.reads != 3 {
		t.Errorf("reads = %d, want 3 (expired)", f.configs.reads)
	}
}

// Over UDP an answer larger than the client takes is truncated; the resolver itself retries upstream over
// TCP when the upstream truncates.
func TestVPCResolver_Truncation(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	m := f.query(t, "big.example.com.")
	if !m.Header.Truncated || len(m.Answers) != 0 {
		t.Errorf("UDP without EDNS: %+v answers=%d, want truncated", m.Header, len(m.Answers))
	}
	if m := f.ask(t, testClientIP, "big.example.com.", dnsmessage.TypeA, "TCP"); m.Header.Truncated || len(m.Answers) != 40 {
		t.Errorf("TCP: truncated=%v answers=%d, want 40", m.Header.Truncated, len(m.Answers))
	}
	raw := f.res.answer(context.Background(), dnsQuery(t, "big.example.com.", dnsmessage.TypeA, 1232), testClientIP, 53001, "UDP")
	var big dnsmessage.Message
	if big.Unpack(raw) != nil || big.Header.Truncated || len(big.Answers) != 40 {
		t.Errorf("UDP with EDNS 1232: truncated=%v answers=%d", big.Header.Truncated, len(big.Answers))
	}
}

func drainRecords(t *testing.T, res *vpcResolver) []queryLogRecord {
	t.Helper()
	var out []queryLogRecord
	for {
		select {
		case d := <-res.records:
			var r queryLogRecord
			if err := json.Unmarshal([]byte(d.event.Message), &r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		default:
			return out
		}
	}
}

// One record per query, in Route 53 Resolver's query log format, into the VPC's log stream of each
// destination log group.
func TestVPCResolver_QueryLogRecord(t *testing.T) {
	block := fwRule("rslvr-frg-01234567890abcdef", 101, 1, "BLOCK", "blocked.example.org")
	block.DomainListID = "rslvr-fdl-01234567890abcdef"
	cfg := firewallOf("", block)
	cfg.QueryLogs = []resolverQueryLog{{ConfigID: "rqlc-1", LogGroupARN: "arn:aws:logs:us-east-1:" + testMgmt + ":log-group:/vpc/dns:*"},
		{ConfigID: "rqlc-2", LogGroupARN: "arn:aws:logs:us-east-1:" + testMgmt + ":log-group:audit"}}
	f := newResolverFixture(t, cfg)
	f.query(t, "www.example.com.")
	f.query(t, "blocked.example.org.")

	var raw []map[string]any
	var batch []queryLogDelivery
	for len(f.res.records) > 0 {
		d := <-f.res.records
		batch = append(batch, d)
		var m map[string]any
		if err := json.Unmarshal([]byte(d.event.Message), &m); err != nil {
			t.Fatal(err)
		}
		raw = append(raw, m)
	}
	if len(raw) != 4 {
		t.Fatalf("%d records, want one per query per destination", len(raw))
	}
	want := map[string]any{"version": "1.100000", "account_id": testMgmt, "region": "us-east-1", "vpc_id": testVPC,
		"query_timestamp": "2026-11-08T17:51:55Z", "query_name": "www.example.com.", "query_type": "A", "query_class": "IN",
		"rcode": "NOERROR", "srcaddr": testClientIP, "srcport": "53001", "transport": "UDP",
		"answers": []any{map[string]any{"Rdata": "192.0.2.1", "Type": "A", "Class": "IN"}}}
	got, _ := json.Marshal(raw[0])
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Errorf("record:\n got %s\nwant %s", got, exp)
	}
	blocked := raw[2]
	if blocked["firewall_rule_action"] != "BLOCK" || blocked["firewall_rule_group_id"] != "rslvr-frg-01234567890abcdef" ||
		blocked["firewall_domain_list_id"] != "rslvr-fdl-01234567890abcdef" || blocked["rcode"] != "NXDOMAIN" || len(sliceOf(blocked["answers"])) != 0 {
		t.Errorf("blocked record = %v", blocked)
	}
	if _, has := raw[0]["firewall_rule_action"]; has {
		t.Error("a query no ALERT or BLOCK rule matched carries no firewall fields")
	}

	f.res.flush(batch)
	if len(f.sink.got) != 2 {
		t.Fatalf("deliveries = %+v", f.sink.got)
	}
	for i, group := range []string{"/vpc/dns", "audit"} {
		d := f.sink.got[i]
		if d.account != testMgmt || d.region != "us-east-1" || d.group != group || d.stream != testVPC || len(d.events) != 2 ||
			d.events[0].TsMs != f.now.UnixMilli() {
			t.Errorf("delivery %d = %+v", i, d)
		}
	}
}

// The listener answers over UDP and over TCP (2-byte length framing), and stops with its context.
func TestVPCResolver_ServesUDPAndTCP(t *testing.T) {
	f := newResolverFixture(t, firewallOf("", fwRule("g", 101, 1, "BLOCK", "blocked.example.org")))
	f.res.now = time.Now
	if err := f.res.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.res.Serve(ctx); close(done) }()

	uc, err := net.Dial("udp", f.res.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uc.Write(dnsQuery(t, "www.example.com.", dnsmessage.TypeA, 0)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := uc.Read(buf)
	var m dnsmessage.Message
	if err != nil || m.Unpack(buf[:n]) != nil || m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Errorf("UDP: %v %+v", err, m)
	}

	tc, err := net.Dial("tcp", f.res.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	for _, c := range []struct {
		name string
		want dnsmessage.RCode
	}{{"blocked.example.org.", dnsmessage.RCodeNameError}, {"www.example.com.", dnsmessage.RCodeSuccess}} {
		if err := writeTCPMessage(tc, dnsQuery(t, c.name, dnsmessage.TypeA, 0)); err != nil {
			t.Fatal(err)
		}
		resp, err := readTCPMessage(tc)
		var tm dnsmessage.Message
		if err != nil || tm.Unpack(resp) != nil || tm.Header.RCode != c.want {
			t.Errorf("TCP %s: %v %+v", c.name, err, tm.Header)
		}
	}
	if f.up.asked("blocked.example.org.") != 0 {
		t.Error("a blocked name was forwarded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop with its context")
	}
}

func TestVPCResolver_SystemNameserver(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(p, []byte("search default.svc.cluster.local\nnameserver 192.0.2.53\nnameserver 192.0.2.54\noptions ndots:5\n"), 0o644)
	if got, err := systemNameserver(p); err != nil || got != "192.0.2.53:53" {
		t.Errorf("systemNameserver = %q %v", got, err)
	}
	_ = os.WriteFile(p, []byte("nameserver 2001:db8::53\n"), 0o644)
	if got, _ := systemNameserver(p); got != "[2001:db8::53]:53" {
		t.Errorf("IPv6 = %q", got)
	}
	_ = os.WriteFile(p, []byte("search x\n"), 0o644)
	if _, err := systemNameserver(p); err == nil {
		t.Error("a resolv.conf with no nameserver is an error")
	}
}

// A message that is not a query is not answered; a query that cannot be read is FORMERR.
func TestVPCResolver_Malformed(t *testing.T) {
	f := newResolverFixture(t, firewallOf(""))
	if got := f.res.answer(context.Background(), []byte{1, 2, 3}, testClientIP, 1, "UDP"); got != nil {
		t.Errorf("garbage answered: %v", got)
	}
	resp := f.res.answer(context.Background(), []byte{0x4a, 0x4a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xff}, testClientIP, 1, "UDP")
	var m dnsmessage.Message
	if m.Unpack(resp) != nil || m.Header.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("a cut-off question = %+v", m.Header)
	}
	if f.up.total() != 0 {
		t.Error("a malformed query was forwarded")
	}
}
