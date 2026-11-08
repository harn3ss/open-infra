// The VPC resolver: Route 53 Resolver for Lambda functions in a VPC, a DNS server inside the aws-shim.
//
// A VPC function's DNS reaches only this server (the Lambda VPC subnet drops DNS to anywhere else; the
// platform's vpc-resolver Service sends port 53 here, VPC_RESOLVER_LISTEN, default :5353, UDP and TCP).
// For each query it names the sender by its address (vpcInterfaces: the function's network interface, its
// account and VPC), applies the VPC's DNS Firewall, resolves what the firewall lets through by forwarding
// to the platform's resolver (VPC_RESOLVER_UPSTREAM, default the first nameserver of the shim's own
// resolv.conf), and logs the query to the VPC's query log destinations. A sender that is no VPC function's
// interface is REFUSED and nothing it asks is forwarded.
//
// DNS Firewall, as AWS evaluates it: the rule groups associated with the VPC by association priority, each
// group's rules by rule priority, the lowest first. A rule matches a query whose name its domain list holds
// (case-insensitive, a trailing dot ignored; "example.com" matches itself alone, a leading "*" matches any
// name that ends with the rest — "*.example.com" every subdomain but not example.com, "*" every name) and,
// when the rule has a Qtype, whose type is that. ALLOW resolves the query; BLOCK answers it with the rule's
// block response (NODATA, NXDOMAIN, or OVERRIDE's CNAME) and never sends it upstream; ALERT logs the match
// and evaluation continues; no match resolves. Unless the deciding ALLOW rule trusts redirection
// (TRUST_REDIRECTION_DOMAIN), each name a CNAME in the answer redirects to is evaluated too, and a blocked
// one turns the answer into that rule's block response.
//
// When a VPC's configuration cannot be read, its FirewallFailOpen decides (the last setting read): ENABLED
// resolves without the firewall, anything else answers SERVFAIL (AWS's default is to fail closed).
//
// Query logs: one record per query, in Route 53 Resolver's query log format (version 1.100000), delivered
// to each of the VPC's query logging configurations' CloudWatch Logs log groups, into a log stream named
// after the VPC's id. Records are batched and flushed every couple of seconds; a query never waits on its
// record, and records are dropped (and the drop logged) when delivery falls behind.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"golang.org/x/net/dns/dnsmessage"
)

// resolverConfigSource is where the resolver reads a VPC's configuration (r53rStore).
type resolverConfigSource interface {
	resolverConfig(ctx context.Context, account, vpcID string) (vpcResolverConfig, error)
	generation() int64 // changes whenever this process writes a configuration
}

// vpcClients names a query's sender: the VPC function interface that had its address (vpcInterfaces).
type vpcClients interface {
	At(ip string, t time.Time) (vpcInterface, bool)
	Ready() bool
}

// queryLogSink delivers query log records into an account's log group (cwlStore.deliver).
type queryLogSink interface {
	deliver(ctx context.Context, account, region, group, stream string, events []putEvent) error
}

const (
	defaultVPCResolverListen = ":5353"
	vpcResolverConfigTTL     = 5 * time.Second  // how long a VPC's configuration is cached
	vpcResolverClientWait    = time.Second      // how long a new sender's interface is waited for
	vpcResolverUpstreamWait  = 4 * time.Second  // one upstream exchange
	vpcResolverFlushEvery    = 2 * time.Second  // query log delivery
	vpcResolverMaxInflight   = 1024             // queries answered at once; more are dropped (clients retry)
	vpcResolverLogQueue      = 20000            // query log records waiting for delivery
	vpcResolverTCPIdle       = 10 * time.Second // a TCP connection with no query is closed
	queryLogVersion          = "1.100000"       // the version Route 53 Resolver's records carry
	maxUDPPayload            = 4096             // the largest UDP answer, whatever a client's EDNS says
	minUDPPayload            = 512              // RFC 1035's, for a client without EDNS
	vpcResolverTCPMaxMessage = 65535
)

type vpcResolver struct {
	configs  resolverConfigSource
	clients  vpcClients
	upstream string // host:port
	logs     queryLogSink
	region   string
	logger   *slog.Logger
	now      func() time.Time

	ttl, clientWait, upstreamWait time.Duration

	mu     sync.Mutex
	cache  map[string]*cachedVPC // account + "/" + VPC id
	logged map[string]time.Time  // when a repeated log line was last written (every)

	records chan queryLogDelivery
	sem     chan struct{}

	pc net.PacketConn
	ln net.Listener
}

func newVPCResolver(configs resolverConfigSource, clients vpcClients, upstream string, logs queryLogSink, region string, logger *slog.Logger) *vpcResolver {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &vpcResolver{configs: configs, clients: clients, upstream: upstream, logs: logs, region: region, logger: logger,
		now: time.Now, ttl: vpcResolverConfigTTL, clientWait: vpcResolverClientWait, upstreamWait: vpcResolverUpstreamWait,
		cache: map[string]*cachedVPC{}, logged: map[string]time.Time{}, records: make(chan queryLogDelivery, vpcResolverLogQueue),
		sem: make(chan struct{}, vpcResolverMaxInflight)}
}

// every reports whether a log line keyed by key may be written now: once per d, so a line a query writes
// does not repeat for every query (an outage, a function retrying a blocked name).
func (s *vpcResolver) every(key string, d time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.logged[key]; ok && now.Sub(last) < d {
		return false
	}
	if len(s.logged) > 10000 {
		s.logged = map[string]time.Time{}
	}
	s.logged[key] = now
	return true
}

// systemNameserver is the first nameserver of resolv.conf, with port 53.
func systemNameserver(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			return net.JoinHostPort(f[1], "53"), nil
		}
	}
	return "", errors.New(path + " names no nameserver")
}

// --- the VPC's configuration ---

type cachedVPC struct {
	cfg     compiledVPC
	fetched time.Time
	gen     int64
}

// compiledVPC is a VPC's configuration, its domain lists made into lookups.
type compiledVPC struct {
	failOpen string
	rules    []compiledRule
	logs     []resolverQueryLog
}

type compiledRule struct {
	resolverRule
	all      bool            // the list holds "*"
	exact    map[string]bool // names the list holds
	suffixes []string        // the rest of each "*…" specification
	qtype    uint16          // 0: every query type
}

func compileVPC(cfg vpcResolverConfig) compiledVPC {
	out := compiledVPC{failOpen: cfg.FailOpen, logs: cfg.QueryLogs}
	for _, r := range cfg.Rules {
		c := compiledRule{resolverRule: r, exact: map[string]bool{}}
		if r.Qtype != "" {
			n, ok := qtypeNumber(r.Qtype)
			if !ok {
				continue // never stored: the front door checks every Qtype
			}
			c.qtype = n
		}
		for _, d := range r.Domains {
			d = strings.ToLower(d)
			if rest, wild := strings.CutPrefix(d, "*"); wild {
				if rest = strings.TrimSuffix(rest, "."); rest == "" {
					c.all = true
				} else {
					c.suffixes = append(c.suffixes, rest)
				}
				continue
			}
			c.exact[strings.TrimSuffix(d, ".")] = true
		}
		out.rules = append(out.rules, c)
	}
	return out
}

// matches reports whether the rule's domain list holds name.
func (r *compiledRule) matches(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	if r.all || r.exact[n] {
		return true
	}
	for _, s := range r.suffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// verdict is the firewall's decision on one name: the ALLOW or BLOCK rule that decided it (nil when none
// did), and the first ALERT rule that matched on the way.
type verdict struct {
	rule, alert *compiledRule
}

func (v verdict) blocked() bool { return v.rule != nil && v.rule.Action == "BLOCK" }

// logged is the rule a query's log record names: the blocking rule, else the first alert.
func (v verdict) logged() *compiledRule {
	if v.blocked() {
		return v.rule
	}
	return v.alert
}

// evaluate runs the VPC's rules, in order, on one name and query type.
func (c compiledVPC) evaluate(name string, qtype dnsmessage.Type) verdict {
	var v verdict
	for i := range c.rules {
		r := &c.rules[i]
		if r.qtype != 0 && uint16(qtype) != r.qtype {
			continue
		}
		if !r.matches(name) {
			continue
		}
		switch r.Action {
		case "ALERT":
			if v.alert == nil {
				v.alert = r
			}
		case "ALLOW", "BLOCK":
			v.rule = r
			return v
		}
	}
	return v
}

// config is a VPC's configuration and whether it was read: cached for a few seconds, read again as soon as
// this process changes one. When it cannot be read, the last one read (if any) is answered with fresh
// false: its fail-open setting decides.
func (s *vpcResolver) config(ctx context.Context, account, vpcID string) (compiledVPC, bool) {
	key := account + "/" + vpcID
	gen := s.configs.generation()
	now := s.now()
	s.mu.Lock()
	e := s.cache[key]
	s.mu.Unlock()
	if e != nil && e.gen == gen && now.Sub(e.fetched) < s.ttl {
		return e.cfg, true
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cfg, err := s.configs.resolverConfig(rctx, account, vpcID)
	if err != nil {
		if s.every("read/"+key, 30*time.Second) {
			s.logger.Warn("vpc resolver: the VPC's Route 53 Resolver configuration could not be read",
				slog.String("vpc", vpcID), slog.String("error", err.Error()))
		}
		if e != nil {
			return e.cfg, false
		}
		return compiledVPC{}, false
	}
	c := compileVPC(cfg)
	s.mu.Lock()
	s.cache[key] = &cachedVPC{cfg: c, fetched: now, gen: gen}
	s.mu.Unlock()
	return c, true
}

// --- answering a query ---

// query is one query the resolver answers.
type query struct {
	raw       []byte
	msg       dnsmessage.Message
	question  dnsmessage.Question
	src       string // the sender's address
	srcPort   int
	transport string // UDP | TCP
	received  time.Time
}

// answer is the resolver's answer to one DNS message from src (nil: nothing is answered).
func (s *vpcResolver) answer(ctx context.Context, raw []byte, src string, srcPort int, transport string) []byte {
	q := query{raw: raw, src: src, srcPort: srcPort, transport: transport, received: s.now()}
	if err := q.msg.Unpack(raw); err != nil {
		var p dnsmessage.Parser
		h, herr := p.Start(raw)
		if herr != nil || h.Response {
			return nil
		}
		return pack(reply(h, nil, dnsmessage.RCodeFormatError))
	}
	if q.msg.Header.Response {
		return nil
	}
	if len(q.msg.Questions) != 1 {
		return pack(reply(q.msg.Header, nil, dnsmessage.RCodeFormatError))
	}
	q.question = q.msg.Questions[0]
	in, known := s.sender(ctx, src)
	if !known {
		rcode := dnsmessage.RCodeRefused
		if !s.clients.Ready() {
			rcode = dnsmessage.RCodeServerFailure // the interfaces are not listed yet: ask again
		}
		return s.fit(q, pack(reply(q.msg.Header, &q.question, rcode)))
	}
	if q.msg.Header.OpCode != 0 {
		return s.fit(q, pack(reply(q.msg.Header, &q.question, dnsmessage.RCodeNotImplemented)))
	}
	cfg, fresh := s.config(ctx, in.Account, in.VpcID)
	firewall := true
	if !fresh {
		if cfg.failOpen != "ENABLED" {
			if s.every("closed/"+in.VpcID, 30*time.Second) {
				s.logger.Warn("vpc resolver: DNS Firewall fails closed (the VPC's configuration cannot be read)",
					slog.String("vpc", in.VpcID), slog.String("function", in.Function), slog.String("query", q.question.Name.String()))
			}
			resp := reply(q.msg.Header, &q.question, dnsmessage.RCodeServerFailure)
			s.record(in, cfg, q, resp, nil)
			return s.fit(q, pack(resp))
		}
		if s.every("open/"+in.VpcID, 30*time.Second) {
			s.logger.Warn("vpc resolver: DNS Firewall fails open (the VPC's configuration cannot be read)",
				slog.String("vpc", in.VpcID), slog.String("function", in.Function))
		}
		firewall = false
	}
	var v verdict
	if firewall {
		v = cfg.evaluate(q.question.Name.String(), q.question.Type)
		if v.alert != nil {
			s.alerted(in, q.question.Name.String(), v.alert)
		}
		if v.blocked() {
			resp := s.blockResponse(ctx, q, v.rule)
			s.blockedLog(in, q.question.Name.String(), v.rule)
			s.record(in, cfg, q, resp, v.logged())
			return s.fit(q, pack(resp))
		}
	}
	up, err := s.forward(ctx, q.raw)
	if err != nil {
		if s.every("upstream", 10*time.Second) {
			s.logger.Warn("vpc resolver: the upstream resolver did not answer", slog.String("upstream", s.upstream), slog.String("error", err.Error()))
		}
		resp := reply(q.msg.Header, &q.question, dnsmessage.RCodeServerFailure)
		s.record(in, cfg, q, resp, v.logged())
		return s.fit(q, pack(resp))
	}
	var resp dnsmessage.Message
	parsed := resp.Unpack(up) == nil
	if firewall && (v.rule == nil || v.rule.Redirection != "TRUST_REDIRECTION_DOMAIN") {
		if !parsed {
			// An answer that cannot be read cannot be inspected: it is not passed on.
			resp = reply(q.msg.Header, &q.question, dnsmessage.RCodeServerFailure)
			s.record(in, cfg, q, resp, v.logged())
			return s.fit(q, pack(resp))
		}
		for _, target := range cnameTargets(resp) {
			tv := cfg.evaluate(target, q.question.Type)
			if tv.alert != nil {
				s.alerted(in, target, tv.alert)
				if v.alert == nil {
					v.alert = tv.alert
				}
			}
			if tv.blocked() {
				blocked := s.blockResponse(ctx, q, tv.rule)
				s.blockedLog(in, target, tv.rule)
				s.record(in, cfg, q, blocked, tv.rule)
				return s.fit(q, pack(blocked))
			}
		}
	}
	binary.BigEndian.PutUint16(up[0:2], q.msg.Header.ID)
	if parsed {
		s.record(in, cfg, q, resp, v.logged())
	}
	return s.fit(q, up)
}

// sender is the VPC function interface that sent from src, waiting a moment for an address the interfaces
// have not listed yet (an execution environment that has just started).
func (s *vpcResolver) sender(ctx context.Context, src string) (vpcInterface, bool) {
	deadline := s.now().Add(s.clientWait)
	for {
		if in, ok := s.clients.At(src, s.now()); ok {
			return in, true
		}
		if !s.clients.Ready() || !s.now().Before(deadline) {
			return vpcInterface{}, false
		}
		select {
		case <-ctx.Done():
			return vpcInterface{}, false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// reply is an answer to h's query carrying q (when known) and rcode.
func reply(h dnsmessage.Header, q *dnsmessage.Question, rcode dnsmessage.RCode) dnsmessage.Message {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode}}
	if q != nil {
		m.Questions = []dnsmessage.Question{*q}
	}
	return m
}

func pack(m dnsmessage.Message) []byte {
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// blockResponse is a BLOCK rule's answer: NODATA (no error, no answer), NXDOMAIN, or OVERRIDE — a CNAME to
// the rule's override domain with its TTL, and that domain's own answer (the override domain is the
// operator's, never the blocked name, so resolving it sends nothing of the blocked query upstream).
func (s *vpcResolver) blockResponse(ctx context.Context, q query, r *compiledRule) dnsmessage.Message {
	switch r.BlockResponse {
	case "NXDOMAIN":
		return reply(q.msg.Header, &q.question, dnsmessage.RCodeNameError)
	case "OVERRIDE":
		target := r.BlockOverrideDomain
		if !strings.HasSuffix(target, ".") {
			target += "."
		}
		name, err := dnsmessage.NewName(target)
		if err != nil {
			return reply(q.msg.Header, &q.question, dnsmessage.RCodeServerFailure)
		}
		m := reply(q.msg.Header, &q.question, dnsmessage.RCodeSuccess)
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.question.Name, Type: dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET, TTL: uint32(r.BlockOverrideTTL)}, Body: &dnsmessage.CNAMEResource{CNAME: name}}}
		if q.question.Type != dnsmessage.TypeCNAME {
			m.Answers = append(m.Answers, s.resolveOverride(ctx, name, q.question.Type)...)
		}
		return m
	}
	return reply(q.msg.Header, &q.question, dnsmessage.RCodeSuccess) // NODATA
}

// resolveOverride is the answer records of an override domain's own query.
func (s *vpcResolver) resolveOverride(ctx context.Context, name dnsmessage.Name, t dnsmessage.Type) []dnsmessage.Resource {
	m := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}}}
	raw, err := m.Pack()
	if err != nil {
		return nil
	}
	resp, err := s.forward(ctx, raw)
	if err != nil {
		return nil
	}
	var r dnsmessage.Message
	if r.Unpack(resp) != nil || r.Header.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	return r.Answers
}

// cnameTargets are the names the answer's CNAME records redirect to.
func cnameTargets(m dnsmessage.Message) []string {
	var out []string
	for _, a := range m.Answers {
		if c, ok := a.Body.(*dnsmessage.CNAMEResource); ok {
			out = append(out, c.CNAME.String())
		}
	}
	return out
}

// alerted and blockedLog write the shim's own line for a matched ALERT or BLOCK rule (once per VPC, name
// and rule every 10 seconds); the customer's record of every query is its query log.
func (s *vpcResolver) alerted(in vpcInterface, name string, r *compiledRule) {
	if !s.every("alert/"+in.VpcID+"/"+name+"/"+r.DomainListID, 10*time.Second) {
		return
	}
	s.logger.Info("vpc resolver: DNS Firewall alert", slog.String("vpc", in.VpcID), slog.String("function", in.Function),
		slog.String("query", name), slog.String("firewall_rule_group_id", r.GroupID), slog.String("firewall_domain_list_id", r.DomainListID))
}

func (s *vpcResolver) blockedLog(in vpcInterface, name string, r *compiledRule) {
	if !s.every("block/"+in.VpcID+"/"+name+"/"+r.DomainListID, 10*time.Second) {
		return
	}
	s.logger.Info("vpc resolver: DNS Firewall block", slog.String("vpc", in.VpcID), slog.String("function", in.Function),
		slog.String("query", name), slog.String("block_response", r.BlockResponse),
		slog.String("firewall_rule_group_id", r.GroupID), slog.String("firewall_domain_list_id", r.DomainListID))
}

// fit is an answer as the client's transport takes it: over UDP, one larger than the client accepts
// (its EDNS payload size, else 512 bytes) is answered truncated, so the client asks again over TCP.
func (s *vpcResolver) fit(q query, resp []byte) []byte {
	if resp == nil || q.transport != "UDP" {
		return resp
	}
	limit := minUDPPayload
	for _, a := range q.msg.Additionals {
		if a.Header.Type == dnsmessage.TypeOPT {
			if n := int(a.Header.Class); n > limit {
				limit = n
			}
		}
	}
	if limit > maxUDPPayload {
		limit = maxUDPPayload
	}
	if len(resp) <= limit {
		return resp
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil
	}
	h.Truncated = true
	m := dnsmessage.Message{Header: h, Questions: []dnsmessage.Question{q.question}}
	return pack(m)
}

// --- forwarding ---

// forward sends a query to the upstream resolver and returns its answer: over UDP, again over TCP when the
// answer is truncated. The query goes upstream under a fresh id; the answer keeps it (the caller puts the
// client's back).
func (s *vpcResolver) forward(ctx context.Context, raw []byte) ([]byte, error) {
	if s.upstream == "" {
		return nil, errors.New("no upstream resolver")
	}
	if len(raw) < 12 {
		return nil, errors.New("short query")
	}
	msg := append([]byte(nil), raw...)
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	binary.BigEndian.PutUint16(msg[0:2], id)
	ctx, cancel := context.WithTimeout(ctx, s.upstreamWait)
	defer cancel()
	resp, err := s.exchangeUDP(ctx, msg, id)
	if err == nil && len(resp) > 2 && resp[2]&0x02 != 0 { // TC
		resp, err = s.exchangeTCP(ctx, msg, id)
	}
	return resp, err
}

func (s *vpcResolver) exchangeUDP(ctx context.Context, msg []byte, id uint16) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", s.upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 12 && binary.BigEndian.Uint16(buf[0:2]) == id && buf[2]&0x80 != 0 {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func (s *vpcResolver) exchangeTCP(ctx context.Context, msg []byte, id uint16) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", s.upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := writeTCPMessage(c, msg); err != nil {
		return nil, err
	}
	for {
		resp, err := readTCPMessage(c)
		if err != nil {
			return nil, err
		}
		if len(resp) >= 12 && binary.BigEndian.Uint16(resp[0:2]) == id {
			return resp, nil
		}
	}
}

func writeTCPMessage(w io.Writer, msg []byte) error {
	if len(msg) > vpcResolverTCPMaxMessage {
		return errors.New("message too long")
	}
	b := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(b, uint16(len(msg)))
	copy(b[2:], msg)
	_, err := w.Write(b)
	return err
}

func readTCPMessage(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// --- query logs ---

// queryLogRecord is one Route 53 Resolver query log record.
type queryLogRecord struct {
	Version              string           `json:"version"`
	AccountID            string           `json:"account_id"`
	Region               string           `json:"region"`
	VpcID                string           `json:"vpc_id"`
	QueryTimestamp       string           `json:"query_timestamp"`
	QueryName            string           `json:"query_name"`
	QueryType            string           `json:"query_type"`
	QueryClass           string           `json:"query_class"`
	Rcode                string           `json:"rcode"`
	Answers              []queryLogAnswer `json:"answers"`
	Srcaddr              string           `json:"srcaddr"`
	Srcport              string           `json:"srcport"`
	Transport            string           `json:"transport"`
	FirewallRuleGroupID  string           `json:"firewall_rule_group_id,omitempty"`
	FirewallRuleAction   string           `json:"firewall_rule_action,omitempty"`
	FirewallDomainListID string           `json:"firewall_domain_list_id,omitempty"`
}

type queryLogAnswer struct {
	Rdata string `json:"Rdata"`
	Type  string `json:"Type"`
	Class string `json:"Class"`
}

type queryLogDelivery struct {
	account, group, stream string
	event                  putEvent
}

// queryLogRecordOf is the record of one answered query; matched is the ALERT or BLOCK rule that matched.
func (s *vpcResolver) queryLogRecordOf(in vpcInterface, q query, resp dnsmessage.Message, matched *compiledRule) queryLogRecord {
	account := in.Account
	if account == "" {
		account = awsidentity.Current().AccountID
	}
	rec := queryLogRecord{Version: queryLogVersion, AccountID: account, Region: s.region, VpcID: in.VpcID,
		QueryTimestamp: q.received.UTC().Format("2006-01-02T15:04:05Z"), QueryName: q.question.Name.String(),
		QueryType: dnsTypeName(q.question.Type), QueryClass: dnsClassName(q.question.Class), Rcode: rcodeName(resp.Header.RCode),
		Answers: []queryLogAnswer{}, Srcaddr: q.src, Srcport: strconv.Itoa(q.srcPort), Transport: q.transport}
	for _, a := range resp.Answers {
		rec.Answers = append(rec.Answers, queryLogAnswer{Rdata: rdata(a.Body), Type: dnsTypeName(a.Header.Type), Class: dnsClassName(a.Header.Class)})
	}
	if matched != nil {
		rec.FirewallRuleGroupID, rec.FirewallRuleAction, rec.FirewallDomainListID = matched.GroupID, matched.Action, matched.DomainListID
	}
	return rec
}

// record queues a query's log record for each of the VPC's query log destinations; it never waits.
func (s *vpcResolver) record(in vpcInterface, cfg compiledVPC, q query, resp dnsmessage.Message, matched *compiledRule) {
	if len(cfg.logs) == 0 || s.logs == nil {
		return
	}
	b, err := json.Marshal(s.queryLogRecordOf(in, q, resp, matched))
	if err != nil {
		return
	}
	for _, dest := range cfg.logs {
		account, group, ok := logGroupOfARN(dest.LogGroupARN)
		if !ok {
			continue
		}
		select {
		case s.records <- queryLogDelivery{account: account, group: group, stream: in.VpcID,
			event: putEvent{TsMs: q.received.UnixMilli(), Message: string(b)}}:
		default:
			if s.every("dropped/"+group, 10*time.Second) {
				s.logger.Warn("vpc resolver: query log records are being dropped (delivery is behind)", slog.String("vpc", in.VpcID),
					slog.String("log_group", group))
			}
		}
	}
}

// runDelivery delivers queued query log records every flush interval until ctx ends, then once more.
func (s *vpcResolver) runDelivery(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var batch []queryLogDelivery
	for {
		select {
		case d := <-s.records:
			batch = append(batch, d)
			if len(batch) >= 5000 {
				s.flush(batch)
				batch = nil
			}
		case <-t.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = nil
			}
		case <-ctx.Done():
			for {
				select {
				case d := <-s.records:
					batch = append(batch, d)
					continue
				default:
				}
				break
			}
			if len(batch) > 0 {
				s.flush(batch)
			}
			return
		}
	}
}

// flush writes a batch into its log streams, oldest record first in each.
func (s *vpcResolver) flush(batch []queryLogDelivery) {
	type dest struct{ account, group, stream string }
	byDest := map[dest][]putEvent{}
	var order []dest
	for _, d := range batch {
		k := dest{d.account, d.group, d.stream}
		if _, seen := byDest[k]; !seen {
			order = append(order, k)
		}
		byDest[k] = append(byDest[k], d.event)
	}
	for _, k := range order {
		events := byDest[k]
		sort.SliceStable(events, func(i, j int) bool { return events[i].TsMs < events[j].TsMs })
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.logs.deliver(ctx, k.account, s.region, k.group, k.stream, events)
		cancel()
		if err != nil {
			s.logger.Warn("vpc resolver: query logs could not be delivered", slog.String("log_group", k.group),
				slog.Int("records", len(events)), slog.String("error", err.Error()))
		}
	}
}

// --- names of DNS values, as the query logs write them ---

var dnsTypeNames = map[dnsmessage.Type]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
	99: "SPF", 255: "ANY", 257: "CAA"}

func dnsTypeName(t dnsmessage.Type) string {
	if n, ok := dnsTypeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func dnsClassName(c dnsmessage.Class) string {
	switch c {
	case dnsmessage.ClassINET:
		return "IN"
	case dnsmessage.ClassCHAOS:
		return "CH"
	case dnsmessage.ClassHESIOD:
		return "HS"
	case dnsmessage.ClassANY:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

func rcodeName(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// rdata is a record's value as the query logs write it (an address, a name, "<preference> <exchange>" …).
func rdata(b dnsmessage.ResourceBody) string {
	switch r := b.(type) {
	case *dnsmessage.AResource:
		return net.IP(r.A[:]).String()
	case *dnsmessage.AAAAResource:
		return net.IP(r.AAAA[:]).String()
	case *dnsmessage.CNAMEResource:
		return r.CNAME.String()
	case *dnsmessage.NSResource:
		return r.NS.String()
	case *dnsmessage.PTRResource:
		return r.PTR.String()
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", r.Pref, r.MX.String())
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target.String())
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s %d %d %d %d %d", r.NS.String(), r.MBox.String(), r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
	case *dnsmessage.TXTResource:
		q := make([]string, len(r.TXT))
		for i, t := range r.TXT {
			q[i] = strconv.Quote(t)
		}
		return strings.Join(q, " ")
	case *dnsmessage.UnknownResource:
		return fmt.Sprintf("\\# %d %s", len(r.Data), hex.EncodeToString(r.Data))
	}
	return ""
}

// --- serving ---

// Listen opens the resolver's UDP and TCP sockets on addr (one port for both).
func (s *vpcResolver) Listen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	tcpAddr := addr
	if host, port, err := net.SplitHostPort(addr); err == nil && port == "0" {
		_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
		tcpAddr = net.JoinHostPort(host, p)
	}
	ln, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		_ = pc.Close()
		return err
	}
	s.pc, s.ln = pc, ln
	return nil
}

// Addr is the address the resolver listens on.
func (s *vpcResolver) Addr() string {
	if s.pc == nil {
		return ""
	}
	return s.pc.LocalAddr().String()
}

// Serve answers queries until ctx ends, then closes its sockets and delivers the query logs it holds.
func (s *vpcResolver) Serve(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.runDelivery(ctx, vpcResolverFlushEvery)
		close(done)
	}()
	go func() {
		<-ctx.Done()
		_ = s.pc.Close()
		_ = s.ln.Close()
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.serveUDP(ctx) }()
	go func() { defer wg.Done(); s.serveTCP(ctx) }()
	wg.Wait()
	<-done
}

func (s *vpcResolver) serveUDP(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		select {
		case s.sem <- struct{}{}:
		default:
			continue // too many queries at once: dropped, the client asks again
		}
		go func() {
			defer func() { <-s.sem }()
			if resp := s.answer(ctx, msg, ua.IP.String(), ua.Port, "UDP"); resp != nil {
				_, _ = s.pc.WriteTo(resp, addr)
			}
		}()
	}
}

func (s *vpcResolver) serveTCP(ctx context.Context) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.serveConn(ctx, c)
	}
}

func (s *vpcResolver) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	for ctx.Err() == nil {
		_ = c.SetDeadline(s.now().Add(vpcResolverTCPIdle))
		msg, err := readTCPMessage(c)
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		resp := s.answer(ctx, msg, ta.IP.String(), ta.Port, "TCP")
		<-s.sem
		if resp == nil {
			continue
		}
		_ = c.SetDeadline(s.now().Add(vpcResolverTCPIdle))
		if writeTCPMessage(c, resp) != nil {
			return
		}
	}
}
