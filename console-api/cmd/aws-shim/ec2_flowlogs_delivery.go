// The delivery of VPC Flow Logs (ec2_flowlogs.go): records of the traffic a VPC's security groups reject,
// published to each flow log's CloudWatch Logs log group, one log stream per network interface.
//
// Where the records come from: a VPC security group's NetworkPolicy is annotated for OVN to log the packets
// it drops (ovn.kubernetes.io/enable_log, log_acl_actions "drop"); ovn-controller writes one acl_log line
// per dropped packet to its node's ovs-ovn pod, whose output the log store (Loki) keeps. Only a packet the
// function sent (egress, from-lport) is recorded: a Lambda function's network interface carries only the
// traffic the function starts and accepts no connection, so nothing inbound ever appears on it. Here the
// inbound packets a group drops are Lambda's own (Knative's activator and probes reaching a starting
// execution environment), never the customer's. The source address of an egress packet is an execution
// environment's, and vpcInterfaces says which function's network interface had it then (vpcnet.go). Lines
// whose address is no VPC function's are someone else's and are ignored.
// As on AWS, traffic to the VPC's DNS resolver and Lambda's own service traffic are never recorded: here
// the shim's VPC resolver port (5353) and its Lambda service port (4568).
//
// Records, as AWS makes them: within a flow log's aggregation window (MaxAggregationInterval, from its
// creation), one record per network interface, 5-tuple and action; packets is the number of packets the
// security group dropped (each a logged line: a retransmitted SYN is another packet), start and end the
// first and last of them, bytes 0 — a logged line carries no length, so bytes are not measured. A window
// is published once it has closed and its lines have had time to reach the log store (flowLogSettle; a
// line that reaches it later than that is not recorded, as AWS's delivery is best effort); each record is a
// CloudWatch Logs event at its start time, in the stream "<eni-id>-all" (AWS's name: one combined stream
// per interface and log group).
//
// The delivery role: before delivering, the flow log's DeliverLogsPermissionArn role must exist, trust
// vpc-flow-logs.amazonaws.com (its trust policy's aws:SourceAccount / aws:SourceArn conditions evaluated),
// and its identity policies must allow logs:CreateLogStream and logs:PutLogEvents on the log group
// (logs:CreateLogGroup too while the group does not exist). If not, nothing is delivered — the window's
// records are dropped, as AWS drops them — and DescribeFlowLogs shows DeliverLogsStatus FAILED with
// "Access error"; once the role can deliver again the status is SUCCESS.
//
// One worker delivers, whatever the number of shim replicas: the one holding a Postgres advisory lock. Its
// cursor is each flow log's published_until_ns (the end of the last published window), so a new worker —
// after a restart or a failover — reads the log store again from the oldest cursor and publishes each
// window exactly once. A window's records and its cursor are written in two commits, one after the other
// and never interrupted by a shutdown; only a crash between the two would publish that one window again.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	flowLogLockKey int64 = 0x666c6f776c6f6773 // "flowlogs": one delivery worker across the shim's replicas
	flowLogTick          = 15 * time.Second
	// flowLogSettle is how long a logged packet's line is given to reach the log store before the windows
	// up to it are published.
	flowLogSettle   = 60 * time.Second
	flowLogMaxPages = 20 // log-store pages read per cycle; a backlog is caught up over cycles
	// flowLogQuery selects OVN's acl_log lines (FLOW_LOGS_LOKI_QUERY overrides it).
	flowLogQuery      = `{namespace="kube-system",app="ovs",container="openvswitch"} |= "acl_log"`
	vpcResolverPort   = 5353 // the shim's VPC resolver (Route 53 Resolver)
	lambdaServicePort = 4568 // the shim's Lambda service port, which execution environments reach
)

// --- one logged packet ---

// aclPacket is one OVN acl_log line: a packet a NetworkPolicy allowed or dropped.
type aclPacket struct {
	Name             string // "<namespace>/<networkpolicy>"
	Verdict          string // allow, drop or reject
	Egress           bool   // from-lport: the pod sent it; to-lport: the pod was to receive it
	Proto            int    // IANA protocol number
	IPv6             bool
	Src, Dst         string
	SrcPort, DstPort int // 0 for ICMP, as AWS records it
	TCPFlags         int // AWS's tcp-flags bitmask (FIN 1, SYN 2, RST 4, SYN-ACK 18)
}

// parseACLLog parses one acl_log line, e.g.
//
//	…|acl_log(ovn_pinctrl0)|INFO|name="ns/deny-egress", verdict=drop, severity=warning, direction=from-lport: tcp,vlan_tci=0x0000,dl_src=…,dl_dst=…,nw_src=10.17.0.2,nw_dst=203.0.113.50,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,tp_src=41391,tp_dst=443,tcp_flags=syn
//
// false for anything else.
func parseACLLog(line string) (aclPacket, bool) {
	i := strings.Index(line, "acl_log(")
	if i < 0 {
		return aclPacket{}, false
	}
	rest := line[i:]
	j := strings.Index(rest, "name=")
	if j < 0 {
		return aclPacket{}, false
	}
	rest = rest[j:]
	k := strings.Index(rest, ": ")
	if k < 0 {
		return aclPacket{}, false
	}
	var p aclPacket
	for _, kv := range strings.Split(rest[:k], ", ") {
		key, val, _ := strings.Cut(strings.TrimSpace(kv), "=")
		switch key {
		case "name":
			p.Name = strings.Trim(val, `"`)
		case "verdict":
			p.Verdict = val
		case "direction":
			switch val {
			case "from-lport":
				p.Egress = true
			case "to-lport":
			default:
				return aclPacket{}, false
			}
		}
	}
	parts := strings.Split(strings.TrimSpace(rest[k+2:]), ",")
	fields := map[string]string{}
	for _, kv := range parts[1:] {
		if key, val, ok := strings.Cut(kv, "="); ok {
			fields[key] = val
		}
	}
	switch parts[0] {
	case "tcp", "tcp6":
		p.Proto = 6
	case "udp", "udp6":
		p.Proto = 17
	case "sctp", "sctp6":
		p.Proto = 132
	case "icmp":
		p.Proto = 1
	case "icmp6":
		p.Proto = 58
	case "ip", "ipv6":
		n, err := strconv.Atoi(fields["nw_proto"])
		if err != nil {
			return aclPacket{}, false
		}
		p.Proto = n
	default:
		return aclPacket{}, false
	}
	p.IPv6 = strings.HasSuffix(parts[0], "6")
	if p.IPv6 {
		p.Src, p.Dst = fields["ipv6_src"], fields["ipv6_dst"]
	} else {
		p.Src, p.Dst = fields["nw_src"], fields["nw_dst"]
	}
	if net.ParseIP(p.Src) == nil || net.ParseIP(p.Dst) == nil {
		return aclPacket{}, false
	}
	if p.Proto == 6 || p.Proto == 17 || p.Proto == 132 {
		p.SrcPort, _ = strconv.Atoi(fields["tp_src"])
		p.DstPort, _ = strconv.Atoi(fields["tp_dst"])
	}
	if p.Proto == 6 {
		p.TCPFlags = awsTCPFlags(fields["tcp_flags"])
	}
	return p, p.Verdict != ""
}

// awsTCPFlags is AWS's tcp-flags value for a packet's flags as OVS prints them ("syn", "syn|ack",
// "fin|ack", "+syn+ack"): FIN 1, SYN 2, RST 4, and 18 for SYN-ACK; other flags count for nothing.
func awsTCPFlags(s string) int {
	// "a|b" and "+a+b" set a and b; "-b" (the masked form) says b is clear.
	has := map[string]bool{}
	set := true
	var tok strings.Builder
	flush := func() {
		if tok.Len() > 0 {
			has[tok.String()] = set
			tok.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '|', '+':
			flush()
			set = true
		case '-':
			flush()
			set = false
		default:
			tok.WriteRune(r)
		}
	}
	flush()
	v := 0
	if has["fin"] {
		v |= 1
	}
	if has["syn"] {
		v |= 2
		if has["ack"] {
			v |= 16
		}
	}
	if has["rst"] {
		v |= 4
	}
	return v
}

// action is the flow log action of a packet's verdict: REJECT for one the security group dropped.
func (p aclPacket) action() string {
	switch p.Verdict {
	case "drop", "reject":
		return "REJECT"
	}
	return "" // an allowed packet is not recorded (only rejected traffic is logged; see ec2_flowlogs.go)
}

// serviceFlow reports whether a packet is the VPC resolver's or Lambda's own service traffic, which AWS
// never records: to (or, coming back, from) the shim's resolver port or its Lambda service port. shim is
// the shim's addresses; when they are not known (known false), the ports alone decide.
func serviceFlow(p aclPacket, shim map[string]bool, known bool) bool {
	peer, port := p.Dst, p.DstPort
	if !p.Egress {
		peer, port = p.Src, p.SrcPort
	}
	if known && !shim[peer] {
		return false
	}
	switch port {
	case vpcResolverPort:
		return p.Proto == 6 || p.Proto == 17
	case lambdaServicePort:
		return p.Proto == 6
	}
	return false
}

// --- records ---

// flowKey is what one record aggregates: an interface's flow (5-tuple) and its action.
type flowKey struct {
	ENI, Src, Dst          string
	SrcPort, DstPort, Prot int
	Action                 string
}

type flowRecord struct {
	key             flowKey
	iface           vpcInterface
	egress, ipv6    bool
	packets         int64
	firstNs, lastNs int64
	tcpFlags        int
}

func (r *flowRecord) add(tsNs int64, flags int) {
	r.packets++
	if r.firstNs == 0 || tsNs < r.firstNs {
		r.firstNs = tsNs
	}
	if tsNs > r.lastNs {
		r.lastNs = tsNs
	}
	r.tcpFlags |= flags
}

// formatFlowRecord is a record in a flow log's format (fields, of version), as AWS writes it: fields
// separated by spaces, "-" for one that does not apply.
func formatFlowRecord(fields []string, version int, r *flowRecord, region, zoneID string) string {
	out := make([]string, len(fields))
	for i, f := range fields {
		var v string
		switch f {
		case "version":
			v = strconv.Itoa(version)
		case "account-id":
			v = r.iface.Account
		case "interface-id":
			v = r.key.ENI
		case "srcaddr", "pkt-srcaddr":
			v = r.key.Src
		case "dstaddr", "pkt-dstaddr":
			v = r.key.Dst
		case "srcport":
			v = strconv.Itoa(r.key.SrcPort)
		case "dstport":
			v = strconv.Itoa(r.key.DstPort)
		case "protocol":
			v = strconv.Itoa(r.key.Prot)
		case "packets":
			v = strconv.FormatInt(r.packets, 10)
		case "bytes":
			v = "0" // a logged packet carries no length: bytes are not measured
		case "start":
			v = strconv.FormatInt(r.firstNs/int64(time.Second), 10)
		case "end":
			v = strconv.FormatInt(r.lastNs/int64(time.Second), 10)
		case "action":
			v = r.key.Action
		case "log-status":
			v = "OK"
		case "vpc-id":
			v = r.iface.VpcID
		case "subnet-id":
			v = r.iface.SubnetID
		case "tcp-flags":
			v = strconv.Itoa(r.tcpFlags)
		case "type":
			v = "IPv4"
			if r.ipv6 {
				v = "IPv6"
			}
		case "region":
			v = region
		case "az-id":
			v = zoneID
		case "flow-direction":
			v = "ingress"
			if r.egress {
				v = "egress"
			}
		}
		// instance-id ("-": a requester-managed interface has no instance of the account's), the sublocation
		// fields (none) and anything empty.
		if v == "" {
			v = "-"
		}
		out[i] = v
	}
	return strings.Join(out, " ")
}

// --- the worker ---

// lokiRanger is the log store's range query (lokiClient.queryRange).
type lokiRanger interface {
	queryRange(ctx context.Context, query string, start, end int64, limit int, forward bool) ([]lokiEntry, error)
}

// interfaceAt says which function's network interface had an address at a time (vpcInterfaces.At).
type interfaceAt interface {
	At(ip string, t time.Time) (vpcInterface, bool)
}

type flowLogDelivery struct {
	db      *sql.DB
	loki    lokiRanger
	query   string
	limit   int // log-store lines per page
	ifaces  interfaceAt
	deliver func(ctx context.Context, account, region, group, stream string, events []putEvent) error
	// role reports whether a flow log's delivery role may deliver to its log group (flowLogRoles.check).
	role func(ctx context.Context, fl ec2FlowLog) (bool, string)
	// shimIPs is the shim's addresses (the VPC resolver's endpoints); ok false when they are not known.
	shimIPs        func(ctx context.Context) (map[string]bool, bool)
	region, zoneID string
	logger         *slog.Logger
	now            func() time.Time
	tick, settle   time.Duration
}

// newFlowLogWorker is the flow logs' delivery worker, or nil while something it needs is not configured:
// the shared store, CloudWatch Logs, the Lambda VPC subnet's interfaces, or the log store (LOKI_URL=off).
// FLOW_LOGS_LOKI_QUERY overrides the LogQL selecting OVN's acl_log lines.
func newFlowLogWorker(h *ec2Handler, db *sql.DB, cwl *cwlStore, ifaces *vpcInterfaces, dyn dynamic.Interface, cs kubernetes.Interface,
	authz *dataplaneauthz.Checker, dir *accounts.Directory, rolesNS string, logger *slog.Logger) *flowLogDelivery {
	lokiURL := getenv("LOKI_URL", "http://loki.monitoring.svc.cluster.local:3100")
	if h == nil || db == nil || cwl == nil || ifaces == nil || lokiURL == "off" {
		return nil
	}
	roles := &flowLogRoles{authz: authz, home: rolesNS, region: h.region(),
		groups: func(ctx context.Context, account, group string) (bool, error) {
			_, ok, err := cwl.getGroup(ctx, accountKeyFor(account, group))
			return ok, err
		}}
	if dyn != nil {
		roles.roles = &dynRoleResolver{dyn: dyn, ns: rolesNS}
	}
	if dir != nil {
		roles.homeOf = dir.HomeOf
	}
	d := &flowLogDelivery{db: db, query: getenv("FLOW_LOGS_LOKI_QUERY", flowLogQuery), ifaces: ifaces, deliver: cwl.deliver,
		loki: &lokiClient{base: strings.TrimRight(lokiURL, "/"), http: &http.Client{Timeout: 20 * time.Second}},
		role: roles.check, region: h.region(), zoneID: h.zoneID(), logger: logger, now: time.Now, tick: flowLogTick, settle: flowLogSettle}
	if cs != nil {
		ep := &vpcResolverEndpoints{cs: cs, ns: getenv("POD_NAMESPACE", "open-infra-aws-shim"), svc: "vpc-resolver", logger: logger}
		d.shimIPs = ep.get
	}
	return d
}

// flowLogRun is the worker's state for one flow log.
type flowLogRun struct {
	fl                  ec2FlowLog
	fields              []string
	version             int
	published, ingested int64 // ns: windows published up to; lines aggregated up to
	persisted           int64 // the cursor the store holds
	windows             map[int64]map[flowKey]*flowRecord
	sent                map[int64]map[string]bool // window -> streams delivered (a retry skips them)
}

type flowLogState struct {
	runs map[string]*flowLogRun
}

func newFlowLogState() *flowLogState { return &flowLogState{runs: map[string]*flowLogRun{}} }

// Run delivers until ctx ends, while this replica holds the advisory lock; another replica waits for it.
func (d *flowLogDelivery) Run(ctx context.Context) {
	if d == nil || d.db == nil {
		return
	}
	for ctx.Err() == nil {
		d.lead(ctx)
		sleepCtx(ctx, d.tick)
	}
}

// lead takes the lock on a connection of its own and delivers on it until the connection fails or ctx ends.
func (d *flowLogDelivery) lead(ctx context.Context) {
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, flowLogLockKey).Scan(&got); err != nil || !got {
		return
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(uctx, `SELECT pg_advisory_unlock($1)`, flowLogLockKey)
	}()
	if d.logger != nil {
		d.logger.Info("ec2 flow logs: delivering (this replica holds the delivery lock)")
	}
	st := newFlowLogState()
	for {
		if err := d.cycle(ctx, conn, st); err != nil && ctx.Err() == nil {
			if d.logger != nil {
				d.logger.Warn("ec2 flow logs: delivery cycle failed", slog.String("error", err.Error()))
			}
			if perr := conn.PingContext(ctx); perr != nil {
				return // the lock's connection is gone: so is the lock
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.tick):
		}
	}
}

// cycle reads the log store from the oldest cursor to settle ago, aggregates, and publishes every window
// that has closed.
func (d *flowLogDelivery) cycle(ctx context.Context, q sqlQueryer, st *flowLogState) error {
	fls, err := listAllFlowLogs(ctx, q)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, fl := range fls {
		present[fl.ID] = true
		run := st.runs[fl.ID]
		if run == nil || fl.PublishedUntil > run.published {
			// New here, or moved on by another worker: start again from the store's cursor.
			fields, version, msg := parseFlowLogFormat(fl.LogFormat)
			if msg != "" {
				continue // never stored: CreateFlowLogs refuses a format it cannot record
			}
			run = &flowLogRun{fields: fields, version: version, published: fl.PublishedUntil, ingested: fl.PublishedUntil,
				windows: map[int64]map[flowKey]*flowRecord{}, sent: map[int64]map[string]bool{}}
			st.runs[fl.ID] = run
		}
		run.fl = fl
		run.persisted = fl.PublishedUntil
	}
	for id := range st.runs {
		if !present[id] {
			delete(st.runs, id)
		}
	}
	if len(st.runs) == 0 {
		return nil
	}
	to := d.now().Add(-d.settle).UnixNano()
	from := int64(-1)
	for _, run := range st.runs {
		if from < 0 || run.ingested < from {
			from = run.ingested
		}
	}
	var readErr error
	if from < to {
		shim, known := map[string]bool(nil), false
		if d.shimIPs != nil {
			shim, known = d.shimIPs(ctx)
		}
		reached, err := d.read(ctx, from, to, func(e lokiEntry) { d.ingest(st, e, shim, known) })
		readErr = err
		for _, run := range st.runs {
			if reached > run.ingested {
				run.ingested = reached
			}
		}
	}
	ids := make([]string, 0, len(st.runs))
	for id := range st.runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := d.publish(ctx, q, st, st.runs[id]); err != nil {
			return err
		}
	}
	return readErr
}

// read pages through the log store's lines in [from, to), oldest first, handing each to fn once, and
// returns how far it read (to, unless it stopped early). A full page's last instant is left to the next
// page, which starts there, so no line is handed over twice and none is skipped.
func (d *flowLogDelivery) read(ctx context.Context, from, to int64, fn func(lokiEntry)) (int64, error) {
	limit := d.limit
	if limit <= 0 {
		limit = lokiMaxEntries
	}
	start := from
	for page := 0; page < flowLogMaxPages; page++ {
		es, err := d.loki.queryRange(ctx, d.query, start, to, limit, true)
		if err != nil {
			return start, err
		}
		if len(es) < limit {
			for _, e := range es {
				if e.TsNs >= start && e.TsNs < to {
					fn(e)
				}
			}
			return to, nil
		}
		last := es[len(es)-1].TsNs
		if last <= start {
			// A whole page in one instant: take it and step past it.
			for _, e := range es {
				if e.TsNs >= start && e.TsNs < to {
					fn(e)
				}
			}
			start++
			continue
		}
		for _, e := range es {
			if e.TsNs >= start && e.TsNs < last {
				fn(e)
			}
		}
		start = last
	}
	return start, nil
}

// ingest attributes one line to the function interface that sent its packet, and adds it to the window of
// each flow log that records it. An inbound packet is never recorded: a function accepts no connection, and
// what a group drops inbound is Lambda's own traffic (see the top of this file).
func (d *flowLogDelivery) ingest(st *flowLogState, e lokiEntry, shim map[string]bool, known bool) {
	p, ok := parseACLLog(e.Line)
	if !ok || !p.Egress {
		return
	}
	action := p.action()
	if action == "" {
		return
	}
	in, ok := d.ifaces.At(p.Src, time.Unix(0, e.TsNs))
	if !ok || serviceFlow(p, shim, known) {
		return
	}
	key := flowKey{ENI: in.ENI, Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort, Prot: p.Proto, Action: action}
	for _, run := range st.runs {
		if e.TsNs < run.ingested || !run.fl.covers(in) || !run.fl.records(action) {
			continue
		}
		w := int64(run.fl.MaxAggregation) * int64(time.Second)
		ws := run.published + (e.TsNs-run.published)/w*w
		recs := run.windows[ws]
		if recs == nil {
			recs = map[flowKey]*flowRecord{}
			run.windows[ws] = recs
		}
		r := recs[key]
		if r == nil {
			r = &flowRecord{key: key, iface: in, egress: p.Egress, ipv6: p.IPv6}
			recs[key] = r
		}
		r.add(e.TsNs, p.TCPFlags)
	}
}

// publish delivers each of a flow log's closed windows and moves its cursor past it.
func (d *flowLogDelivery) publish(ctx context.Context, q sqlQueryer, st *flowLogState, run *flowLogRun) error {
	w := int64(run.fl.MaxAggregation) * int64(time.Second)
	if w <= 0 {
		return nil
	}
	// The pair (records, cursor) is never split by a shutdown.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	checked, allowed := false, false
	for run.published+w <= run.ingested {
		ws := run.published
		if recs := run.windows[ws]; len(recs) > 0 {
			if !checked {
				checked = true
				why := ""
				allowed, why = d.role(wctx, run.fl)
				if err := d.recordStatus(wctx, q, run, allowed, why); err != nil {
					return err
				}
			}
			if allowed {
				if err := d.deliverWindow(wctx, run, ws, recs); err != nil {
					return err // kept for the next cycle; the streams already delivered are not delivered again
				}
			}
			// A window the role could not deliver is dropped, as on AWS.
			moved, err := advanceFlowLog(wctx, q, run.fl.ID, run.persisted, ws+w)
			if err != nil {
				return err
			}
			if !moved {
				delete(st.runs, run.fl.ID) // deleted, or another worker's: the next cycle reads the store again
				return nil
			}
			run.persisted = ws + w
		}
		run.published = ws + w
		delete(run.windows, ws)
		delete(run.sent, ws)
	}
	if run.published != run.persisted {
		moved, err := advanceFlowLog(wctx, q, run.fl.ID, run.persisted, run.published)
		if err != nil {
			return err
		}
		if !moved {
			delete(st.runs, run.fl.ID)
			return nil
		}
		run.persisted = run.published
	}
	return nil
}

// recordStatus records a change of a flow log's delivery status.
func (d *flowLogDelivery) recordStatus(ctx context.Context, q sqlQueryer, run *flowLogRun, allowed bool, why string) error {
	status, msg := "SUCCESS", ""
	if !allowed {
		status, msg = "FAILED", flowLogAccessError
	}
	if run.fl.DeliverStatus == status && run.fl.DeliverError == msg {
		return nil
	}
	if d.logger != nil {
		if allowed {
			d.logger.Info("ec2 flow logs: the delivery role can deliver again", slog.String("flowLog", run.fl.ID))
		} else {
			d.logger.Warn("ec2 flow logs: the delivery role cannot deliver", slog.String("flowLog", run.fl.ID),
				slog.String("role", run.fl.DeliverRole), slog.String("reason", why))
		}
	}
	if err := setFlowLogStatus(ctx, q, run.fl.ID, status, msg); err != nil {
		return err
	}
	run.fl.DeliverStatus, run.fl.DeliverError = status, msg
	return nil
}

// deliverWindow writes one window's records, each interface's into its stream, oldest first.
func (d *flowLogDelivery) deliverWindow(ctx context.Context, run *flowLogRun, ws int64, recs map[flowKey]*flowRecord) error {
	byENI := map[string][]*flowRecord{}
	for _, r := range recs {
		byENI[r.key.ENI] = append(byENI[r.key.ENI], r)
	}
	enis := make([]string, 0, len(byENI))
	for e := range byENI {
		enis = append(enis, e)
	}
	sort.Strings(enis)
	if run.sent[ws] == nil {
		run.sent[ws] = map[string]bool{}
	}
	for _, eni := range enis {
		stream := eni + "-all"
		if run.sent[ws][stream] {
			continue
		}
		rs := byENI[eni]
		events := make([]putEvent, len(rs))
		for i, r := range rs {
			events[i] = putEvent{TsMs: r.firstNs / int64(time.Second) * 1000, // the record's start, as AWS stamps it
				Message: formatFlowRecord(run.fields, run.version, r, d.region, d.zoneID)}
		}
		sort.SliceStable(events, func(i, j int) bool {
			if events[i].TsMs != events[j].TsMs {
				return events[i].TsMs < events[j].TsMs
			}
			return events[i].Message < events[j].Message
		})
		if err := d.deliver(ctx, run.fl.Account, d.region, run.fl.LogGroup, stream, events); err != nil {
			return err
		}
		run.sent[ws][stream] = true
	}
	return nil
}

// --- the delivery role ---

// flowLogRoles decides whether a flow log's delivery role may deliver to its log group.
type flowLogRoles struct {
	roles  roleResolverIn
	authz  *dataplaneauthz.Checker
	groups func(ctx context.Context, account, group string) (bool, error) // whether the log group exists
	home   string                                                         // the IAM home: the management account's roles
	homeOf func(account string) (string, bool)                            // a member account's home
	region string
}

func (c *flowLogRoles) check(ctx context.Context, fl ec2FlowLog) (bool, string) {
	if !roleARNRe.MatchString(fl.DeliverRole) {
		return false, "not an IAM role ARN"
	}
	acct := strings.Split(fl.DeliverRole, ":")[4]
	if acct != fl.Account {
		return false, "the role is another account's"
	}
	name := roleNameOf(fl.DeliverRole)
	ns := c.home
	if ns == "" {
		ns = dataplaneauthz.DefaultHomeNamespace
	}
	if !awsidentity.Current().IsManagement(acct) {
		home, ok := "", false
		if c.homeOf != nil {
			home, ok = c.homeOf(acct)
		}
		if !ok || home == "" {
			return false, "the account has no home namespace"
		}
		ns = home
	}
	if c.roles == nil {
		return false, "roles cannot be read on this shim"
	}
	rr, ok := c.roles.ResolveIn(ctx, ns, name)
	if !ok {
		return false, "the role does not exist"
	}
	if !trustsService(rr.trust, flowLogsService) {
		return false, "the role does not trust " + flowLogsService
	}
	if ok, why := flowLogTrustConditions(rr.trustDoc, fl.Account, fl.ARN(c.region)); !ok {
		return false, why
	}
	if c.authz == nil {
		return true, "" // no IAM policy world to evaluate the role's policies in: its trust decides
	}
	p := iamauthz.Principal{Account: acct, Type: iamauthz.Role, ID: dataplaneauthz.QualifiedName(c.home, ns, strings.ToLower(name))}
	group := "arn:aws:logs:" + c.region + ":" + acct + ":log-group:" + fl.LogGroup
	checks := []struct{ action, resource string }{
		{"logs:CreateLogStream", group + ":log-stream:*"},
		{"logs:PutLogEvents", group + ":log-stream:*"},
	}
	if c.groups != nil {
		if exists, err := c.groups(ctx, acct, fl.LogGroup); err == nil && !exists {
			checks = append(checks, struct{ action, resource string }{"logs:CreateLogGroup", group})
		}
	}
	for _, ch := range checks {
		if d := c.authz.IAM().Authorize(ctx, p, ch.action, ch.resource, nil, iamauthz.WithResourceAccount(acct)); !d.Allowed {
			return false, "the role's policies do not allow " + ch.action + " on " + ch.resource + ": " + d.Reason
		}
	}
	return true, ""
}

// flowLogTrustConditions evaluates a delivery role's trust policy conditions on its statements that name
// the flow logs service, as AWS recommends writing them against the confused deputy: aws:SourceAccount
// (the flow log's account) and aws:SourceArn (its ARN), with StringEquals, StringLike, ArnEquals or
// ArnLike. A document with no condition adds nothing to spec.trust; an Allow with a condition on anything
// else grants nothing, a Deny naming the service denies whatever its condition, and a document that does
// not parse allows nothing.
func flowLogTrustConditions(doc, account, flowLogARN string) (bool, string) {
	if strings.TrimSpace(doc) == "" {
		return true, ""
	}
	var d struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(doc), &d) != nil {
		return false, "the role's trust policy does not parse"
	}
	type stmt struct {
		Effect    string
		Principal any
		Action    any
		Condition map[string]map[string]any
	}
	var stmts []stmt
	if json.Unmarshal(d.Statement, &stmts) != nil {
		var one stmt
		if json.Unmarshal(d.Statement, &one) != nil {
			return false, "the role's trust policy does not parse"
		}
		stmts = []stmt{one}
	}
	conditioned := false
	for _, s := range stmts {
		if len(s.Condition) > 0 {
			conditioned = true
		}
	}
	if !conditioned {
		return true, ""
	}
	values := map[string]string{"aws:sourceaccount": account, "aws:sourcearn": flowLogARN}
	met := func(cond map[string]map[string]any) (ok, evaluable bool) {
		for op, keys := range cond {
			for key, want := range keys {
				have, known := values[strings.ToLower(key)]
				if !known {
					return false, false
				}
				var pats []string
				switch v := want.(type) {
				case string:
					pats = []string{v}
				case []any:
					for _, x := range v {
						if s, ok := x.(string); ok {
							pats = append(pats, s)
						}
					}
				}
				var match bool
				switch op {
				case "StringEquals", "ArnEquals":
					for _, pat := range pats {
						match = match || pat == have
					}
				case "StringLike", "ArnLike":
					for _, pat := range pats {
						match = match || ec2Glob(pat, have)
					}
				default:
					return false, false
				}
				if !match {
					return false, true
				}
			}
		}
		return true, true
	}
	allowed := false
	for _, s := range stmts {
		if !namesService(s.Principal, flowLogsService) || !allowsAssume(s.Action) {
			continue
		}
		ok, evaluable := met(s.Condition)
		if strings.EqualFold(s.Effect, "Deny") {
			if ok || !evaluable {
				return false, "the role's trust policy denies " + flowLogsService
			}
			continue
		}
		if ok && evaluable {
			allowed = true
		}
	}
	if !allowed {
		return false, "the role's trust policy conditions do not allow " + flowLogsService + " for this flow log"
	}
	return true, ""
}

// namesService reports whether a trust statement's Principal names service ("*", or {"Service": …}).
func namesService(p any, service string) bool {
	switch v := p.(type) {
	case string:
		return v == "*"
	case map[string]any:
		switch s := v["Service"].(type) {
		case string:
			return s == service
		case []any:
			for _, x := range s {
				if x == service {
					return true
				}
			}
		}
	}
	return false
}

// allowsAssume reports whether a trust statement's Action covers sts:AssumeRole.
func allowsAssume(a any) bool {
	switch v := a.(type) {
	case string:
		return v == "sts:AssumeRole" || v == "sts:*" || v == "*"
	case []any:
		for _, x := range v {
			if s, _ := x.(string); allowsAssume(s) {
				return true
			}
		}
	}
	return false
}

// --- the shim's own addresses ---

// vpcResolverEndpoints is the shim's addresses, as the VPC resolver Service's endpoints list them (every
// shim pod serves the resolver and the Lambda service port), re-read each minute.
type vpcResolverEndpoints struct {
	cs      kubernetes.Interface
	ns, svc string
	logger  *slog.Logger

	mu     sync.Mutex
	ips    map[string]bool
	ok     bool
	at     time.Time
	warned bool
}

func (r *vpcResolverEndpoints) get(ctx context.Context) (map[string]bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.at) < time.Minute {
		return r.ips, r.ok
	}
	r.at = time.Now()
	l, err := r.cs.DiscoveryV1().EndpointSlices(r.ns).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + r.svc})
	if err != nil {
		if !r.warned && r.logger != nil {
			r.warned = true
			r.logger.Warn("ec2 flow logs: the VPC resolver's endpoints cannot be read; resolver and Lambda service flows are recognized by port alone",
				slog.String("error", err.Error()))
		}
		return r.ips, r.ok
	}
	ips := map[string]bool{}
	for _, s := range l.Items {
		for _, ep := range s.Endpoints {
			for _, a := range ep.Addresses {
				ips[a] = true
			}
		}
	}
	r.ips, r.ok = ips, len(ips) > 0
	return r.ips, r.ok
}
