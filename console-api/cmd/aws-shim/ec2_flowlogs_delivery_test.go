package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

const flAccount = "111122223333"

// aclLine is an acl_log line as ovn-controller writes it (the shape verified on the cluster).
func aclLine(at time.Time, verdict, direction, flow string) string {
	return at.UTC().Format("2006-01-02T15:04:05.000Z") + `|00007|acl_log(ovn_pinctrl0)|INFO|name="fn-ns/sg-web", verdict=` + verdict +
		`, severity=warning, direction=` + direction + `: ` + flow
}

func tcpFlow(src, dst string, sport, dport int, flags string) string {
	return fmt.Sprintf("tcp,vlan_tci=0x0000,dl_src=0a:58:0a:11:00:05,dl_dst=0a:58:0a:11:00:01,nw_src=%s,nw_dst=%s,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,tp_src=%d,tp_dst=%d,tcp_flags=%s",
		src, dst, sport, dport, flags)
}

func udpFlow(src, dst string, sport, dport int) string {
	return fmt.Sprintf("udp,vlan_tci=0x0000,dl_src=0a:58:0a:11:00:01,dl_dst=0a:58:0a:11:00:06,nw_src=%s,nw_dst=%s,nw_tos=0,nw_ecn=0,nw_ttl=63,nw_frag=no,tp_src=%d,tp_dst=%d",
		src, dst, sport, dport)
}

func icmpFlow(src, dst string) string {
	return "icmp,vlan_tci=0x0000,dl_src=0a:58:0a:11:00:06,dl_dst=0a:58:0a:11:00:01,nw_src=" + src + ",nw_dst=" + dst +
		",nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,icmp_type=8,icmp_code=0"
}

// The acl_log lines OVN writes: egress (from-lport) and ingress (to-lport), drop and allow, TCP, UDP, ICMP
// and IPv6; anything else is no packet.
func TestParseACLLog(t *testing.T) {
	at := time.Date(2026, 11, 8, 16, 59, 44, 920e6, time.UTC)
	real := `2026-11-08T16:59:44.920Z|00007|acl_log(ovn_pinctrl0)|INFO|name="fn-ns/deny-egress", verdict=drop, severity=warning, direction=from-lport: tcp,vlan_tci=0x0000,dl_src=0a:58:0a:11:00:cf,dl_dst=0a:58:0a:11:00:01,nw_src=10.17.0.207,nw_dst=198.51.100.7,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,tp_src=41391,tp_dst=443,tcp_flags=syn`
	for _, c := range []struct {
		name, line string
		want       aclPacket
	}{
		{"egress tcp drop (the shape of a line from a cluster)", real, aclPacket{Name: "fn-ns/deny-egress", Verdict: "drop", Egress: true, Proto: 6,
			Src: "10.17.0.207", Dst: "198.51.100.7", SrcPort: 41391, DstPort: 443, TCPFlags: 2}},
		{"ingress udp drop", aclLine(at, "drop", "to-lport", udpFlow("192.0.2.10", "10.17.0.6", 53000, 9999)),
			aclPacket{Name: "fn-ns/sg-web", Verdict: "drop", Proto: 17, Src: "192.0.2.10", Dst: "10.17.0.6", SrcPort: 53000, DstPort: 9999}},
		{"egress icmp drop: ports 0", aclLine(at, "drop", "from-lport", icmpFlow("10.17.0.6", "203.0.113.9")),
			aclPacket{Name: "fn-ns/sg-web", Verdict: "drop", Egress: true, Proto: 1, Src: "10.17.0.6", Dst: "203.0.113.9"}},
		{"egress tcp allow, SYN-ACK", strings.Replace(aclLine(at, "allow", "from-lport", tcpFlow("10.17.0.5", "198.51.100.8", 80, 40000, "syn|ack")),
			`name="fn-ns/sg-web"`, `name="np/sg-web.fn-ns/egress/IPv4/0"`, 1),
			aclPacket{Name: "np/sg-web.fn-ns/egress/IPv4/0", Verdict: "allow", Egress: true, Proto: 6, Src: "10.17.0.5", Dst: "198.51.100.8",
				SrcPort: 80, DstPort: 40000, TCPFlags: 18}},
		{"IPv6 tcp drop", aclLine(at, "drop", "from-lport", "tcp6,vlan_tci=0x0000,dl_src=0a:58:0a:11:00:05,dl_dst=0a:58:0a:11:00:01,ipv6_src=fd00:10:17::5,ipv6_dst=2001:db8::7,ipv6_label=0x00000,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,tp_src=40000,tp_dst=443,tcp_flags=fin|ack"),
			aclPacket{Name: "fn-ns/sg-web", Verdict: "drop", Egress: true, Proto: 6, IPv6: true, Src: "fd00:10:17::5", Dst: "2001:db8::7",
				SrcPort: 40000, DstPort: 443, TCPFlags: 1}},
	} {
		got, ok := parseACLLog(c.line)
		if !ok || got != c.want {
			t.Errorf("%s: got %+v (ok %v), want %+v", c.name, got, ok, c.want)
		}
	}
	for _, line := range []string{
		"2026-11-08T16:59:44.920Z|00008|binding|INFO|Claiming lport x for this chassis.",
		aclLine(at, "drop", "sideways", tcpFlow("10.17.0.5", "198.51.100.7", 1, 2, "syn")),
		aclLine(at, "drop", "from-lport", "arp,vlan_tci=0x0000,dl_src=0a:58:0a:11:00:05,arp_spa=10.17.0.5"),
		aclLine(at, "drop", "from-lport", tcpFlow("not-an-ip", "198.51.100.7", 1, 2, "syn")),
	} {
		if p, ok := parseACLLog(line); ok {
			t.Errorf("not a packet, parsed as %+v: %s", p, line)
		}
	}
	if (aclPacket{Verdict: "allow"}).action() != "" || (aclPacket{Verdict: "drop"}).action() != "REJECT" || (aclPacket{Verdict: "reject"}).action() != "REJECT" {
		t.Error("only a dropped (or rejected) packet is recorded, as REJECT")
	}
}

func TestAWSTCPFlags(t *testing.T) {
	for in, want := range map[string]int{"syn": 2, "syn|ack": 18, "ack": 0, "fin|ack": 1, "rst": 4, "rst|ack": 4, "psh|ack": 0,
		"+syn+ack": 18, "+syn-ack": 2, "": 0, "fin|syn": 3} {
		if got := awsTCPFlags(in); got != want {
			t.Errorf("tcp_flags=%q: %d, want %d", in, got, want)
		}
	}
}

// The VPC resolver's and Lambda's own traffic is never recorded, as on AWS; the same ports elsewhere are.
func TestServiceFlow(t *testing.T) {
	shim := map[string]bool{"10.42.0.20": true}
	for _, c := range []struct {
		p     aclPacket
		known bool
		want  bool
	}{
		{aclPacket{Egress: true, Proto: 17, Src: "10.17.0.5", Dst: "10.42.0.20", DstPort: 5353}, true, true},
		{aclPacket{Egress: true, Proto: 6, Src: "10.17.0.5", Dst: "10.42.0.20", DstPort: 5353}, true, true},
		{aclPacket{Egress: true, Proto: 6, Src: "10.17.0.5", Dst: "10.42.0.20", DstPort: 4568}, true, true},
		{aclPacket{Egress: true, Proto: 17, Src: "10.17.0.5", Dst: "10.42.0.20", DstPort: 4568}, true, false},
		{aclPacket{Egress: false, Proto: 17, Src: "10.42.0.20", Dst: "10.17.0.5", SrcPort: 5353, DstPort: 40000}, true, true},
		{aclPacket{Egress: true, Proto: 17, Src: "10.17.0.5", Dst: "198.51.100.7", DstPort: 5353}, true, false},
		{aclPacket{Egress: true, Proto: 6, Src: "10.17.0.5", Dst: "10.42.0.20", DstPort: 443}, true, false},
		// The shim's addresses unknown: the ports alone decide.
		{aclPacket{Egress: true, Proto: 17, Src: "10.17.0.5", Dst: "198.51.100.7", DstPort: 5353}, false, true},
	} {
		if got := serviceFlow(c.p, shim, c.known); got != c.want {
			t.Errorf("%+v known=%v: %v, want %v", c.p, c.known, got, c.want)
		}
	}
}

// --- fakes ---

type fakeIfaces map[string]vpcInterface

func (f fakeIfaces) At(ip string, _ time.Time) (vpcInterface, bool) { in, ok := f[ip]; return in, ok }

// fakeExec is a store connection that records the statements the worker runs; affect is what each
// UPDATE reports (1 unless set).
type fakeExec struct {
	stmts  []string
	affect int64
}

func (f *fakeExec) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	parts := []string{strings.Fields(query)[0]}
	for _, a := range args {
		parts = append(parts, fmt.Sprint(a))
	}
	f.stmts = append(f.stmts, strings.Join(parts, " "))
	if f.affect == 0 {
		return driver.RowsAffected(1), nil
	}
	return driver.RowsAffected(f.affect), nil
}
func (f *fakeExec) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, errors.New("not served")
}
func (f *fakeExec) QueryRowContext(context.Context, string, ...any) *sql.Row { return nil }

type delivered struct {
	account, group, stream string
	events                 []putEvent
}

type fakeDeliverer struct {
	got  []delivered
	fail map[string]int // stream -> failures left
}

func (f *fakeDeliverer) deliver(_ context.Context, account, region, group, stream string, events []putEvent) error {
	if f.fail[stream] > 0 {
		f.fail[stream]--
		return errors.New("the log store is unavailable")
	}
	f.got = append(f.got, delivered{account, group, stream, append([]putEvent(nil), events...)})
	return nil
}

func (f *fakeDeliverer) messages(group, stream string) []string {
	var out []string
	for _, d := range f.got {
		if d.group == group && d.stream == stream {
			for _, e := range d.events {
				out = append(out, e.Message)
			}
		}
	}
	return out
}

// --- the worker ---

var flT0 = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

func flAt(sec int) int64 { return flT0.Add(time.Duration(sec) * time.Second).UnixNano() }

func flSecs(sec int) string { return fmt.Sprint(flT0.Unix() + int64(sec)) }

const (
	flENIA = "eni-0aaaaaaaaaaaaaaa1"
	flENIB = "eni-0bbbbbbbbbbbbbbb2"
)

func flIfaces() fakeIfaces {
	return fakeIfaces{
		"10.17.0.5": {IP: "10.17.0.5", Account: flAccount, Function: "orders", VpcID: "vpc-lambda", SubnetID: "subnet-a", ENI: flENIA},
		"10.17.0.6": {IP: "10.17.0.6", Account: flAccount, Function: "reports", VpcID: "vpc-lambda", SubnetID: "subnet-b", ENI: flENIB},
	}
}

func flRun(t *testing.T, st *flowLogState, fl ec2FlowLog) {
	t.Helper()
	if fl.LogFormat == "" {
		fl.LogFormat = defaultFlowLogFormat
	}
	if fl.TrafficType == "" {
		fl.TrafficType = "REJECT"
	}
	if fl.DeliverStatus == "" {
		fl.DeliverStatus = "SUCCESS"
	}
	fields, version, msg := parseFlowLogFormat(fl.LogFormat)
	if msg != "" {
		t.Fatal(msg)
	}
	fl.PublishedUntil = flT0.UnixNano()
	st.runs[fl.ID] = &flowLogRun{fl: fl, fields: fields, version: version, published: fl.PublishedUntil, ingested: fl.PublishedUntil,
		persisted: fl.PublishedUntil, windows: map[int64]map[flowKey]*flowRecord{}, sent: map[int64]map[string]bool{}}
}

func flDelivery(dl *fakeDeliverer, roleOK *bool) *flowLogDelivery {
	return &flowLogDelivery{ifaces: flIfaces(), deliver: dl.deliver, region: "us-east-1", zoneID: "use1-az1", now: time.Now,
		role: func(context.Context, ec2FlowLog) (bool, string) {
			if roleOK != nil && !*roleOK {
				return false, "the role does not trust " + flowLogsService
			}
			return true, ""
		}}
}

func ingestAll(d *flowLogDelivery, st *flowLogState, lines map[int]string, until int) {
	secs := make([]int, 0, len(lines))
	for s := range lines {
		secs = append(secs, s)
	}
	sort.Ints(secs)
	for _, s := range secs {
		d.ingest(st, lokiEntry{TsNs: flAt(s), Line: lines[s]}, map[string]bool{"10.42.0.20": true}, true)
	}
	for _, run := range st.runs {
		if flAt(until) > run.ingested {
			run.ingested = flAt(until)
		}
	}
}

// A dropped packet's line is attributed to the interface that sent it (egress) or was to receive it
// (ingress), recorded by each flow log whose VPC, subnet or interface it is, in that flow log's account,
// aggregated per window into one record per interface and 5-tuple (packets = the dropped packets, start and
// end the first and last), and published once the window has closed, each interface's records into its
// stream, oldest first. Allowed packets, other addresses' lines and the resolver's and Lambda's own
// traffic are never recorded.
func TestFlowLogDelivery_AttributesAggregatesAndPublishes(t *testing.T) {
	dl := &fakeDeliverer{}
	d := flDelivery(dl, nil)
	st := newFlowLogState()
	flRun(t, st, ec2FlowLog{ID: "fl-vpc", Account: flAccount, ResourceType: "VPC", ResourceID: "vpc-lambda", LogGroup: "flows-vpc", MaxAggregation: 60})
	flRun(t, st, ec2FlowLog{ID: "fl-sub", Account: flAccount, ResourceType: "Subnet", ResourceID: "subnet-b", LogGroup: "flows-sub", MaxAggregation: 60,
		LogFormat: "${version} ${interface-id} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${flow-direction} ${action}"})
	flRun(t, st, ec2FlowLog{ID: "fl-eni", Account: flAccount, ResourceType: "NetworkInterface", ResourceID: flENIA, LogGroup: "flows-eni", MaxAggregation: 600})
	// Another account's VPC of the same name: none of this account's traffic.
	flRun(t, st, ec2FlowLog{ID: "fl-other", Account: testMember, ResourceType: "VPC", ResourceID: "vpc-lambda", LogGroup: "flows-vpc", MaxAggregation: 60})
	ingestAll(d, st, map[int]string{
		5:  aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn")),
		6:  aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn")), // retransmitted
		8:  aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn")),
		9:  aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41392, 443, "syn")), // another flow
		10: aclLine(flT0, "drop", "to-lport", udpFlow("192.0.2.10", "10.17.0.6", 53000, 9999)),           // ingress
		11: aclLine(flT0, "allow", "from-lport", tcpFlow("10.17.0.5", "198.51.100.8", 40000, 80, "syn")), // allowed: never
		12: aclLine(flT0, "drop", "from-lport", tcpFlow("10.99.0.1", "198.51.100.7", 40000, 443, "syn")), // no function's
		13: aclLine(flT0, "drop", "from-lport", udpFlow("10.17.0.5", "10.42.0.20", 40001, 5353)),         // the resolver
		14: aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "10.42.0.20", 40002, 4568, "syn")),  // Lambda's own
		15: aclLine(flT0, "drop", "from-lport", icmpFlow("10.17.0.6", "203.0.113.9")),
		16: "level=info msg=\"not an acl_log line\"",
		65: aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn")), // the next minute
	}, 70)
	q := &fakeExec{}
	for _, id := range []string{"fl-eni", "fl-other", "fl-sub", "fl-vpc"} {
		if err := d.publish(context.Background(), q, st, st.runs[id]); err != nil {
			t.Fatal(err)
		}
	}
	vpcA := dl.messages("flows-vpc", flENIA+"-all")
	wantA := []string{
		"2 " + flAccount + " " + flENIA + " 10.17.0.5 198.51.100.7 41391 443 6 3 0 " + flSecs(5) + " " + flSecs(8) + " REJECT OK",
		"2 " + flAccount + " " + flENIA + " 10.17.0.5 198.51.100.7 41392 443 6 1 0 " + flSecs(9) + " " + flSecs(9) + " REJECT OK",
	}
	if strings.Join(vpcA, "\n") != strings.Join(wantA, "\n") {
		t.Errorf("the VPC flow log's records of %s:\n%s\nwant\n%s", flENIA, strings.Join(vpcA, "\n"), strings.Join(wantA, "\n"))
	}
	vpcB := dl.messages("flows-vpc", flENIB+"-all")
	wantB := []string{
		"2 " + flAccount + " " + flENIB + " 192.0.2.10 10.17.0.6 53000 9999 17 1 0 " + flSecs(10) + " " + flSecs(10) + " REJECT OK",
		"2 " + flAccount + " " + flENIB + " 10.17.0.6 203.0.113.9 0 0 1 1 0 " + flSecs(15) + " " + flSecs(15) + " REJECT OK",
	}
	if strings.Join(vpcB, "\n") != strings.Join(wantB, "\n") {
		t.Errorf("the VPC flow log's records of %s:\n%s\nwant\n%s", flENIB, strings.Join(vpcB, "\n"), strings.Join(wantB, "\n"))
	}
	sub := dl.messages("flows-sub", flENIB+"-all")
	wantSub := []string{
		"5 " + flENIB + " vpc-lambda subnet-b - 0 IPv4 192.0.2.10 10.17.0.6 us-east-1 use1-az1 - ingress REJECT",
		"5 " + flENIB + " vpc-lambda subnet-b - 0 IPv4 10.17.0.6 203.0.113.9 us-east-1 use1-az1 - egress REJECT",
	}
	if strings.Join(sub, "\n") != strings.Join(wantSub, "\n") {
		t.Errorf("the subnet flow log's custom records:\n%s\nwant\n%s", strings.Join(sub, "\n"), strings.Join(wantSub, "\n"))
	}
	if len(dl.messages("flows-sub", flENIA+"-all")) != 0 {
		t.Error("subnet-b's flow log must not record subnet-a's interface")
	}
	for _, g := range dl.got {
		if g.account != flAccount {
			t.Errorf("delivered into account %s: another account's flow log recorded this account's traffic", g.account)
		}
		if g.group == "flows-eni" {
			t.Error("a 10-minute window must not be published before it closes")
		}
		for i, e := range g.events {
			if i > 0 && e.TsMs < g.events[i-1].TsMs {
				t.Errorf("events out of order in %s", g.stream)
			}
		}
	}
	for _, g := range dl.got {
		if g.group == "flows-vpc" && g.stream == flENIA+"-all" && g.events[0].TsMs != (flT0.Unix()+5)*1000 {
			t.Errorf("an event is stamped with its record's start: %d", g.events[0].TsMs)
		}
	}
	// The cursor moved a window, for each 60-second flow log (the other account's too: its window was empty).
	for _, id := range []string{"fl-vpc", "fl-sub", "fl-other"} {
		if st.runs[id].published != flAt(60) || st.runs[id].persisted != flAt(60) {
			t.Errorf("%s cursor at %d, want %d", id, st.runs[id].published, flAt(60))
		}
	}
	if st.runs["fl-eni"].published != flAt(0) {
		t.Errorf("the 10-minute flow log's cursor must stay put")
	}
	// The next minute closes: its one packet is the 60-second flow log's next record, delivered once.
	n := len(dl.got)
	ingestAll(d, st, nil, 125)
	for _, id := range []string{"fl-eni", "fl-other", "fl-sub", "fl-vpc"} {
		if err := d.publish(context.Background(), q, st, st.runs[id]); err != nil {
			t.Fatal(err)
		}
	}
	if len(dl.got) != n+1 || dl.got[n].group != "flows-vpc" || len(dl.got[n].events) != 1 ||
		dl.got[n].events[0].Message != "2 "+flAccount+" "+flENIA+" 10.17.0.5 198.51.100.7 41391 443 6 1 0 "+flSecs(65)+" "+flSecs(65)+" REJECT OK" {
		t.Errorf("the second window: %+v", dl.got[n:])
	}
	// Ten minutes on, the 10-minute window holds every packet of orders' interface, in one record per flow.
	ingestAll(d, st, nil, 610)
	if err := d.publish(context.Background(), q, st, st.runs["fl-eni"]); err != nil {
		t.Fatal(err)
	}
	eni := dl.messages("flows-eni", flENIA+"-all")
	if len(eni) != 2 || !strings.Contains(eni[0], " 41391 443 6 4 0 "+flSecs(5)+" "+flSecs(65)+" REJECT OK") {
		t.Errorf("the 10-minute window's records: %v", eni)
	}
}

// A delivery role that cannot deliver drops the window's records, as AWS does, and DescribeFlowLogs says
// FAILED / "Access error"; once it can again, the status is SUCCESS. A failed write keeps the window for
// the next cycle, without writing again the streams it had written.
func TestFlowLogDelivery_RoleFailureAndRetry(t *testing.T) {
	dl := &fakeDeliverer{fail: map[string]int{}}
	roleOK := false
	d := flDelivery(dl, &roleOK)
	st := newFlowLogState()
	flRun(t, st, ec2FlowLog{ID: "fl-vpc", Account: flAccount, ResourceType: "VPC", ResourceID: "vpc-lambda", LogGroup: "flows", MaxAggregation: 60})
	run := st.runs["fl-vpc"]
	ingestAll(d, st, map[int]string{5: aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn"))}, 61)
	q := &fakeExec{}
	if err := d.publish(context.Background(), q, st, run); err != nil {
		t.Fatal(err)
	}
	if len(dl.got) != 0 {
		t.Fatalf("a role that cannot deliver delivered: %+v", dl.got)
	}
	if run.fl.DeliverStatus != "FAILED" || run.fl.DeliverError != flowLogAccessError || run.published != flAt(60) ||
		!strings.Contains(strings.Join(q.stmts, "\n"), "UPDATE fl-vpc FAILED Access error") {
		t.Errorf("status %s %q, cursor %d, statements %v", run.fl.DeliverStatus, run.fl.DeliverError, run.published, q.stmts)
	}
	// The role is fixed; the next window's write fails once for one of its two streams.
	roleOK = true
	dl.fail[flENIB+"-all"] = 1
	ingestAll(d, st, map[int]string{
		65: aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn")),
		66: aclLine(flT0, "drop", "from-lport", icmpFlow("10.17.0.6", "203.0.113.9")),
	}, 121)
	if err := d.publish(context.Background(), q, st, run); err == nil {
		t.Fatal("a failed write must be reported")
	}
	if run.published != flAt(60) || run.fl.DeliverStatus != "SUCCESS" {
		t.Fatalf("after a failed write the window stays: cursor %d status %s", run.published, run.fl.DeliverStatus)
	}
	if err := d.publish(context.Background(), q, st, run); err != nil {
		t.Fatal(err)
	}
	if len(dl.messages("flows", flENIA+"-all")) != 1 || len(dl.messages("flows", flENIB+"-all")) != 1 || run.published != flAt(120) {
		t.Errorf("the retry writes each stream once: %+v (cursor %d)", dl.got, run.published)
	}
	// Another worker moved the cursor (or the flow log was deleted): this one lets it go.
	ingestAll(d, st, map[int]string{125: aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", 41391, 443, "syn"))}, 181)
	if err := d.publish(context.Background(), &fakeExec{affect: -1}, st, run); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.runs["fl-vpc"]; ok {
		t.Error("a flow log whose cursor this worker no longer holds must be dropped")
	}
}

// flowLogLoki serves entries (sorted) as the log store's range query does, end inclusive, limit lines.
type flowLogLoki struct {
	entries []lokiEntry
	queries int
}

func (f *flowLogLoki) queryRange(_ context.Context, _ string, start, end int64, limit int, _ bool) ([]lokiEntry, error) {
	f.queries++
	var out []lokiEntry
	for _, e := range f.entries {
		if e.TsNs >= start && e.TsNs <= end {
			out = append(out, e)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

// Paging through the log store hands each line over exactly once, in order, however the pages fall —
// several lines of one instant at a page's edge included — and stops at the range's end.
func TestFlowLogRead_Pages(t *testing.T) {
	var es []lokiEntry
	for i, ts := range []int64{1, 2, 3, 3, 3, 4, 5, 5, 6, 9, 10} {
		es = append(es, lokiEntry{TsNs: ts, Line: fmt.Sprint("line-", i)})
	}
	for _, limit := range []int{3, 4, 5, 100} {
		d := &flowLogDelivery{loki: &flowLogLoki{entries: es}, limit: limit}
		var got []string
		reached, err := d.read(context.Background(), 1, 10, func(e lokiEntry) { got = append(got, e.Line) })
		if err != nil {
			t.Fatal(err)
		}
		want := "line-0 line-1 line-2 line-3 line-4 line-5 line-6 line-7 line-8 line-9" // [1, 10): not the line at 10
		if strings.Join(got, " ") != want || reached != 10 {
			t.Errorf("limit %d: got %v (reached %d)", limit, got, reached)
		}
	}
	// At the page cap a read stops early, before the instant it has not finished.
	many := make([]lokiEntry, 0, 100)
	for i := 0; i < 100; i++ {
		many = append(many, lokiEntry{TsNs: int64(i + 1), Line: fmt.Sprint(i)})
	}
	d := &flowLogDelivery{loki: &flowLogLoki{entries: many}, limit: 2}
	n := 0
	reached, _ := d.read(context.Background(), 1, 1000, func(lokiEntry) { n++ })
	if reached != int64(flowLogMaxPages+1) || n != flowLogMaxPages {
		t.Errorf("capped read: %d lines, reached %d", n, reached)
	}
}

func TestFlowLogFormat(t *testing.T) {
	if f, v, msg := parseFlowLogFormat(""); msg != "" || v != 2 || canonicalFlowLogFormat(f) != defaultFlowLogFormat {
		t.Errorf("the default format: %v %d %q", f, v, msg)
	}
	if _, v, msg := parseFlowLogFormat("${version}  ${vpc-id} ${az-id}"); msg != "" || v != 4 {
		t.Errorf("a version 4 field: %d %q", v, msg)
	}
	if _, v, msg := parseFlowLogFormat("${flow-direction} ${srcaddr}"); msg != "" || v != 5 {
		t.Errorf("flow-direction is version 5: %d %q", v, msg)
	}
	for format, want := range map[string]string{
		"${version} ${traffic-path} ${ecs-task-id}": "not recorded by the open-infra shim: ${traffic-path}, ${ecs-task-id}",
		"${version} ${no-such-field}":               "Unknown fields provided in LogFormat: ${no-such-field}",
		"version srcaddr":                           "LogFormat must list fields as ${field-id}",
	} {
		if _, _, msg := parseFlowLogFormat(format); !strings.Contains(msg, want) {
			t.Errorf("%q: %q, want it to say %q", format, msg, want)
		}
	}
}

// AWS's recommended trust policy against the confused deputy (aws:SourceAccount, aws:SourceArn) is
// evaluated; a condition the platform cannot evaluate grants nothing; a Deny naming the service denies.
func TestFlowLogTrustConditions(t *testing.T) {
	arn := "arn:aws:ec2:us-east-1:" + flAccount + ":vpc-flow-log/fl-0123456789abcdef0"
	stmt := func(effect, cond string) string {
		c := ""
		if cond != "" {
			c = `,"Condition":` + cond
		}
		return `{"Effect":"` + effect + `","Principal":{"Service":"vpc-flow-logs.amazonaws.com"},"Action":"sts:AssumeRole"` + c + `}`
	}
	recommended := `{"StringEquals":{"aws:SourceAccount":"` + flAccount + `"},"ArnLike":{"aws:SourceArn":"arn:aws:ec2:us-east-1:` + flAccount + `:vpc-flow-log/*"}}`
	for _, c := range []struct {
		name, doc string
		want      bool
	}{
		{"no document", "", true},
		{"no condition", `{"Version":"2012-10-17","Statement":[` + stmt("Allow", "") + `]}`, true},
		{"AWS's recommended conditions", `{"Statement":[` + stmt("Allow", recommended) + `]}`, true},
		{"one statement, not a list", `{"Statement":` + stmt("Allow", recommended) + `}`, true},
		{"another account", `{"Statement":[` + stmt("Allow", `{"StringEquals":{"aws:SourceAccount":"444455556666"}}`) + `]}`, false},
		{"another flow log", `{"Statement":[` + stmt("Allow", `{"ArnEquals":{"aws:SourceArn":"arn:aws:ec2:us-east-1:`+flAccount+`:vpc-flow-log/fl-1"}}`) + `]}`, false},
		{"a key not evaluated", `{"Statement":[` + stmt("Allow", `{"StringEquals":{"aws:SourceVpc":"vpc-1"}}`) + `]}`, false},
		{"an explicit Deny", `{"Statement":[` + stmt("Allow", "") + `,` + stmt("Deny", `{"StringEquals":{"aws:SourceAccount":"`+flAccount+`"}}`) + `]}`, false},
		{"does not parse", `{"Statement":`, false},
	} {
		if got, why := flowLogTrustConditions(c.doc, flAccount, arn); got != c.want {
			t.Errorf("%s: %v (%s), want %v", c.name, got, why, c.want)
		}
	}
}

type flowLogRoleSet map[string]resolvedRole // "<ns>/<name>"

func (f flowLogRoleSet) ResolveIn(_ context.Context, ns, name string) (resolvedRole, bool) {
	r, ok := f[ns+"/"+name]
	return r, ok
}

// The delivery role must exist in the flow log's account, trust the flow logs service, and its policies
// must allow writing to the log group (creating it too, while it does not exist).
func TestFlowLogRoles_Check(t *testing.T) {
	mgmt := awsidentity.Current().AccountID
	const home = "open-infra-console"
	trusted := resolvedRole{trust: []string{"Service::" + flowLogsService}}
	roles := flowLogRoleSet{home + "/FlowLogsDelivery": trusted, home + "/LambdaRole": {trust: []string{"Service::lambda.amazonaws.com"}},
		memberHome + "/FlowLogsDelivery": trusted}
	checker := func(id string, actions ...string) *dataplaneauthz.Checker {
		return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "delivery", AppliesTo: []string{"Role::" + id},
				Statements: []policyengine.Statement{dpAllow(actions, "*")}}}}, nil
		}, time.Minute)
	}
	exists := true
	c := &flowLogRoles{roles: roles, home: home, region: "us-east-1", homeOf: func(a string) (string, bool) { return memberHome, a == testMember },
		groups: func(context.Context, string, string) (bool, error) { return exists, nil }}
	fl := ec2FlowLog{ID: "fl-0123456789abcdef0", Account: mgmt, LogGroup: "flows", DeliverRole: "arn:aws:iam::" + mgmt + ":role/FlowLogsDelivery"}
	c.authz = checker("flowlogsdelivery", "logs:CreateLogStream", "logs:PutLogEvents")
	if ok, why := c.check(context.Background(), fl); !ok {
		t.Fatalf("a trusted role allowed to write: %s", why)
	}
	exists = false
	if ok, _ := c.check(context.Background(), fl); ok {
		t.Error("while the group does not exist, the role must also be allowed logs:CreateLogGroup")
	}
	c.authz = checker("flowlogsdelivery", "logs:*")
	if ok, why := c.check(context.Background(), fl); !ok {
		t.Errorf("logs:* allows it all: %s", why)
	}
	exists = true
	c.authz = checker("flowlogsdelivery", "logs:CreateLogStream")
	if ok, why := c.check(context.Background(), fl); ok || !strings.Contains(why, "logs:PutLogEvents") {
		t.Errorf("without logs:PutLogEvents: %v %s", ok, why)
	}
	c.authz = checker("flowlogsdelivery", "logs:*")
	for name, role := range map[string]string{
		"a role that trusts another service": "arn:aws:iam::" + mgmt + ":role/LambdaRole",
		"a role that does not exist":         "arn:aws:iam::" + mgmt + ":role/NoSuchRole",
		"another account's role":             "arn:aws:iam::444455556666:role/FlowLogsDelivery",
	} {
		f := fl
		f.DeliverRole = role
		if ok, _ := c.check(context.Background(), f); ok {
			t.Errorf("%s must not deliver", name)
		}
	}
	// A member account's role is in its home, its principal qualified by it.
	member := ec2FlowLog{ID: "fl-0123456789abcdef1", Account: testMember, LogGroup: "flows", DeliverRole: "arn:aws:iam::" + testMember + ":role/FlowLogsDelivery"}
	c.authz = checker(memberHome+"/flowlogsdelivery", "logs:*")
	if ok, why := c.check(context.Background(), member); !ok {
		t.Errorf("a member account's role: %s", why)
	}
	c.authz = checker("flowlogsdelivery", "logs:*") // the management account's role's policy is not the member's
	if ok, _ := c.check(context.Background(), member); ok {
		t.Error("a member account's role must be decided by its own policies")
	}
}
