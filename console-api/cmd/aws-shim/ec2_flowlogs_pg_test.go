package main

// VPC Flow Logs against a real Postgres store (OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go): the
// operations, their accounts, the client token, and the delivery worker's cursor, restart and lock.

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

var flowLogIDsRe = regexp.MustCompile(`<item>(fl-[0-9a-f]{17})</item>`)

func flowLogIDsOf(body string) []string {
	var out []string
	for _, m := range flowLogIDsRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestServicesPG_EC2FlowLogs(t *testing.T) {
	ctx := context.Background()
	db := freshPGDB(t)
	st := &ec2FlowLogStore{db: db}
	for i := 0; i < 2; i++ {
		if err := st.ensureSchema(ctx); err != nil {
			t.Fatalf("ensureSchema (run %d): %v", i+1, err)
		}
	}
	h := eniFixture(t)
	h.flowLogs = st
	h.door.authz = doorAccountsAuthz(t)
	call := func(f url.Values) string {
		t.Helper()
		w := ec2Call(h, ec2Alice, f)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", f.Get("Action"), w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	// A VPC of the account and one it does not have: one flow log, one unsuccessful item.
	body := call(flCreate(map[string]string{"ResourceId.2": "vpc-missing",
		"TagSpecification.1.ResourceType": "vpc-flow-log", "TagSpecification.1.Tag.1.Key": "Name", "TagSpecification.1.Tag.1.Value": "rejects"}))
	ids := flowLogIDsOf(body)
	if len(ids) != 1 || !strings.Contains(body, "<unsuccessful><item><error><code>InvalidVpcID.NotFound</code>") ||
		!strings.Contains(body, "<resourceId>vpc-missing</resourceId>") || !strings.HasPrefix(body, xmlHeader+`<CreateFlowLogsResponse xmlns="`+ec2XMLNS+`">`) {
		t.Fatalf("CreateFlowLogs: %s", body)
	}
	vpcFL := ids[0]
	// The same again: AWS's FlowLogAlreadyExists, nothing made.
	body = call(flCreate(nil))
	if len(flowLogIDsOf(body)) != 0 || !strings.Contains(body, "<code>FlowLogAlreadyExists</code>") {
		t.Errorf("a second identical flow log: %s", body)
	}
	// A subnet, by its log group's ARN, with a 1-minute interval and a custom format.
	body = call(flCreate(map[string]string{"ResourceType": "Subnet", "ResourceId.1": "s-a", "LogGroupName": "",
		"LogDestination": "arn:aws:logs:us-east-1:" + eniTestAccount + ":log-group:subnet-flows:*", "MaxAggregationInterval": "60",
		"LogFormat": "${version}  ${interface-id} ${srcaddr} ${dstaddr} ${action}"}))
	if len(flowLogIDsOf(body)) != 1 || !strings.Contains(body, "<unsuccessful/>") {
		t.Fatalf("a subnet's flow log: %s", body)
	}
	subnetFL := flowLogIDsOf(body)[0]
	// Lambda's network interface, and one that is not the account's.
	eni := lambdaENIID(eniTestAccount, "orders", "s-a")
	body = call(flCreate(map[string]string{"ResourceType": "NetworkInterface", "ResourceId.1": eni, "ResourceId.2": "eni-00000000000000000"}))
	if len(flowLogIDsOf(body)) != 1 || !strings.Contains(body, "<code>InvalidNetworkInterfaceID.NotFound</code>") ||
		!strings.Contains(body, "<resourceId>eni-00000000000000000</resourceId>") {
		t.Fatalf("an interface's flow log: %s", body)
	}
	// A client token: the same request answers the same flow log; other parameters are refused.
	tok := map[string]string{"ResourceType": "Subnet", "ResourceId.1": "s-b", "ClientToken": "tok-1"}
	first := call(flCreate(tok))
	again := call(flCreate(tok))
	if ids := flowLogIDsOf(first); len(ids) != 1 || strings.Join(flowLogIDsOf(again), ",") != ids[0] ||
		!strings.Contains(again, "<clientToken>tok-1</clientToken>") {
		t.Errorf("a retried client token: %s / %s", first, again)
	}
	tok["LogGroupName"] = "other-flows"
	if w := ec2Call(h, ec2Alice, flCreate(tok)); w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>IdempotentParameterMismatch</Code>") {
		t.Errorf("a client token with other parameters: %d %s", w.Code, w.Body.String())
	}
	// DescribeFlowLogs: the account's four, by id and by filter.
	all := call(url.Values{"Action": {"DescribeFlowLogs"}})
	if strings.Count(all, "<flowLogId>") != 4 {
		t.Fatalf("DescribeFlowLogs: %s", all)
	}
	one := call(url.Values{"Action": {"DescribeFlowLogs"}, "FlowLogId.1": {vpcFL}})
	mustContain(t, "DescribeFlowLogs", one, "<flowLogSet><item><resourceId>s-vpc</resourceId><logDestinationType>cloud-watch-logs</logDestinationType>"+
		"<deliverLogsPermissionArn>"+flRoleARN+"</deliverLogsPermissionArn><creationTime>",
		"<trafficType>REJECT</trafficType><deliverLogsStatus>SUCCESS</deliverLogsStatus><logFormat>"+defaultFlowLogFormat+"</logFormat>"+
			"<flowLogStatus>ACTIVE</flowLogStatus><logGroupName>flows</logGroupName><logDestination>arn:aws:logs:us-east-1:"+eniTestAccount+":log-group:flows</logDestination>"+
			"<flowLogId>"+vpcFL+"</flowLogId><maxAggregationInterval>600</maxAggregationInterval><tagSet><item><key>Name</key><value>rejects</value></item></tagSet>")
	sub := call(url.Values{"Action": {"DescribeFlowLogs"}, "Filter.1.Name": {"resource-id"}, "Filter.1.Value.1": {"s-a"}})
	mustContain(t, "the subnet's flow log", sub, "<flowLogId>"+subnetFL+"</flowLogId>", "<logGroupName>subnet-flows</logGroupName>",
		"<logFormat>${version} ${interface-id} ${srcaddr} ${dstaddr} ${action}</logFormat>", "<maxAggregationInterval>60</maxAggregationInterval>")
	for _, c := range []struct {
		name, value string
		want        int
	}{
		{"log-group-name", "flows", 3}, {"tag:Name", "rejects", 1}, {"deliver-log-status", "SUCCESS", 4}, {"deliver-log-status", "FAILED", 0},
		{"traffic-type", "REJECT", 4}, {"log-destination-type", "cloud-watch-logs", 4}, {"flow-log-id", subnetFL, 1}, {"resource-id", eni, 1},
	} {
		got := call(url.Values{"Action": {"DescribeFlowLogs"}, "Filter.1.Name": {c.name}, "Filter.1.Value.1": {c.value}})
		if n := strings.Count(got, "<flowLogId>"); n != c.want {
			t.Errorf("filter %s=%s: %d, want %d", c.name, c.value, n, c.want)
		}
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeFlowLogs"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {"s-vpc"}}); w.Code != 400 {
		t.Errorf("an unknown filter: %d", w.Code)
	}
	// A member account sees none of them, and deletes none of them.
	member := memberCtx()
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeFlowLogs"}}); w.Code != 200 || strings.Contains(w.Body.String(), "<flowLogId>") {
		t.Errorf("a member account's DescribeFlowLogs: %d %s", w.Code, w.Body.String())
	}
	if w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DeleteFlowLogs"}, "FlowLogId.1": {vpcFL}}); !strings.Contains(w.Body.String(), "InvalidFlowLogId.NotFound") {
		t.Errorf("a member account deleting the management account's flow log: %s", w.Body.String())
	}
	// DeleteFlowLogs: the known one goes; an unknown one is AWS's unsuccessful item.
	body = call(url.Values{"Action": {"DeleteFlowLogs"}, "FlowLogId.1": {vpcFL}, "FlowLogId.2": {"fl-00000000000000000"}})
	if !strings.Contains(body, "<unsuccessful><item><error><code>InvalidFlowLogId.NotFound</code><message>These flow log ids in the input list are not found: [TotalCount: 1] fl-00000000000000000</message></error><resourceId>fl-00000000000000000</resourceId></item></unsuccessful>") {
		t.Errorf("DeleteFlowLogs: %s", body)
	}
	if got := call(url.Values{"Action": {"DescribeFlowLogs"}, "FlowLogId.1": {vpcFL}}); strings.Contains(got, "<flowLogId>") {
		t.Errorf("a deleted flow log is described: %s", got)
	}
	if body := call(flCreate(nil)); len(flowLogIDsOf(body)) != 1 {
		t.Errorf("once deleted, the same flow log can be made again: %s", body)
	}
}

// The delivery worker over the real stores: each closed window is published once, a restarted worker
// (state lost) publishes nothing again and loses nothing, and a role that cannot deliver shows as FAILED.
func TestServicesPG_EC2FlowLogDelivery(t *testing.T) {
	ctx := context.Background()
	db := freshPGDB(t)
	fst, cwl := &ec2FlowLogStore{db: db}, &cwlStore{db: db}
	if err := fst.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cwl.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	mgmt := awsidentity.Current().AccountID
	fl := ec2FlowLog{ID: "fl-0aaaaaaaaaaaaaaa1", Account: mgmt, ResourceType: "VPC", ResourceID: "vpc-lambda", TrafficType: "REJECT",
		LogGroup: "flows", LogDestination: "arn:aws:logs:us-east-1:" + mgmt + ":log-group:flows", DeliverRole: "arn:aws:iam::" + mgmt + ":role/FlowLogsDelivery",
		LogFormat: defaultFlowLogFormat, MaxAggregation: 60, Created: flT0}
	if res, err := fst.create(ctx, mgmt, "", "", []ec2FlowLog{fl}, nil); err != nil || len(res.IDs) != 1 {
		t.Fatalf("create: %v %+v", err, res)
	}
	ifaces := flIfaces()
	for ip, in := range ifaces {
		in.Account = mgmt
		ifaces[ip] = in
	}
	syn := func(sec, sport int) lokiEntry {
		return lokiEntry{TsNs: flAt(sec), Line: aclLine(flT0, "drop", "from-lport", tcpFlow("10.17.0.5", "198.51.100.7", sport, 443, "syn"))}
	}
	loki := &flowLogLoki{entries: []lokiEntry{syn(5, 41391), syn(6, 41391), syn(65, 41392)}}
	roleOK := true
	now := flT0
	d := &flowLogDelivery{db: db, loki: loki, ifaces: ifaces, deliver: cwl.deliver, region: "us-east-1", zoneID: "use1-az1",
		role: func(context.Context, ec2FlowLog) (bool, string) {
			return roleOK, "the role does not trust " + flowLogsService
		},
		now: func() time.Time { return now }, settle: flowLogSettle, tick: 10 * time.Millisecond}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	events := func() []string {
		t.Helper()
		es, _, _, err := cwl.getEvents(ctx, accountKeyFor(mgmt, "flows"), flENIA+"-all", true, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range es {
			out = append(out, e.Message)
		}
		return out
	}
	cycle := func(at int, fresh bool, st *flowLogState) *flowLogState {
		t.Helper()
		now = flT0.Add(time.Duration(at) * time.Second)
		if fresh {
			st = newFlowLogState()
		}
		if err := d.cycle(ctx, conn, st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := cycle(130, true, nil) // read up to +70s: the first minute has closed, the second has not
	want1 := "2 " + mgmt + " " + flENIA + " 10.17.0.5 198.51.100.7 41391 443 6 2 0 " + flSecs(5) + " " + flSecs(6) + " REJECT OK"
	if got := events(); len(got) != 1 || got[0] != want1 {
		t.Fatalf("the first window: %v", got)
	}
	cycle(130, true, nil) // a restart: the store's cursor says the first minute is published
	cycle(140, false, st)
	if got := events(); len(got) != 1 {
		t.Fatalf("a restarted worker published again: %v", got)
	}
	st = cycle(190, true, nil) // a restarted worker reads the second minute from the store's cursor
	if got := events(); len(got) != 2 || !strings.Contains(got[1], " 41392 443 6 1 0 "+flSecs(65)+" ") {
		t.Fatalf("the second window, after a restart: %v", got)
	}
	// The role stops being able to deliver: the third minute is not delivered, and the flow log says so.
	roleOK = false
	loki.entries = append(loki.entries, syn(135, 41393)) // the third minute (the worker has read to +130s)
	st = cycle(250, false, st)
	all, err := listAllFlowLogs(ctx, db)
	if err != nil || len(all) != 1 || all[0].DeliverStatus != "FAILED" || all[0].DeliverError != flowLogAccessError || all[0].PublishedUntil != flAt(180) {
		t.Fatalf("after a role failure: %+v %v", all, err)
	}
	if got := events(); len(got) != 2 {
		t.Errorf("a role that cannot deliver delivered: %v", got)
	}
	roleOK = true
	loki.entries = append(loki.entries, syn(195, 41394))
	cycle(310, false, st)
	all, _ = listAllFlowLogs(ctx, db)
	if got := events(); len(got) != 3 || all[0].DeliverStatus != "SUCCESS" || all[0].DeliverError != "" {
		t.Errorf("after the role is fixed: %v %+v", got, all)
	}
	// The cursor only moves from where the store has it.
	if moved, err := advanceFlowLog(ctx, db, fl.ID, flAt(0), flAt(60)); err != nil || moved {
		t.Errorf("a stale cursor moved: %v %v", moved, err)
	}
}

// One replica delivers: the one holding the advisory lock. Another waits; it takes over when the first stops.
func TestServicesPG_EC2FlowLogDeliveryLock(t *testing.T) {
	db := freshPGDB(t)
	fst := &ec2FlowLogStore{db: db}
	if err := fst.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	worker := func() *flowLogDelivery {
		return &flowLogDelivery{db: db, loki: &flowLogLoki{}, ifaces: fakeIfaces{}, now: time.Now, settle: flowLogSettle, tick: 10 * time.Millisecond,
			deliver: func(context.Context, string, string, string, string, []putEvent) error { return nil },
			role:    func(context.Context, ec2FlowLog) (bool, string) { return true, "" }}
	}
	held := func() bool {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	waitFor := func(want bool) {
		t.Helper()
		for i := 0; i < 200; i++ {
			if held() == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("lock held = %v never came", want)
	}
	ctx1, stop1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() { worker().lead(ctx1); close(done1) }()
	waitFor(true)
	// A second replica does not lead while the first does: its lead returns at once.
	returned := make(chan struct{})
	go func() { worker().lead(context.Background()); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("a second replica led beside the first")
	}
	stop1()
	<-done1
	waitFor(false)
	ctx2, stop2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { worker().lead(ctx2); close(done2) }()
	waitFor(true) // the second replica takes over
	stop2()
	<-done2
}
