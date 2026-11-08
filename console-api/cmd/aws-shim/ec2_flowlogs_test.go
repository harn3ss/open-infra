package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
)

const flRoleARN = "arn:aws:iam::" + eniTestAccount + ":role/FlowLogsDelivery"

var newFlowLogIDRe = regexp.MustCompile(`^fl-[0-9a-f]{17}$`)

// flCreate is a CreateFlowLogs that names everything a CloudWatch Logs flow log needs, changed by set
// (an empty value removes the parameter).
func flCreate(set map[string]string) url.Values {
	f := url.Values{"Action": {"CreateFlowLogs"}, "ResourceType": {"VPC"}, "ResourceId.1": {"s-vpc"}, "TrafficType": {"REJECT"},
		"LogGroupName": {"flows"}, "DeliverLogsPermissionArn": {flRoleARN}}
	for k, v := range set {
		if v == "" {
			f.Del(k)
		} else {
			f.Set(k, v)
		}
	}
	return f
}

// CreateFlowLogs refuses what AWS refuses, with AWS's codes, and what the platform does not serve —
// accepted traffic, S3 and Firehose destinations, transit gateways, cross-account delivery, record
// fields it does not record — saying what is served. A valid request gets past every check to the store.
func TestEC2_CreateFlowLogs_Validation(t *testing.T) {
	h := eniFixture(t)
	h.flowLogs = &ec2FlowLogStore{db: unreachableDB(t)}
	many := map[string]string{}
	for i := 1; i <= maxFlowLogResources+1; i++ {
		many["ResourceId."+strconv.Itoa(i)] = "s-vpc"
	}
	for _, c := range []struct {
		name string
		set  map[string]string
		code string
		says string
	}{
		{"no resource type", map[string]string{"ResourceType": ""}, "MissingParameter", "ResourceType"},
		{"a transit gateway", map[string]string{"ResourceType": "TransitGateway"}, "InvalidParameterValue", "served: VPC, Subnet, NetworkInterface"},
		{"an unknown resource type", map[string]string{"ResourceType": "Instance"}, "InvalidParameterValue", "resourceType"},
		{"no resource", map[string]string{"ResourceId.1": ""}, "MissingParameter", "ResourceId"},
		{"over 300 resources", many, "InvalidParameter", "at most 300"},
		{"no traffic type", map[string]string{"TrafficType": ""}, "MissingParameter", "TrafficType"},
		{"all traffic", map[string]string{"TrafficType": "ALL"}, "InvalidParameter", "records the traffic a VPC's security groups reject (REJECT)"},
		{"accepted traffic", map[string]string{"TrafficType": "ACCEPT"}, "InvalidParameter", "not accepted traffic"},
		{"an unknown traffic type", map[string]string{"TrafficType": "SOME"}, "InvalidParameterValue", "trafficType"},
		{"an S3 destination", map[string]string{"LogDestinationType": "s3", "LogDestination": "arn:aws:s3:::flow-bucket", "LogGroupName": ""},
			"InvalidParameter", "served: cloud-watch-logs"},
		{"a Firehose destination", map[string]string{"LogDestinationType": "kinesis-data-firehose"}, "InvalidParameter", "served: cloud-watch-logs"},
		{"group and destination", map[string]string{"LogDestination": "arn:aws:logs:us-east-1:" + eniTestAccount + ":log-group:flows"},
			"InvalidParameter", "only provide LogGroupName or only provide LogDestination"},
		{"neither group nor destination", map[string]string{"LogGroupName": ""}, "InvalidParameter", "either LogGroupName or LogDestination"},
		{"a destination that is not a log group", map[string]string{"LogGroupName": "", "LogDestination": "arn:aws:s3:::flow-bucket"},
			"InvalidParameter", "ARN of a CloudWatch Logs log group"},
		{"another region's group", map[string]string{"LogGroupName": "", "LogDestination": "arn:aws:logs:eu-west-1:" + eniTestAccount + ":log-group:flows"},
			"InvalidParameter", "one region us-east-1"},
		{"another account's group", map[string]string{"LogGroupName": "", "LogDestination": "arn:aws:logs:us-east-1:444455556666:log-group:flows"},
			"InvalidParameter", "its own account's log groups"},
		{"a malformed group name", map[string]string{"LogGroupName": "flows and more!"}, "InvalidParameter", "is not valid"},
		{"a service's own group", map[string]string{"LogGroupName": "/aws/lambda/orders"}, "InvalidParameter", "service's own logs"},
		{"no delivery role", map[string]string{"DeliverLogsPermissionArn": ""}, "InvalidParameter", "DeliverLogsPermissionArn is required"},
		{"a delivery role that is no role", map[string]string{"DeliverLogsPermissionArn": "FlowLogsDelivery"}, "InvalidParameter", "not an IAM role ARN"},
		{"another account's role", map[string]string{"DeliverLogsPermissionArn": "arn:aws:iam::444455556666:role/FlowLogsDelivery"},
			"InvalidParameter", "own account"},
		{"a 5-minute interval", map[string]string{"MaxAggregationInterval": "300"}, "InvalidParameter", "60 or 600"},
		{"a field not recorded", map[string]string{"LogFormat": "${version} ${traffic-path}"}, "InvalidParameter", "${traffic-path}"},
		{"an unknown field", map[string]string{"LogFormat": "${version} ${colour}"}, "InvalidParameter", "Unknown fields"},
		{"cross-account delivery", map[string]string{"DeliverCrossAccountRole": "arn:aws:iam::444455556666:role/x"}, "InvalidParameter", "own account"},
		{"S3 destination options", map[string]string{"DestinationOptions.FileFormat": "parquet"}, "InvalidParameter", "Amazon S3"},
		{"tag fields", map[string]string{"TagFieldSpecification.1.ResourceType": "instance"}, "InvalidParameter", "tag fields"},
	} {
		w := ec2Call(h, ec2Alice, flCreate(c.set))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") || !strings.Contains(w.Body.String(), xesc(c.says)) {
			t.Errorf("%s: want %s saying %q, got %d %s", c.name, c.code, c.says, w.Code, w.Body.String())
		}
	}
	// Valid, with a custom format, a 1-minute interval, a destination ARN and tags: the request reaches the
	// store (here unreachable).
	w := ec2Call(h, ec2Alice, flCreate(map[string]string{"LogGroupName": "", "LogDestination": "arn:aws:logs:us-east-1:" + eniTestAccount + ":log-group:flows:*",
		"MaxAggregationInterval": "60", "LogFormat": "${version} ${interface-id} ${srcaddr} ${dstaddr} ${action} ${flow-direction}",
		"TagSpecification.1.ResourceType": "vpc-flow-log", "TagSpecification.1.Tag.1.Key": "Name", "TagSpecification.1.Tag.1.Value": "rejects"}))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a valid request must reach the store: %d %s", w.Code, w.Body.String())
	}
	// Without the store, every flow log operation says so.
	h.flowLogs = nil
	for _, op := range []string{"CreateFlowLogs", "DescribeFlowLogs", "DeleteFlowLogs"} {
		if w := ec2Call(h, ec2Alice, url.Values{"Action": {op}, "FlowLogId.1": {"fl-0123456789abcdef0"}}); w.Code != http.StatusServiceUnavailable ||
			!strings.Contains(w.Body.String(), "flow-log store is not configured") {
			t.Errorf("%s without a store: %d %s", op, w.Code, w.Body.String())
		}
	}
}

// The delivery role is passed to the flow logs service: the caller needs iam:PassRole on it, passed to
// vpc-flow-logs.amazonaws.com (AWS's iam:PassedToService), besides ec2:CreateFlowLogs.
func TestEC2_CreateFlowLogs_NeedsPassRole(t *testing.T) {
	passTo := func(service string) []policyengine.Statement {
		stmts, unsupported, err := policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*",
		  "Condition":{"StringEquals":{"iam:PassedToService":"` + service + `"}}}]}`)
		if err != nil || len(unsupported) > 0 {
			t.Fatalf("import: %v %v", err, unsupported)
		}
		return stmts
	}
	create := dpAllow([]string{"ec2:CreateFlowLogs", "ec2:DescribeVpcs"}, "*")
	for _, c := range []struct {
		name   string
		stmts  []policyengine.Statement
		denied bool
	}{
		{"no iam:PassRole", []policyengine.Statement{create}, true},
		{"iam:PassRole to Lambda only", append(passTo("lambda.amazonaws.com"), create), true},
		{"iam:PassRole to the flow logs service", append(passTo(flowLogsService), create), false},
		{"iam:PassRole on the role", []policyengine.Statement{create, dpAllow([]string{"iam:PassRole"}, "Role::FlowLogsDelivery")}, false},
		{"iam:PassRole on another role", []policyengine.Statement{create, dpAllow([]string{"iam:PassRole"}, "Role::OtherRole")}, true},
	} {
		h := eniFixture(t)
		h.flowLogs = &ec2FlowLogStore{db: unreachableDB(t)}
		h.door.authz = checkerInMode(t, "enforce", userDoc(c.stmts...))
		w := ec2Call(h, testUser, flCreate(nil))
		denied := w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "<Code>UnauthorizedOperation</Code>") &&
			strings.Contains(w.Body.String(), "iam:PassRole")
		if denied != c.denied {
			t.Errorf("%s: denied=%v, want %v (%d %s)", c.name, denied, c.denied, w.Code, w.Body.String())
		}
	}
}

// The XML of the flow-log operations, as EC2 writes it.
func TestEC2_FlowLogXML(t *testing.T) {
	fl := ec2FlowLog{ID: "fl-0123456789abcdef0", Account: flAccount, ResourceType: "VPC", ResourceID: "vpc-lambda", TrafficType: "REJECT",
		LogGroup: "flows", LogDestination: "arn:aws:logs:us-east-1:" + flAccount + ":log-group:flows", DeliverRole: "arn:aws:iam::" + flAccount + ":role/FlowLogsDelivery",
		LogFormat: defaultFlowLogFormat, MaxAggregation: 600, Tags: map[string]string{"Name": "rejects"}, DeliverStatus: "FAILED",
		DeliverError: flowLogAccessError, Created: time.Date(2026, 11, 8, 10, 0, 0, 383e6, time.UTC)}
	want := "<deliverLogsErrorMessage>Access error</deliverLogsErrorMessage><resourceId>vpc-lambda</resourceId>" +
		"<logDestinationType>cloud-watch-logs</logDestinationType><deliverLogsPermissionArn>arn:aws:iam::" + flAccount + ":role/FlowLogsDelivery</deliverLogsPermissionArn>" +
		"<creationTime>2026-11-08T10:00:00.383Z</creationTime><trafficType>REJECT</trafficType><deliverLogsStatus>FAILED</deliverLogsStatus>" +
		"<logFormat>" + defaultFlowLogFormat + "</logFormat><flowLogStatus>ACTIVE</flowLogStatus><logGroupName>flows</logGroupName>" +
		"<logDestination>arn:aws:logs:us-east-1:" + flAccount + ":log-group:flows</logDestination><flowLogId>fl-0123456789abcdef0</flowLogId>" +
		"<maxAggregationInterval>600</maxAggregationInterval><tagSet><item><key>Name</key><value>rejects</value></item></tagSet>"
	if got := flowLogXML(fl); got != want {
		t.Errorf("FlowLog:\n%s\nwant\n%s", got, want)
	}
	if got := unsuccessfulXML(nil); got != "<unsuccessful/>" {
		t.Errorf("no unsuccessful items: %s", got)
	}
	got := unsuccessfulXML([]flowLogUnsuccessful{flowLogNotFound("VPC", "vpc-missing")})
	if got != "<unsuccessful><item><error><code>InvalidVpcID.NotFound</code><message>The vpc ID &#39;vpc-missing&#39; does not exist</message></error>"+
		"<resourceId>vpc-missing</resourceId></item></unsuccessful>" {
		t.Errorf("an unsuccessful item: %s", got)
	}
	if fl.ARN("us-east-1") != "arn:aws:ec2:us-east-1:"+flAccount+":vpc-flow-log/fl-0123456789abcdef0" {
		t.Errorf("ARN: %s", fl.ARN("us-east-1"))
	}
	if !newFlowLogIDRe.MatchString(newFlowLogID()) {
		t.Errorf("a flow log id is fl- and 17 hex digits: %s", newFlowLogID())
	}
}
