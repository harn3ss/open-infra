// VPC Flow Logs (CreateFlowLogs, DescribeFlowLogs, DeleteFlowLogs) for the network interfaces of Lambda
// functions in a VPC (vpcnet.go): a flow log on a VPC, a subnet or one of Lambda's network interfaces
// (ec2_network_interfaces.go) records the flows its interfaces' security groups rejected into a
// CloudWatch Logs log group, one log stream per network interface — as on AWS.
//
// Kept in the shim's Postgres (the SQS store), each flow log in its account; its records are made by the
// delivery worker (ec2_flowlogs_delivery.go) from the packets OVN logs as dropped by a VPC security
// group's NetworkPolicy. Only rejected traffic is logged (OVN would log every packet of an accepted
// connection), so TrafficType is REJECT; ACCEPT and ALL are refused. The destination is CloudWatch Logs
// alone: Amazon S3 and Kinesis Data Firehose destinations, transit gateways and the record fields the
// platform does not record are refused, naming what is served, never accepted and left empty.
//
// Authorization, as AWS: ec2:CreateFlowLogs, ec2:DescribeFlowLogs, ec2:DeleteFlowLogs on the flow log
// (VpcFlowLog::<id>, VpcFlowLog::* for a create and a describe), and iam:PassRole, passed to
// vpc-flow-logs.amazonaws.com, on the DeliverLogsPermissionArn role.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/lib/pq"
)

const (
	// flowLogsService is the service principal a flow log's delivery role trusts and is passed to.
	flowLogsService = "vpc-flow-logs.amazonaws.com"
	// defaultFlowLogFormat is AWS's default record format (version 2).
	defaultFlowLogFormat = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}"
	flowLogAccessError   = "Access error" // DeliverLogsErrorMessage when the delivery role cannot deliver
	maxFlowLogResources  = 300            // ResourceId.N: AWS's maximum for a VPC, subnet or interface
	maxFlowLogIDs        = 1000           // FlowLogId.N
)

// ec2FlowLog is one flow log.
type ec2FlowLog struct {
	ID, Account                           string
	ResourceType, ResourceID, TrafficType string
	LogGroup, LogDestination              string // the log group's name, and its ARN
	DeliverRole                           string // DeliverLogsPermissionArn
	LogFormat                             string
	MaxAggregation                        int // seconds: 60 or 600
	Tags                                  map[string]string
	DeliverStatus, DeliverError           string
	Created                               time.Time
	// PublishedUntil (Unix ns) is the delivery cursor: every aggregation window ending at or before it has
	// been published. It starts at the flow log's creation and moves a window at a time.
	PublishedUntil int64
}

// ARN is the flow log's ARN (vpc-flow-log/<id>).
func (fl ec2FlowLog) ARN(region string) string {
	return "arn:aws:ec2:" + region + ":" + fl.Account + ":vpc-flow-log/" + fl.ID
}

// covers reports whether the flow log monitors in: its VPC, its subnet or the interface itself, in the
// flow log's own account.
func (fl ec2FlowLog) covers(in vpcInterface) bool {
	if in.Account != fl.Account {
		return false
	}
	switch fl.ResourceType {
	case "VPC":
		return in.VpcID == fl.ResourceID
	case "Subnet":
		return in.SubnetID == fl.ResourceID
	case "NetworkInterface":
		return in.ENI == fl.ResourceID
	}
	return false
}

// records reports whether the flow log records traffic with action (ACCEPT or REJECT).
func (fl ec2FlowLog) records(action string) bool {
	return fl.TrafficType == "ALL" || fl.TrafficType == action
}

// flowLogUnsuccessful is one resource or flow log an operation could not act on (UnsuccessfulItem).
type flowLogUnsuccessful struct {
	ResourceID string `json:"resourceId"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

// flowLogCreateResult is a CreateFlowLogs answer, kept with its client token for a retry.
type flowLogCreateResult struct {
	IDs          []string              `json:"ids"`
	Unsuccessful []flowLogUnsuccessful `json:"unsuccessful"`
}

var errIdempotentMismatch = errors.New("client token reused with other parameters")

// sqlQueryer is what the store runs its statements on: the pool, or the delivery worker's own connection.
type sqlQueryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type ec2FlowLogStore struct{ db *sql.DB }

// Each row is its account's (the account column is the owning account's id, management included); a
// resource has at most one flow log of a traffic type to a destination (FlowLogAlreadyExists).
func (s *ec2FlowLogStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS ec2_flow_logs (
    flow_log_id        text PRIMARY KEY,
    account            text NOT NULL,
    resource_type      text NOT NULL,
    resource_id        text NOT NULL,
    traffic_type       text NOT NULL,
    log_group          text NOT NULL,
    log_destination    text NOT NULL,
    deliver_role       text NOT NULL,
    log_format         text NOT NULL,
    max_aggregation    integer NOT NULL,
    tags               jsonb NOT NULL DEFAULT '{}',
    deliver_status     text NOT NULL DEFAULT 'SUCCESS',
    deliver_error      text NOT NULL DEFAULT '',
    created            timestamptz NOT NULL,
    published_until_ns bigint NOT NULL,
    UNIQUE (account, resource_id, traffic_type, log_destination)
);
CREATE TABLE IF NOT EXISTS ec2_flow_log_tokens (
    account      text NOT NULL,
    client_token text NOT NULL,
    params_hash  text NOT NULL,
    result       jsonb NOT NULL,
    created      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account, client_token)
);`)
	return err
}

// create records the flow logs of one CreateFlowLogs (refused: the resources already refused), in one
// transaction. A retry with the same client token answers what the first call did; with other
// parameters, errIdempotentMismatch.
func (s *ec2FlowLogStore) create(ctx context.Context, account, token, paramsHash string, fls []ec2FlowLog,
	refused []flowLogUnsuccessful) (flowLogCreateResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return flowLogCreateResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if token != "" {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "ec2-flow-log-token/"+account+"/"+token); err != nil {
			return flowLogCreateResult{}, err
		}
		var hash string
		var prior []byte
		err := tx.QueryRowContext(ctx, `SELECT params_hash, result FROM ec2_flow_log_tokens WHERE account=$1 AND client_token=$2`,
			account, token).Scan(&hash, &prior)
		switch {
		case err == nil:
			if hash != paramsHash {
				return flowLogCreateResult{}, errIdempotentMismatch
			}
			var res flowLogCreateResult
			if err := json.Unmarshal(prior, &res); err != nil {
				return flowLogCreateResult{}, err
			}
			return res, nil
		case !errors.Is(err, sql.ErrNoRows):
			return flowLogCreateResult{}, err
		}
	}
	res := flowLogCreateResult{IDs: []string{}, Unsuccessful: append([]flowLogUnsuccessful{}, refused...)}
	for _, fl := range fls {
		tags, _ := json.Marshal(fl.Tags)
		var id string
		err := tx.QueryRowContext(ctx, `INSERT INTO ec2_flow_logs (flow_log_id, account, resource_type, resource_id, traffic_type,
    log_group, log_destination, deliver_role, log_format, max_aggregation, tags, created, published_until_ns)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (account, resource_id, traffic_type, log_destination) DO NOTHING RETURNING flow_log_id`,
			fl.ID, account, fl.ResourceType, fl.ResourceID, fl.TrafficType, fl.LogGroup, fl.LogDestination, fl.DeliverRole,
			fl.LogFormat, fl.MaxAggregation, string(tags), fl.Created, fl.Created.UnixNano()).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			res.Unsuccessful = append(res.Unsuccessful, flowLogUnsuccessful{ResourceID: fl.ResourceID, Code: "FlowLogAlreadyExists",
				Message: "Error. There is an existing Flow Log with the same configuration and log destination."})
		case err != nil:
			return flowLogCreateResult{}, err
		default:
			res.IDs = append(res.IDs, id)
		}
	}
	if token != "" {
		b, _ := json.Marshal(res)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ec2_flow_log_tokens (account, client_token, params_hash, result) VALUES ($1,$2,$3,$4)`,
			account, token, paramsHash, string(b)); err != nil {
			return flowLogCreateResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return flowLogCreateResult{}, err
	}
	return res, nil
}

const flowLogColumns = `flow_log_id, account, resource_type, resource_id, traffic_type, log_group, log_destination, deliver_role,
    log_format, max_aggregation, tags, deliver_status, deliver_error, created, published_until_ns`

func scanFlowLogs(rows *sql.Rows) ([]ec2FlowLog, error) {
	defer rows.Close()
	var out []ec2FlowLog
	for rows.Next() {
		var fl ec2FlowLog
		var tags []byte
		if err := rows.Scan(&fl.ID, &fl.Account, &fl.ResourceType, &fl.ResourceID, &fl.TrafficType, &fl.LogGroup, &fl.LogDestination,
			&fl.DeliverRole, &fl.LogFormat, &fl.MaxAggregation, &tags, &fl.DeliverStatus, &fl.DeliverError, &fl.Created,
			&fl.PublishedUntil); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tags, &fl.Tags)
		out = append(out, fl)
	}
	return out, rows.Err()
}

// list is an account's flow logs, oldest first.
func (s *ec2FlowLogStore) list(ctx context.Context, account string) ([]ec2FlowLog, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+flowLogColumns+` FROM ec2_flow_logs WHERE account=$1 ORDER BY created, flow_log_id`, account)
	if err != nil {
		return nil, err
	}
	return scanFlowLogs(rows)
}

// listAll is every account's flow logs (the delivery worker's).
func listAllFlowLogs(ctx context.Context, q sqlQueryer) ([]ec2FlowLog, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+flowLogColumns+` FROM ec2_flow_logs ORDER BY created, flow_log_id`)
	if err != nil {
		return nil, err
	}
	return scanFlowLogs(rows)
}

// delete removes the account's flow logs with ids, returning the ids it removed.
func (s *ec2FlowLogStore) delete(ctx context.Context, account string, ids []string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `DELETE FROM ec2_flow_logs WHERE account=$1 AND flow_log_id = ANY($2) RETURNING flow_log_id`,
		account, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	gone := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		gone[id] = true
	}
	return gone, rows.Err()
}

// advanceFlowLog moves a flow log's delivery cursor from `from` to `to`; false when the cursor is not at
// `from` (the flow log was deleted, or another worker moved it).
func advanceFlowLog(ctx context.Context, q sqlQueryer, id string, from, to int64) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE ec2_flow_logs SET published_until_ns=$3 WHERE flow_log_id=$1 AND published_until_ns=$2`, id, from, to)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// setFlowLogStatus records a flow log's delivery status (SUCCESS, or FAILED with AWS's error message).
func setFlowLogStatus(ctx context.Context, q sqlQueryer, id, status, message string) error {
	_, err := q.ExecContext(ctx, `UPDATE ec2_flow_logs SET deliver_status=$2, deliver_error=$3 WHERE flow_log_id=$1`, id, status, message)
	return err
}

// newFlowLogID is a flow log id in AWS's shape: fl- and 17 hex digits.
func newFlowLogID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return "fl-" + hex.EncodeToString(b)[:17]
}

// --- the record format ---

// flowLogFieldInfo is one flow log record field: the version that introduced it, and whether the platform
// records it.
type flowLogFieldInfo struct {
	version int
	served  bool
}

// flowLogFields is every field AWS documents (the Amazon VPC User Guide's "Flow log records"). Served:
// what a VPC security group's logged packets give truthfully — versions 2 to 4 and flow-direction (bytes
// is 0, not measured; instance-id is "-", as for any requester-managed interface; the sublocation fields
// are "-", there being none). The rest — the AWS service ranges, the traffic path, ECS, reject reasons,
// encryption status, tags and next hops — are refused rather than filled with guesses.
var flowLogFields = func() map[string]flowLogFieldInfo {
	m := map[string]flowLogFieldInfo{}
	add := func(v int, served bool, names ...string) {
		for _, n := range names {
			m[n] = flowLogFieldInfo{version: v, served: served}
		}
	}
	add(2, true, "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets",
		"bytes", "start", "end", "action", "log-status")
	add(3, true, "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr")
	add(4, true, "region", "az-id", "sublocation-type", "sublocation-id")
	add(5, true, "flow-direction")
	add(5, false, "pkt-src-aws-service", "pkt-dst-aws-service", "traffic-path")
	add(7, false, "ecs-cluster-arn", "ecs-cluster-name", "ecs-container-instance-arn", "ecs-container-instance-id",
		"ecs-container-id", "ecs-second-container-id", "ecs-service-name", "ecs-task-definition-arn", "ecs-task-arn", "ecs-task-id")
	add(8, false, "reject-reason")
	add(9, false, "resource-id")
	add(10, false, "encryption-status")
	add(11, false, "instance-tag", "instance-tag-2", "interface-tag", "interface-tag-2", "asg-tag", "asg-tag-2", "interface-type",
		"next-hop-interface-id", "next-hop-subnet-id", "next-hop-az-id", "next-hop-vpc-id", "next-hop-interface-type")
	return m
}()

var flowLogFieldRe = regexp.MustCompile(`^\$\{([a-z0-9-]+)\}$`)

// parseFlowLogFormat is a LogFormat's fields in order (the default format's when format is empty) and the
// record version they make (2 for the default; for a custom format the highest of its fields', as AWS
// says). A malformed format, an unknown field or one the platform does not record is refused with the
// message saying which.
func parseFlowLogFormat(format string) (fields []string, version int, msg string) {
	if strings.TrimSpace(format) == "" {
		format = defaultFlowLogFormat
	}
	var unknown, unserved []string
	for _, tok := range strings.Fields(format) {
		m := flowLogFieldRe.FindStringSubmatch(tok)
		if m == nil {
			return nil, 0, "LogFormat must list fields as ${field-id}, separated by spaces: '" + tok + "' is not one"
		}
		info, ok := flowLogFields[m[1]]
		switch {
		case !ok:
			unknown = append(unknown, tok)
		case !info.served:
			unserved = append(unserved, tok)
		default:
			fields = append(fields, m[1])
			if info.version > version {
				version = info.version
			}
		}
	}
	if len(unknown) > 0 {
		return nil, 0, "Unknown fields provided in LogFormat: " + strings.Join(unknown, ", ")
	}
	if len(unserved) > 0 {
		return nil, 0, "LogFormat fields not recorded by the open-infra shim: " + strings.Join(unserved, ", ") +
			" (it records the fields of versions 2 to 4 and ${flow-direction})"
	}
	if len(fields) == 0 {
		return nil, 0, "LogFormat must include at least one field"
	}
	return fields, version, ""
}

// canonicalFlowLogFormat is a format's fields as ${field} joined by single spaces, as DescribeFlowLogs
// answers it.
func canonicalFlowLogFormat(fields []string) string {
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = "${" + f + "}"
	}
	return strings.Join(parts, " ")
}

// --- the operations ---

var logGroupNameRe = regexp.MustCompile(`^[\.\-_/#A-Za-z0-9]{1,512}$`)

func (h *ec2Handler) flowLogStoreMissing(w http.ResponseWriter, requestID string) bool {
	if h.flowLogs == nil {
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "the flow-log store is not configured on this shim (set SQS_PG_URI)")
		return true
	}
	return false
}

func (h *ec2Handler) createFlowLogs(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.flowLogStoreMissing(w, requestID) {
		return
	}
	bad := func(code, msg string) { writeEC2Error(w, http.StatusBadRequest, code, requestID, msg) }
	f := r.Form
	resType := f.Get("ResourceType")
	switch resType {
	case "":
		bad("MissingParameter", "The request must contain the parameter ResourceType")
		return
	case "VPC", "Subnet", "NetworkInterface":
	case "TransitGateway", "TransitGatewayAttachment", "RegionalNatGateway":
		bad("InvalidParameterValue", "ResourceType "+resType+" is not served by the open-infra shim (served: VPC, Subnet, NetworkInterface)")
		return
	default:
		bad("InvalidParameterValue", "Value ("+resType+") for parameter resourceType is invalid. Valid values: VPC, Subnet, NetworkInterface, TransitGateway, TransitGatewayAttachment, RegionalNatGateway")
		return
	}
	ids := ec2List(f, "ResourceId")
	if len(ids) == 0 {
		bad("MissingParameter", "The request must contain the parameter ResourceId")
		return
	}
	if len(ids) > maxFlowLogResources {
		bad("InvalidParameter", "ResourceIds can contain at most "+strconv.Itoa(maxFlowLogResources)+" resources")
		return
	}
	traffic := f.Get("TrafficType")
	switch traffic {
	case "":
		bad("MissingParameter", "The request must contain the parameter TrafficType")
		return
	case "REJECT":
	case "ACCEPT", "ALL":
		// OVN logs every packet of an allowed connection, so accepted traffic is not logged at all: a flow
		// log that asked for it would be silently incomplete.
		bad("InvalidParameter", "TrafficType "+traffic+" is not served by the open-infra shim: it records the traffic a VPC's security groups reject (REJECT), not accepted traffic")
		return
	default:
		bad("InvalidParameterValue", "Value ("+traffic+") for parameter trafficType is invalid. Valid values: ACCEPT, REJECT, ALL")
		return
	}
	switch dt := f.Get("LogDestinationType"); dt {
	case "", "cloud-watch-logs":
	case "s3", "kinesis-data-firehose":
		bad("InvalidParameter", "LogDestinationType "+dt+" is not served by the open-infra shim (served: cloud-watch-logs)")
		return
	default:
		bad("InvalidParameterValue", "Value ("+dt+") for parameter logDestinationType is invalid. Valid values: cloud-watch-logs, s3, kinesis-data-firehose")
		return
	}
	if f.Get("DeliverCrossAccountRole") != "" {
		bad("InvalidParameter", "DeliverCrossAccountRole is not served by the open-infra shim: a flow log delivers to a log group of its own account")
		return
	}
	for k := range f {
		if strings.HasPrefix(k, "DestinationOptions.") {
			bad("InvalidParameter", "DestinationOptions apply to an Amazon S3 destination, which the open-infra shim does not serve")
			return
		}
		if strings.HasPrefix(k, "TagFieldSpecification.") {
			bad("InvalidParameter", "TagFieldSpecification is not served by the open-infra shim (its tag fields are not recorded)")
			return
		}
	}
	owner := h.ownerAccount(ctx)
	region := h.region()
	group, dest := f.Get("LogGroupName"), f.Get("LogDestination")
	switch {
	case group != "" && dest != "":
		bad("InvalidParameter", "Please only provide LogGroupName or only provide LogDestination.")
		return
	case group == "" && dest == "":
		bad("InvalidParameter", "Please provide either LogGroupName or LogDestination.")
		return
	case dest != "":
		acct, name, ok := logGroupOfARN(dest)
		if !ok {
			bad("InvalidParameter", "LogDestination must be the ARN of a CloudWatch Logs log group (arn:aws:logs:<region>:<account>:log-group:<name>)")
			return
		}
		if p := strings.SplitN(dest, ":", 7); p[3] != region {
			bad("InvalidParameter", "LogDestination names region "+p[3]+"; this install is the one region "+region)
			return
		}
		if acct != owner {
			bad("InvalidParameter", "LogDestination is a log group of account "+acct+"; a flow log delivers to its own account's log groups (cross-account delivery is not served by the open-infra shim)")
			return
		}
		group = name
	}
	if !logGroupNameRe.MatchString(group) || memberKeyRe.MatchString(group) {
		bad("InvalidParameter", "The log group name '"+group+"' is not valid: 1 to 512 characters of [.-_/#A-Za-z0-9]")
		return
	}
	if isDerivedName(group) {
		bad("InvalidParameter", "The log group '"+group+"' is a group AWS keeps a service's own logs in; give the flow log a log group of its own")
		return
	}
	role := f.Get("DeliverLogsPermissionArn")
	if role == "" {
		bad("InvalidParameter", "DeliverLogsPermissionArn is required when the log destination type is cloud-watch-logs")
		return
	}
	if !roleARNRe.MatchString(role) {
		bad("InvalidParameter", "DeliverLogsPermissionArn '"+role+"' is not an IAM role ARN")
		return
	}
	if strings.Split(role, ":")[4] != owner {
		bad("InvalidParameter", "DeliverLogsPermissionArn must be a role of the flow log's own account ("+owner+")")
		return
	}
	agg := 600
	if v := f.Get("MaxAggregationInterval"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || (n != 60 && n != 600) {
			bad("InvalidParameter", "Invalid value for MaxAggregationInterval: "+v+". It must be 60 or 600 (seconds)")
			return
		}
		agg = n
	}
	fields, _, msg := parseFlowLogFormat(f.Get("LogFormat"))
	if msg != "" {
		bad("InvalidParameter", msg)
		return
	}
	format := canonicalFlowLogFormat(fields)
	if f.Get("LogFormat") == "" {
		format = defaultFlowLogFormat
	}
	// The delivery role is passed to the flow logs service: iam:PassRole on it, as AWS requires.
	roleName := roleNameOf(role)
	if ok, reason := callerMayPassRole(ctx, h.door.cs, h.door.authz, claims, h.passRoleNamespace(ctx), roleName, flowLogsService, r); !ok {
		h.audit(ctx, "CreateFlowLogs", role, reason)
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
		return
	}
	// Each resource must be one of the account's (an unknown one is in the unsuccessful set).
	known, denied, err := h.flowLogResources(ctx, claims, resType)
	if err != nil {
		h.readFailed(w, requestID, "flow log resources", denied, err)
		return
	}
	tags := ec2TagSpec(f, "vpc-flow-log")
	destARN := "arn:aws:logs:" + region + ":" + owner + ":log-group:" + group
	created := time.Now().UTC().Truncate(time.Microsecond)
	var fls []ec2FlowLog
	var refused []flowLogUnsuccessful
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if !known[id] {
			refused = append(refused, flowLogNotFound(resType, id))
			continue
		}
		fls = append(fls, ec2FlowLog{ID: newFlowLogID(), Account: owner, ResourceType: resType, ResourceID: id, TrafficType: traffic,
			LogGroup: group, LogDestination: destARN, DeliverRole: role, LogFormat: format, MaxAggregation: agg, Tags: tags, Created: created})
	}
	token := f.Get("ClientToken")
	res, err := h.flowLogs.create(ctx, owner, token, flowLogParamsHash(f), fls, refused)
	if errors.Is(err, errIdempotentMismatch) {
		bad("IdempotentParameterMismatch", "The client token you have provided is associated with a request that had different parameters.")
		return
	}
	if err != nil {
		h.readFailed(w, requestID, "flow logs", false, err)
		return
	}
	ids2 := make([]string, len(res.IDs))
	for i, id := range res.IDs {
		ids2[i] = xesc(id)
	}
	writeEC2(w, requestID, "CreateFlowLogs", unsuccessfulXML(res.Unsuccessful)+xset("flowLogIdSet", ids2)+xtag("clientToken", token))
}

// flowLogNotFound is the unsuccessful item for a resource the account does not have.
func flowLogNotFound(resType, id string) flowLogUnsuccessful {
	switch resType {
	case "VPC":
		return flowLogUnsuccessful{ResourceID: id, Code: "InvalidVpcID.NotFound", Message: "The vpc ID '" + id + "' does not exist"}
	case "Subnet":
		return flowLogUnsuccessful{ResourceID: id, Code: "InvalidSubnetID.NotFound", Message: "The subnet ID '" + id + "' does not exist"}
	}
	return flowLogUnsuccessful{ResourceID: id, Code: "InvalidNetworkInterfaceID.NotFound", Message: "The networkInterface ID '" + id + "' does not exist"}
}

// flowLogResources is the ids of the account's resources of resType a flow log may monitor: its VPCs, its
// subnets, or its Lambda functions' network interfaces.
func (h *ec2Handler) flowLogResources(ctx context.Context, claims iam.Claims, resType string) (map[string]bool, bool, error) {
	out := map[string]bool{}
	switch resType {
	case "VPC", "Subnet":
		gvr := vpcGVR
		if resType == "Subnet" {
			gvr = subnetGVR
		}
		items, denied, err := h.listForCaller(ctx, claims, gvr)
		if err != nil {
			return nil, denied, err
		}
		for i := range items {
			out[items[i].GetName()] = true
		}
	case "NetworkInterface":
		enis, denied, err := h.lambdaENIsForCaller(ctx, claims)
		if err != nil {
			return nil, denied, err
		}
		for _, e := range enis {
			out[e.ID] = true
		}
	}
	return out, false, nil
}

// flowLogParamsHash identifies a CreateFlowLogs request's parameters for its client token (everything but
// the token, the action and the signature).
func flowLogParamsHash(f url.Values) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		switch {
		case k == "Action", k == "Version", k == "ClientToken", k == "DryRun", strings.HasPrefix(k, "X-Amz-"):
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		_, _ = h.Write([]byte(k + "=" + strings.Join(f[k], "\x00") + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// unsuccessfulXML is an operation's unsuccessful set (UnsuccessfulItem: error code and message, resourceId).
func unsuccessfulXML(items []flowLogUnsuccessful) string {
	out := make([]string, len(items))
	for i, u := range items {
		out[i] = "<error>" + xtag("code", u.Code) + xtag("message", u.Message) + "</error>" + xtag("resourceId", u.ResourceID)
	}
	return xset("unsuccessful", out)
}

var flowLogFilters = []string{"flow-log-id", "resource-id", "log-group-name", "traffic-type", "deliver-log-status", "log-destination-type"}

func (h *ec2Handler) describeFlowLogs(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if h.flowLogStoreMissing(w, requestID) {
		return
	}
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, flowLogFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	ids := ec2List(r.Form, "FlowLogId")
	if len(ids) > maxFlowLogIDs {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameter", requestID, "FlowLogIds can contain at most "+strconv.Itoa(maxFlowLogIDs)+" ids")
		return
	}
	all, err := h.flowLogs.list(ctx, h.ownerAccount(ctx))
	if err != nil {
		h.readFailed(w, requestID, "flow logs", false, err)
		return
	}
	want := setOf(ids)
	var sel []ec2FlowLog
	for _, fl := range all {
		if len(ids) > 0 && !want[fl.ID] {
			continue // an id the account does not have describes nothing, as on AWS
		}
		rec := ec2Record{fields: map[string][]string{"flow-log-id": {fl.ID}, "resource-id": {fl.ResourceID}, "log-group-name": {fl.LogGroup},
			"traffic-type": {fl.TrafficType}, "deliver-log-status": {fl.DeliverStatus}, "log-destination-type": {"cloud-watch-logs"}}, tags: fl.Tags}
		if rec.matches(fs) {
			sel = append(sel, fl)
		}
	}
	start, end, next, msg, ok := ec2Page(r.Form, len(sel), 1, 1000)
	if !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	items := make([]string, 0, end-start)
	for _, fl := range sel[start:end] {
		items = append(items, flowLogXML(fl))
	}
	writeEC2(w, requestID, "DescribeFlowLogs", xset("flowLogSet", items)+xtag("nextToken", next))
}

// flowLogXML is a flow log as DescribeFlowLogs answers it (FlowLog).
func flowLogXML(fl ec2FlowLog) string {
	status := fl.DeliverStatus
	if status == "" {
		status = "SUCCESS"
	}
	return xtag("deliverLogsErrorMessage", fl.DeliverError) + xtag("resourceId", fl.ResourceID) +
		"<logDestinationType>cloud-watch-logs</logDestinationType>" + xtag("deliverLogsPermissionArn", fl.DeliverRole) +
		xtag("creationTime", ec2Time(fl.Created)) + xtag("trafficType", fl.TrafficType) + xtag("deliverLogsStatus", status) +
		xtag("logFormat", fl.LogFormat) + "<flowLogStatus>ACTIVE</flowLogStatus>" + xtag("logGroupName", fl.LogGroup) +
		xtag("logDestination", fl.LogDestination) + xtag("flowLogId", fl.ID) +
		"<maxAggregationInterval>" + strconv.Itoa(fl.MaxAggregation) + "</maxAggregationInterval>" + xtags(fl.Tags)
}

func (h *ec2Handler) deleteFlowLogs(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.flowLogStoreMissing(w, requestID) {
		return
	}
	ids := ec2List(r.Form, "FlowLogId")
	if len(ids) == 0 {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter FlowLogId")
		return
	}
	if len(ids) > maxFlowLogIDs {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameter", requestID, "FlowLogIds can contain at most "+strconv.Itoa(maxFlowLogIDs)+" ids")
		return
	}
	// The first id was authorized at the door (ec2ScopeName); each other one is, too, before anything is deleted.
	for _, id := range ids[1:] {
		if ok, reason := decide(ctx, r, h.door.authz, claims, "ec2:DeleteFlowLogs", "VpcFlowLog", id,
			dataPlaneOnly(ctx, r, h.door.authz, claims, "ec2:DeleteFlowLogs", "VpcFlowLog", id)); !ok {
			h.audit(ctx, "DeleteFlowLogs", id, reason)
			writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
			return
		}
	}
	gone, err := h.flowLogs.delete(ctx, h.ownerAccount(ctx), ids)
	if err != nil {
		h.readFailed(w, requestID, "flow logs", false, err)
		return
	}
	var missing []string
	for _, id := range ids {
		if !gone[id] {
			missing = append(missing, id)
		}
	}
	var items []flowLogUnsuccessful
	if len(missing) > 0 {
		msg := "These flow log ids in the input list are not found: [TotalCount: " + strconv.Itoa(len(missing)) + "] " + strings.Join(missing, ", ")
		for _, id := range missing {
			items = append(items, flowLogUnsuccessful{ResourceID: id, Code: "InvalidFlowLogId.NotFound", Message: msg})
		}
	}
	writeEC2(w, requestID, "DeleteFlowLogs", unsuccessfulXML(items))
}

// passRoleNamespace is the namespace the caller's account's IAM roles are in: the IAM home for the
// management account, a member account's home for a member's (a role is passed within its own account).
func (h *ec2Handler) passRoleNamespace(ctx context.Context) string {
	ns := h.rolesNS
	if ns == "" {
		ns = dataplaneauthz.DefaultHomeNamespace
	}
	return accountNamespace(ctx, ns)
}
