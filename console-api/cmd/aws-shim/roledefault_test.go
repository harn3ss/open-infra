package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
)

// An assumed-role session's complete authority is its data-plane policy (iam.CanDo passes a role), so every
// front door must check it on EVERY operation — including the ones that name no resource (List*, Describe-
// all) and the creates — default-deny, on <Type>::* (AWS's Resource "*") when the op names none. A User's
// behavior is unchanged: coarse RBAC + the additive data-plane check where an op names a resource.
//
// Each case drives one real operation through a front door's serve(). The SAR reactor ALLOWS everything, so
// a denial can only come from the data-plane check; backends are absent or unreachable, so an operation that
// passes authorization ends in a backend error (5xx / NotFound / validation), never in the denial code.

// roleDoorCase is one operation at one front door.
type roleDoorCase struct {
	door, op string
	action   string // the AWS action the role must be allowed
	resType  string // the data-plane resource type the op is checked on
	resName  string // the resource the op names; "" = resource-less (checked on <resType>::* for a role)
	denyCode string // the front door's access-denied error code
	// userAlwaysChecked: the front door already runs a User's data-plane check on resource-less ops too
	// (API Gateway, S3), so a governed User without the grant is denied there — unchanged.
	userAlwaysChecked bool
	call              func(t *testing.T, authz *dataplaneauthz.Checker, claims iam.Claims) *httptest.ResponseRecorder
}

func jsonOp(target, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	return req
}

func formOp(params url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// unreachableDB is a Postgres handle whose every query fails fast (nothing listens on port 1): it gets a
// handler that checks for a configured store BEFORE authorization past that check.
func unreachableDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://u:p@127.0.0.1:1/x?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func fakeDynWith(gvrs ...schema.GroupVersionResource) *dynamicfake.FakeDynamicClient {
	kinds := map[schema.GroupVersionResource]string{}
	for _, g := range gvrs {
		kinds[g] = "List"
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), kinds)
}

// server is the serve half of awsService (the REST v1 handler is reached through a mux, not the registry).
type server interface {
	serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string)
}

func serveWith(h server, req *http.Request, claims iam.Claims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, req, claims, "req")
	return w
}

func roleDoorCases() []roleDoorCase {
	return []roleDoorCase{
		// --- SQS ---
		{door: "sqs", op: "ListQueues", action: "sqs:ListQueues", resType: "Queue", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSQSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("AmazonSQS.ListQueues", `{}`), c)
			}},
		{door: "sqs", op: "CreateQueue", action: "sqs:CreateQueue", resType: "Queue", resName: "jobs", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSQSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`), c)
			}},
		// --- SNS ---
		{door: "sns", op: "ListTopics", action: "sns:ListTopics", resType: "Topic", denyCode: "AuthorizationError",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSNSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"ListTopics"}}), c)
			}},
		{door: "sns", op: "CreateTopic", action: "sns:CreateTopic", resType: "Topic", resName: "alerts", denyCode: "AuthorizationError",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSNSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"CreateTopic"}, "Name": {"alerts"}}), c)
			}},
		// --- KMS ---
		{door: "kms", op: "CreateKey", action: "kms:CreateKey", resType: "Key", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newKMSHandler(csWithSAR(true), nil, "default", "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("TrentService.CreateKey", `{}`), c)
			}},
		{door: "kms", op: "ListKeys", action: "kms:ListKeys", resType: "Key", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newKMSHandler(csWithSAR(true), nil, "default", "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("TrentService.ListKeys", `{}`), c)
			}},
		// --- Secrets Manager ---
		{door: "secretsmanager", op: "ListSecrets", action: "secretsmanager:ListSecrets", resType: "Secret", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSecretsHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("secretsmanager.ListSecrets", `{}`), c)
			}},
		{door: "secretsmanager", op: "CreateSecret", action: "secretsmanager:CreateSecret", resType: "Secret", resName: "db-creds", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSecretsHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("secretsmanager.CreateSecret", `{"Name":"db-creds","SecretString":"x"}`), c)
			}},
		// --- SSM Parameter Store ---
		{door: "ssm", op: "DescribeParameters", action: "ssm:DescribeParameters", resType: "Parameter", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSSMHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("AmazonSSM.DescribeParameters", `{}`), c)
			}},
		// --- DynamoDB ---
		{door: "dynamodb", op: "ListTables", action: "dynamodb:ListTables", resType: "Table", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("DynamoDB_20120810.ListTables", `{}`), c)
			}},
		{door: "dynamodb", op: "CreateTable", action: "dynamodb:CreateTable", resType: "Table", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("DynamoDB_20120810.CreateTable", `{"TableName":"orders"}`), c)
			}},
		{door: "dynamodb", op: "BatchGetItem", action: "dynamodb:BatchGetItem", resType: "Table", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("DynamoDB_20120810.BatchGetItem",
					`{"RequestItems":{"orders":{"Keys":[{"id":{"S":"1"}}]}}}`), c)
			}},
		{door: "dynamodb", op: "TransactWriteItems", action: "dynamodb:PutItem", resType: "Table", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("DynamoDB_20120810.TransactWriteItems",
					`{"TransactItems":[{"Put":{"TableName":"orders","Item":{"id":{"S":"1"}}}}]}`), c)
			}},
		// --- DynamoDB Streams ---
		{door: "dynamodbstreams", op: "ListStreams", action: "dynamodb:ListStreams", resType: "Table", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newDDBStreamsHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("DynamoDBStreams_20120810.ListStreams", `{}`), c)
			}},
		// --- CloudWatch Logs ---
		{door: "logs", op: "DescribeLogGroups", action: "logs:DescribeLogGroups", resType: "LogGroup", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newCWLHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("Logs_20140328.DescribeLogGroups", `{}`), c)
			}},
		{door: "logs", op: "CreateLogGroup", action: "logs:CreateLogGroup", resType: "LogGroup", resName: "app", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newCWLHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("Logs_20140328.CreateLogGroup", `{"logGroupName":"app"}`), c)
			}},
		// --- CloudWatch metrics ---
		{door: "monitoring", op: "ListMetrics", action: "cloudwatch:ListMetrics", resType: "Namespace", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newCWHandler(csWithSAR(true), "default", "open-infra", "us-east-1", &cwStore{db: unreachableDB(t)}, nil, discardLogger())
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"ListMetrics"}}), c)
			}},
		// --- Kinesis ---
		{door: "kinesis", op: "ListStreams", action: "kinesis:ListStreams", resType: "Stream", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newKinesisHandler(csWithSAR(true), "default", "open-infra", "us-east-1", &kinesisStore{db: unreachableDB(t)}, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("Kinesis_20131202.ListStreams", `{}`), c)
			}},
		{door: "kinesis", op: "CreateStream", action: "kinesis:CreateStream", resType: "Stream", resName: "events", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newKinesisHandler(csWithSAR(true), "default", "open-infra", "us-east-1", &kinesisStore{db: unreachableDB(t)}, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("Kinesis_20131202.CreateStream", `{"StreamName":"events","ShardCount":1}`), c)
			}},
		// --- Route 53 Resolver (DNS Firewall, query logging): one case per resource family ---
		{door: "route53resolver", op: "ListFirewallDomainLists", action: "route53resolver:ListFirewallDomainLists", resType: "FirewallDomainList", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"ListFirewallDomainLists", `{}`), c)
			}},
		{door: "route53resolver", op: "UpdateFirewallDomains", action: "route53resolver:UpdateFirewallDomains", resType: "FirewallDomainList", resName: "rslvr-fdl-0123456789abcdef0", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"UpdateFirewallDomains",
					`{"FirewallDomainListId":"rslvr-fdl-0123456789abcdef0","Operation":"ADD","Domains":["example.com"]}`), c)
			}},
		{door: "route53resolver", op: "CreateFirewallRuleGroup", action: "route53resolver:CreateFirewallRuleGroup", resType: "FirewallRuleGroup", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"CreateFirewallRuleGroup", `{"Name":"egress","CreatorRequestId":"r1"}`), c)
			}},
		{door: "route53resolver", op: "ListFirewallRules", action: "route53resolver:ListFirewallRules", resType: "FirewallRuleGroup", resName: "rslvr-frg-0123456789abcdef0", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"ListFirewallRules", `{"FirewallRuleGroupId":"rslvr-frg-0123456789abcdef0"}`), c)
			}},
		{door: "route53resolver", op: "AssociateFirewallRuleGroup", action: "route53resolver:AssociateFirewallRuleGroup", resType: "FirewallRuleGroup", resName: "rslvr-frg-0123456789abcdef0", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"AssociateFirewallRuleGroup",
					`{"FirewallRuleGroupId":"rslvr-frg-0123456789abcdef0","VpcId":"vpc-0a1b2c3d","Priority":101,"Name":"egress","CreatorRequestId":"r1"}`), c)
			}},
		{door: "route53resolver", op: "ListFirewallRuleGroupAssociations", action: "route53resolver:ListFirewallRuleGroupAssociations", resType: "FirewallRuleGroupAssociation", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"ListFirewallRuleGroupAssociations", `{}`), c)
			}},
		{door: "route53resolver", op: "UpdateFirewallConfig", action: "route53resolver:UpdateFirewallConfig", resType: "FirewallConfig", resName: firewallConfigID("", "vpc-0a1b2c3d"), denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"UpdateFirewallConfig", `{"ResourceId":"vpc-0a1b2c3d","FirewallFailOpen":"ENABLED"}`), c)
			}},
		{door: "route53resolver", op: "ListFirewallConfigs", action: "route53resolver:ListFirewallConfigs", resType: "FirewallConfig", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"ListFirewallConfigs", `{}`), c)
			}},
		{door: "route53resolver", op: "CreateResolverQueryLogConfig", action: "route53resolver:CreateResolverQueryLogConfig", resType: "ResolverQueryLogConfig", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"CreateResolverQueryLogConfig",
					`{"Name":"dns","CreatorRequestId":"r1","DestinationArn":"arn:aws:logs:us-east-1:open-infra:log-group:dns"}`), c)
			}},
		{door: "route53resolver", op: "AssociateResolverQueryLogConfig", action: "route53resolver:AssociateResolverQueryLogConfig", resType: "ResolverQueryLogConfig", resName: "rqlc-0123456789abcdef", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"AssociateResolverQueryLogConfig",
					`{"ResolverQueryLogConfigId":"rqlc-0123456789abcdef","ResourceId":"vpc-0a1b2c3d"}`), c)
			}},
		{door: "route53resolver", op: "ListResolverQueryLogConfigAssociations", action: "route53resolver:ListResolverQueryLogConfigAssociations", resType: "ResolverQueryLogConfig", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"ListResolverQueryLogConfigAssociations", `{}`), c)
			}},
		{door: "route53resolver", op: "ListTagsForResource", action: "route53resolver:ListTagsForResource", resType: "FirewallRuleGroup", resName: "rslvr-frg-0123456789abcdef0", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				return serveWith(r53rTestHandler(t, a), jsonOp(r53rTargetPrefix+"ListTagsForResource",
					`{"ResourceArn":"arn:aws:route53resolver:us-east-1:open-infra:firewall-rule-group/rslvr-frg-0123456789abcdef0"}`), c)
			}},
		// --- EventBridge ---
		{door: "events", op: "ListRules", action: "events:ListRules", resType: "Rule", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newEBHandler(csWithSAR(true), "default", "default", "open-infra", "us-east-1", nil, nil, nil, discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("AWSEvents.ListRules", `{}`), c)
			}},
		// --- RDS ---
		{door: "rds", op: "DescribeDBInstances", action: "rds:DescribeDBInstances", resType: "DBInstance", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newRDSHandler(csWithSAR(true), nil, "default", "open-infra", "us-east-1", discardLogger())
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"DescribeDBInstances"}}), c)
			}},
		{door: "rds", op: "CreateDBInstance", action: "rds:CreateDBInstance", resType: "DBInstance", resName: "app-db", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newRDSHandler(csWithSAR(true), nil, "default", "open-infra", "us-east-1", discardLogger())
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"CreateDBInstance"}, "DBInstanceIdentifier": {"app-db"}}), c)
			}},
		// --- Glue / Athena ---
		{door: "glue", op: "GetDatabases", action: "glue:GetDatabases", resType: "Database", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newGlueHandler(csWithSAR(true), "default", "open-infra", "us-east-1", "http://127.0.0.1:1", discardLogger())
				h.authz = a
				return serveWith(h, jsonOp(glueTargetPrefix+".GetDatabases", `{}`), c)
			}},
		{door: "athena", op: "ListWorkGroups", action: "athena:ListWorkGroups", resType: "WorkGroup", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newAthenaHandler(csWithSAR(true), "default", "open-infra", "us-east-1", "http://127.0.0.1:1", "", "", "iceberg", "s3://out/", discardLogger())
				h.authz = a
				return serveWith(h, jsonOp(athenaTargetPrefix+".ListWorkGroups", `{}`), c)
			}},
		// --- Cognito ---
		{door: "cognito-idp", op: "ListUserPools", action: "cognito-idp:ListUserPools", resType: "UserPool", denyCode: "NotAuthorizedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newCognitoHandler(csWithSAR(true), "default", "open-infra", "us-east-1", "http://shim", &cognitoStore{db: unreachableDB(t)}, testSigner(t), discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("AWSCognitoIdentityProviderService.ListUserPools", `{"MaxResults":10}`), c)
			}},
		{door: "cognito-idp", op: "CreateUserPool", action: "cognito-idp:CreateUserPool", resType: "UserPool", denyCode: "NotAuthorizedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newCognitoHandler(csWithSAR(true), "default", "open-infra", "us-east-1", "http://shim", &cognitoStore{db: unreachableDB(t)}, testSigner(t), discardLogger())
				h.authz = a
				return serveWith(h, jsonOp("AWSCognitoIdentityProviderService.CreateUserPool", `{"PoolName":"users"}`), c)
			}},
		// --- ECS ---
		{door: "ecs", op: "ListClusters", action: "ecs:ListClusters", resType: "Service", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := ecsTestDoorway(true)
				h.authz = a
				h.shimDyn = fakeDynWith(configMapGVR)
				return serveWith(h, jsonOp(ecsTargetPrefix+".ListClusters", `{}`), c)
			}},
		// --- API Gateway (HTTP v2, REST v1) ---
		{door: "apigateway-v2", op: "GetApis", action: "apigateway:GetApis", resType: "Api", denyCode: "AccessDeniedException", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newAPIGWHandler(csWithSAR(true), "default", "open-infra", "us-east-1", "default", "svc.cluster.local", "http://shim", &apigwStore{db: unreachableDB(t)}, discardLogger())
				h.authz = a
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/v2/apis", nil), c)
			}},
		{door: "apigateway-v1", op: "GetRestApis", action: "apigateway:GetRestApis", resType: "Api", denyCode: "AccessDeniedException", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newAPIGWV1Handler(csWithSAR(true), "default", "default", "svc.cluster.local", "http://shim", &apigwV1Store{db: unreachableDB(t)}, a, discardLogger())
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/restapis", nil), c)
			}},
		// --- Step Functions ---
		{door: "states", op: "ListStateMachines", action: "states:ListStateMachines", resType: "StateMachine", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSFNHandler(csWithSAR(true), fakeDynWith(gvrStateMachines), nil, nil, a, "default", "open-infra", "us-east-1", discardLogger())
				return serveWith(h, jsonOp("AWSStepFunctions.ListStateMachines", `{}`), c)
			}},
		{door: "states", op: "StartExecution", action: "states:StartExecution", resType: "StateMachine", resName: "etl", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSFNHandler(csWithSAR(true), fakeDynWith(gvrStateMachines), nil, nil, a, "default", "open-infra", "us-east-1", discardLogger())
				return serveWith(h, jsonOp("AWSStepFunctions.StartExecution",
					`{"stateMachineArn":"arn:aws:states:us-east-1:open-infra:stateMachine:etl"}`), c)
			}},
		// --- IAM (writes with the shim's own identity — an escalation path for an ungated role) ---
		{door: "iam", op: "ListRoles", action: "iam:ListRoles", resType: "Role", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newIAMHandler(csWithSAR(true), fakeDynWith(gvrRoles), nil, a, "default", "open-infra", "us-east-1", discardLogger())
				return serveWith(h, formOp(url.Values{"Action": {"ListRoles"}}), c)
			}},
		{door: "iam", op: "CreateAccessKey", action: "iam:CreateAccessKey", resType: "User", resName: "admin", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				// No key store here: an authorized call ends at "access-key store not configured", after the gate.
				h := newIAMHandler(csWithSAR(true), fakeDynWith(gvrRoles), nil, a, "default", "open-infra", "us-east-1", discardLogger())
				return serveWith(h, formOp(url.Values{"Action": {"CreateAccessKey"}, "UserName": {"admin"}}), c)
			}},
		// Authorized on its ARN (instance-profile/*), as AWS does and as ListGroups is on group/*: a governed
		// User's policy is read for it.
		{door: "iam", op: "ListInstanceProfiles", action: "iam:ListInstanceProfiles", resType: "ARN", denyCode: "AccessDenied", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _ := profileFixture(t)
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"ListInstanceProfiles"}}), c)
			}},
		// --- EC2: a VPC's structure, read from its kinds and its stacks' templates ---
		{door: "ec2", op: "DescribeRouteTables", action: "ec2:DescribeRouteTables", resType: "RouteTable", denyCode: "UnauthorizedOperation",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _, _ := structuralFixture(t)
				h.door.authz = a
				return ec2Call(h, c, url.Values{"Action": {"DescribeRouteTables"}})
			}},
		{door: "ec2", op: "DescribeInternetGateways", action: "ec2:DescribeInternetGateways", resType: "InternetGateway", denyCode: "UnauthorizedOperation",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _, _ := structuralFixture(t)
				h.door.authz = a
				return ec2Call(h, c, url.Values{"Action": {"DescribeInternetGateways"}})
			}},
		// --- EC2: Lambda's network interfaces and VPC Flow Logs (no flow-log store here: an authorized call
		// ends at "not configured", after the gate) ---
		{door: "ec2", op: "DescribeNetworkInterfaces", action: "ec2:DescribeNetworkInterfaces", resType: "NetworkInterface", denyCode: "UnauthorizedOperation",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := eniFixture(t)
				h.door.authz = a
				return ec2Call(h, c, url.Values{"Action": {"DescribeNetworkInterfaces"}})
			}},
		{door: "ec2", op: "CreateFlowLogs", action: "ec2:CreateFlowLogs", resType: "VpcFlowLog", denyCode: "UnauthorizedOperation",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := eniFixture(t)
				h.door.authz = a
				return ec2Call(h, c, flCreate(nil))
			}},
		{door: "ec2", op: "DescribeFlowLogs", action: "ec2:DescribeFlowLogs", resType: "VpcFlowLog", denyCode: "UnauthorizedOperation",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := eniFixture(t)
				h.door.authz = a
				return ec2Call(h, c, url.Values{"Action": {"DescribeFlowLogs"}})
			}},
		{door: "ec2", op: "DeleteFlowLogs", action: "ec2:DeleteFlowLogs", resType: "VpcFlowLog", resName: "fl-0123456789abcdef0", denyCode: "UnauthorizedOperation",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := eniFixture(t)
				h.door.authz = a
				return ec2Call(h, c, url.Values{"Action": {"DeleteFlowLogs"}, "FlowLogId.1": {"fl-0123456789abcdef0"}})
			}},
		// --- SES ---
		{door: "ses", op: "GetSendQuota", action: "ses:GetSendQuota", resType: "Identity", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSESHandler(csWithSAR(true), "default", "127.0.0.1:1", a, discardLogger())
				return serveWith(h, formOp(url.Values{"Action": {"GetSendQuota"}}), c)
			}},
		{door: "ses", op: "VerifyEmailIdentity", action: "ses:VerifyEmailIdentity", resType: "Identity", resName: "ops@example.com", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSESHandler(csWithSAR(true), "default", "127.0.0.1:1", a, discardLogger())
				return serveWith(h, formOp(url.Values{"Action": {"VerifyEmailIdentity"}, "EmailAddress": {"ops@example.com"}}), c)
			}},
		// --- CloudFormation ---
		// A stack action that names no stack is checked on Stack::* for a User too (AWS's Resource "*").
		{door: "cloudformation", op: "ListStacks", action: "cloudformation:ListStacks", resType: "Stack", denyCode: "AccessDenied", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _ := cfnTestDoorway(t, "")
				h.cfg = &rest.Config{Host: "http://127.0.0.1:1"}
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"ListStacks"}}), c)
			}},
		{door: "cloudformation", op: "CreateStack", action: "cloudformation:CreateStack", resType: "Stack", resName: "app", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _ := cfnTestDoorway(t, "")
				h.cfg = &rest.Config{Host: "http://127.0.0.1:1"}
				h.authz = a
				return serveWith(h, formOp(url.Values{"Action": {"CreateStack"}, "StackName": {"app"}}), c)
			}},
		{door: "cloudformation", op: "DeleteStack(arn)", action: "cloudformation:DeleteStack", resType: "Stack", resName: "app", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _ := cfnTestDoorway(t, "")
				h.cfg = &rest.Config{Host: "http://127.0.0.1:1"}
				h.authz = a
				// A StackId ARN is gated on the stack it names.
				return serveWith(h, formOp(url.Values{"Action": {"DeleteStack"},
					"StackName": {"arn:aws:cloudformation:us-east-1:000000000000:stack/app/1a2b3c"}}), c)
			}},
		// --- AppSync (GraphQL data plane names no API: GraphQLApi::*; management names its API) ---
		{door: "appsync", op: "GraphQL", action: "appsync:GraphQL", resType: "GraphQLApi", denyCode: "UnauthorizedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newAppsyncHandler(csWithSAR(true), "http://127.0.0.1:1", "default", discardLogger())
				h.authz = a
				return serveWith(h, httptest.NewRequest(http.MethodPost, "http://shim/graphql", strings.NewReader(`{"query":"{a}"}`)), c)
			}},
		{door: "appsync", op: "GetResolver", action: "appsync:GetResolver", resType: "GraphQLApi", resName: "team-a.notes", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newAppsyncHandler(csWithSAR(true), "http://127.0.0.1:1", "default", discardLogger())
				h.authz = a
				h.apis = newFakeAPIStore()
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/v1/apis/team-a.notes/types/Query/resolvers/getTodo", nil), c)
			}},
		// --- S3 (already closed for roles; ListBuckets is now checked on Bucket::*) ---
		{door: "s3", op: "ListBuckets", action: "s3:ListAllMyBuckets", resType: "Bucket", denyCode: "AccessDenied", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				mc, err := minio.New("127.0.0.1:1", &minio.Options{Creds: credentials.NewStaticV4("a", "b", "")})
				if err != nil {
					t.Fatal(err)
				}
				h := &s3Handler{cs: csWithSAR(true), mc: mc, authzNS: "default", authz: a, logger: discardLogger()}
				ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/", nil).WithContext(ctx), c)
			}},
		// --- SES v2 (signing name email; the same handler and actions as v1, under /v2/email/) ---
		{door: "email", op: "GetAccount", action: "ses:GetAccount", resType: "Identity", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSESHandler(csWithSAR(true), "default", "127.0.0.1:1", a, discardLogger())
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/v2/email/account", nil), c)
			}},
		// Authorized before anything else, as on AWS: an authorized call then ends at "not served".
		{door: "email", op: "GetEmailIdentity", action: "ses:GetEmailIdentity", resType: "Identity", resName: "ops@example.com", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newSESHandler(csWithSAR(true), "default", "127.0.0.1:1", a, discardLogger())
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/v2/email/identities/ops@example.com", nil), c)
			}},
		// --- ACM (a stack's certificates: no stacks here, so an authorized call finds none) ---
		{door: "acm", op: "ListCertificates", action: "acm:ListCertificates", resType: "Certificate", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				door, _ := cfnTestDoorway(t, "")
				door.authz = a
				return serveWith(newACMHandler(door, discardLogger()), jsonOp("CertificateManager.ListCertificates", `{}`), c)
			}},
		{door: "acm", op: "DescribeCertificate", action: "acm:DescribeCertificate", resType: "Certificate", resName: "0a1b2c3d", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				door, _ := cfnTestDoorway(t, "")
				door.authz = a
				return serveWith(newACMHandler(door, discardLogger()), jsonOp("CertificateManager.DescribeCertificate",
					`{"CertificateArn":"arn:aws:acm:us-east-1:000000000000:certificate/0a1b2c3d"}`), c)
			}},
		// --- CloudFront (a stack's distributions) ---
		{door: "cloudfront", op: "ListDistributions", action: "cloudfront:ListDistributions", resType: "Distribution", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				door, _ := cfnTestDoorway(t, "")
				door.authz = a
				return serveWith(newCloudFrontHandler(door, discardLogger()), httptest.NewRequest(http.MethodGet, "http://shim/2020-05-31/distribution", nil), c)
			}},
		{door: "cloudfront", op: "CreateInvalidation", action: "cloudfront:CreateInvalidation", resType: "Distribution", resName: "E1ABCDEF", denyCode: "AccessDenied",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				door, _ := cfnTestDoorway(t, "")
				door.authz = a
				return serveWith(newCloudFrontHandler(door, discardLogger()),
					httptest.NewRequest(http.MethodPost, "http://shim/2020-05-31/distribution/E1ABCDEF/invalidation", nil), c)
			}},
		// --- ECR (the control plane; the registry's own token realm is ecr_role_test.go's) ---
		{door: "ecr", op: "DescribeRepositories", action: "ecr:DescribeRepositories", resType: "Repository", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newECRTestHandler(csWithSAR(true), "")
				h.authz = a
				return serveWith(h, ecrRequest("DescribeRepositories", `{}`), c)
			}},
		{door: "ecr", op: "CreateRepository", action: "ecr:CreateRepository", resType: "Repository", resName: "app", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newECRTestHandler(csWithSAR(true), "")
				h.authz = a
				return serveWith(h, ecrRequest("CreateRepository", `{"repositoryName":"app"}`), c)
			}},
		// --- EKS (every operation is on the one cluster the shim fronts) ---
		{door: "eks", op: "DescribeCluster", action: "eks:DescribeCluster", resType: "Cluster", resName: "open-infra", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newEKSTestHandler(true)
				h.authz = a
				return serveWith(h, eksReq(http.MethodGet, "/clusters/open-infra"), c)
			}},
		// --- Lambda ---
		// DryRun is authorized exactly as an invoke and then returns, before any upstream call.
		{door: "lambda", op: "Invoke(DryRun)", action: "lambda:InvokeFunction", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.authz = a
				req := httptest.NewRequest(http.MethodPost, "http://shim/2015-03-31/functions/orders/invocations", nil)
				req.Header.Set("X-Amz-Invocation-Type", "DryRun")
				return serveWith(h, req, c)
			}},
		{door: "lambda", op: "ListFunctions", action: "lambda:ListFunctions", resType: "Function", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(), discardLogger(), "default")
				h.authz = a
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/2015-03-31/functions/", nil), c)
			}},
		{door: "lambda", op: "GetFunction", action: "lambda:GetFunction", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(), discardLogger(), "default")
				h.authz = a
				return serveWith(h, httptest.NewRequest(http.MethodGet, "http://shim/2015-03-31/functions/orders", nil), c)
			}},
		// The control plane (lambda_manage.go). CreateFunction names no Role here, so an authorized call ends at
		// Lambda's validation error, before iam:PassRole (which its own test decides).
		{door: "lambda", op: "CreateFunction", action: "lambda:CreateFunction", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", `{"FunctionName":"orders","Runtime":"nodejs20.x","Handler":"index.handler"}`), c)
			}},
		{door: "lambda", op: "UpdateFunctionCode", action: "lambda:UpdateFunctionCode", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/code", `{"ZipFile":"UEs="}`), c)
			}},
		{door: "lambda", op: "UpdateFunctionConfiguration", action: "lambda:UpdateFunctionConfiguration", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", `{"Timeout":5}`), c)
			}},
		{door: "lambda", op: "DeleteFunction", action: "lambda:DeleteFunction", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders", nil), c)
			}},
		// Versions and aliases (lambda_versions.go), each decided on the function they belong to.
		{door: "lambda", op: "PublishVersion", action: "lambda:PublishVersion", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/versions", `{}`), c)
			}},
		{door: "lambda", op: "ListVersionsByFunction", action: "lambda:ListVersionsByFunction", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/versions", nil), c)
			}},
		{door: "lambda", op: "CreateAlias", action: "lambda:CreateAlias", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/aliases", `{"Name":"live","FunctionVersion":"$LATEST"}`), c)
			}},
		{door: "lambda", op: "GetAlias", action: "lambda:GetAlias", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/aliases/live", nil), c)
			}},
		{door: "lambda", op: "UpdateAlias", action: "lambda:UpdateAlias", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/aliases/live", `{"FunctionVersion":"$LATEST"}`), c)
			}},
		{door: "lambda", op: "DeleteAlias", action: "lambda:DeleteAlias", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders/aliases/live", nil), c)
			}},
		{door: "lambda", op: "ListAliases", action: "lambda:ListAliases", resType: "Function", resName: "orders", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
				h.fns = newFnLocator(fnDyn(zipFunction("default", "orders")), discardLogger(), "default")
				h.authz = a
				return serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/aliases", nil), c)
			}},
		// --- Organizations (the management account's; an operation that names no account is checked on
		// Account::* for a User too, so a governed User without the grant is denied it) ---
		// No cluster client here: an authorized call ends at "not available", after the gate.
		{door: "organizations", op: "ListAccounts", action: "organizations:ListAccounts", resType: "Account", denyCode: "AccessDeniedException", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newOrganizationsHandler(csWithSAR(true), nil, "default", a, orgMgmt, discardLogger())
				return serveWith(h, jsonOp(organizationsTargetPrefix+"ListAccounts", `{}`), c)
			}},
		{door: "organizations", op: "DescribeAccount", action: "organizations:DescribeAccount", resType: "Account", resName: "912345678901", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h := newOrganizationsHandler(csWithSAR(true), nil, "default", a, orgMgmt, discardLogger())
				return serveWith(h, jsonOp(organizationsTargetPrefix+"DescribeAccount", `{"AccountId":"912345678901"}`), c)
			}},
		// --- Service Quotas (the caller's own account's; a call that names no quota is checked on Quota::*
		// for a User too) ---
		{door: "servicequotas", op: "ListServices", action: "servicequotas:ListServices", resType: "Quota", denyCode: "AccessDeniedException", userAlwaysChecked: true,
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _ := sqTestHandler(t, true)
				h.authz = a
				return serveWith(h, jsonOp(serviceQuotasTargetPrefix+"ListServices", `{}`), c)
			}},
		{door: "servicequotas", op: "RequestServiceQuotaIncrease", action: "servicequotas:RequestServiceQuotaIncrease", resType: "Quota", resName: "lambda/L-B99A9384", denyCode: "AccessDeniedException",
			call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
				h, _ := sqTestHandler(t, true)
				h.authz = a
				return serveWith(h, jsonOp(serviceQuotasTargetPrefix+"RequestServiceQuotaIncrease",
					`{"ServiceCode":"lambda","QuotaCode":"L-B99A9384","DesiredValue":2000}`), c)
			}},
	}
}

// isDenied: the front door's denial code in the body, or (API Gateway) in the x-amzn-errortype header.
func isDenied(w *httptest.ResponseRecorder, code string) bool {
	return strings.Contains(w.Body.String(), code) || strings.Contains(w.Header().Get("x-amzn-errortype"), code)
}

// userChecker is a data-plane engine with one policy for User::tester that governs the service (an action
// of it on "*") without granting the op under test.
func userChecker(service string) *dataplaneauthz.Checker {
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::tester"},
			Statements: []policyengine.Statement{dpAllow([]string{service + ":NotTheOperationUnderTest"}, "*")}}}}, nil
	}, time.Minute)
}

func TestAssumedRoleDefaultDeny_EveryFrontDoor(t *testing.T) {
	role := ecrRoleClaims()
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
	for _, tc := range roleDoorCases() {
		tc := tc
		t.Run(tc.door+"/"+tc.op, func(t *testing.T) {
			service := strings.SplitN(tc.action, ":", 2)[0]
			expect := func(name string, authz *dataplaneauthz.Checker, claims iam.Claims, wantDenied bool) {
				t.Helper()
				w := tc.call(t, authz, claims)
				if got := isDenied(w, tc.denyCode); got != wantDenied {
					t.Errorf("%s: denied=%v, want %v (status %d, body %.300s)", name, got, wantDenied, w.Code, w.Body.String())
				}
			}
			// An assumed role is default-deny.
			expect("role with no policy", roleChecker(), role, true)
			expect("role, data-plane engine not configured", nil, role, true)
			expect("role with only another service's grant", roleChecker(dpAllow([]string{"nosuchservice:*"}, "*")), role, true)
			expect("role with "+tc.action+" on *", roleChecker(dpAllow([]string{tc.action}, "*")), role, false)
			expect("role with "+service+":* on "+tc.resType+"::*", roleChecker(dpAllow([]string{service + ":*"}, tc.resType+"::*")), role, false)
			expect("role with an explicit Deny", roleChecker(dpAllow([]string{tc.action}, "*"), dpDeny([]string{tc.action}, "*")), role, true)
			if tc.resName == "" {
				// A resource-less op is AWS's Resource "*": a grant scoped to one named resource does not reach it.
				expect("role with "+tc.action+" on one resource only", roleChecker(dpAllow([]string{tc.action}, tc.resType+"::some-other")), role, true)
			} else {
				expect("role with "+tc.action+" on "+tc.resType+"::"+tc.resName, roleChecker(dpAllow([]string{tc.action}, tc.resType+"::"+tc.resName)), role, false)
				expect("role with "+tc.action+" on another resource", roleChecker(dpAllow([]string{tc.action}, tc.resType+"::some-other")), role, true)
			}
			// A User is unchanged: RBAC allows, no data-plane policy → allowed.
			expect("user with no data-plane policy", nil, user, false)
			expect("user, policy governs another principal", roleChecker(), user, false)
			if tc.resName == "" {
				// A governed User's resource-less op keeps today's behavior: not checked — except where the front
				// door already checked it (API Gateway, S3), where it stays denied.
				expect("user governed for "+service+" without this grant", userChecker(service), user, tc.userAlwaysChecked)
			}
		})
	}
}

// deniedByDataPlane is closed for an assumed role even with no data-plane engine (a resource-scoped op at
// any front door — Lambda Invoke, an SQS SendMessage — denies the role), and unchanged for a User.
func TestDeniedByDataPlane_RoleClosedWithoutEngine(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://shim/", nil)
	if denied, _ := deniedByDataPlane(context.Background(), nil, ecrRoleClaims(), "lambda:InvokeFunction", "Function", "fn", req); !denied {
		t.Fatal("an assumed role must be denied when no data-plane engine is configured")
	}
	if denied, _ := deniedByDataPlane(context.Background(), nil, iam.Claims{Sub: "tester"}, "lambda:InvokeFunction", "Function", "fn", req); denied {
		t.Fatal("a User's data-plane check stays a no-op without an engine")
	}
	// The resource-scoped role flows that already work keep working: a grant on the named resource allows.
	ok := roleChecker(dpAllow([]string{"sqs:SendMessage", "sqs:ReceiveMessage"}, "Queue::jobs"), dpAllow([]string{"s3:GetObject"}, "Bucket::assets"))
	for _, c := range []struct{ action, typ, id string }{
		{"sqs:SendMessage", "Queue", "jobs"}, {"sqs:ReceiveMessage", "Queue", "jobs"}, {"s3:GetObject", "Bucket", "assets"},
	} {
		if denied, reason := dataPlaneDenied(context.Background(), ok, ecrRoleClaims(), c.action, c.typ, c.id, req); denied {
			t.Errorf("%s on %s::%s must stay allowed under its grant: %s", c.action, c.typ, c.id, reason)
		}
	}
	if denied, _ := dataPlaneDenied(context.Background(), ok, ecrRoleClaims(), "sqs:SendMessage", "Queue", "other", req); !denied {
		t.Error("a queue the role is not granted must be denied")
	}
}

// DynamoDB's multi-table ops are authorized for a role on every table they touch, in AWS's action names.
func TestDynamoRoleChecks(t *testing.T) {
	cases := []struct {
		op   string
		body string
		want []dynamoCheck
	}{
		{"GetItem", `{"TableName":"orders"}`, []dynamoCheck{{"dynamodb:GetItem", "orders"}}},
		{"ListTables", `{}`, []dynamoCheck{{"dynamodb:ListTables", ""}}},
		{"BatchGetItem", `{"RequestItems":{"b":{},"a":{}}}`, []dynamoCheck{{"dynamodb:BatchGetItem", "a"}, {"dynamodb:BatchGetItem", "b"}}},
		{"BatchWriteItem", `{"RequestItems":{}}`, []dynamoCheck{{"dynamodb:BatchWriteItem", ""}}},
		{"TransactWriteItems", `{"TransactItems":[{"Put":{"TableName":"a"}},{"Update":{"TableName":"b"}},{"Delete":{"TableName":"c"}},{"ConditionCheck":{"TableName":"d"}},{"Put":{}}]}`,
			[]dynamoCheck{{"dynamodb:PutItem", "a"}, {"dynamodb:UpdateItem", "b"}, {"dynamodb:DeleteItem", "c"}, {"dynamodb:ConditionCheckItem", "d"}, {"dynamodb:PutItem", "*"}}},
		{"TransactGetItems", `{"TransactItems":[{"Get":{"TableName":"a"}}]}`, []dynamoCheck{{"dynamodb:GetItem", "a"}}},
		{"RestoreTableToPointInTime", `{"SourceTableName":"src","TargetTableName":"dst"}`,
			[]dynamoCheck{{"dynamodb:RestoreTableToPointInTime", "src"}, {"dynamodb:RestoreTableToPointInTime", "dst"}}},
	}
	for _, c := range cases {
		body := readJSONBody(jsonOp("x", c.body))
		table, _ := body["TableName"].(string)
		got := dynamoRoleChecks(c.op, table, body)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.op, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.op, got, c.want)
				break
			}
		}
	}
}

// STS GetCallerIdentity stays allowed for an assumed role with no policy at all, as on AWS (no permission
// is needed to ask who you are).
func TestSTS_GetCallerIdentityNeedsNoPolicy(t *testing.T) {
	h := &stsHandler{account: "open-infra", logger: discardLogger()}
	w := serveWith(h, formOp(url.Values{"Action": {"GetCallerIdentity"}}), ecrRoleClaims())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "assumed-role/"+ecrTestRole) {
		t.Fatalf("GetCallerIdentity for a role session: status %d body %s", w.Code, w.Body.String())
	}
}
