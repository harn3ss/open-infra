package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/rest"
)

// AWS authorizes a request before it looks at the resource the request names: a caller whose policy does
// not allow the action is answered AccessDenied whether or not the resource exists, so a denial never tells
// it what is there. Each case here names a resource that does not exist, at one front door, through the
// door's own serve(), with its store empty (emptyDB) — so a door that looks first answers NotFound (or
// succeeds, for a delete of nothing) where AWS answers AccessDenied.

// awsDenialRe is what the IAM probes (probe/iam-lib.sh shim_decision) and an SDK user read as an IAM
// denial: AWS's denial codes, or its "… is not authorized to perform: <action> …" message.
var awsDenialRe = regexp.MustCompile(`AccessDenied|AccessDeniedException|UnauthorizedOperation|AuthorizationError|AuthorizationErrorException|not authorized to perform`)

// assertAWSDenied fails unless w is an AWS authorization denial: a 4xx whose error code or message an SDK
// reads as one, not a NotFound or a success.
func assertAWSDenied(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	body := w.Body.String()
	if w.Code < 400 || w.Code >= 500 || !(awsDenialRe.MatchString(body) || awsDenialRe.MatchString(w.Header().Get("x-amzn-errortype"))) {
		t.Errorf("%s: status %d, body %.300s — want AWS's AccessDenied, whether or not the resource exists", what, w.Code, body)
	}
}

// missingCase is one operation naming a resource that does not exist.
type missingCase struct {
	door, op string
	call     func(t *testing.T, authz *dataplaneauthz.Checker, claims iam.Claims) *httptest.ResponseRecorder
}

const nope = "iam-parity-nope"

func missingResourceCases() []missingCase {
	sqsH := func(t *testing.T, a *dataplaneauthz.Checker) *sqsHandler {
		h := newSQSHandler(csWithSAR(true), "default", "000000000000", "us-east-1", &sqsStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	snsH := func(t *testing.T, a *dataplaneauthz.Checker) *snsHandler {
		h := newSNSHandler(csWithSAR(true), "default", "000000000000", "us-east-1", &snsStore{db: emptyDB(t)}, nil, discardLogger())
		h.authz = a
		return h
	}
	kmsH := func(t *testing.T, a *dataplaneauthz.Checker) *kmsHandler {
		h := newKMSHandler(csWithSAR(true), nil, "default", "default", "000000000000", "us-east-1", nil, &kmsStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	secretsH := func(t *testing.T, a *dataplaneauthz.Checker) *secretsHandler {
		h := newSecretsHandler(csWithSAR(true), "default", "000000000000", "us-east-1", nil, &secretsStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	ssmH := func(t *testing.T, a *dataplaneauthz.Checker) *ssmHandler {
		h := newSSMHandler(csWithSAR(true), "default", "000000000000", "us-east-1", nil, &ssmStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	dynamoH := func(t *testing.T, a *dataplaneauthz.Checker) *dynamoHandler {
		h := newDynamoHandler(csWithSAR(true), "default", nil, emptyDB(t), "db", discardLogger())
		h.authz = a
		return h
	}
	cwlH := func(t *testing.T, a *dataplaneauthz.Checker) *cwlHandler {
		h := newCWLHandler(csWithSAR(true), "default", "000000000000", "us-east-1", &cwlStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	cwH := func(t *testing.T, a *dataplaneauthz.Checker) *cwHandler {
		h := newCWHandler(csWithSAR(true), "default", "000000000000", "us-east-1", &cwStore{db: emptyDB(t)}, nil, discardLogger())
		h.authz = a
		return h
	}
	kinesisH := func(t *testing.T, a *dataplaneauthz.Checker) *kinesisHandler {
		h := newKinesisHandler(csWithSAR(true), "default", "000000000000", "us-east-1", &kinesisStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	ebH := func(t *testing.T, a *dataplaneauthz.Checker) *ebHandler {
		h := newEBHandler(csWithSAR(true), "default", "default", "000000000000", "us-east-1", &ebStore{db: emptyDB(t)}, nil, nil, discardLogger())
		h.authz = a
		return h
	}
	cognitoH := func(t *testing.T, a *dataplaneauthz.Checker) *cognitoHandler {
		h := newCognitoHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://shim", &cognitoStore{db: emptyDB(t)}, testSigner(t), discardLogger())
		h.authz = a
		return h
	}
	agwH := func(t *testing.T, a *dataplaneauthz.Checker) *apigwHandler {
		h := newAPIGWHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "default", "svc.cluster.local", "http://shim", &apigwStore{db: emptyDB(t)}, discardLogger())
		h.authz = a
		return h
	}
	agwV1H := func(t *testing.T, a *dataplaneauthz.Checker) *apigwV1Handler {
		return newAPIGWV1Handler(csWithSAR(true), "default", "default", "svc.cluster.local", "http://shim", &apigwV1Store{db: emptyDB(t)}, a, discardLogger())
	}
	get := func(path string) *http.Request { return httptest.NewRequest(http.MethodGet, "http://shim"+path, nil) }
	del := func(path string) *http.Request {
		return httptest.NewRequest(http.MethodDelete, "http://shim"+path, nil)
	}
	cf := func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims, method, path string) *httptest.ResponseRecorder {
		f := newCFFixture(t, func(*authzv1.ResourceAttributes) bool { return true })
		f.door.authz = a
		w := httptest.NewRecorder()
		f.h.serve(w, httptest.NewRequest(method, "http://cloudfront/2020-05-31/"+path, strings.NewReader("<InvalidationBatch/>")), c, "r")
		return w
	}
	appsync := func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims, req *http.Request) *httptest.ResponseRecorder {
		h := newAppsyncHandler(csWithSAR(true), "http://127.0.0.1:1", "default", discardLogger())
		h.authz = a
		h.apis = newFakeAPIStore()
		return serveWith(h, req, c)
	}
	queueURL := `"QueueUrl":"http://shim/000000000000/` + nope + `"`
	topicARN := "arn:aws:sns:us-east-1:000000000000:" + nope
	keyID := "00000000-0000-4000-8000-000000000000"
	return []missingCase{
		{door: "sqs", op: "GetQueueUrl", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(sqsH(t, a), jsonOp("AmazonSQS.GetQueueUrl", `{"QueueName":"`+nope+`"}`), c)
		}},
		{door: "sqs", op: "GetQueueAttributes", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(sqsH(t, a), jsonOp("AmazonSQS.GetQueueAttributes", `{`+queueURL+`}`), c)
		}},
		{door: "sqs", op: "ReceiveMessage", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(sqsH(t, a), jsonOp("AmazonSQS.ReceiveMessage", `{`+queueURL+`}`), c)
		}},
		{door: "sqs", op: "DeleteQueue", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(sqsH(t, a), jsonOp("AmazonSQS.DeleteQueue", `{`+queueURL+`}`), c)
		}},
		{door: "sns", op: "GetTopicAttributes", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(snsH(t, a), formOp(url.Values{"Action": {"GetTopicAttributes"}, "TopicArn": {topicARN}}), c)
		}},
		{door: "sns", op: "Publish", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(snsH(t, a), formOp(url.Values{"Action": {"Publish"}, "TopicArn": {topicARN}, "Message": {"x"}}), c)
		}},
		{door: "sns", op: "GetSubscriptionAttributes", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(snsH(t, a), formOp(url.Values{"Action": {"GetSubscriptionAttributes"}, "SubscriptionArn": {topicARN + ":0000"}}), c)
		}},
		{door: "kms", op: "DescribeKey", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(kmsH(t, a), jsonOp("TrentService.DescribeKey", `{"KeyId":"`+keyID+`"}`), c)
		}},
		{door: "kms", op: "GetKeyPolicy", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(kmsH(t, a), jsonOp("TrentService.GetKeyPolicy", `{"KeyId":"`+keyID+`","PolicyName":"default"}`), c)
		}},
		{door: "kms", op: "Encrypt", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(kmsH(t, a), jsonOp("TrentService.Encrypt", `{"KeyId":"`+keyID+`","Plaintext":"eA=="}`), c)
		}},
		{door: "kms", op: "DeleteAlias", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(kmsH(t, a), jsonOp("TrentService.DeleteAlias", `{"AliasName":"alias/`+nope+`"}`), c)
		}},
		{door: "secretsmanager", op: "DescribeSecret", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(secretsH(t, a), jsonOp("secretsmanager.DescribeSecret", `{"SecretId":"`+nope+`"}`), c)
		}},
		{door: "secretsmanager", op: "GetSecretValue", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(secretsH(t, a), jsonOp("secretsmanager.GetSecretValue", `{"SecretId":"`+nope+`"}`), c)
		}},
		{door: "ssm", op: "GetParameter", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(ssmH(t, a), jsonOp("AmazonSSM.GetParameter", `{"Name":"/`+nope+`"}`), c)
		}},
		{door: "ssm", op: "GetParameterHistory", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(ssmH(t, a), jsonOp("AmazonSSM.GetParameterHistory", `{"Name":"/`+nope+`"}`), c)
		}},
		{door: "ssm", op: "DeleteParameter", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(ssmH(t, a), jsonOp("AmazonSSM.DeleteParameter", `{"Name":"/`+nope+`"}`), c)
		}},
		{door: "ssm", op: "SendCommand(another document)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := ssmH(t, a)
			h.ec2, _ = ec2Fixture(t)
			return serveWith(h, jsonOp("AmazonSSM.SendCommand", `{"DocumentName":"`+nope+`","InstanceIds":["i-00000000000000000"]}`), c)
		}},
		{door: "ssm", op: "SendCommand(no such instance)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := ssmH(t, a)
			h.ec2, _ = ec2Fixture(t)
			return serveWith(h, jsonOp("AmazonSSM.SendCommand", `{"DocumentName":"AWS-RunShellScript","InstanceIds":["i-00000000000000000"],"Parameters":{"commands":["true"]}}`), c)
		}},
		{door: "dynamodb", op: "DescribeTable", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(dynamoH(t, a), jsonOp("DynamoDB_20120810.DescribeTable", `{"TableName":"`+nope+`"}`), c)
		}},
		{door: "dynamodb", op: "GetItem", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(dynamoH(t, a), jsonOp("DynamoDB_20120810.GetItem", `{"TableName":"`+nope+`","Key":{"id":{"S":"1"}}}`), c)
		}},
		{door: "dynamodb", op: "DeleteTable", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(dynamoH(t, a), jsonOp("DynamoDB_20120810.DeleteTable", `{"TableName":"`+nope+`"}`), c)
		}},
		{door: "dynamodb", op: "DescribeContinuousBackups", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(dynamoH(t, a), jsonOp("DynamoDB_20120810.DescribeContinuousBackups", `{"TableName":"`+nope+`"}`), c)
		}},
		{door: "logs", op: "GetLogEvents", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cwlH(t, a), jsonOp("Logs_20140328.GetLogEvents", `{"logGroupName":"`+nope+`","logStreamName":"s"}`), c)
		}},
		{door: "logs", op: "DeleteLogGroup", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cwlH(t, a), jsonOp("Logs_20140328.DeleteLogGroup", `{"logGroupName":"`+nope+`"}`), c)
		}},
		{door: "logs", op: "PutRetentionPolicy", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cwlH(t, a), jsonOp("Logs_20140328.PutRetentionPolicy", `{"logGroupName":"`+nope+`","retentionInDays":1}`), c)
		}},
		{door: "monitoring", op: "SetAlarmState", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cwH(t, a), formOp(url.Values{"Action": {"SetAlarmState"}, "AlarmName": {nope}, "StateValue": {"ALARM"}, "StateReason": {"x"}}), c)
		}},
		{door: "monitoring", op: "DeleteAlarms", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cwH(t, a), formOp(url.Values{"Action": {"DeleteAlarms"}, "AlarmNames.member.1": {nope}}), c)
		}},
		{door: "kinesis", op: "DescribeStream", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(kinesisH(t, a), jsonOp("Kinesis_20131202.DescribeStream", `{"StreamName":"`+nope+`"}`), c)
		}},
		{door: "kinesis", op: "DeleteStream", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(kinesisH(t, a), jsonOp("Kinesis_20131202.DeleteStream", `{"StreamName":"`+nope+`"}`), c)
		}},
		{door: "events", op: "DescribeRule", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(ebH(t, a), jsonOp("AWSEvents.DescribeRule", `{"Name":"`+nope+`"}`), c)
		}},
		{door: "events", op: "DeleteRule", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(ebH(t, a), jsonOp("AWSEvents.DeleteRule", `{"Name":"`+nope+`"}`), c)
		}},
		{door: "rds", op: "DescribeDBInstances(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newRDSHandler(csWithSAR(true), nil, "default", "000000000000", "us-east-1", discardLogger())
			h.authz = a
			return serveWith(h, formOp(url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {nope}}), c)
		}},
		{door: "rds", op: "DeleteDBSnapshot", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newRDSHandler(csWithSAR(true), nil, "default", "000000000000", "us-east-1", discardLogger())
			h.authz = a
			return serveWith(h, formOp(url.Values{"Action": {"DeleteDBSnapshot"}, "DBSnapshotIdentifier": {nope}}), c)
		}},
		{door: "glue", op: "GetDatabase", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newGlueHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://127.0.0.1:1", discardLogger())
			h.authz = a
			return serveWith(h, jsonOp(glueTargetPrefix+".GetDatabase", `{"Name":"`+nope+`"}`), c)
		}},
		{door: "athena", op: "GetWorkGroup", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newAthenaHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://127.0.0.1:1", "", "", "iceberg", "s3://out/", discardLogger())
			h.authz = a
			return serveWith(h, jsonOp(athenaTargetPrefix+".GetWorkGroup", `{"WorkGroup":"`+nope+`"}`), c)
		}},
		{door: "cognito-idp", op: "DescribeUserPool", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cognitoH(t, a), jsonOp("AWSCognitoIdentityProviderService.DescribeUserPool", `{"UserPoolId":"us-east-1_nope"}`), c)
		}},
		{door: "cognito-idp", op: "DeleteUserPool", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cognitoH(t, a), jsonOp("AWSCognitoIdentityProviderService.DeleteUserPool", `{"UserPoolId":"us-east-1_nope"}`), c)
		}},
		{door: "cognito-idp", op: "DescribeUserPoolClient", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(cognitoH(t, a), jsonOp("AWSCognitoIdentityProviderService.DescribeUserPoolClient", `{"UserPoolId":"us-east-1_nope","ClientId":"nope"}`), c)
		}},
		{door: "apigateway-v2", op: "GetApi", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(agwH(t, a), get("/v2/apis/nope123"), c)
		}},
		{door: "apigateway-v2", op: "DeleteApi", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(agwH(t, a), del("/v2/apis/nope123"), c)
		}},
		{door: "apigateway-v1", op: "GetRestApi", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(agwV1H(t, a), get("/restapis/nope123"), c)
		}},
		{door: "apigateway-v1", op: "GetResources", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(agwV1H(t, a), get("/restapis/nope123/resources"), c)
		}},
		{door: "apigateway-v1", op: "GetApiKey", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(agwV1H(t, a), get("/apikeys/nope123"), c)
		}},
		{door: "apigateway-v1", op: "GetUsagePlan", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return serveWith(agwV1H(t, a), get("/usageplans/nope123"), c)
		}},
		{door: "states", op: "DescribeStateMachine", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newSFNHandler(csWithSAR(true), fakeDynWith(gvrStateMachines), nil, nil, a, "default", "000000000000", "us-east-1", discardLogger())
			return serveWith(h, jsonOp("AWSStepFunctions.DescribeStateMachine", `{"stateMachineArn":"arn:aws:states:us-east-1:000000000000:stateMachine:`+nope+`"}`), c)
		}},
		{door: "states", op: "DescribeExecution", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newSFNHandler(csWithSAR(true), fakeDynWith(gvrStateMachines), nil, nil, a, "default", "000000000000", "us-east-1", discardLogger())
			return serveWith(h, jsonOp("AWSStepFunctions.DescribeExecution", `{"executionArn":"arn:aws:states:us-east-1:000000000000:execution:`+nope+`:run"}`), c)
		}},
		{door: "iam", op: "GetRole", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newIAMHandler(csWithSAR(true), fakeDynWith(gvrRoles), nil, a, "default", "000000000000", "us-east-1", discardLogger())
			return serveWith(h, formOp(url.Values{"Action": {"GetRole"}, "RoleName": {nope}}), c)
		}},
		{door: "iam", op: "GetInstanceProfile", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := profileFixture(t)
			h.authz = a
			return serveWith(h, formOp(url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {nope}}), c)
		}},
		{door: "iam", op: "ListInstanceProfilesForRole", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := profileFixture(t)
			h.authz = a
			return serveWith(h, formOp(url.Values{"Action": {"ListInstanceProfilesForRole"}, "RoleName": {nope}}), c)
		}},
		{door: "cloudformation", op: "DescribeStacks(name)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := cfnTestDoorway(t, "")
			h.cfg = &rest.Config{Host: "http://127.0.0.1:1"}
			h.authz = a
			return serveWith(h, formOp(url.Values{"Action": {"DescribeStacks"}, "StackName": {nope}}), c)
		}},
		{door: "cloudformation", op: "GetTemplate", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := cfnTestDoorway(t, "")
			h.cfg = &rest.Config{Host: "http://127.0.0.1:1"}
			h.authz = a
			return serveWith(h, formOp(url.Values{"Action": {"GetTemplate"}, "StackName": {nope}}), c)
		}},
		{door: "appsync", op: "GetGraphqlApi", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return appsync(t, a, c, get("/v1/apis/"+nope))
		}},
		{door: "appsync", op: "GetResolver", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return appsync(t, a, c, get("/v1/apis/"+nope+"/types/Query/resolvers/f"))
		}},
		{door: "appsync", op: "DeleteDataSource", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return appsync(t, a, c, del("/v1/apis/"+nope+"/datasources/d"))
		}},
		// A distribution id as the probe writes one (lower-case hex): no distribution has it.
		{door: "cloudfront", op: "GetDistribution", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return cf(t, a, c, http.MethodGet, "distribution/E032f6e71")
		}},
		{door: "cloudfront", op: "GetDistributionConfig", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return cf(t, a, c, http.MethodGet, "distribution/E032f6e71/config")
		}},
		{door: "cloudfront", op: "GetDistribution(well-formed)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return cf(t, a, c, http.MethodGet, "distribution/ENOPE0000000000")
		}},
		{door: "cloudfront", op: "GetCachePolicy", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return cf(t, a, c, http.MethodGet, "cache-policy/nope_policy")
		}},
		{door: "cloudfront", op: "CreateInvalidation", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			return cf(t, a, c, http.MethodPost, "distribution/E032f6e71/invalidation")
		}},
		{door: "ec2", op: "DescribeInstances(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := ec2Fixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {"i-00000000000000000"}})
		}},
		{door: "ec2", op: "DescribeVolumes(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := ec2Fixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {"vol-00000000000000000"}})
		}},
		{door: "ec2", op: "DescribeInternetGateways(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _, _ := structuralFixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeInternetGateways"}, "InternetGatewayId.1": {"igw-00000000000000000"}})
		}},
		{door: "ec2", op: "DescribeRouteTables(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _, _ := structuralFixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeRouteTables"}, "RouteTableId.1": {"rtb-00000000000000000"}})
		}},
		{door: "ec2", op: "DescribeNetworkAcls(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _, _ := structuralFixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {"acl-00000000000000000"}})
		}},
		{door: "ec2", op: "DescribeVpcEndpoints(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _, _ := structuralFixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeVpcEndpoints"}, "VpcEndpointId.1": {"vpce-00000000000000000"}})
		}},
		{door: "ec2", op: "DeleteVolume", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := ec2Fixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DeleteVolume"}, "VolumeId": {"vol-00000000000000000"}})
		}},
		{door: "ec2", op: "DeleteFlowLogs", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := eniFixture(t)
			h.flowLogs = &ec2FlowLogStore{db: emptyDB(t)}
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DeleteFlowLogs"}, "FlowLogId.1": {"fl-00000000000000000"}})
		}},
		{door: "ec2", op: "DescribeNetworkInterfaces(id)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := eniFixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"DescribeNetworkInterfaces"}, "NetworkInterfaceId.1": {"eni-00000000000000000"}})
		}},
		{door: "ec2", op: "TerminateInstances", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h, _ := ec2Fixture(t)
			h.door.authz = a
			return ec2Call(h, c, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {"i-00000000000000000"}})
		}},
		{door: "lambda", op: "GetFunction", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := readLambda(func(*authzv1.ResourceAttributes) bool { return true })
			h.authz = a
			return lambdaGet(h, "/2015-03-31/functions/"+nope, c)
		}},
		{door: "eks", op: "DescribeCluster(another)", call: func(t *testing.T, a *dataplaneauthz.Checker, c iam.Claims) *httptest.ResponseRecorder {
			h := newEKSTestHandler(true)
			h.authz = a
			return serveWith(h, get("/clusters/"+nope), c)
		}},
	}
}

// Every case, as a User whose policy governs the service without allowing the operation, is AWS's
// AccessDenied though the resource does not exist; the same request by the same User allowed the whole
// service is not — so the case reaches the door's authorization, and only that refuses it.
func TestEnforce_MissingResourceIsAccessDeniedNotNotFound(t *testing.T) {
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
	for _, tc := range missingResourceCases() {
		tc := tc
		t.Run(tc.door+"/"+tc.op, func(t *testing.T) {
			service := tc.door
			switch tc.door {
			case "monitoring":
				service = "cloudwatch"
			case "apigateway-v1", "apigateway-v2":
				service = "apigateway"
			case "dynamodbstreams":
				service = "dynamodb"
			}
			denied := checkerInMode(t, "enforce", userDoc(dpAllow([]string{service + ":NotTheOperationUnderTest"}, "*")))
			assertAWSDenied(t, "a User without the action", tc.call(t, denied, user))
			allowed := checkerInMode(t, "enforce", userDoc(dpAllow([]string{service + ":*"}, "*")))
			if w := tc.call(t, allowed, user); awsDenialRe.MatchString(w.Body.String()) {
				t.Errorf("a User allowed %s:* was denied too (status %d, %.300s): the case does not reach authorization", service, w.Code, w.Body.String())
			}
		})
	}
}

// --- emptyDB: a database/sql driver whose every table is empty ---

// emptyDB is a *sql.DB on which every query returns no rows and every statement changes none: the store of a
// front door that holds nothing, so a lookup finds no resource.
func emptyDB(t *testing.T) *sql.DB {
	t.Helper()
	emptyDriverOnce.Do(func() { sql.Register("openinfra-empty", emptyDriver{}) })
	db, err := sql.Open("openinfra-empty", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var emptyDriverOnce sync.Once

type emptyDriver struct{}

func (emptyDriver) Open(string) (driver.Conn, error) { return emptyConn{}, nil }

type emptyConn struct{}

func (emptyConn) Prepare(string) (driver.Stmt, error) { return emptyStmt{}, nil }
func (emptyConn) Close() error                        { return nil }
func (emptyConn) Begin() (driver.Tx, error)           { return emptyTx{}, nil }
func (emptyConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return emptyTx{}, nil
}

type emptyTx struct{}

func (emptyTx) Commit() error   { return nil }
func (emptyTx) Rollback() error { return nil }

type emptyStmt struct{}

func (emptyStmt) Close() error                               { return nil }
func (emptyStmt) NumInput() int                              { return -1 }
func (emptyStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(0), nil }
func (emptyStmt) Query([]driver.Value) (driver.Rows, error)  { return emptyRows{}, nil }

type emptyRows struct{}

func (emptyRows) Columns() []string         { return nil }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }
