package cfn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/policyengine"
	"gopkg.in/yaml.v3"
)

// AWSManagedPolicy is one AWS managed policy open-infra ships as a kind: Policy in the management
// account's IAM home namespace (platform/abstraction/managed-policies/, generated from this table by
// ManagedPolicyLibrary). It carries AWS's name, path and ARN, so a principal attaches it the way it does on
// AWS, and AWS's published document filtered to the services open-infra serves: an action of a service it
// does not run is listed in the policy's description as not served, never granted.
type AWSManagedPolicy struct {
	Name     string // AWS's PolicyName, e.g. "PowerUserAccess"
	Path     string // AWS's path: "/", "/service-role/" or "/job-function/"
	Category string // job-function | service (the console groups them so)
	Summary  string // what AWS documents it for, one sentence
	Doc      string // AWS's published policy document
	// Exact ships the document unfiltered: a job-function policy whose meaning is its wildcards or its
	// NotAction carve-out (AdministratorAccess, PowerUserAccess) is AWS's document byte for byte, whatever
	// services exist here.
	Exact bool
}

// ARN is the policy's AWS ARN, arn:aws:iam::aws:policy<path><name>.
func (p AWSManagedPolicy) ARN() string { return "arn:aws:iam::aws:policy" + p.Path + p.Name }

// ObjectName is the kind: Policy name the policy ships as: "aws-" and AWS's name, lowercased, with the
// characters a Kubernetes name cannot hold replaced by "-" (AWSLambda_FullAccess -> aws-awslambda-fullaccess).
func (p AWSManagedPolicy) ObjectName() string { return ManagedPolicyObjectName(p.Name) }

// ManagedPolicyObjectName is the kind: Policy name of the AWS managed policy with this PolicyName.
func ManagedPolicyObjectName(policyName string) string {
	var b strings.Builder
	b.WriteString("aws-")
	for _, r := range strings.ToLower(policyName) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// awsManagedPolicies is the shipped set: the job-function policies, then the service policies the estate
// attaches and the in-repo templates use, each ranked into the library by how often it is attached. A
// managed policy of a service open-infra does not serve (Glue's service role, Amplify, Redshift …) is not
// shipped; attaching one is a caveat (managedPolicyRefs), never a widened grant.
var awsManagedPolicies = []AWSManagedPolicy{
	{Name: "AdministratorAccess", Path: "/", Category: "job-function", Exact: true,
		Summary: "Provides full access to AWS services and resources.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
	{Name: "PowerUserAccess", Path: "/", Category: "job-function", Exact: true,
		Summary: "Provides full access to AWS services and resources, but does not allow management of Users and groups.",
		Doc: `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":["account:GetAccountInformation","account:GetPrimaryEmail","account:ListRegions","iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization"],"Resource":"*"}]}`},
	{Name: "ReadOnlyAccess", Path: "/", Category: "job-function",
		Summary: "Provides read-only access to AWS services and resources.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Sid":"ReadOnlyActions","Effect":"Allow","Action":[` +
			`"acm:Describe*","acm:Get*","acm:List*",` +
			`"apigateway:GET",` +
			`"appsync:Get*","appsync:List*",` +
			`"athena:Batch*","athena:Get*","athena:List*",` +
			`"cloudformation:Describe*","cloudformation:Detect*","cloudformation:Estimate*","cloudformation:Get*","cloudformation:List*","cloudformation:ValidateTemplate",` +
			`"cloudfront:Describe*","cloudfront:Get*","cloudfront:List*",` +
			`"cloudwatch:Describe*","cloudwatch:Get*","cloudwatch:List*",` +
			`"cognito-idp:AdminGet*","cognito-idp:AdminList*","cognito-idp:Describe*","cognito-idp:Get*","cognito-idp:List*",` +
			`"dynamodb:BatchGet*","dynamodb:Describe*","dynamodb:Get*","dynamodb:List*","dynamodb:PartiQLSelect","dynamodb:Query","dynamodb:Scan",` +
			`"ec2:Describe*","ec2:Get*",` +
			`"ecr:BatchCheck*","ecr:BatchGet*","ecr:Describe*","ecr:Get*","ecr:List*",` +
			`"ecs:Describe*","ecs:List*",` +
			`"eks:Describe*","eks:List*",` +
			`"events:Describe*","events:List*","events:Test*",` +
			`"glue:BatchGet*","glue:Get*","glue:List*",` +
			`"iam:Generate*","iam:Get*","iam:List*","iam:Simulate*",` +
			`"kinesis:Describe*","kinesis:Get*","kinesis:List*",` +
			`"kms:Describe*","kms:Get*","kms:List*",` +
			`"lambda:Get*","lambda:List*",` +
			`"logs:Describe*","logs:FilterLogEvents","logs:Get*","logs:List*","logs:StartQuery","logs:StopQuery","logs:TestMetricFilter",` +
			`"organizations:Describe*","organizations:List*",` +
			`"rds:Describe*","rds:Download*","rds:List*",` +
			`"s3:Describe*","s3:Get*","s3:List*",` +
			`"secretsmanager:Describe*","secretsmanager:GetResourcePolicy","secretsmanager:List*",` +
			`"ses:Describe*","ses:Get*","ses:List*",` +
			`"sns:Check*","sns:Get*","sns:List*",` +
			`"sqs:Get*","sqs:List*","sqs:Receive*",` +
			`"ssm:Describe*","ssm:Get*","ssm:List*",` +
			`"states:Describe*","states:GetExecutionHistory","states:List*",` +
			`"xray:BatchGet*","xray:Get*"` +
			`],"Resource":"*"},` +
			// open-infra's own kinds with no AWS service (openinfra:<Verb><Kind>, internal/awsaction): AWS's
			// read-only shape over them, so a read-only principal sees every product resource.
			`{"Sid":"OpenInfraReadOnlyActions","Effect":"Allow","Action":["openinfra:Describe*","openinfra:Get*","openinfra:List*"],"Resource":"*"}]}`},
	{Name: "ViewOnlyAccess", Path: "/job-function/", Category: "job-function",
		Summary: "Grants permissions to view resources and basic metadata across all AWS services, without reading their data.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[` +
			`"acm:ListCertificates","apigateway:GET","appsync:ListGraphqlApis","athena:List*","cloudformation:DescribeStacks","cloudformation:ListStacks",` +
			`"cloudfront:ListDistributions","cloudwatch:DescribeAlarms","cloudwatch:ListMetrics","cognito-idp:ListUserPools",` +
			`"dynamodb:DescribeTable","dynamodb:ListTables","ec2:Describe*","ecr:DescribeRepositories","ecs:Describe*","ecs:List*",` +
			`"eks:DescribeCluster","eks:ListClusters","events:ListRules","glue:GetDatabases","glue:GetTables","iam:List*",` +
			`"kinesis:DescribeStream","kinesis:ListStreams","kms:ListAliases","kms:ListKeys","lambda:List*","logs:DescribeLogGroups",` +
			`"organizations:DescribeOrganization","organizations:ListAccounts","rds:Describe*","rds:List*",` +
			`"s3:GetBucketLocation","s3:ListAllMyBuckets","s3:ListBucket","secretsmanager:ListSecrets","ses:ListIdentities",` +
			`"sns:ListTopics","sqs:ListQueues","ssm:DescribeParameters","states:ListStateMachines"` +
			`],"Resource":"*"},` +
			`{"Effect":"Allow","Action":["openinfra:Describe*","openinfra:List*"],"Resource":"*"}]}`},
	{Name: "IAMFullAccess", Path: "/", Category: "job-function",
		Summary: "Provides full access to IAM.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","organizations:DescribeAccount","organizations:DescribeOrganization","organizations:DescribeOrganizationalUnit","organizations:DescribePolicy","organizations:ListChildren","organizations:ListParents","organizations:ListPoliciesForTarget","organizations:ListRoots","organizations:ListPolicies","organizations:ListTargetsForPolicy"],"Resource":"*"}]}`},
	{Name: "IAMUserChangePassword", Path: "/", Category: "job-function",
		Summary: "Provides the ability for an IAM user to change their own password.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ChangePassword"],"Resource":["arn:aws:iam::*:user/${aws:username}"]},{"Effect":"Allow","Action":["iam:GetAccountPasswordPolicy"],"Resource":"*"}]}`},

	// --- service policies, by estate attachments ---
	{Name: "AWSLambdaVPCAccessExecutionRole", Path: "/service-role/", Category: "service",
		Summary: "Provides minimum permissions for a Lambda function to execute while accessing a resource within a VPC.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Sid":"AWSLambdaVPCAccessExecutionPermissions","Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","ec2:CreateNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DescribeSubnets","ec2:DeleteNetworkInterface","ec2:AssignPrivateIpAddresses","ec2:UnassignPrivateIpAddresses"],"Resource":"*"}]}`},
	{Name: "AmazonS3FullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to all buckets.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}`},
	{Name: "AmazonS3ReadOnlyAccess", Path: "/", Category: "service",
		Summary: "Provides read only access to all buckets.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","s3:Describe*","s3-object-lambda:Get*","s3-object-lambda:List*"],"Resource":"*"}]}`},
	{Name: "AmazonECSTaskExecutionRolePolicy", Path: "/service-role/", Category: "service",
		Summary: "Provides access to other AWS service resources that are required to run Amazon ECS tasks.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`},
	{Name: "AmazonCognitoPowerUser", Path: "/", Category: "service",
		Summary: "Provides administrative access to existing Amazon Cognito resources.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cognito-identity:*","cognito-idp:*","cognito-sync:*","iam:ListRoles","iam:ListOpenIdConnectProviders","iam:GetRole","iam:ListSAMLProviders","iam:GetSAMLProvider","kinesis:ListStreams","lambda:GetPolicy","lambda:ListFunctions","sns:GetSMSSandboxAccountStatus","sns:ListPlatformApplications","ses:ListIdentities","ses:GetIdentityVerificationAttributes","mobiletargeting:GetApps","acm:ListCertificates"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":["cognito-idp.amazonaws.com","email.cognito-idp.amazonaws.com"]}}},` +
			`{"Effect":"Allow","Action":["iam:DeleteServiceLinkedRole","iam:GetServiceLinkedRoleDeletionStatus"],"Resource":"arn:aws:iam::*:role/aws-service-role/cognito-idp.amazonaws.com/AWSServiceRoleForAmazonCognitoIdp*"}]}`},
	{Name: "AWSLambdaBasicExecutionRole", Path: "/service-role/", Category: "service",
		Summary: "Provides write permissions to CloudWatch Logs.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`},
	{Name: "AmazonSSMManagedInstanceCore", Path: "/", Category: "service",
		Summary: "The policy for Amazon EC2 Role to enable AWS Systems Manager service core functionality.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:DescribeAssociation","ssm:GetDeployablePatchSnapshotForInstance","ssm:GetDocument","ssm:DescribeDocument","ssm:GetManifest","ssm:GetParameter","ssm:GetParameters","ssm:ListAssociations","ssm:ListInstanceAssociations","ssm:PutInventory","ssm:PutComplianceItems","ssm:PutConfigurePackageResult","ssm:UpdateAssociationStatus","ssm:UpdateInstanceAssociationStatus","ssm:UpdateInstanceInformation"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":["ssmmessages:CreateControlChannel","ssmmessages:CreateDataChannel","ssmmessages:OpenControlChannel","ssmmessages:OpenDataChannel"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":["ec2messages:AcknowledgeMessage","ec2messages:DeleteMessage","ec2messages:FailMessage","ec2messages:GetEndpoint","ec2messages:GetMessages","ec2messages:SendReply"],"Resource":"*"}]}`},
	{Name: "AWSCloudFormationFullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to AWS CloudFormation.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:*"],"Resource":"*"}]}`},
	{Name: "CloudWatchFullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to CloudWatch.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["autoscaling:Describe*","cloudwatch:*","logs:*","sns:*","iam:GetPolicy","iam:GetPolicyVersion","iam:GetRole","oam:ListSinks"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::*:role/aws-service-role/events.amazonaws.com/AWSServiceRoleForCloudWatchEvents*","Condition":{"StringLike":{"iam:AWSServiceName":"events.amazonaws.com"}}},` +
			`{"Effect":"Allow","Action":["oam:ListAttachedLinks"],"Resource":"arn:aws:oam:*:*:sink/*"}]}`},
	{Name: "AmazonRDSFullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to Amazon RDS via the AWS Management Console.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds:*","application-autoscaling:DeleteScalingPolicy","application-autoscaling:DeregisterScalableTarget","application-autoscaling:DescribeScalableTargets","application-autoscaling:DescribeScalingActivities","application-autoscaling:DescribeScalingPolicies","application-autoscaling:PutScalingPolicy","application-autoscaling:RegisterScalableTarget","cloudwatch:DescribeAlarms","cloudwatch:GetMetricStatistics","cloudwatch:PutMetricAlarm","cloudwatch:DeleteAlarms","cloudwatch:ListMetrics","cloudwatch:GetMetricData","ec2:DescribeAccountAttributes","ec2:DescribeAvailabilityZones","ec2:DescribeCoipPools","ec2:DescribeInternetGateways","ec2:DescribeLocalGatewayRouteTablePermissions","ec2:DescribeLocalGatewayRouteTables","ec2:DescribeLocalGatewayRouteTableVpcAssociations","ec2:DescribeLocalGateways","ec2:DescribeSecurityGroups","ec2:DescribeSubnets","ec2:DescribeVpcAttribute","ec2:DescribeVpcs","ec2:GetCoipPoolUsage","sns:ListSubscriptions","sns:ListTopics","sns:Publish","logs:DescribeLogStreams","logs:GetLogEvents","outposts:GetOutpostInstanceTypes","devops-guru:GetResourceCollection"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":"pi:*","Resource":["arn:aws:pi:*:*:metrics/rds/*","arn:aws:pi:*:*:perf-reports/rds/*"]},` +
			`{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringLike":{"iam:AWSServiceName":["rds.amazonaws.com","rds.application-autoscaling.amazonaws.com"]}}}]}`},
	{Name: "AWSStepFunctionsFullAccess", Path: "/", Category: "service",
		Summary: "An access policy for providing a user/role/etc access to the AWS StepFunctions API.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"states:*","Resource":"*"},` +
			`{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::*:role/service-role/StepFunctions*","Condition":{"StringEquals":{"iam:PassedToService":"states.amazonaws.com"}}},` +
			`{"Effect":"Allow","Action":["xray:GetTraceSummaries","xray:BatchGetTraces"],"Resource":"*"}]}`},
	{Name: "AmazonSQSFullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to Amazon SQS via the AWS Management Console.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Action":["sqs:*"],"Effect":"Allow","Resource":"*"}]}`},
	{Name: "AmazonSQSReadOnlyAccess", Path: "/", Category: "service",
		Summary: "Provides read only access to Amazon SQS via the AWS Management Console.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:GetQueueAttributes","sqs:GetQueueUrl","sqs:ListDeadLetterSourceQueues","sqs:ListQueues","sqs:ListMessageMoveTasks","sqs:ListQueueTags"],"Resource":"*"}]}`},
	{Name: "AmazonSSMFullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to Amazon SSM.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:PutMetricData","ds:CreateComputer","ds:DescribeDirectories","ec2:DescribeInstanceStatus","logs:*","ssm:*","ec2messages:*"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::*:role/aws-service-role/ssm.amazonaws.com/AWSServiceRoleForAmazonSSM*","Condition":{"StringLike":{"iam:AWSServiceName":"ssm.amazonaws.com"}}},` +
			`{"Effect":"Allow","Action":["iam:DeleteServiceLinkedRole","iam:GetServiceLinkedRoleDeletionStatus"],"Resource":"arn:aws:iam::*:role/aws-service-role/ssm.amazonaws.com/AWSServiceRoleForAmazonSSM*"},` +
			`{"Effect":"Allow","Action":["ssmmessages:CreateControlChannel","ssmmessages:CreateDataChannel","ssmmessages:OpenControlChannel","ssmmessages:OpenDataChannel"],"Resource":"*"}]}`},
	{Name: "CloudWatchAgentServerPolicy", Path: "/", Category: "service",
		Summary: "Permissions required to use AmazonCloudWatchAgent on servers.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:PutMetricData","ec2:DescribeVolumes","ec2:DescribeTags","logs:PutLogEvents","logs:PutRetentionPolicy","logs:DescribeLogStreams","logs:DescribeLogGroups","logs:CreateLogStream","logs:CreateLogGroup","xray:PutTraceSegments","xray:PutTelemetryRecords","xray:GetSamplingRules","xray:GetSamplingTargets","xray:GetSamplingStatisticSummaries"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":["ssm:GetParameter"],"Resource":"arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"}]}`},
	{Name: "AWSAppSyncInvokeFullAccess", Path: "/", Category: "service",
		Summary: "Provides full invoke access to the AppSync service, both via the AWS Management Console and the API.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["appsync:GraphQL","appsync:GetGraphqlApi","appsync:ListGraphqlApis","appsync:ListApiKeys"],"Resource":"*"}]}`},
	{Name: "AWSLambda_FullAccess", Path: "/", Category: "service",
		Summary: "Grants full access to AWS Lambda service, AWS Lambda console features, and other related AWS services.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeStacks","cloudformation:ListStackResources","cloudwatch:ListMetrics","cloudwatch:GetMetricData","ec2:DescribeSecurityGroups","ec2:DescribeSubnets","ec2:DescribeVpcs","kms:ListAliases","iam:GetPolicy","iam:GetPolicyVersion","iam:GetRole","iam:GetRolePolicy","iam:ListAttachedRolePolicies","iam:ListRolePolicies","iam:ListRoles","lambda:*","logs:DescribeLogGroups","states:DescribeStateMachine","states:ListStateMachines","tag:GetResources","xray:GetTraceSummaries","xray:BatchGetTraces"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}},` +
			`{"Effect":"Allow","Action":["logs:DescribeLogStreams","logs:GetLogEvents","logs:FilterLogEvents","logs:StartLiveTail","logs:StopLiveTail"],"Resource":"arn:aws:logs:*:*:log-group:/aws/lambda/*"}]}`},
	{Name: "AWSLambdaFullAccess", Path: "/", Category: "service",
		Summary: "Deprecated by AWS in favour of AWSLambda_FullAccess, and still attached in estates: full access to Lambda and the services its console uses.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeChangeSet","cloudformation:DescribeStackResources","cloudformation:DescribeStacks","cloudformation:GetTemplate","cloudformation:ListStackResources","cloudwatch:*","cognito-identity:ListIdentityPools","cognito-sync:GetCognitoEvents","cognito-sync:SetCognitoEvents","dynamodb:*","ec2:DescribeSecurityGroups","ec2:DescribeSubnets","ec2:DescribeVpcs","events:*","iam:GetPolicy","iam:GetPolicyVersion","iam:GetRole","iam:GetRolePolicy","iam:ListAttachedRolePolicies","iam:ListRolePolicies","iam:ListRoles","iam:PassRole","iot:AttachPrincipalPolicy","iot:AttachThingPrincipal","iot:CreateKeysAndCertificate","iot:CreatePolicy","iot:CreateThing","iot:CreateTopicRule","iot:DescribeEndpoint","iot:GetTopicRule","iot:ListPolicies","iot:ListThings","iot:ListTopicRules","iot:ReplaceTopicRule","kinesis:DescribeStream","kinesis:ListStreams","kinesis:PutRecord","kms:ListAliases","lambda:*","logs:*","s3:*","sns:ListSubscriptions","sns:ListSubscriptionsByTopic","sns:ListTopics","sns:Publish","sns:Subscribe","sns:Unsubscribe","sqs:ListQueues","sqs:SendMessage","tag:GetResources","xray:PutTelemetryRecords","xray:PutTraceSegments"],"Resource":"*"}]}`},
	{Name: "AWSLambdaRole", Path: "/service-role/", Category: "service",
		Summary: "Default policy for AWS Lambda service role: invoke any function.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:InvokeFunction"],"Resource":["*"]}]}`},
	{Name: "AmazonDynamoDBFullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to Amazon DynamoDB via the AWS Management Console.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Action":["dynamodb:*","dax:*","application-autoscaling:DeleteScalingPolicy","application-autoscaling:DeregisterScalableTarget","application-autoscaling:DescribeScalableTargets","application-autoscaling:DescribeScalingActivities","application-autoscaling:DescribeScalingPolicies","application-autoscaling:PutScalingPolicy","application-autoscaling:RegisterScalableTarget","cloudwatch:DeleteAlarms","cloudwatch:DescribeAlarmHistory","cloudwatch:DescribeAlarms","cloudwatch:DescribeAlarmsForMetric","cloudwatch:GetMetricStatistics","cloudwatch:ListMetrics","cloudwatch:PutMetricAlarm","cloudwatch:GetMetricData","ec2:DescribeVpcs","ec2:DescribeSubnets","ec2:DescribeSecurityGroups","iam:GetRole","iam:ListRoles","kms:DescribeKey","kms:ListAliases","sns:CreateTopic","sns:DeleteTopic","sns:ListSubscriptions","sns:ListSubscriptionsByTopic","sns:ListTopics","sns:Subscribe","sns:Unsubscribe","sns:SetTopicAttributes","lambda:CreateFunction","lambda:ListFunctions","lambda:ListEventSourceMappings","lambda:CreateEventSourceMapping","lambda:DeleteEventSourceMapping","lambda:GetFunctionConfiguration","lambda:DeleteFunction","resource-groups:ListGroups","resource-groups:ListGroupResources","resource-groups:GetGroup","resource-groups:GetGroupQuery","resource-groups:DeleteGroup","resource-groups:CreateGroup","tag:GetResources","kinesis:ListStreams","kinesis:DescribeStream","kinesis:DescribeStreamSummary"],"Effect":"Allow","Resource":"*"},` +
			`{"Action":"cloudwatch:GetInsightRuleReport","Effect":"Allow","Resource":"arn:aws:cloudwatch:*:*:insight-rule/DynamoDBContributorInsights*"},` +
			`{"Action":["iam:PassRole"],"Effect":"Allow","Resource":"*","Condition":{"StringLike":{"iam:PassedToService":["application-autoscaling.amazonaws.com","application-autoscaling.amazonaws.com.cn","dax.amazonaws.com"]}}},` +
			`{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole"],"Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":["replication.dynamodb.amazonaws.com","dax.amazonaws.com","dynamodb.application-autoscaling.amazonaws.com","contributorinsights.dynamodb.amazonaws.com","kinesisreplication.dynamodb.amazonaws.com"]}}}]}`},
	{Name: "AmazonDynamoDBReadOnlyAccess", Path: "/", Category: "service",
		Summary: "Provides read only access to Amazon DynamoDB via the AWS Management Console.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Action":["application-autoscaling:DescribeScalableTargets","application-autoscaling:DescribeScalingActivities","application-autoscaling:DescribeScalingPolicies","cloudwatch:DescribeAlarmHistory","cloudwatch:DescribeAlarms","cloudwatch:DescribeAlarmsForMetric","cloudwatch:GetMetricData","cloudwatch:GetMetricStatistics","cloudwatch:ListMetrics","cloudwatch:GetInsightRuleReport","dynamodb:BatchGetItem","dynamodb:Describe*","dynamodb:List*","dynamodb:GetItem","dynamodb:GetResourcePolicy","dynamodb:Query","dynamodb:Scan","dynamodb:PartiQLSelect","dax:Describe*","dax:List*","dax:GetItem","dax:BatchGetItem","dax:Query","dax:Scan","ec2:DescribeVpcs","ec2:DescribeSubnets","ec2:DescribeSecurityGroups","iam:GetRole","iam:ListRoles","kms:DescribeKey","kms:ListAliases","sns:ListSubscriptionsByTopic","sns:ListTopics","lambda:ListFunctions","lambda:ListEventSourceMappings","lambda:GetFunctionConfiguration","resource-groups:ListGroups","resource-groups:ListGroupResources","resource-groups:GetGroup","resource-groups:GetGroupQuery","tag:GetResources","kinesis:ListStreams","kinesis:DescribeStream","kinesis:DescribeStreamSummary"],"Effect":"Allow","Resource":"*"}]}`},
	{Name: "SecretsManagerReadWrite", Path: "/", Category: "service",
		Summary: "Provides read/write access to AWS Secrets Manager via the AWS Management Console.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Sid":"BasePermissions","Effect":"Allow","Action":["secretsmanager:*","cloudformation:CreateChangeSet","cloudformation:DescribeChangeSet","cloudformation:DescribeStackResource","cloudformation:DescribeStacks","cloudformation:ExecuteChangeSet","docdb-elastic:GetCluster","docdb-elastic:ListClusters","ec2:DescribeSecurityGroups","ec2:DescribeSubnets","ec2:DescribeVpcs","kms:DescribeKey","kms:ListAliases","kms:ListKeys","lambda:ListFunctions","rds:DescribeDBClusters","rds:DescribeDBInstances","redshift:DescribeClusters","redshift-serverless:ListWorkgroups","redshift-serverless:GetNamespace","tag:GetResources"],"Resource":"*"},` +
			`{"Sid":"LambdaPermissions","Effect":"Allow","Action":["lambda:AddPermission","lambda:CreateFunction","lambda:GetFunction","lambda:InvokeFunction","lambda:UpdateFunctionConfiguration"],"Resource":"arn:aws:lambda:*:*:function:SecretsManager*"},` +
			`{"Sid":"SARPermissions","Effect":"Allow","Action":["serverlessrepo:CreateCloudFormationChangeSet","serverlessrepo:GetApplication"],"Resource":"arn:aws:serverlessrepo:*:*:applications/SecretsManager*"},` +
			`{"Sid":"S3Permissions","Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::awsserverlessrepo-changesets*","arn:aws:s3:::secrets-manager-rotation-apps-*/*"]}]}`},
	{Name: "AmazonRDSReadOnlyAccess", Path: "/", Category: "service",
		Summary: "Provides read only access to Amazon RDS via the AWS Management Console.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Action":["rds:Describe*","rds:ListTagsForResource","ec2:DescribeAccountAttributes","ec2:DescribeAvailabilityZones","ec2:DescribeInternetGateways","ec2:DescribeSecurityGroups","ec2:DescribeSubnets","ec2:DescribeVpcAttribute","ec2:DescribeVpcs"],"Effect":"Allow","Resource":"*"},` +
			`{"Action":["cloudwatch:GetMetricStatistics","cloudwatch:ListMetrics","cloudwatch:GetMetricData","logs:DescribeLogStreams","logs:GetLogEvents","devops-guru:GetResourceCollection"],"Effect":"Allow","Resource":"*"}]}`},
	{Name: "AmazonEC2FullAccess", Path: "/", Category: "service",
		Summary: "Provides full access to Amazon EC2 via the AWS Management Console.",
		Doc: `{"Version":"2012-10-17","Statement":[{"Action":"ec2:*","Effect":"Allow","Resource":"*"},{"Effect":"Allow","Action":"elasticloadbalancing:*","Resource":"*"},{"Effect":"Allow","Action":"cloudwatch:*","Resource":"*"},{"Effect":"Allow","Action":"autoscaling:*","Resource":"*"},` +
			`{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":["autoscaling.amazonaws.com","ec2scheduled.amazonaws.com","elasticloadbalancing.amazonaws.com","spot.amazonaws.com","spotfleet.amazonaws.com","transitgateway.amazonaws.com"]}}}]}`},
	{Name: "AmazonEC2ReadOnlyAccess", Path: "/", Category: "service",
		Summary: "Provides read only access to Amazon EC2 via the AWS Management Console.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"},{"Effect":"Allow","Action":"elasticloadbalancing:Describe*","Resource":"*"},{"Effect":"Allow","Action":["cloudwatch:ListMetrics","cloudwatch:GetMetricStatistics","cloudwatch:Describe*"],"Resource":"*"},{"Effect":"Allow","Action":"autoscaling:Describe*","Resource":"*"}]}`},
	{Name: "AmazonAPIGatewayAdministrator", Path: "/", Category: "service",
		Summary: "Provides full access to create/edit/delete APIs in Amazon API Gateway via the AWS Management Console.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["apigateway:*"],"Resource":"arn:aws:apigateway:*::/*"}]}`},
	{Name: "AmazonEC2ContainerRegistryReadOnly", Path: "/", Category: "service",
		Summary: "Provides read-only access to Amazon EC2 Container Registry repositories.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:GetRepositoryPolicy","ecr:DescribeRepositories","ecr:ListImages","ecr:DescribeImages","ecr:BatchGetImage","ecr:GetLifecyclePolicy","ecr:GetLifecyclePolicyPreview","ecr:ListTagsForResource","ecr:DescribeImageScanFindings"],"Resource":"*"}]}`},
	{Name: "AmazonEC2ContainerRegistryPullOnly", Path: "/", Category: "service",
		Summary: "Provides read-only access to pull images from Amazon ECR repositories.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:BatchImportUpstreamImage"],"Resource":"*"}]}`},
	{Name: "AmazonEC2ContainerRegistryPowerUser", Path: "/", Category: "service",
		Summary: "Provides full access to Amazon EC2 Container Registry repositories, but does not allow repository deletion or policy changes.",
		Doc:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:GetRepositoryPolicy","ecr:DescribeRepositories","ecr:ListImages","ecr:DescribeImages","ecr:BatchGetImage","ecr:GetLifecyclePolicy","ecr:GetLifecyclePolicyPreview","ecr:ListTagsForResource","ecr:DescribeImageScanFindings","ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload","ecr:PutImage"],"Resource":"*"}]}`},
}

// notShippedManagedPolicies are AWS managed policies an estate attaches that open-infra deliberately does
// not ship, with why: every action they grant belongs to a service it does not run. Attaching one is a
// caveat naming the reason.
var notShippedManagedPolicies = map[string]string{
	"AWSGlueServiceRole":                            "it is Glue's service role (crawlers and jobs run as it); open-infra serves the Glue catalog, not Glue jobs",
	"AmplifyBackendDeployFullAccess":                "Amplify backends are not served",
	"AdministratorAccess-Amplify":                   "Amplify backends are not served",
	"AmazonCognitoDeveloperAuthenticatedIdentities": "Cognito identity pools (cognito-identity) are not served",
	"AmazonAPIGatewayInvokeFullAccess":              "execute-api permissions are not evaluated here: an API's own authorizer guards its invocation",
}

// ManagedPolicies returns the shipped AWS managed policies, in library order.
func ManagedPolicies() []AWSManagedPolicy {
	return append([]AWSManagedPolicy(nil), awsManagedPolicies...)
}

// ManagedPolicyByName finds a shipped AWS managed policy by its PolicyName.
func ManagedPolicyByName(name string) (AWSManagedPolicy, bool) {
	for _, p := range awsManagedPolicies {
		if p.Name == name {
			return p, true
		}
	}
	return AWSManagedPolicy{}, false
}

// ManagedPolicyByARN finds a shipped AWS managed policy by its ARN (arn:aws:iam::aws:policy[/path]/<Name>).
// A customer managed policy (an account id in place of "aws") is not one.
func ManagedPolicyByARN(arn string) (AWSManagedPolicy, bool) {
	if !strings.HasPrefix(arn, "arn:aws:iam::aws:policy/") {
		return AWSManagedPolicy{}, false
	}
	for _, p := range awsManagedPolicies {
		if p.ARN() == arn {
			return p, true
		}
	}
	// AWS accepts the name without its path in some tools; resolve by the last segment as a fallback,
	// only when that name is unambiguous in the library (it always is: AWS names are unique).
	name := arn[strings.LastIndex(arn, "/")+1:]
	return ManagedPolicyByName(name)
}

// servedPrefix reports whether an action's service is one open-infra authorizes: a data-plane service the
// aws-shim enforces (policyengine.SupportedServices, or one it enforces in part), Organizations and STS
// (the management account's front doors), and open-infra's own kinds (openinfra:).
func servedPrefix(action string) bool {
	if action == "*" {
		return true
	}
	svc, _, ok := strings.Cut(action, ":")
	if !ok {
		return false
	}
	if policyengine.SupportedServices[svc] {
		return true
	}
	if _, ok := policyengine.SupportedActions[svc]; ok {
		return true
	}
	switch svc {
	case "organizations", "sts", "openinfra":
		return true
	}
	return false
}

// awsDocument is an AWS policy document in AWS's field order, so the library reads as AWS publishes it.
type awsDocument struct {
	Version   string         `json:"Version"`
	Statement []awsStatement `json:"Statement"`
}

type awsStatement struct {
	Sid         string                    `json:"Sid,omitempty"`
	Effect      string                    `json:"Effect"`
	Action      any                       `json:"Action,omitempty"`
	NotAction   any                       `json:"NotAction,omitempty"`
	Resource    any                       `json:"Resource,omitempty"`
	NotResource any                       `json:"NotResource,omitempty"`
	Condition   map[string]map[string]any `json:"Condition,omitempty"`
}

// ServedDocument is the policy's document as shipped, and the services it names that are not served here
// (sorted). An Exact policy is AWS's document whatever it names. Otherwise each statement's Action list
// keeps only served actions, a statement left with none is dropped, and NotAction, Resource and Condition
// stay as AWS wrote them (a carve-out only ever narrows).
func (p AWSManagedPolicy) ServedDocument() (awsDocument, []string, error) {
	var doc awsDocument
	if err := json.Unmarshal([]byte(p.Doc), &doc); err != nil {
		return doc, nil, fmt.Errorf("%s: %w", p.Name, err)
	}
	if p.Exact {
		return doc, nil, nil
	}
	missing := map[string]bool{}
	var kept []awsStatement
	for _, st := range doc.Statement {
		if st.NotAction != nil {
			kept = append(kept, st)
			continue
		}
		var acts []string
		single := false
		switch a := st.Action.(type) {
		case string:
			acts, single = []string{a}, true
		case []any:
			for _, x := range a {
				s, _ := x.(string)
				acts = append(acts, s)
			}
		}
		var served []string
		for _, a := range acts {
			if servedPrefix(a) {
				served = append(served, a)
			} else if svc, _, ok := strings.Cut(a, ":"); ok {
				missing[svc] = true
			}
		}
		if len(served) == 0 {
			continue
		}
		if single {
			st.Action = served[0]
		} else {
			list := make([]any, len(served))
			for i, a := range served {
				list[i] = a
			}
			st.Action = list
		}
		kept = append(kept, st)
	}
	doc.Statement = kept
	var out []string
	for s := range missing {
		out = append(out, s)
	}
	sort.Strings(out)
	return doc, out, nil
}

// DataPlaneStatements is the shipped document as today's data-plane statements (policyengine.ImportAWS),
// which a Policy carries beside its document until every front door evaluates the document itself: what
// the importer cannot honor faithfully (an action it does not front, a condition it cannot evaluate) is
// left out, so the derived grant is never wider than the document.
func (p AWSManagedPolicy) DataPlaneStatements() ([]policyengine.Statement, error) {
	doc, _, err := p.ServedDocument()
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(doc)
	stmts, _, err := policyengine.ImportAWS(string(b))
	return stmts, err
}

// managedPolicyRefs turns a role's ManagedPolicyArns into the names of the shipped managed policies to
// attach (the role's spec.policies), with a caveat per policy naming what of it is not served here. An ARN
// the library does not ship (a customer managed policy, an AWS policy of an unserved service) is a caveat:
// nothing is attached for it.
func managedPolicyRefs(id string, v any) ([]string, []string, []Finding) {
	arns, f := stringList(id, "ManagedPolicyArns", v)
	var refs, caveats, unmapped []string
	for _, arn := range arns {
		mp, ok := ManagedPolicyByARN(arn)
		if !ok {
			name := arn[strings.LastIndex(arn, "/")+1:]
			if why, known := notShippedManagedPolicies[name]; known && strings.HasPrefix(arn, "arn:aws:iam::aws:policy/") {
				caveats = append(caveats, fmt.Sprintf("managed policy %s is NOT attached — %s", name, why))
				continue
			}
			unmapped = append(unmapped, arn)
			continue
		}
		_, missing, err := mp.ServedDocument()
		if err != nil {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("managed policy %s did not parse (%v) — this is an engine bug", mp.Name, err)})
			continue
		}
		refs = append(refs, mp.ObjectName())
		cav := fmt.Sprintf("managed policy %s is attached (kind: Policy %s)", mp.Name, mp.ObjectName())
		if len(missing) > 0 {
			cav += "; its actions for " + strings.Join(missing, ", ") + " are not served here"
		}
		caveats = append(caveats, cav)
	}
	if len(unmapped) > 0 {
		caveats = append(caveats, "ManagedPolicyArns "+strings.Join(unmapped, ", ")+" are NOT attached — not an AWS managed policy open-infra ships; express the access as an inline Policy, or attach a kind: Policy by name in spec.policies")
	}
	return refs, caveats, f
}

// maxCompanionNameLen is the longest name a role's companion kind: Policy gets: a Kubernetes label value
// (the policy's name is carried in labels), which is also the RFC 1123 label limit.
const maxCompanionNameLen = 63

// companionPolicyName is <role>-<suffix>, the name of a companion kind: Policy of a role (an inline
// policy). One that does not fit maxCompanionNameLen is shortened with a hash of the full name appended, so
// it stays unique per (role, suffix): a long stack name or policy name never fails the deploy on a
// too-long name.
func companionPolicyName(roleName, suffix string) string {
	n := roleName + "-" + suffix // unchanged for every name that fits, so no deployed policy is renamed
	if len(n) <= maxCompanionNameLen {
		return n
	}
	sum := sha256.Sum256([]byte(roleName + "\x00" + suffix))
	head := strings.Trim(n[:maxCompanionNameLen-9], "-")
	return head + "-" + hex.EncodeToString(sum[:])[:8]
}

// ManagedPolicyLibraryPath is where ManagedPolicyLibrary's output lives, relative to the repository root.
const ManagedPolicyLibraryPath = "platform/abstraction/managed-policies/aws-managed-policies.yaml"

// ManagedPolicyLibrary renders the shipped AWS managed policies as kind: Policy manifests for the
// management account's IAM home namespace (open-infra-console): AWS's name, path and ARN, the document as
// shipped (ServedDocument), and — until every front door evaluates spec.document — the data-plane
// statements derived from it. A test keeps the file in step with this table.
func ManagedPolicyLibrary() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`# AWS MANAGED POLICIES, as AWS names them — generated from cfn/managed_policies.go by
#   UPDATE_MANAGED_POLICIES=1 go test ./cfn -run TestManagedPolicyLibraryIsCurrent
# Do not edit by hand.
#
# Each is a kind: Policy in the management account's IAM home namespace carrying AWS's PolicyName, ARN
# and document: attach one to a User, Group or Role by its ARN (the IAM API, CloudFormation
# ManagedPolicyArns) or by its object name (spec.policies), exactly as on AWS. A document keeps only
# the actions of services open-infra serves; the description names what is not served, which is never
# granted. AdministratorAccess and PowerUserAccess are AWS's documents unchanged: PowerUserAccess
# allows everything except IAM, Organizations and Account management (its NotAction), as AWS.
#
# spec.dataPlane is DERIVED from spec.document by the AWS importer, for the front doors that read
# data-plane statements; it is never wider than the document and goes away once every door evaluates
# spec.document. These policies grant nothing until attached (no appliesTo).
#
# GitOps: raw claim-kind manifests (SkipDryRunOnMissingResource; sync-wave 4, after the Policy XRD).
`)
	for _, p := range awsManagedPolicies {
		doc, missing, err := p.ServedDocument()
		if err != nil {
			return nil, err
		}
		docJSON, err := json.MarshalIndent(doc, "    ", "  ")
		if err != nil {
			return nil, err
		}
		stmts, err := p.DataPlaneStatements()
		if err != nil {
			return nil, err
		}
		desc := p.Summary
		if len(missing) > 0 {
			desc += " Not served here (never granted): " + strings.Join(missing, ", ") + "."
		}
		meta := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Policy",
			"metadata": map[string]any{
				"name":      p.ObjectName(),
				"namespace": "open-infra-console",
				"labels": map[string]any{
					"openinfra.dev/managed-policy":     "true",
					"openinfra.dev/aws-managed-policy": "true",
					"openinfra.dev/policy-category":    p.Category,
				},
				"annotations": map[string]any{
					"openinfra.dev/title":             p.Name,
					"argocd.argoproj.io/sync-wave":    "4",
					"argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true",
				},
			},
		}
		head, err := yaml2(meta)
		if err != nil {
			return nil, err
		}
		spec := map[string]any{
			"policyName":  p.Name,
			"arn":         p.ARN(),
			"description": desc,
		}
		if len(stmts) > 0 {
			spec["dataPlane"] = map[string]any{"statements": statementsToSpec(stmts)}
		}
		specYAML, err := yaml2(map[string]any{"spec": spec})
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "---\n# %s (%s)\n", p.Name, p.ARN())
		b.Write(head)
		b.Write(specYAML)
		// The document is JSON, which is also YAML (a flow mapping): it reads exactly as AWS shows it.
		fmt.Fprintf(&b, "  document:\n    %s\n", docJSON)
	}
	return b.Bytes(), nil
}

// yaml2 marshals v as YAML indented by two spaces, the repository's manifest style.
func yaml2(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
