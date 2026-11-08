package awsaction

import "strings"

const (
	groupPlatform = "openinfra.dev"
	groupIAM      = "iam.openinfra.dev"
)

// row builds an entry whose verbs map to the given actions (get, list, create, update, delete).
func row(group, kind, resource, service, resourceType, cfnType, arn, get, list, create, update, del string) *Entry {
	return &Entry{
		Group: group, Kind: kind, Resource: resource, Service: service, ResourceType: resourceType,
		CfnType: cfnType, ARN: arn,
		Actions: map[Verb]string{Get: get, List: list, Create: create, Update: update, Delete: del},
	}
}

// native is a kind with no AWS analog: openinfra:<Verb><Kind> on arn:…:openinfra:…:<type>/<name>.
func native(kind, resource, resourceType, note string) *Entry {
	e := row(groupPlatform, kind, resource, "openinfra", resourceType, "",
		"arn:{partition}:openinfra:{region}:{account}:"+resourceType+"/{name}",
		"openinfra:Get"+kind, "openinfra:List"+plural(kind), "openinfra:Create"+kind,
		"openinfra:Update"+kind, "openinfra:Delete"+kind)
	e.Note = note
	return e
}

func plural(kind string) string {
	switch {
	case strings.HasSuffix(kind, "y") && !strings.HasSuffix(kind, "ey"):
		return strings.TrimSuffix(kind, "y") + "ies"
	case strings.HasSuffix(kind, "s"):
		return kind + "es"
	}
	return kind + "s"
}

// ec2Row is an EC2 resource: its Describe* calls take no resource-level permission.
func ec2Row(kind, resource, resourceType, cfnType, describe, create, update, del string) *Entry {
	e := row(groupPlatform, kind, resource, "ec2", resourceType, cfnType,
		"arn:{partition}:ec2:{region}:{account}:"+resourceType+"/{name}", describe, describe, create, update, del)
	e.GlobalDescribe = true
	return e
}

func sagemakerJob(kind, resource, resourceType, noun string) *Entry {
	e := row(groupPlatform, kind, resource, "sagemaker", resourceType, "",
		"arn:{partition}:sagemaker:{region}:{account}:"+resourceType+"/{name}",
		"sagemaker:Describe"+noun, "sagemaker:List"+noun+"s", "sagemaker:Create"+noun,
		"sagemaker:Create"+noun, "sagemaker:Stop"+noun)
	e.Note = "a job is immutable on AWS: changing one re-runs it (Create" + noun + "), and deleting one stops it"
	return e
}

func sagemakerResource(kind, resource, resourceType, cfnType, noun string) *Entry {
	return row(groupPlatform, kind, resource, "sagemaker", resourceType, cfnType,
		"arn:{partition}:sagemaker:{region}:{account}:"+resourceType+"/{name}",
		"sagemaker:Describe"+noun, "sagemaker:List"+noun+"s", "sagemaker:Create"+noun,
		"sagemaker:Update"+noun, "sagemaker:Delete"+noun)
}

func has(field string) func(map[string]any) bool {
	return func(spec map[string]any) bool {
		v, ok := spec[field]
		return ok && v != nil && v != false && v != ""
	}
}

func not(f func(map[string]any) bool) func(map[string]any) bool {
	return func(spec map[string]any) bool { return !f(spec) }
}

func both(a, b func(map[string]any) bool) func(map[string]any) bool {
	return func(spec map[string]any) bool { return a(spec) && b(spec) }
}

// table is every claim kind, keyed by kind.
func table() []*Entry {
	var t []*Entry
	add := func(e *Entry) *Entry { t = append(t, e); return e }

	// ---- IAM (iam.openinfra.dev) ----
	u := add(row(groupIAM, "User", "users", "iam", "user", "AWS::IAM::User", "arn:{partition}:iam::{account}:user/{name}",
		"iam:GetUser", "iam:ListUsers", "iam:CreateUser", "iam:UpdateUser", "iam:DeleteUser"))
	u.FieldActions = map[string]FieldRule{
		"policies":           {Actions: []string{"iam:AttachUserPolicy", "iam:DetachUserPolicy"}},
		"groups":             {Actions: []string{"iam:AddUserToGroup", "iam:RemoveUserFromGroup"}},
		"permissionBoundary": {Actions: []string{"iam:PutUserPermissionsBoundary"}},
		"passwordSecretRef":  {Actions: []string{"iam:UpdateLoginProfile"}},
		"disabled":           {Actions: []string{"iam:UpdateLoginProfile"}},
	}
	g := add(row(groupIAM, "Group", "groups", "iam", "group", "AWS::IAM::Group", "arn:{partition}:iam::{account}:group/{name}",
		"iam:GetGroup", "iam:ListGroups", "iam:CreateGroup", "iam:UpdateGroup", "iam:DeleteGroup"))
	g.FieldActions = map[string]FieldRule{
		"policies": {Actions: []string{"iam:AttachGroupPolicy", "iam:DetachGroupPolicy"}},
	}
	r := add(row(groupIAM, "Role", "roles", "iam", "role", "AWS::IAM::Role", "arn:{partition}:iam::{account}:role/{name}",
		"iam:GetRole", "iam:ListRoles", "iam:CreateRole", "iam:UpdateRole", "iam:DeleteRole"))
	r.FieldActions = map[string]FieldRule{
		"policies":           {Actions: []string{"iam:AttachRolePolicy", "iam:DetachRolePolicy"}},
		"trust":              {Actions: []string{"iam:UpdateAssumeRolePolicy"}},
		"permissionBoundary": {Actions: []string{"iam:PutRolePermissionsBoundary"}},
	}
	add(row(groupIAM, "Policy", "policies", "iam", "policy", "AWS::IAM::ManagedPolicy", "arn:{partition}:iam::{account}:policy/{name}",
		"iam:GetPolicy", "iam:ListPolicies", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy"))
	grant := add(row(groupIAM, "Grant", "grants", "iam", "user", "", "arn:{partition}:iam::{account}:user/{spec.subject}",
		"iam:ListAttachedUserPolicies", "iam:ListAttachedUserPolicies", "iam:AttachUserPolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy"))
	grant.Note = "a Grant raises its subject's permissions for a while: on AWS that is attaching a policy to the user, so it is the IAM write it amounts to (never openinfra:, which PowerUserAccess would cover)"
	add(row(groupPlatform, "IdentityProvider", "identityproviders", "iam", "oidc-provider", "AWS::IAM::OIDCProvider",
		"arn:{partition}:iam::{account}:oidc-provider/{name}",
		"iam:GetOpenIDConnectProvider", "iam:ListOpenIDConnectProviders", "iam:CreateOpenIDConnectProvider",
		"iam:UpdateOpenIDConnectProviderThumbprint", "iam:DeleteOpenIDConnectProvider")).FieldActions = map[string]FieldRule{
		"audiences": {Actions: []string{"iam:AddClientIDToOpenIDConnectProvider", "iam:RemoveClientIDFromOpenIDConnectProvider"}},
	}

	// ---- compute ----
	app := add(row(groupPlatform, "Application", "applications", "ecs", "service", "AWS::ECS::Service",
		"arn:{partition}:ecs:{region}:{account}:service/default/{name}",
		"ecs:DescribeServices", "ecs:ListServices", "ecs:CreateService", "ecs:UpdateService", "ecs:DeleteService"))
	app.PassRoleFields = []string{"assumeRole"}
	db := row(groupPlatform, "Application", "applications", "rds", "db", "AWS::RDS::DBInstance",
		"arn:{partition}:rds:{region}:{account}:db:{name}",
		"rds:DescribeDBInstances", "rds:DescribeDBInstances", "rds:CreateDBInstance", "rds:ModifyDBInstance", "rds:DeleteDBInstance")
	app.Variants = []Variant{
		{Name: "database-only", Replace: true, When: both(has("database"), not(has("image"))), Entry: db},
		{Name: "database", When: both(has("database"), has("image")), Entry: db},
	}
	app.Note = "an Application is an ECS service; its database block is an RDS DB instance (alone, when it runs no image)"
	fn := add(row(groupPlatform, "Function", "functions", "lambda", "function", "AWS::Lambda::Function",
		"arn:{partition}:lambda:{region}:{account}:function:{name}",
		"lambda:GetFunction", "lambda:ListFunctions", "lambda:CreateFunction", "lambda:UpdateFunctionConfiguration", "lambda:DeleteFunction"))
	fn.FieldActions = map[string]FieldRule{
		"image":               {Actions: []string{"lambda:UpdateFunctionCode"}},
		"code":                {Actions: []string{"lambda:UpdateFunctionCode"}},
		"reservedConcurrency": {Actions: []string{"lambda:PutFunctionConcurrency"}},
		"aliases":             {Actions: []string{"lambda:CreateAlias", "lambda:UpdateAlias", "lambda:DeleteAlias"}},
		"versions":            {Actions: []string{"lambda:PublishVersion", "lambda:DeleteFunction"}},
		"vpcConfig":           {Actions: []string{"lambda:UpdateFunctionConfiguration"}},
	}
	vm := add(ec2Row("VirtualMachine", "virtualmachines", "instance", "AWS::EC2::Instance",
		"ec2:DescribeInstances", "ec2:RunInstances", "ec2:ModifyInstanceAttribute", "ec2:TerminateInstances"))
	vm.FieldActions = map[string]FieldRule{
		"running":      {Actions: []string{"ec2:StartInstances", "ec2:StopInstances"}, ByValue: map[string][]string{"true": {"ec2:StartInstances"}, "false": {"ec2:StopInstances"}}},
		"elasticIp":    {Actions: []string{"ec2:AssociateAddress"}},
		"volumes":      {Actions: []string{"ec2:AttachVolume", "ec2:DetachVolume"}},
		"instanceRole": {Actions: []string{"ec2:AssociateIamInstanceProfile"}},
	}
	vm.PassRoleFields = []string{"instanceRole"}
	add(row(groupPlatform, "AutoScalingGroup", "autoscalinggroups", "autoscaling", "autoScalingGroup", "AWS::AutoScaling::AutoScalingGroup",
		"arn:{partition}:autoscaling:{region}:{account}:autoScalingGroup:{uuid}:autoScalingGroupName/{name}",
		"autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeAutoScalingGroups", "autoscaling:CreateAutoScalingGroup",
		"autoscaling:UpdateAutoScalingGroup", "autoscaling:DeleteAutoScalingGroup")).GlobalDescribe = true
	vmi := add(row(groupPlatform, "VmImage", "vmimages", "ec2", "image", "", "arn:{partition}:ec2:{region}::image/{name}",
		"ec2:DescribeImages", "ec2:DescribeImages", "ec2:ImportImage", "ec2:ModifyImageAttribute", "ec2:DeregisterImage"))
	vmi.GlobalDescribe = true
	vmi.Note = "an image (AMI) ARN carries no account, as AWS's"
	add(ec2Row("Volume", "volumes", "volume", "AWS::EC2::Volume", "ec2:DescribeVolumes", "ec2:CreateVolume", "ec2:ModifyVolume", "ec2:DeleteVolume"))
	sj := add(row(groupPlatform, "ScheduledJob", "scheduledjobs", "scheduler", "schedule", "AWS::Scheduler::Schedule",
		"arn:{partition}:scheduler:{region}:{account}:schedule/default/{name}",
		"scheduler:GetSchedule", "scheduler:ListSchedules", "scheduler:CreateSchedule", "scheduler:UpdateSchedule", "scheduler:DeleteSchedule"))
	sj.Note = "a ScheduledJob is an EventBridge Scheduler schedule (default group)"

	// ---- networking ----
	sg := add(ec2Row("SecurityGroup", "securitygroups", "security-group", "AWS::EC2::SecurityGroup",
		"ec2:DescribeSecurityGroups", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:DeleteSecurityGroup"))
	sg.FieldActions = map[string]FieldRule{
		"ingress": {Actions: []string{"ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"}},
		"egress":  {Actions: []string{"ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress"}},
		// A group's VPC is set when it is created (CreateSecurityGroup's VpcId), as on AWS.
		"vpc": {Actions: []string{"ec2:CreateSecurityGroup"}},
	}
	add(ec2Row("Vpc", "vpcs", "vpc", "AWS::EC2::VPC", "ec2:DescribeVpcs", "ec2:CreateVpc", "ec2:ModifyVpcAttribute", "ec2:DeleteVpc"))
	add(ec2Row("Subnet", "subnets", "subnet", "AWS::EC2::Subnet", "ec2:DescribeSubnets", "ec2:CreateSubnet", "ec2:ModifySubnetAttribute", "ec2:DeleteSubnet"))
	nat := add(ec2Row("NatGateway", "natgateways", "natgateway", "AWS::EC2::NatGateway", "ec2:DescribeNatGateways", "ec2:CreateNatGateway", "ec2:CreateNatGateway", "ec2:DeleteNatGateway"))
	nat.Note = "a NAT gateway can't be modified on AWS: a change replaces it (CreateNatGateway)"
	add(ec2Row("VpcEndpoint", "vpcendpoints", "vpc-endpoint", "AWS::EC2::VPCEndpoint", "ec2:DescribeVpcEndpoints", "ec2:CreateVpcEndpoint", "ec2:ModifyVpcEndpoint", "ec2:DeleteVpcEndpoints"))
	add(ec2Row("TransitGateway", "transitgateways", "transit-gateway", "AWS::EC2::TransitGateway", "ec2:DescribeTransitGateways", "ec2:CreateTransitGateway", "ec2:ModifyTransitGateway", "ec2:DeleteTransitGateway"))
	add(ec2Row("ElasticIp", "elasticips", "elastic-ip", "AWS::EC2::EIP", "ec2:DescribeAddresses", "ec2:AllocateAddress", "ec2:AssociateAddress", "ec2:ReleaseAddress"))
	fl := add(ec2Row("FlowLog", "flowlogs", "vpc-flow-log", "AWS::EC2::FlowLog", "ec2:DescribeFlowLogs", "ec2:CreateFlowLogs", "ec2:CreateFlowLogs", "ec2:DeleteFlowLogs"))
	fl.Note = "a flow log can't be modified on AWS: a change replaces it (CreateFlowLogs)"
	add(row(groupPlatform, "HttpApi", "httpapis", "apigateway", "apis", "AWS::ApiGatewayV2::Api",
		"arn:{partition}:apigateway:{region}::/apis/{name}",
		"apigateway:GET", "apigateway:GET", "apigateway:POST", "apigateway:PATCH", "apigateway:DELETE")).Note =
		"API Gateway's management actions are its HTTP verbs, and its ARNs carry no account, as on AWS"
	add(row(groupPlatform, "StaticSite", "staticsites", "cloudfront", "distribution", "AWS::CloudFront::Distribution",
		"arn:{partition}:cloudfront::{account}:distribution/{name}",
		"cloudfront:GetDistribution", "cloudfront:ListDistributions", "cloudfront:CreateDistribution",
		"cloudfront:UpdateDistribution", "cloudfront:DeleteDistribution"))

	// ---- storage and data ----
	b := add(row(groupPlatform, "Bucket", "buckets", "s3", "bucket", "AWS::S3::Bucket", "arn:{partition}:s3:::{name}",
		"s3:GetBucketLocation", "s3:ListAllMyBuckets", "s3:CreateBucket", "s3:PutBucketPolicy", "s3:DeleteBucket"))
	b.NameField = "bucketName"
	b.FieldActions = map[string]FieldRule{
		"versioning":     {Actions: []string{"s3:PutBucketVersioning"}},
		"lifecycleRules": {Actions: []string{"s3:PutLifecycleConfiguration"}},
		"objectLock":     {Actions: []string{"s3:PutBucketObjectLockConfiguration"}},
		"policy":         {Actions: []string{"s3:PutBucketPolicy"}},
		"tags":           {Actions: []string{"s3:PutBucketTagging"}},
	}
	b.Note = "an S3 bucket ARN carries no region or account; a change to a field S3 has no single action for takes s3:PutBucketPolicy, the broadest bucket-configuration right, so it never needs less"
	tb := add(row(groupPlatform, "Table", "tables", "dynamodb", "table", "AWS::DynamoDB::Table",
		"arn:{partition}:dynamodb:{region}:{account}:table/{name}",
		"dynamodb:DescribeTable", "dynamodb:ListTables", "dynamodb:CreateTable", "dynamodb:UpdateTable", "dynamodb:DeleteTable"))
	tb.NameField = "tableName"
	tb.FieldActions = map[string]FieldRule{"ttlAttribute": {Actions: []string{"dynamodb:UpdateTimeToLive"}}}
	q := add(row(groupPlatform, "Queue", "queues", "sqs", "queue", "AWS::SQS::Queue", "arn:{partition}:sqs:{region}:{account}:{name}",
		"sqs:GetQueueAttributes", "sqs:ListQueues", "sqs:CreateQueue", "sqs:SetQueueAttributes", "sqs:DeleteQueue"))
	q.NameField = "queueName"
	topic := row(groupPlatform, "Queue", "queues", "sns", "topic", "AWS::SNS::Topic", "arn:{partition}:sns:{region}:{account}:{name}",
		"sns:GetTopicAttributes", "sns:ListTopics", "sns:CreateTopic", "sns:SetTopicAttributes", "sns:DeleteTopic")
	topic.NameField = "queueName"
	q.Variants = []Variant{{Name: "fanout", Replace: true, When: has("fanout"), Entry: topic}}
	q.Note = "a Queue is an SQS queue; with fanout it is an SNS topic"
	add(row(groupPlatform, "Stream", "streams", "kinesis", "stream", "AWS::Kinesis::Stream",
		"arn:{partition}:kinesis:{region}:{account}:stream/{name}",
		"kinesis:DescribeStream", "kinesis:ListStreams", "kinesis:CreateStream", "kinesis:CreateStream", "kinesis:DeleteStream")).Note =
		"a Stream's source is fixed at creation: a change re-creates it (CreateStream)"
	add(row(groupPlatform, "FileShare", "fileshares", "elasticfilesystem", "file-system", "AWS::EFS::FileSystem",
		"arn:{partition}:elasticfilesystem:{region}:{account}:file-system/{name}",
		"elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeFileSystems", "elasticfilesystem:CreateFileSystem",
		"elasticfilesystem:UpdateFileSystem", "elasticfilesystem:DeleteFileSystem"))
	add(row(groupPlatform, "DatabaseProxy", "databaseproxies", "rds", "db-proxy", "AWS::RDS::DBProxy",
		"arn:{partition}:rds:{region}:{account}:db-proxy:{name}",
		"rds:DescribeDBProxies", "rds:DescribeDBProxies", "rds:CreateDBProxy", "rds:ModifyDBProxy", "rds:DeleteDBProxy"))
	add(row(groupPlatform, "Query", "queries", "athena", "workgroup", "",
		"arn:{partition}:athena:{region}:{account}:workgroup/primary",
		"athena:GetQueryExecution", "athena:ListQueryExecutions", "athena:StartQueryExecution",
		"athena:StartQueryExecution", "athena:StopQueryExecution")).Note =
		"a Query is an Athena query execution; Athena authorizes query actions on their workgroup (primary)"
	mig := add(row(groupPlatform, "Migration", "migrations", "dms", "task", "AWS::DMS::ReplicationTask",
		"arn:{partition}:dms:{region}:{account}:task:{name}",
		"dms:DescribeReplicationTasks", "dms:DescribeReplicationTasks", "dms:CreateReplicationTask",
		"dms:ModifyReplicationTask", "dms:DeleteReplicationTask"))
	mig.GlobalDescribe = true
	rep := add(row(groupPlatform, "Replication", "replications", "dms", "task", "AWS::DMS::ReplicationTask",
		"arn:{partition}:dms:{region}:{account}:task:{name}",
		"dms:DescribeReplicationTasks", "dms:DescribeReplicationTasks", "dms:CreateReplicationTask",
		"dms:ModifyReplicationTask", "dms:DeleteReplicationTask"))
	rep.GlobalDescribe = true
	rep.Note = "two-site replication is a continuous DMS replication task"
	add(native("DataFlow", "dataflows", "dataflow", "a cross-engine data flow graph has no single AWS analog"))
	add(native("DataClassification", "dataclassifications", "data-classification", "a data classification level has no AWS analog"))
	add(row(groupPlatform, "Parameter", "parameters", "ssm", "parameter", "AWS::SSM::Parameter",
		"arn:{partition}:ssm:{region}:{account}:parameter{name}",
		"ssm:GetParameter", "ssm:DescribeParameters", "ssm:PutParameter", "ssm:PutParameter", "ssm:DeleteParameter")).NameFormat =
		func(n string) string { return "/" + strings.TrimLeft(n, "/") }
	byKindFix(t, "Parameter").NameField = "path"
	add(row(groupPlatform, "BackupVault", "backupvaults", "backup", "backupVault", "AWS::Backup::BackupVault",
		"arn:{partition}:backup:{region}:{account}:backup-vault:{name}",
		"backup:DescribeBackupVault", "backup:ListBackupVaults", "backup:CreateBackupVault",
		"backup:PutBackupVaultAccessPolicy", "backup:DeleteBackupVault"))
	add(row(groupPlatform, "BackupPlan", "backupplans", "backup", "backupPlan", "AWS::Backup::BackupPlan",
		"arn:{partition}:backup:{region}:{account}:backup-plan:{name}",
		"backup:GetBackupPlan", "backup:ListBackupPlans", "backup:CreateBackupPlan", "backup:UpdateBackupPlan", "backup:DeleteBackupPlan"))

	// ---- security ----
	k := add(row(groupPlatform, "EncryptionKey", "encryptionkeys", "kms", "key", "AWS::KMS::Key",
		"arn:{partition}:kms:{region}:{account}:key/{name}",
		"kms:DescribeKey", "kms:ListKeys", "kms:CreateKey", "kms:UpdateKeyDescription", "kms:ScheduleKeyDeletion"))
	k.FieldActions = map[string]FieldRule{"rotationDays": {Actions: []string{"kms:EnableKeyRotation"}}}
	d := add(row(groupPlatform, "Destruction", "destructions", "kms", "key", "",
		"arn:{partition}:kms:{region}:{account}:key/{name}",
		"kms:DescribeKey", "kms:ListKeys", "kms:ScheduleKeyDeletion", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"))
	d.NameField = "encryptionKey"
	d.Note = "a Destruction is KMS ScheduleKeyDeletion on its key, and deleting it before its date is CancelKeyDeletion"
	add(row(groupPlatform, "CertificateAuthority", "certificateauthorities", "acm-pca", "certificate-authority", "AWS::ACMPCA::CertificateAuthority",
		"arn:{partition}:acm-pca:{region}:{account}:certificate-authority/{name}",
		"acm-pca:DescribeCertificateAuthority", "acm-pca:ListCertificateAuthorities", "acm-pca:CreateCertificateAuthority",
		"acm-pca:UpdateCertificateAuthority", "acm-pca:DeleteCertificateAuthority"))
	cr := add(row(groupPlatform, "ConfigRule", "configrules", "config", "ConfigRule", "AWS::Config::ConfigRule",
		"arn:{partition}:config:{region}:{account}:config-rule/{name}",
		"config:DescribeConfigRules", "config:DescribeConfigRules", "config:PutConfigRule", "config:PutConfigRule", "config:DeleteConfigRule"))
	cr.GlobalDescribe = true
	add(row(groupPlatform, "UserPool", "userpools", "cognito-idp", "userpool", "AWS::Cognito::UserPool",
		"arn:{partition}:cognito-idp:{region}:{account}:userpool/{name}",
		"cognito-idp:DescribeUserPool", "cognito-idp:ListUserPools", "cognito-idp:CreateUserPool",
		"cognito-idp:UpdateUserPool", "cognito-idp:DeleteUserPool"))
	dir := add(row(groupPlatform, "Directory", "directories", "ds", "directory", "AWS::DirectoryService::MicrosoftAD",
		"arn:{partition}:ds:{region}:{account}:directory/{name}",
		"ds:DescribeDirectories", "ds:DescribeDirectories", "ds:CreateMicrosoftAD", "ds:UpdateSettings", "ds:DeleteDirectory"))
	dir.GlobalDescribe = true
	add(row(groupPlatform, "FaultInjection", "faultinjections", "fis", "experiment", "AWS::FIS::ExperimentTemplate",
		"arn:{partition}:fis:{region}:{account}:experiment/{name}",
		"fis:GetExperiment", "fis:ListExperiments", "fis:StartExperiment", "fis:StartExperiment", "fis:StopExperiment")).Note =
		"a FaultInjection is a running FIS experiment: changing one starts it again, deleting it stops it"
	add(row(groupPlatform, "EmailSender", "emailsenders", "ses", "identity", "AWS::SES::EmailIdentity",
		"arn:{partition}:ses:{region}:{account}:identity/{name}",
		"ses:GetEmailIdentity", "ses:ListEmailIdentities", "ses:CreateEmailIdentity",
		"ses:PutEmailIdentityMailFromAttributes", "ses:DeleteEmailIdentity")).NameField = "fromAddress"

	// ---- application integration ----
	smx := add(row(groupPlatform, "StateMachine", "statemachines", "states", "stateMachine", "AWS::StepFunctions::StateMachine",
		"arn:{partition}:states:{region}:{account}:stateMachine:{name}",
		"states:DescribeStateMachine", "states:ListStateMachines", "states:CreateStateMachine",
		"states:UpdateStateMachine", "states:DeleteStateMachine"))
	smx.PassRoleFields = []string{"roleArn"}
	add(row(groupPlatform, "Execution", "executions", "states", "execution", "",
		"arn:{partition}:states:{region}:{account}:execution:{spec.stateMachineRef}:{name}",
		"states:DescribeExecution", "states:ListExecutions", "states:StartExecution", "states:StartExecution", "states:StopExecution")).Note =
		"an execution is immutable: changing one starts it again, deleting it stops it"
	gq := add(row(groupPlatform, "GraphQLApi", "graphqlapis", "appsync", "apis", "AWS::AppSync::GraphQLApi",
		"arn:{partition}:appsync:{region}:{account}:apis/{name}",
		"appsync:GetGraphqlApi", "appsync:ListGraphqlApis", "appsync:CreateGraphqlApi", "appsync:UpdateGraphqlApi", "appsync:DeleteGraphqlApi"))
	gq.FieldActions = map[string]FieldRule{
		"schema":      {Actions: []string{"appsync:StartSchemaCreation"}},
		"resolvers":   {Actions: []string{"appsync:UpdateResolver"}},
		"dataSources": {Actions: []string{"appsync:UpdateDataSource"}},
	}

	// ---- machine learning ----
	add(sagemakerResource("Model", "models", "endpoint", "AWS::SageMaker::Endpoint", "Endpoint")).Note = "a served Model is a SageMaker endpoint"
	add(sagemakerResource("ModelPackage", "modelpackages", "model-package", "AWS::SageMaker::ModelPackage", "ModelPackage"))
	add(sagemakerResource("ModelMonitor", "modelmonitors", "monitoring-schedule", "AWS::SageMaker::MonitoringSchedule", "MonitoringSchedule"))
	add(sagemakerResource("FeatureGroup", "featuregroups", "feature-group", "AWS::SageMaker::FeatureGroup", "FeatureGroup"))
	add(sagemakerJob("TrainingJob", "trainingjobs", "training-job", "TrainingJob"))
	add(sagemakerJob("ProcessingJob", "processingjobs", "processing-job", "ProcessingJob"))
	add(sagemakerJob("BatchTransform", "batchtransforms", "transform-job", "TransformJob"))
	add(sagemakerJob("TuningJob", "tuningjobs", "hyper-parameter-tuning-job", "HyperParameterTuningJob"))
	return t
}

func byKindFix(t []*Entry, kind string) *Entry {
	for _, e := range t {
		if e.Kind == kind {
			return e
		}
	}
	panic("awsaction: no row for " + kind)
}

var byKind, byResource = index(table())

func index(t []*Entry) (map[string]*Entry, map[string]*Entry) {
	k, r := map[string]*Entry{}, map[string]*Entry{}
	for _, e := range t {
		if _, dup := k[e.Kind]; dup {
			panic("awsaction: duplicate row for " + e.Kind)
		}
		k[e.Kind] = e
		r[e.Group+"/"+e.Resource] = e
	}
	return k, r
}
