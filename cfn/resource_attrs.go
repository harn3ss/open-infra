// Resource attributes after deploy (#347 item H): what Ref and Fn::GetAtt return for every translated type.
//
// A stack's Outputs — and the cross-stack exports Fn::ImportValue reads — are evaluated against the
// deployed stack (outputs.go). This table is what each type's Ref and documented Fn::GetAtt attributes
// resolve to there. The rule is AWS's documented shape wherever it carries meaning on open-infra:
//
//   - ARNs use the stack's AWS::Region / AWS::AccountId (the install's identity, cfn/awsidentity), so an
//     ARN a template builds with !Sub "arn:${AWS::Partition}:…:${AWS::AccountId}:…" is the same string the
//     Output reports, and the same one the aws-shim reports for the resource.
//   - A queue, topic, subscription, parameter, key or alias the shim's own SQS/SNS/SSM/KMS store serves
//     (service.go) resolves to exactly what that store holds — serviceRef / serviceAtt, the values the
//     translator created it under — before anything in this table.
//   - An id another stack passes back in (a VPC, a subnet, a security group) is the resource's open-infra
//     name: that is what the translators accept from a parameter or Fn::ImportValue (a raw vpc-/subnet-/sg-
//     id is opaque to them), so a network stack's exports are usable by the stacks that import them.
//   - A resource that provisions nothing of its own (an internet gateway, a route table, a CloudFront
//     policy) gets a stable synthetic id in the AWS shape (igw-…, rtb-…), derived from the stack and the
//     logical id, as an Elastic IP's AllocationId already was.
//
// A Ref or attribute missing from this table does not resolve on open-infra. Plan refuses an Output that
// uses one (CheckOutputReferences, nothing is created), and a create whose Output still cannot resolve
// fails rather than completing with the Output missing.
//
// Extension points: a type whose values belong to a service backend (a queue's URL, a key's id, a
// parameter's name) resolves through one small function per value — sqsQueueURL, kmsKeyID,
// ssmParameterName, … — so the backend that owns the value changes it in one place. A queue's or topic's
// name, URL and ARN are service.go's own (svcQueueName, svcQueueURL, …) whether or not the SQS/SNS store
// serves it, so a queue URL is always built on SQS_QUEUE_URL_BASE (Capabilities.SQSURLBase).
package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// attrEnv is what an attribute resolver reads about one in-stack resource.
type attrEnv struct {
	id    string
	typ   string
	res   *StackResource // the resource's own deployed entry (nil for a type that provisions nothing of its own)
	props map[string]any // its resolved properties
	sctx  *stackCtx
	d     *deployedAttrs // live status reads; nil when only static values are wanted
}

func (e *attrEnv) pseudo(name, def string) string {
	if e.sctx != nil && e.sctx.resolver != nil {
		if v, ok := e.sctx.resolver.pseudo[name].(string); ok && v != "" {
			return v
		}
	}
	return def
}

// The pseudo-parameters come from the install's identity (pseudoParams); the same identity is the
// fallback for an env with no resolver.
func (e *attrEnv) region() string { return e.pseudo("AWS::Region", awsidentity.Current().Region) }
func (e *attrEnv) account() string {
	return e.pseudo("AWS::AccountId", awsidentity.Current().AccountID)
}
func (e *attrEnv) urlSuffix() string { return e.pseudo("AWS::URLSuffix", awsidentity.URLSuffix) }
func (e *attrEnv) stack() string     { return e.pseudo("AWS::StackName", "") }

// ident is the identity the stack's ARNs carry: its AWS::AccountId and AWS::Region.
func (e *attrEnv) ident() awsidentity.Identity {
	return awsidentity.Identity{AccountID: e.account(), Region: e.region()}
}

// name is the resource's open-infra name: the deployed object's, else the name the stack gives it.
func (e *attrEnv) name() string {
	if e.res != nil && e.res.Name != "" {
		return e.res.Name
	}
	if e.sctx != nil {
		return e.sctx.name(e.id)
	}
	return e.id
}

// prop is a resolved property as a concrete string ("" when unset or not concrete).
func (e *attrEnv) prop(k string) string {
	v, _ := concrete(e.props[k])
	return v
}

// awsName is the resource's AWS-visible name: its name property when set (QueueName, BucketName, …),
// else its open-infra name.
func (e *attrEnv) awsName(prop string) string {
	if v := e.prop(prop); v != "" {
		return v
	}
	return e.name()
}

// arn is a regional ARN in the stack's account and region; globalARN one of a global service (IAM).
func (e *attrEnv) arn(service, resource string) string {
	return e.ident().RegionalARN(service, resource)
}

func (e *attrEnv) globalARN(service, resource string) string {
	return e.ident().ARN(service, "", resource)
}

// synthID is a stable id in AWS's shape for a resource that provisions nothing of its own: prefix + n hex
// digits derived from the stack and the logical id (as an Elastic IP's AllocationId).
func (e *attrEnv) synthID(prefix string, n int) string {
	sum := sha256.Sum256([]byte(e.stack() + "/" + e.id + "/" + prefix))
	return prefix + hex.EncodeToString(sum[:])[:n]
}

// az is the availability zone a resource names, or the region's first zone (Fn::GetAZs's first entry).
func (e *attrEnv) az() string {
	if v := e.prop("AvailabilityZone"); v != "" {
		return v
	}
	return e.region() + "a"
}

// status reads a field of the deployed resource's live status (pending while unset).
func (e *attrEnv) status(field, what string) (string, bool) {
	if e.d == nil {
		return "", false
	}
	v, ok := e.d.statusString(e.id, field, what)
	s, _ := v.(string)
	return s, ok
}

type attrFunc func(e *attrEnv) (string, bool)

// typeAttrs is one type's Ref and documented attributes.
type typeAttrs struct {
	ref   attrFunc
	attrs map[string]attrFunc
}

func static(f func(e *attrEnv) string) attrFunc {
	return func(e *attrEnv) (string, bool) { v := f(e); return v, v != "" }
}

func nameAttr(e *attrEnv) string { return e.name() }

// ---- extension points: values a service backend owns ----

// sqsQueueName is a queue's name: QueueName when set, else the stack's name for it (svcQueueName — the
// name an imported IAM policy scopes the queue's ARN to, inStackARN).
func sqsQueueName(e *attrEnv) string {
	if e.sctx == nil {
		return e.awsName("QueueName")
	}
	return svcQueueName(e.id, e.sctx)
}

// sqsQueueURL is a queue's URL, <SQS_QUEUE_URL_BASE>/<account>/<name> (svcQueueURL; AWS's URL shape when
// the deploying environment names no base, as the CLI does).
func sqsQueueURL(e *attrEnv) string {
	if e.sctx == nil {
		return "https://sqs." + e.region() + "." + e.urlSuffix() + "/" + e.account() + "/" + sqsQueueName(e)
	}
	return svcQueueURL(sqsQueueName(e), e.sctx)
}

// snsTopicName is a topic's name: TopicName when set, else the stack's name for it (svcTopicName).
func snsTopicName(e *attrEnv) string {
	if e.sctx == nil {
		return e.awsName("TopicName")
	}
	return svcTopicName(e.id, e.sctx)
}

// ssmParameterName is a parameter's name where the SSM store does not serve it (a kind: Parameter): Name
// when set, else its open-infra name. A served one resolves through serviceRef (svcParamName).
func ssmParameterName(e *attrEnv) string { return e.awsName("Name") }

// kmsKeyID is a key's id where the KMS store does not serve it: its open-infra EncryptionKey name. A
// served one resolves through serviceRef (svcKMSKeyID — the id the KMS store holds it under).
func kmsKeyID(e *attrEnv) string { return e.name() }

// dynamoTableName is a table's DynamoDB name.
func dynamoTableName(e *attrEnv) string { return e.awsName("TableName") }

// attrFunctionName is a Lambda function's name (FunctionName when set, else the stack's name for it).
func attrFunctionName(e *attrEnv) string {
	if e.sctx != nil {
		return e.sctx.functionName(e.id)
	}
	return e.awsName("FunctionName")
}

// svcStaticAttr is a front-door-served resource's Ref (attr "") or attribute: the name or ARN the stack
// created it under (serviceStatic, translate_service.go) — a secret's ARN, a log group's, rule's, bus's,
// repository's or alarm's name and ARN, a repository's URI.
func svcStaticAttr(attr string) attrFunc {
	return func(e *attrEnv) (string, bool) {
		if e.sctx == nil {
			return "", false
		}
		return serviceStatic(e.id, attr, e.sctx)
	}
}

// bucketName is an S3 bucket's name.
func s3BucketName(e *attrEnv) string { return e.awsName("BucketName") }

// iamPath is an IAM resource's Path ("/" by default), with a trailing slash.
func iamPath(e *attrEnv) string {
	p := e.prop("Path")
	if p == "" {
		return "/"
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// iamID is an IAM unique id in AWS's shape (AROA… for a role, AIDA… for a user, AGPA… for a group,
// ANPA… for a policy): prefix + 17 upper-case base-32-ish characters derived from the resource.
func iamID(e *attrEnv, prefix string) string {
	return prefix + strings.ToUpper(e.synthID("", 17))
}

// dbEndpoint is an AWS::RDS::DBInstance's endpoint: the in-cluster Service its kind: Application database
// is served on, per engine.
func dbEndpoint(e *attrEnv) (host, port string) {
	engine := ""
	if e.res != nil {
		if db, ok := e.res.Spec["database"].(map[string]any); ok {
			engine, _ = db["engine"].(string)
		}
	}
	ns := ""
	if e.d != nil {
		ns = e.d.namespace
	}
	n := e.name()
	switch engine {
	case "mysql", "mariadb":
		host, port = n+"-mysql", "3306"
	case "sqlserver":
		host, port = n+"-sqlserver", "1433"
	case "babelfish":
		host, port = n+"-babelfish", "1433"
	default: // postgres (CloudNativePG's read-write Service)
		host, port = n+"-db-rw", "5432"
	}
	if p := e.prop("Port"); p != "" {
		port = p
	}
	if ns != "" {
		host += "." + ns + ".svc.cluster.local"
	}
	return host, port
}

// resourceAttrs is every type's Ref and documented attributes on open-infra.
var resourceAttrs = map[string]typeAttrs{
	// --- storage ---
	"AWS::S3::Bucket": {ref: static(s3BucketName), attrs: map[string]attrFunc{
		"Arn":                 static(func(e *attrEnv) string { return awsidentity.S3BucketARN(s3BucketName(e)) }),
		"DomainName":          static(func(e *attrEnv) string { return s3BucketName(e) + ".s3." + e.urlSuffix() }),
		"RegionalDomainName":  static(func(e *attrEnv) string { return s3BucketName(e) + ".s3." + e.region() + "." + e.urlSuffix() }),
		"DualStackDomainName": static(func(e *attrEnv) string { return s3BucketName(e) + ".s3.dualstack." + e.region() + "." + e.urlSuffix() }),
		"WebsiteURL": static(func(e *attrEnv) string {
			return "http://" + s3BucketName(e) + ".s3-website-" + e.region() + "." + e.urlSuffix()
		}),
	}},
	"AWS::S3::BucketPolicy": {ref: static(nameAttr)},
	"AWS::EC2::Volume":      {ref: static(nameAttr), attrs: map[string]attrFunc{"VolumeId": static(nameAttr)}},
	"AWS::EFS::FileSystem": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"FileSystemId": static(nameAttr),
		"Arn":          static(func(e *attrEnv) string { return e.arn("elasticfilesystem", "file-system/"+e.name()) }),
	}},
	"AWS::DynamoDB::Table": {ref: static(dynamoTableName), attrs: map[string]attrFunc{
		"Arn": static(func(e *attrEnv) string { return e.arn("dynamodb", "table/"+dynamoTableName(e)) }),
		"StreamArn": func(e *attrEnv) (string, bool) {
			if _, ok := e.props["StreamSpecification"].(map[string]any); !ok {
				return "", false // AWS: only a table with a stream has one
			}
			t := dynamoTableName(e)
			return e.arn("dynamodb", "table/"+t+"/stream/"+t), true
		},
	}},

	// --- messaging (served by the SQS/SNS store: serviceRef/serviceAtt first, resolveResourceAttr) ---
	"AWS::SQS::Queue": {ref: static(sqsQueueURL), attrs: map[string]attrFunc{
		"Arn":       static(func(e *attrEnv) string { return e.arn("sqs", sqsQueueName(e)) }),
		"QueueName": static(sqsQueueName),
		"QueueUrl":  static(sqsQueueURL),
	}},
	"AWS::SNS::Topic": {ref: static(func(e *attrEnv) string { return e.arn("sns", snsTopicName(e)) }), attrs: map[string]attrFunc{
		"TopicArn":  static(func(e *attrEnv) string { return e.arn("sns", snsTopicName(e)) }),
		"TopicName": static(snsTopicName),
	}},
	// A queue or topic policy exists only in the SQS/SNS store (its translator refuses without it); Ref is
	// its id.
	"AWS::SQS::QueuePolicy": {ref: static(func(e *attrEnv) string { return svcPolicyID(e.id, e.sctx) })},
	"AWS::SNS::TopicPolicy": {ref: static(func(e *attrEnv) string { return svcPolicyID(e.id, e.sctx) })},
	"AWS::SNS::Subscription": {ref: static(func(e *attrEnv) string {
		return e.arn("sns", e.name()+":"+e.synthID("", 32))
	})},

	// --- served through their own front doors (translate_service.go): what the stack created them under ---
	"AWS::SecretsManager::Secret": {ref: svcStaticAttr(""), attrs: map[string]attrFunc{"Id": svcStaticAttr("Id")}},
	"AWS::Logs::LogGroup":         {ref: svcStaticAttr(""), attrs: map[string]attrFunc{"Arn": svcStaticAttr("Arn")}},
	"AWS::Events::Rule":           {ref: svcStaticAttr(""), attrs: map[string]attrFunc{"Arn": svcStaticAttr("Arn")}},
	"AWS::Events::EventBus": {ref: svcStaticAttr(""), attrs: map[string]attrFunc{
		"Arn": svcStaticAttr("Arn"), "Name": svcStaticAttr("Name"),
	}},
	"AWS::ECR::Repository": {ref: svcStaticAttr(""), attrs: map[string]attrFunc{
		"Arn": svcStaticAttr("Arn"), "RepositoryUri": svcStaticAttr("RepositoryUri"),
	}},
	"AWS::CloudWatch::Alarm": {ref: svcStaticAttr(""), attrs: map[string]attrFunc{"Arn": svcStaticAttr("Arn")}},

	// --- config and keys ---
	"AWS::SSM::Parameter": {ref: static(ssmParameterName), attrs: map[string]attrFunc{
		"Type":  static(func(e *attrEnv) string { return e.prop("Type") }),
		"Value": static(func(e *attrEnv) string { return e.prop("Value") }),
	}},
	"AWS::KMS::Key": {ref: static(kmsKeyID), attrs: map[string]attrFunc{
		"KeyId": static(kmsKeyID),
		"Arn":   static(func(e *attrEnv) string { return e.arn("kms", "key/"+kmsKeyID(e)) }),
	}},
	// An alias exists only in the KMS store (translateKMSAlias refuses without it); Ref is its name.
	"AWS::KMS::Alias": {ref: static(func(e *attrEnv) string { return e.prop("AliasName") })},

	// --- compute ---
	"AWS::Lambda::Function": {ref: static(attrFunctionName), attrs: map[string]attrFunc{
		"Arn": static(func(e *attrEnv) string { return e.arn("lambda", "function:"+attrFunctionName(e)) }),
	}},
	"AWS::StepFunctions::StateMachine": {ref: static(func(e *attrEnv) string { return e.arn("states", "stateMachine:"+e.awsName("StateMachineName")) }), attrs: map[string]attrFunc{
		"Arn":  static(func(e *attrEnv) string { return e.arn("states", "stateMachine:"+e.awsName("StateMachineName")) }),
		"Name": static(func(e *attrEnv) string { return e.awsName("StateMachineName") }),
	}},
	"AWS::EC2::Instance": {ref: instanceID, attrs: map[string]attrFunc{
		"InstanceId":       instanceID,
		"AvailabilityZone": static(func(e *attrEnv) string { return e.az() }),
		"PublicIp": func(e *attrEnv) (string, bool) {
			if e.d == nil {
				return "", false
			}
			v, ok := e.d.vmLanIP(e.id)
			s, _ := v.(string)
			return s, ok
		},
		"PrivateIp": func(e *attrEnv) (string, bool) { return e.status("ip", "VM "+e.name()+"'s private IP") },
		// AWS's private DNS name for that address (ip-a-b-c-d.ec2.internal in us-east-1).
		"PrivateDnsName": func(e *attrEnv) (string, bool) {
			ip, ok := e.status("ip", "VM "+e.name()+"'s private IP")
			if !ok {
				return "", false
			}
			return awsidentity.PrivateDNSName(ip, e.region()), true
		},
		// The public DNS name of the VM's LAN IP on the install's public DNS suffix; "" for an instance with
		// no public address, or on an install with no suffix, as AWS reports it then.
		"PublicDnsName": instancePublicDNSName,
	}},
	"AWS::ECS::Cluster": {ref: static(func(e *attrEnv) string { return e.awsName("ClusterName") }), attrs: map[string]attrFunc{
		"Arn": static(func(e *attrEnv) string { return e.arn("ecs", "cluster/"+e.awsName("ClusterName")) }),
	}},
	"AWS::ECS::Service": {ref: static(func(e *attrEnv) string { return ecsServiceARN(e) }), attrs: map[string]attrFunc{
		"Name":       static(func(e *attrEnv) string { return e.awsName("ServiceName") }),
		"ServiceArn": static(ecsServiceARN),
	}},
	"AWS::ECS::TaskDefinition": {ref: static(ecsTaskDefinitionARN), attrs: map[string]attrFunc{
		"TaskDefinitionArn": static(ecsTaskDefinitionARN),
	}},
	"AWS::RDS::DBInstance": {ref: static(func(e *attrEnv) string { return e.awsName("DBInstanceIdentifier") }), attrs: map[string]attrFunc{
		"Endpoint.Address": static(func(e *attrEnv) string { h, _ := dbEndpoint(e); return h }),
		"Endpoint.Port":    static(func(e *attrEnv) string { _, p := dbEndpoint(e); return p }),
		"DBInstanceArn":    static(func(e *attrEnv) string { return e.arn("rds", "db:"+e.awsName("DBInstanceIdentifier")) }),
	}},

	// --- identity ---
	"AWS::IAM::Role": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"Arn":    static(func(e *attrEnv) string { return e.globalARN("iam", "role"+iamPath(e)+e.name()) }),
		"RoleId": static(func(e *attrEnv) string { return iamID(e, "AROA") }),
	}},
	"AWS::IAM::User": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"Arn": static(func(e *attrEnv) string { return e.globalARN("iam", "user"+iamPath(e)+e.name()) }),
	}},
	"AWS::IAM::Group": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"Arn": static(func(e *attrEnv) string { return e.globalARN("iam", "group"+iamPath(e)+e.name()) }),
	}},
	"AWS::IAM::ManagedPolicy": {ref: static(func(e *attrEnv) string { return e.globalARN("iam", "policy"+iamPath(e)+e.name()) }), attrs: map[string]attrFunc{
		"PolicyArn": static(func(e *attrEnv) string { return e.globalARN("iam", "policy"+iamPath(e)+e.name()) }),
		"PolicyId":  static(func(e *attrEnv) string { return iamID(e, "ANPA") }),
	}},
	"AWS::IAM::Policy": {ref: static(nameAttr), attrs: map[string]attrFunc{"Id": static(nameAttr)}},
	"AWS::IAM::InstanceProfile": {ref: static(func(e *attrEnv) string { return e.awsName("InstanceProfileName") }), attrs: map[string]attrFunc{
		"Arn": static(func(e *attrEnv) string {
			return e.globalARN("iam", "instance-profile"+iamPath(e)+e.awsName("InstanceProfileName"))
		}),
	}},
	"AWS::Cognito::UserPool": {ref: static(cognitoPoolID), attrs: map[string]attrFunc{
		"UserPoolId": static(cognitoPoolID),
		"Arn":        static(func(e *attrEnv) string { return e.arn("cognito-idp", "userpool/"+cognitoPoolID(e)) }),
		"ProviderName": static(func(e *attrEnv) string {
			return "cognito-idp." + e.region() + "." + e.urlSuffix() + "/" + cognitoPoolID(e)
		}),
		"ProviderURL": func(e *attrEnv) (string, bool) {
			return e.status("issuer", "user pool "+e.name()+"'s issuer URL")
		},
	}},

	// --- networking ---
	"AWS::EC2::VPC": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"VpcId":     static(nameAttr),
		"CidrBlock": static(func(e *attrEnv) string { return e.prop("CidrBlock") }),
	}},
	"AWS::EC2::Subnet": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"SubnetId":         static(nameAttr),
		"VpcId":            static(func(e *attrEnv) string { return e.prop("VpcId") }),
		"CidrBlock":        static(func(e *attrEnv) string { return e.prop("CidrBlock") }),
		"AvailabilityZone": static(func(e *attrEnv) string { return e.az() }),
	}},
	"AWS::EC2::SecurityGroup": {ref: static(nameAttr), attrs: map[string]attrFunc{
		"GroupId": static(nameAttr),
		"VpcId":   static(func(e *attrEnv) string { return e.prop("VpcId") }),
	}},
	"AWS::EC2::SecurityGroupIngress": {ref: static(func(e *attrEnv) string { return e.synthID("sgr-", 17) }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return e.synthID("sgr-", 17) }),
	}},
	"AWS::EC2::SecurityGroupEgress": {ref: static(func(e *attrEnv) string { return e.synthID("sgr-", 17) }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return e.synthID("sgr-", 17) }),
	}},
	"AWS::EC2::InternetGateway": {ref: static(func(e *attrEnv) string { return e.synthID("igw-", 17) }), attrs: map[string]attrFunc{
		"InternetGatewayId": static(func(e *attrEnv) string { return e.synthID("igw-", 17) }),
	}},
	"AWS::EC2::VPCGatewayAttachment": {ref: static(func(e *attrEnv) string { return e.synthID("IGW|", 12) })},
	"AWS::EC2::RouteTable": {ref: static(func(e *attrEnv) string { return e.synthID("rtb-", 17) }), attrs: map[string]attrFunc{
		"RouteTableId": static(func(e *attrEnv) string { return e.synthID("rtb-", 17) }),
	}},
	"AWS::EC2::Route": {ref: static(func(e *attrEnv) string { return e.synthID("rtb-", 17) + "|" + e.prop("DestinationCidrBlock") })},
	"AWS::EC2::SubnetRouteTableAssociation": {ref: static(func(e *attrEnv) string { return e.synthID("rtbassoc-", 17) }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return e.synthID("rtbassoc-", 17) }),
	}},
	"AWS::EC2::NetworkAcl": {ref: static(func(e *attrEnv) string { return e.synthID("acl-", 17) }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return e.synthID("acl-", 17) }),
	}},
	"AWS::EC2::NetworkAclEntry": {ref: static(func(e *attrEnv) string { return e.synthID("acl-", 17) + "|" + e.prop("RuleNumber") })},
	"AWS::EC2::NatGateway":      {ref: static(nameAttr), attrs: map[string]attrFunc{"NatGatewayId": static(nameAttr)}},
	"AWS::EC2::EIP": {ref: eipPublicIP, attrs: map[string]attrFunc{
		"PublicIp":     eipPublicIP,
		"AllocationId": static(func(e *attrEnv) string { return eipAllocationID(e.stack(), e.id) }),
	}},
	"AWS::EC2::EIPAssociation": {ref: static(func(e *attrEnv) string { return e.synthID("eipassoc-", 17) }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return e.synthID("eipassoc-", 17) }),
	}},
	"AWS::EC2::VPCEndpoint": {ref: static(nameAttr), attrs: map[string]attrFunc{"Id": static(nameAttr)}},
	"AWS::EC2::VPCPeeringConnection": {ref: static(func(e *attrEnv) string { return e.synthID("pcx-", 17) }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return e.synthID("pcx-", 17) }),
	}},
	"AWS::EC2::TransitGateway":           {ref: static(nameAttr), attrs: map[string]attrFunc{"Id": static(nameAttr)}},
	"AWS::EC2::TransitGatewayAttachment": {ref: static(nameAttr), attrs: map[string]attrFunc{"Id": static(nameAttr)}},
	"AWS::EC2::FlowLog":                  {ref: static(nameAttr), attrs: map[string]attrFunc{"Id": static(nameAttr)}},

	// --- edge ---
	"AWS::CloudFront::Distribution": {ref: static(func(e *attrEnv) string { return cloudFrontID(e, "E") }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return cloudFrontID(e, "E") }),
		"DomainName": func(e *attrEnv) (string, bool) {
			if e.sctx == nil || e.sctx.resolver == nil {
				return "", false
			}
			return e.sctx.resolver.cloudFrontGetAtt(e.id, "DomainName")
		},
	}},
	"AWS::CloudFront::OriginAccessControl": {ref: static(func(e *attrEnv) string { return cloudFrontID(e, "E") }), attrs: map[string]attrFunc{
		"Id": static(func(e *attrEnv) string { return cloudFrontID(e, "E") }),
	}},
	"AWS::CloudFront::CloudFrontOriginAccessIdentity": {ref: static(func(e *attrEnv) string { return cloudFrontID(e, "E") }), attrs: map[string]attrFunc{
		"Id":                static(func(e *attrEnv) string { return cloudFrontID(e, "E") }),
		"S3CanonicalUserId": static(func(e *attrEnv) string { return e.synthID("", 64) }),
	}},
	"AWS::CloudFront::CachePolicy":           {ref: static(cloudFrontPolicyID), attrs: map[string]attrFunc{"Id": static(cloudFrontPolicyID)}},
	"AWS::CloudFront::OriginRequestPolicy":   {ref: static(cloudFrontPolicyID), attrs: map[string]attrFunc{"Id": static(cloudFrontPolicyID)}},
	"AWS::CloudFront::ResponseHeadersPolicy": {ref: static(cloudFrontPolicyID), attrs: map[string]attrFunc{"Id": static(cloudFrontPolicyID)}},
	"AWS::CertificateManager::Certificate": {ref: static(func(e *attrEnv) string {
		return e.arn("acm", "certificate/"+uuidShape(e.synthID("", 32)))
	})},

	// --- a nested stack: its Ref is the child stack's StackId (its Outputs resolve through Fn::GetAtt) ---
	StackTypeName: {ref: func(e *attrEnv) (string, bool) {
		if e.res != nil && e.res.PhysicalID != "" {
			return e.res.PhysicalID, true
		}
		return "", false
	}},

	// --- API Gateway (REST v1): the API's id is the one the apigateway store assigned ---
	"AWS::ApiGateway::RestApi": {ref: func(e *attrEnv) (string, bool) {
		if e.res != nil && e.res.ProvisionedID != "" {
			return e.res.ProvisionedID, true
		}
		return "", false
	}},
	"AWS::ApiGateway::Stage": {ref: static(func(e *attrEnv) string { return e.prop("StageName") })},

	// --- signals (signals.go) ---
	waitConditionHandleType: {ref: static(func(e *attrEnv) string {
		var f func(string, string) string
		if e.sctx != nil {
			f = e.sctx.signalURL
		}
		return handleURL(f, e.stack(), e.id)
	})},
	waitConditionType: {ref: static(nameAttr), attrs: map[string]attrFunc{
		"Data": func(e *attrEnv) (string, bool) {
			if e.res == nil || e.res.SignalData == "" {
				return "", false
			}
			return e.res.SignalData, true
		},
	}},
}

// instanceID is an instance's Ref and InstanceId: its VM's status.instanceId, the i- id the guest's
// instance metadata reports and the aws-shim's EC2 and SSM APIs take. The VM's composite sets it when it is
// first rendered (and the aws-shim's status reader derives it for a VM rendered before that), so it waits
// like any status attribute until the VM exists. A deploy path that cannot read live status (the CLI)
// gets the VM's name, as it always has.
func instanceID(e *attrEnv) (string, bool) {
	if e.d == nil || e.d.sr == nil {
		return e.name(), true
	}
	return e.status("instanceId", "instance "+e.name()+"'s instance id")
}

// eipPublicIP is an Elastic IP's address: its instance VM's LAN IP.
// instancePublicDNSName is an instance's PublicDnsName: ec2-<lan ip>.<PublicDNSSuffix> once its VM has a
// LAN IP; "" when the VM is not exposed (it has no public address) or the install sets no suffix.
func instancePublicDNSName(e *attrEnv) (string, bool) {
	if e.d == nil {
		return "", false
	}
	if sr, ok := e.d.byID[e.id]; ok && sr.Kind == "VirtualMachine" {
		expose, _ := sr.Spec["expose"].(bool)
		ports, _ := sr.Spec["ports"].([]any)
		if !expose && len(ports) == 0 {
			return "", true // no public address, so no public DNS name
		}
	}
	id := awsidentity.Current()
	if id.PublicDNSSuffix == "" {
		return "", true
	}
	v, ok := e.d.vmLanIP(e.id)
	ip, _ := v.(string)
	if !ok {
		return "", false
	}
	return id.PublicDNSName(ip), true
}

func eipPublicIP(e *attrEnv) (string, bool) {
	if e.d == nil {
		return "", false
	}
	v, ok := e.d.eipAddress(e.id)
	s, _ := v.(string)
	return s, ok
}

func ecsServiceARN(e *attrEnv) string {
	cluster := e.prop("Cluster")
	if cluster == "" {
		cluster = "default"
	}
	return e.arn("ecs", "service/"+cluster+"/"+e.awsName("ServiceName"))
}

func ecsTaskDefinitionARN(e *attrEnv) string {
	return e.arn("ecs", "task-definition/"+e.awsName("Family")+":1")
}

func cognitoPoolID(e *attrEnv) string { return e.region() + "_" + e.synthID("", 9) }

// cloudFrontID is a CloudFront id in its shape: E + 13 upper-case characters.
func cloudFrontID(e *attrEnv, prefix string) string {
	return prefix + strings.ToUpper(e.synthID("", 13))
}

// cloudFrontPolicyID is a CloudFront policy id: a UUID.
func cloudFrontPolicyID(e *attrEnv) string { return uuidShape(e.synthID("", 32)) }

// uuidShape formats 32 hex digits as a UUID.
func uuidShape(h string) string {
	if len(h) < 32 {
		return h
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// attrKnown reports whether typ's attr (attr "" = Ref) resolves on open-infra after deploy.
func attrKnown(typ, attr string) bool {
	if isCustomResourceType(typ) {
		return true // a custom resource's attributes are whatever its handler returns
	}
	if typ == StackTypeName {
		// A nested stack's Ref is its StackId; its attributes are its Outputs (nested_stacks.go).
		return attr == "" || strings.HasPrefix(attr, "Outputs.")
	}
	ta, ok := resourceAttrs[typ]
	if !ok {
		return false
	}
	if attr == "" {
		return ta.ref != nil
	}
	_, ok = ta.attrs[attr]
	return ok
}

// AttrNames lists the attributes typ documents on open-infra (Ref excluded), sorted.
func AttrNames(typ string) []string {
	out := make([]string, 0, len(resourceAttrs[typ].attrs))
	for k := range resourceAttrs[typ].attrs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveResourceAttr resolves one in-stack resource's Ref (attr "") or attribute. A resource the shim's
// own SQS/SNS/SSM/KMS store serves resolves to what that store holds (service.go); a documented attribute
// the store does not answer for falls through to the table.
func resolveResourceAttr(e *attrEnv, attr string) (string, bool) {
	if e.sctx.servedBy(e.id) {
		var v string
		var ok bool
		if attr == "" {
			v, ok = serviceRef(e.id, e.sctx)
		} else {
			v, ok = serviceAtt(e.id, attr, e.sctx)
		}
		if ok {
			return v, true
		}
	}
	ta, ok := resourceAttrs[e.typ]
	if !ok {
		return "", false
	}
	f := ta.ref
	if attr != "" {
		f = ta.attrs[attr]
	}
	if f == nil {
		return "", false
	}
	return f(e)
}
