// The CloudFormation resource-type -> open-infra kind mapping table.
//
// This table is the ENGINE'S PUBLIC CONTRACT and the honesty rail: the engine can only
// provision a resource type listed here as `supported` (or, with caveats, `partial`).
// Anything not in this table — or listed `unsupported`/`gated` — is refused. The default
// for an unknown type is `unsupported`. There is deliberately no catch-all that maps an
// unrecognized type to "something close"; a type we cannot fully model must fail loud.
//
// Statuses:
//
//	supported   — a backing kind exists and the mapping is faithful.
//	partial     — a backing kind exists but the mapping is lossy (some properties don't
//	              translate, or it is provisioned as part of another kind); the caveat is
//	              surfaced loudly and the type is NOT claimed as full CFN compatibility.
//	gated       — a backing kind is not yet available (blocked on another issue); refused.
//	unsupported — no backing kind, or explicitly out of scope for v1; refused.
package main

import "strings"

type Status string

const (
	Supported   Status = "supported"
	Partial     Status = "partial"
	Gated       Status = "gated"
	Unsupported Status = "unsupported"
)

type MapEntry struct {
	Kind   string // the open-infra kind (or the primitive), empty when unsupported
	Status Status
	Note   string
}

// mappingTable is the seed. Grow it deliberately, the gated way every capability graduates
// here — a type is added only once it has a backing kind and a faithful mapping.
var mappingTable = map[string]MapEntry{
	// --- supported: a faithful backing kind ---
	"AWS::Lambda::Function":            {Kind: "Function", Status: Supported, Note: "scale-to-zero Function"},
	"AWS::StepFunctions::StateMachine": {Kind: "StateMachine", Status: Supported, Note: "Amazon States Language engine"},
	"AWS::AppSync::GraphQLApi":         {Kind: "GraphQLApi", Status: Supported, Note: "resolver-first GraphQL"},
	"AWS::IAM::Role":                   {Kind: "Role", Status: Partial, Note: "kind: Role is now a first-class assumable identity (a trust policy + attached data-plane Policies; sts:AssumeRole issues temporary session credentials on the aws-shim — #111). But there is no CFN CREATE translator yet: an inline role policy document (service:Action + conditions) still has no faithful automatic form, and the trust policy must be authored natively. Plan-recognized, not create-deployable (Deployable=false)."},
	"AWS::IAM::ManagedPolicy":          {Kind: "Policy", Status: Supported, Note: "like IAM::Policy: a create translator imports the DATA-PLANE part into an enforced kind: Policy spec.dataPlane when the ManagedPolicy carries inline Groups/Users/Roles attachments (a Roles attachment governs the assumed sts:AssumeRole session, #111); a standalone ManagedPolicy (attached via ManagedPolicyArns) has no principal here and BLOCKS, as does any control-plane/unmappable/conditioned part"},
	"AWS::IAM::Policy":                 {Kind: "Policy", Status: Supported, Note: "inline policy -> a Policy; a create translator imports the DATA-PLANE part (s3/dynamodb/lambda actions on recognizable ARNs, no conditions) into an enforced kind: Policy spec.dataPlane, and BLOCKS anything it can't honor faithfully (control-plane/unmappable/conditioned parts) — narrow the policy or author it natively"},
	"AWS::IAM::User":                   {Kind: "User", Status: Supported},
	"AWS::IAM::Group":                  {Kind: "Group", Status: Partial, Note: "maps at plan, but no create translator (Deployable=false): a Group's permissions are its attached AWS policies (unmappable automatically), and its required clusterRole can't be derived from them — author the Group + its policy attachment natively"},
	"AWS::KMS::Key":                    {Kind: "EncryptionKey", Status: Supported, Note: "customer key in Vault Transit"},

	// --- partial: backing kind exists but the mapping is lossy ---
	"AWS::S3::Bucket":                       {Kind: "Bucket", Status: Partial, Note: "a standalone MinIO bucket (kind: Bucket) with versioning + lifecycle; Object Lock (WORM retention) maps to a MinIO lock-enabled bucket; an in-stack AWS::S3::BucketPolicy collates in as spec.policy (public \"*\" principals only — AWS-IAM-ARN principals refuse); BucketEncryption needs the opt-in objectEncryption stack; CorsConfiguration is a MinIO ceiling (MinIO does CORS globally via MINIO_API_CORS_ALLOW_ORIGIN, not per bucket — PutBucketCors returns MalformedXML) and refuses loudly; website/replication do not map"},
	"AWS::S3::BucketPolicy":                 {Kind: "Bucket", Status: Supported, Note: "collated into its in-stack AWS::S3::Bucket as spec.policy; * (public) principals only — AWS-IAM-ARN principals refuse; not standalone"},
	"AWS::SQS::Queue":                       {Kind: "Queue", Status: Partial, Note: "a standalone managed queue (kind: Queue) — a NATS JetStream WorkQueue stream. FIFO maps: FifoQueue/.fifo -> strict per-message-group ordering (each MessageGroupId is a <queue>.<group> subject token; groups run in parallel) + a 5m publish-dedup window (Nats-Msg-Id, from MessageDeduplicationId). Per-queue encryption does NOT map (NATS encryption is substrate-level); ContentBasedDeduplication needs a producer-set Nats-Msg-Id (no auto-hash front door); visibility/delay/DLQ are consumer-side caveats."},
	"AWS::SNS::Topic":                       {Kind: "Queue", Status: Partial, Note: "a standalone fan-out topic (kind: Queue, fanout) — a NATS JetStream Limits stream. An inline lambda Subscription to an in-stack Function maps (the subscribing kind: Function gets the topic in spec.queues and reads the stream); every other inline Subscription protocol (sqs/http/email/sms/...) refuses honestly, as do FIFO and encryption."},
	"AWS::SNS::Subscription":                {Kind: "Function", Status: Partial, Note: "collated into the subscribing kind: Function via spec.queues, not standalone. ONLY a lambda subscription whose Endpoint is an in-stack AWS::Lambda::Function maps (the Function reads the topic's JetStream stream directly); an out-of-stack topic/endpoint refuses, an sqs sub refuses (open-infra builds no topic→queue bridge — point the consumer at the topic stream via spec.queues), and http/email/sms/application/firehose refuse (no outward push-delivery surface)."},
	"AWS::RDS::DBInstance":                  {Kind: "Application(database)", Status: Partial, Note: "managed DB via an Application's database block. Engine maps (postgres/aurora-postgresql->CNPG; mysql/mariadb/aurora-mysql->MariaDB; sqlserver-*->babelfish); AllocatedStorage->storage size and common DBInstanceClasses->CPU/memory requests (a documented mapping table). Burst-credit accounting, EBS-optimized throughput, Aurora distributed storage, StorageType/provisioned-IOPS do NOT map; an unknown class falls back to engine defaults with a caveat."},
	"AWS::EC2::VPC":                         {Kind: "Vpc", Status: Partial, Note: "a create translator provisions a kind: Vpc (kube-ovn network domain; #120). The VPC-level CidrBlock is informational (subnets carry the CIDRs); DNS/tenancy/tags don't map."},
	"AWS::EC2::Subnet":                      {Kind: "Subnet", Status: Partial, Note: "a create translator provisions a kind: Subnet with real OVN isolation (#120): CidrBlock->cidr, a VpcId !Ref to an in-stack AWS::EC2::VPC->vpc, MapPublicIpOnLaunch->private (public=>not private). AZ/IPv6/tags don't map."},
	"AWS::EC2::Instance":                    {Kind: "VirtualMachine", Status: Partial, Note: "a create translator provisions a kind: VirtualMachine (#115). ImageId names an open-infra catalog OS in place of the AMI — a raw ami- id or an out-of-catalog OS refuses with the catalog listed; a recognized PUBLIC image SSM-parameter path (ubuntu/debian/fedora/windows) maps. InstanceType->CPU/memory (common types), UserData->cloud-init (#! scripts; #cloud-config isn't merged), root BlockDeviceMapping->diskSize. SubnetId->places the VM in a kind: Subnet (real OVN isolation, #120; a raw subnet- id refuses like an AMI). Security-group isolation maps via kind: SecurityGroup (CFN SG translation is a follow-on); KeyName/IAM-profile/AZ/extra disks don't map."},
	"AWS::EC2::Volume":                      {Kind: "Volume", Status: Partial, Note: "block volume (Longhorn); Size and Encrypted map faithfully (Encrypted -> LUKS keyed by a customer kind: EncryptionKey, KmsKeyId must reference an in-stack KMS::Key). VolumeType/Iops/Throughput do NOT map: Longhorn is replica-based durability, not provisioned IOPS — mapping an IOPS number would fabricate a performance contract, so it stays explicitly unmapped. AZ has no equivalent."},
	"AWS::EC2::EIP":                         {Kind: "ElasticIp", Status: Partial, Note: "a static public IP -> kind: ElasticIp (a kube-ovn IptablesEIP on a kind: NatGateway; #120). Plan-recognized, NOT create-deployable (Deployable=false): an AWS EIP names no gateway and its association is instance-side (InstanceId), so the NatGateway binding + FIP/DNAT association our model needs can't be derived from the template — author kind: ElasticIp natively (naming its natGateway + target)."},
	"AWS::EC2::NatGateway":                  {Kind: "NatGateway", Status: Partial, Note: "a NAT gateway -> kind: NatGateway (a kube-ovn VpcNatGateway; SNAT egress + the flat-LAN border device, #120). Plan-recognized, NOT create-deployable (Deployable=false): the gateway's internalIp (lanIp) and VPC binding are not carried by the template (AWS auto-assigns them) and inventing an IP would fabricate the route anchor — author kind: NatGateway natively. ConnectivityType/AllocationId/MaxDrainDuration don't map."},
	"AWS::EC2::InternetGateway":             {Kind: "(implicit)", Status: Partial, Note: "on open-infra the border device is a kind: NatGateway (which serves both the NAT-GW and, on a flat /24, the Internet-Gateway role); a standalone InternetGateway provisions nothing. Public reachability is attached with kind: ElasticIp + a kind: Vpc default route to the gateway."},
	"AWS::EC2::VPCGatewayAttachment":        {Kind: "(implicit)", Status: Partial, Note: "the IGW<->VPC attachment is implied by a kind: NatGateway plus the VPC's default route (kind: Vpc spec.routes); provisions nothing on its own."},
	"AWS::EC2::NetworkAcl":                  {Kind: "Subnet(acls)", Status: Partial, Note: "a Network ACL -> the acls on a kind: Subnet (stateless OVN switch rules, #120). Plan-recognized, NOT create-deployable: an AWS NetworkAcl is a reusable rule set attached to subnets via separate NetworkAclEntry + SubnetNetworkAclAssociation resources; author the rules directly on the target kind: Subnet spec.acls."},
	"AWS::EC2::NetworkAclEntry":             {Kind: "Subnet(acls)", Status: Partial, Note: "one rule of a Network ACL -> one entry in a kind: Subnet spec.acls (direction/action/protocol/cidr/port); authored on the subnet, not standalone."},
	"AWS::EC2::SubnetNetworkAclAssociation": {Kind: "(implicit)", Status: Partial, Note: "the ACL<->subnet association is implicit: rules live directly on the target kind: Subnet spec.acls; provisions nothing on its own."},
	"AWS::EC2::VPCPeeringConnection":        {Kind: "Vpc(peerings)", Status: Partial, Note: "VPC peering -> kind: Vpc spec.peerings on BOTH VPCs + a spec.routes entry each (#120). Plan-recognized, NOT create-deployable: the /30 interconnect IPs are not carried by the template and peering is two-sided VPC config — author it on both kind: Vpc. Non-transitive, like AWS."},
	"AWS::EC2::TransitGateway":              {Kind: "TransitGateway", Status: Partial, Note: "a transit hub -> kind: TransitGateway (a subnet-less kube-ovn Vpc that peers every spoke; #120). Plan-recognized, NOT create-deployable: the per-spoke /30 links + each spoke's own attachment/route wiring aren't derivable from the template — author kind: TransitGateway (hub) + each spoke's kind: Vpc."},
	"AWS::EC2::TransitGatewayAttachment":    {Kind: "TransitGateway", Status: Partial, Note: "a TGW<->VPC attachment -> one entry in kind: TransitGateway spec.attachments plus the spoke's own kind: Vpc peering+route; authored, not standalone."},
	"AWS::EC2::RouteTable":                  {Kind: "Vpc(routes)", Status: Partial, Note: "a route table -> kind: Vpc spec.routes (kube-ovn keeps routes on the VPC, not a standalone table). Plan-recognized; author the routes on the kind: Vpc."},
	"AWS::EC2::Route":                       {Kind: "Vpc(routes)", Status: Partial, Note: "one route -> one kind: Vpc spec.routes entry (cidr -> nextHop). Plan-recognized, NOT create-deployable: an AWS route targets a gateway id (igw/nat/pcx) that maps to a next-hop IP the template doesn't carry — author the route on the kind: Vpc."},
	"AWS::EC2::SubnetRouteTableAssociation": {Kind: "(implicit)", Status: Partial, Note: "route-table<->subnet association is implicit: kube-ovn routes are VPC-scoped (kind: Vpc spec.routes), not per-subnet-table; provisions nothing on its own."},
	"AWS::EC2::FlowLog":                     {Kind: "FlowLog", Status: Partial, Note: "VPC flow logs -> kind: FlowLog (OVS sFlow -> a node-local collector -> Loki; #120). Plan-recognized, NOT create-deployable: OVS sFlow is per-bridge/per-node (scope to a VPC/subnet by filtering records on CIDR in Loki), and the AWS ResourceId (a vpc-/subnet-/eni- id) + LogDestination (CloudWatch/S3) don't map — author kind: FlowLog natively. TrafficType ALL only (sampled)."},
	"AWS::EFS::FileSystem":                  {Kind: "FileShare", Status: Partial, Note: "maps at plan, but no create translator by design: EFS is elastic (no size) and kind: FileShare requires a size — inventing one would be a guess"},
	// Faithfully translated AS PART OF their parent AWS::AppSync::GraphQLApi (schema SDL / VTL /
	// APPSYNC_JS carried byte-for-byte via the collation) — NOT lossy, so not "partial". They are
	// simply not standalone: a bare one whose ApiId names no in-stack GraphQLApi refuses at deploy
	// (an orphan, not a silent success). See #118.
	"AWS::AppSync::DataSource":            {Kind: "GraphQLApi", Status: Supported, Note: "faithfully translated as part of its parent GraphQLApi; not standalone — a bare one (no in-stack API) refuses"},
	"AWS::AppSync::Resolver":              {Kind: "GraphQLApi", Status: Supported, Note: "faithfully translated as part of its parent GraphQLApi (VTL/JS byte-for-byte); not standalone — a bare one refuses"},
	"AWS::AppSync::FunctionConfiguration": {Kind: "GraphQLApi", Status: Supported, Note: "faithfully translated as part of its parent GraphQLApi (pipeline function); not standalone — a bare one refuses"},
	"AWS::AppSync::GraphQLSchema":         {Kind: "GraphQLApi", Status: Supported, Note: "faithfully translated as part of its parent GraphQLApi (schema SDL); not standalone — a bare one refuses"},
	"AWS::DynamoDB::Table":                {Kind: "Table", Status: Partial, Note: "table via kind: Table — registers name + key schema, TTL, and global secondary indexes on the aws-shim's FerretDB data layer; functions only where the aws-shim DynamoDB front door is enabled (opt-in). No capacity/throughput, local secondary indexes, streams, or per-table SSE — those block."},

	// --- unsupported: explicitly out of scope for v1 ---
	"AWS::Cognito::UserPool":              {Kind: "UserPool", Status: Partial, Note: "a hosted OIDC pool (Keycloak realm); Cognito-specific config (MFA, Lambda triggers, schema) does not transfer"},
	"AWS::Cognito::UserPoolClient":        {Kind: "UserPool(client)", Status: Partial, Note: "the pool's app client is created with the UserPool; a standalone client resource has no separate kind"},
	"AWS::SSM::Parameter":                 {Kind: "Parameter", Status: Partial, Note: "SSM Parameter Store -> kind: Parameter (Vault KV-v2): Name->path, Value, Type (SecureString held encrypted at rest, materialized into the namespace Secret). StringList stores a plain comma-separated string; Description/AllowedPattern/DataType/Tags are advisory caveats; an Expiration policy maps to spec.expiresAt (reaper-enforced); notification policies are caveats."},
	"AWS::CloudFormation::Stack":          {Status: Unsupported, Note: "nested stacks are out of scope for v1"},
	"AWS::CloudFormation::CustomResource": {Status: Unsupported, Note: "Lambda-backed custom resources are out of scope for v1"},
	"AWS::ECS::Service":                   {Kind: "Application", Status: Partial, Note: "a Service + its referenced TaskDefinition collate into one Application (Deployment+Service+Ingress+HPA). Multi-container tasks map to a multi-container Pod (primary + sidecars) with per-container CPU/memory and shared scratch Volumes (emptyDir) + MountPoints. The LB's HTTP target port maps to the Service port (set Application.domain for Ingress+TLS). TaskRoleArn maps to workload identity (the app assumes the kind: Role via sts:AssumeRoleWithWebIdentity — #111). NetworkConfiguration's awsvpc subnet places the app in a kind: Subnet (real OVN isolation, #120; a raw subnet- id refuses). Security-group isolation maps via kind: SecurityGroup (CFN SG translation is a follow-on); host-path/EFS volumes, container DependsOn ordering, and ExecutionRoleArn do NOT transfer."},
	"AWS::ECS::TaskDefinition":            {Kind: "Application (container)", Status: Partial, Note: "the container spec — collated into the referencing Service's Application (containers->pod containers, Cpu/Memory->requests/limits, shared Volumes->emptyDir + MountPoints); a bare TaskDefinition provisions nothing"},
	"AWS::ECS::Cluster":                   {Kind: "(implicit)", Status: Partial, Note: "a grouping with no open-infra counterpart (the k3s cluster is the cluster) — provisions nothing"},
}

// Lookup returns the mapping entry for a CFN resource type. An unknown type — or any
// Custom:: resource — is unsupported by default: the engine never guesses.
func Lookup(cfnType string) MapEntry {
	if e, ok := mappingTable[cfnType]; ok {
		return e
	}
	if strings.HasPrefix(cfnType, "Custom::") {
		return MapEntry{Status: Unsupported, Note: "custom resource — out of scope for v1"}
	}
	return MapEntry{Status: Unsupported, Note: "no backing open-infra kind"}
}

// mappable reports whether a status can be provisioned (supported outright, or partial
// with caveats). gated/unsupported cannot.
func (e MapEntry) mappable() bool { return e.Status == Supported || e.Status == Partial }
