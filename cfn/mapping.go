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
	"AWS::IAM::ManagedPolicy":          {Kind: "Policy", Status: Supported, Note: "like IAM::Policy: a create translator imports the DATA-PLANE part into an enforced kind: Policy spec.dataPlane when the ManagedPolicy carries inline Groups/Users attachments; a standalone ManagedPolicy (attached via ManagedPolicyArns) has no principal here and BLOCKS, as does any control-plane/unmappable/conditioned part"},
	"AWS::IAM::Policy":                 {Kind: "Policy", Status: Supported, Note: "inline policy -> a Policy; a create translator imports the DATA-PLANE part (s3/dynamodb/lambda actions on recognizable ARNs, no conditions) into an enforced kind: Policy spec.dataPlane, and BLOCKS anything it can't honor faithfully (control-plane/unmappable/conditioned parts) — narrow the policy or author it natively"},
	"AWS::IAM::User":                   {Kind: "User", Status: Supported},
	"AWS::IAM::Group":                  {Kind: "Group", Status: Partial, Note: "maps at plan, but no create translator (Deployable=false): a Group's permissions are its attached AWS policies (unmappable automatically), and its required clusterRole can't be derived from them — author the Group + its policy attachment natively"},
	"AWS::KMS::Key":                    {Kind: "EncryptionKey", Status: Supported, Note: "customer key in Vault Transit"},

	// --- partial: backing kind exists but the mapping is lossy ---
	"AWS::S3::Bucket":      {Kind: "Bucket", Status: Partial, Note: "a standalone MinIO bucket (kind: Bucket) with versioning + lifecycle; Object Lock (WORM retention) maps to a MinIO lock-enabled bucket; BucketEncryption needs the opt-in objectEncryption stack; policy/website/CORS/replication do not map"},
	"AWS::SQS::Queue":      {Kind: "Queue", Status: Partial, Note: "a standalone managed queue (kind: Queue) — a NATS JetStream WorkQueue stream. FIFO maps: FifoQueue/.fifo -> strict per-message-group ordering (each MessageGroupId is a <queue>.<group> subject token; groups run in parallel) + a 5m publish-dedup window (Nats-Msg-Id, from MessageDeduplicationId). Per-queue encryption does NOT map (NATS encryption is substrate-level); ContentBasedDeduplication needs a producer-set Nats-Msg-Id (no auto-hash front door); visibility/delay/DLQ are consumer-side caveats."},
	"AWS::SNS::Topic":      {Kind: "Queue", Status: Partial, Note: "a standalone fan-out topic (kind: Queue, fanout) — a NATS JetStream Limits stream. Inline Subscriptions, FIFO, and encryption don't map (consumers subscribe to the stream themselves)."},
	"AWS::RDS::DBInstance": {Kind: "Application(database)", Status: Partial, Note: "managed DB via an Application's database block. Engine maps (postgres/aurora-postgresql->CNPG; mysql/mariadb/aurora-mysql->MariaDB; sqlserver-*->babelfish); AllocatedStorage->storage size and common DBInstanceClasses->CPU/memory requests (a documented mapping table). Burst-credit accounting, EBS-optimized throughput, Aurora distributed storage, StorageType/provisioned-IOPS do NOT map; an unknown class falls back to engine defaults with a caveat."},
	"AWS::EC2::Instance":   {Kind: "VirtualMachine", Status: Partial, Note: "a create translator provisions a kind: VirtualMachine (#115). ImageId names an open-infra catalog OS in place of the AMI — a raw ami- id or an out-of-catalog OS refuses with the catalog listed; a recognized PUBLIC image SSM-parameter path (ubuntu/debian/fedora/windows) maps. InstanceType->CPU/memory (common types), UserData->cloud-init (#! scripts; #cloud-config isn't merged), root BlockDeviceMapping->diskSize. SubnetId->places the VM in a kind: Subnet (real OVN isolation, #120; a raw subnet- id refuses like an AMI). Security-group isolation maps via kind: SecurityGroup (CFN SG translation is a follow-on); KeyName/IAM-profile/AZ/extra disks don't map."},
	"AWS::EC2::Volume":     {Kind: "Volume", Status: Partial, Note: "block volume (Longhorn); Size and Encrypted map faithfully (Encrypted -> LUKS keyed by a customer kind: EncryptionKey, KmsKeyId must reference an in-stack KMS::Key). VolumeType/Iops/Throughput do NOT map: Longhorn is replica-based durability, not provisioned IOPS — mapping an IOPS number would fabricate a performance contract, so it stays explicitly unmapped. AZ has no equivalent."},
	"AWS::EFS::FileSystem": {Kind: "FileShare", Status: Partial, Note: "maps at plan, but no create translator by design: EFS is elastic (no size) and kind: FileShare requires a size — inventing one would be a guess"},
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
