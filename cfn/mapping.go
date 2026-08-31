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
	"AWS::IAM::Role":                   {Kind: "Role", Status: Supported},
	"AWS::IAM::ManagedPolicy":          {Kind: "Policy", Status: Supported},
	"AWS::IAM::Policy":                 {Kind: "Policy", Status: Supported, Note: "inline policy -> a Policy"},
	"AWS::IAM::User":                   {Kind: "User", Status: Supported},
	"AWS::IAM::Group":                  {Kind: "Group", Status: Supported},
	"AWS::KMS::Key":                    {Kind: "EncryptionKey", Status: Supported, Note: "customer key in Vault Transit"},

	// --- partial: backing kind exists but the mapping is lossy ---
	"AWS::S3::Bucket":                     {Kind: "Application(storage.buckets)", Status: Partial, Note: "no standalone bucket kind — a bucket is provisioned via an Application's storage.buckets (MinIO)"},
	"AWS::SQS::Queue":                     {Kind: "Application(queues)", Status: Partial, Note: "no standalone queue kind — provisioned via an Application's queues (NATS JetStream)"},
	"AWS::SNS::Topic":                     {Kind: "Application(queues)", Status: Partial, Note: "pub/sub maps to NATS via an Application's queues"},
	"AWS::RDS::DBInstance":                {Kind: "Application(database)", Status: Partial, Note: "managed DB is provisioned via an Application's database block (CloudNativePG / MariaDB); engine/size mapping is lossy"},
	"AWS::EC2::Instance":                  {Kind: "VirtualMachine", Status: Partial, Note: "AMI/instance-type -> os/cpu/memory is lossy; no 1:1 AMI catalog"},
	"AWS::EC2::Volume":                    {Kind: "Volume", Status: Partial, Note: "block volume (Longhorn)"},
	"AWS::EFS::FileSystem":                {Kind: "FileShare", Status: Partial, Note: "SMB share on Longhorn"},
	"AWS::AppSync::DataSource":            {Kind: "GraphQLApi", Status: Partial, Note: "a sub-part of a GraphQLApi's spec, not a standalone resource"},
	"AWS::AppSync::Resolver":              {Kind: "GraphQLApi", Status: Partial, Note: "a sub-part of a GraphQLApi's spec"},
	"AWS::AppSync::FunctionConfiguration": {Kind: "GraphQLApi", Status: Partial, Note: "a sub-part of a GraphQLApi's spec"},
	"AWS::AppSync::GraphQLSchema":         {Kind: "GraphQLApi", Status: Partial, Note: "a sub-part of a GraphQLApi's spec"},

	// --- gated: backing kind not yet available (blocked on a pending decision) ---
	"AWS::DynamoDB::Table": {Status: Gated, Note: "no DynamoDB-equivalent data layer yet — gated on the wide-column/KV data-layer decision"},

	// --- unsupported: explicitly out of scope for v1 ---
	"AWS::Cognito::UserPool":              {Status: Unsupported, Note: "no managed user pool — open-infra consumes OIDC/JWT identity only"},
	"AWS::Cognito::UserPoolClient":        {Status: Unsupported, Note: "OIDC/JWT consumption only; no managed user pool"},
	"AWS::CloudFormation::Stack":          {Status: Unsupported, Note: "nested stacks are out of scope for v1"},
	"AWS::CloudFormation::CustomResource": {Status: Unsupported, Note: "Lambda-backed custom resources are out of scope for v1"},
	"AWS::ECS::Cluster":                   {Status: Unsupported, Note: "no container-orchestration service kind yet"},
	"AWS::ECS::Service":                   {Status: Unsupported, Note: "no container-orchestration service kind yet"},
	"AWS::ECS::TaskDefinition":            {Status: Unsupported, Note: "no container-orchestration service kind yet"},
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
