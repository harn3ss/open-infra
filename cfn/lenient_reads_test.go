package cfn

import (
	"strings"
	"testing"
)

// The properties the fidelity guard once deferred as read leniently: each is now read in its AWS shape,
// and a value of another shape is refused (or, where it cannot apply here, reported) — never skipped.
// One test per property, each with the value that used to be ignored.

// lenientRun translates a whole stack and returns its findings (joined) and its rendered output.
func lenientRun(t *testing.T, tmpl string) (string, string) {
	t.Helper()
	r := guardRunAll(mustParse(t, []byte(tmpl)))
	if r.panic != "" {
		t.Fatalf("panic: %s", r.panic)
	}
	return strings.Join(sortedSet(r.findings), "\n"), r.out
}

func wantRefused(t *testing.T, what, findings, needle string) {
	t.Helper()
	if !strings.Contains(findings, needle) {
		t.Fatalf("%s must be refused (%q), got findings:\n%s", what, needle, findings)
	}
}

func wantClean(t *testing.T, what, findings string) {
	t.Helper()
	if findings != "" {
		t.Fatalf("%s must translate, got findings:\n%s", what, findings)
	}
}

func lenientBucket(props string) string {
	return "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: " + props + "\n"
}

// ---- AWS::S3::Bucket.ObjectLockConfiguration ----

func TestLenient_S3ObjectLockConfiguration(t *testing.T) {
	// A string (or any non-object) used to be skipped: the bucket was created with no lock at all.
	f, _ := lenientRun(t, lenientBucket(`{ ObjectLockConfiguration: "x" }`))
	wantRefused(t, "a non-object ObjectLockConfiguration", f, "ObjectLockConfiguration must be an object")
	// Days of the wrong shape, both periods, an unknown key and ObjectLockEnabled other than Enabled refuse.
	for props, needle := range map[string]string{
		`{ ObjectLockConfiguration: { ObjectLockEnabled: Enabled, Rule: { DefaultRetention: { Mode: COMPLIANCE, Days: "thirty" } } } }`:    "DefaultRetention.Days must be a positive whole number",
		`{ ObjectLockConfiguration: { ObjectLockEnabled: Enabled, Rule: { DefaultRetention: { Mode: COMPLIANCE, Days: 1, Years: 1 } } } }`: "Days or Years, not both",
		`{ ObjectLockConfiguration: { ObjectLockEnabled: Enabled, Rule: { DefaultRetention: { Mode: COMPLIANCE, Days: 1 }, Extra: 1 } } }`: "property Extra is not translatable",
		`{ ObjectLockConfiguration: { ObjectLockEnabled: Disabled, Rule: { DefaultRetention: { Mode: GOVERNANCE, Days: 1 } } } }`:          "ObjectLockEnabled must be Enabled",
		`{ ObjectLockConfiguration: { ObjectLockEnabled: Enabled, Rule: { DefaultRetention: { Mode: COMPLIANCE, Days: 0 } } } }`:           "positive whole number",
	} {
		f, _ := lenientRun(t, lenientBucket(props))
		wantRefused(t, props, f, needle)
	}
	// The AWS shape maps: a whole number of years.
	m, fs := translateS3Bucket("B", map[string]any{"ObjectLockConfiguration": map[string]any{"ObjectLockEnabled": "Enabled",
		"Rule": map[string]any{"DefaultRetention": map[string]any{"Mode": "GOVERNANCE", "Years": "2"}}}}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if ol, _ := m.Spec["objectLock"].(map[string]any); ol["mode"] != "GOVERNANCE" || ol["years"] != 2 {
		t.Fatalf("objectLock = %#v", m.Spec["objectLock"])
	}
}

// ---- AWS::S3::Bucket.LifecycleConfiguration.Rules[].Filter ----

func TestLenient_S3LifecycleFilter(t *testing.T) {
	// A Filter that is not an object used to be skipped: the rule then expired the WHOLE bucket.
	f, _ := lenientRun(t, lenientBucket(`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, Filter: "logs/" } ] } }`))
	wantRefused(t, "a non-object Filter", f, "Filter must be an object")
	f, _ = lenientRun(t, lenientBucket(`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, Prefix: a/, Filter: { Prefix: b/ } } ] } }`))
	wantRefused(t, "Prefix and Filter together", f, "sets both Prefix and Filter")
	f, _ = lenientRun(t, lenientBucket(`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, Filter: { Prefix: [ a ] } } ] } }`))
	wantRefused(t, "a Filter.Prefix that is not a value", f, "Prefix must be a value")
	f, out := lenientRun(t, lenientBucket(`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, Filter: { Prefix: logs/ } } ] } }`))
	wantClean(t, "a Filter.Prefix rule", f)
	if !strings.Contains(out, `"prefix":"logs/"`) {
		t.Fatalf("Filter.Prefix not mapped: %s", out)
	}
}

// ---- AWS::S3::Bucket.LifecycleConfiguration.Rules[].NoncurrentVersionExpiration ----

func TestLenient_S3LifecycleNoncurrentVersionExpiration(t *testing.T) {
	// Beside another action, a NoncurrentVersionExpiration of the wrong shape used to be skipped: old
	// versions were then kept forever.
	for props, needle := range map[string]string{
		`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, NoncurrentVersionExpiration: 7 } ] } }`:                                                 "NoncurrentVersionExpiration must be an object",
		`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, NoncurrentVersionExpiration: { Days: 7 } } ] } }`:                                       "property Days is not translatable",
		`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30, NoncurrentVersionExpiration: { NoncurrentDays: 7, NewerNoncurrentVersions: 2 } } ] } }`: "property NewerNoncurrentVersions is not translatable",
		`{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, NoncurrentVersionExpiration: { NoncurrentDays: "a week" } } ] } }`:                                            "NoncurrentDays must be a positive whole number",
	} {
		f, _ := lenientRun(t, lenientBucket(props))
		wantRefused(t, props, f, needle)
	}
	f, out := lenientRun(t, lenientBucket(`{ VersioningConfiguration: { Status: Enabled }, LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, NoncurrentVersionExpiration: { NoncurrentDays: 7 } } ] } }`))
	wantClean(t, "a NoncurrentDays rule", f)
	if !strings.Contains(out, `"noncurrentExpireDays":7`) {
		t.Fatalf("NoncurrentDays not mapped: %s", out)
	}
}

// ---- AWS::SNS::Topic.Subscription ----

func TestLenient_SNSTopicSubscription(t *testing.T) {
	stack := func(sub string) string {
		return "Resources:\n  T:\n    Type: AWS::SNS::Topic\n    Properties: { Subscription: " + sub + " }\n" +
			"  Fn: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: \"registry.example/fn:1\" } } }\n"
	}
	// Not a list, an entry that is not an object, an entry with a key SNS does not define, and an entry
	// missing its Endpoint used to be skipped: the subscriber never received the topic's messages.
	for sub, needle := range map[string]string{
		`{ Protocol: lambda, Endpoint: !GetAtt Fn.Arn }`: "Subscription must be a list",
		`[ "x" ]`: "each Subscription must be an object",
		`[ { Protocol: lambda, Endpoint: !GetAtt Fn.Arn, FilterPolicy: { a: [b] } } ]`: "property FilterPolicy is not translatable",
		`[ { Protocol: lambda } ]`: "missing Endpoint",
	} {
		f, _ := lenientRun(t, stack(sub))
		wantRefused(t, sub, f, needle)
	}
	f, _ := lenientRun(t, stack(`[ { Protocol: lambda, Endpoint: !GetAtt Fn.Arn } ]`))
	wantClean(t, "a lambda subscription to an in-stack Function", f)
}

// ---- AWS::SSM::Parameter.Policies ----

func TestLenient_SSMParameterPolicies(t *testing.T) {
	try := func(pol string) []Finding {
		_, fs := translateSSMParameter("P", map[string]any{"Name": "/app/x", "Value": "v", "Policies": pol}, nil)
		return fs
	}
	// A policy of an unknown type, or an Expiration without a usable Timestamp, used to be skipped: the
	// parameter then never expired.
	for pol, needle := range map[string]string{
		`[{"Key":"v"}]`: "which SSM does not define",
		`[{"Type":"Expire","Version":"1.0","Attributes":{"Timestamp":"2030-01-01T00:00:00Z"}}]`:                                                                                             "is not an SSM parameter policy",
		`[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"next tuesday"}}]`:                                                                                                 "needs an ISO 8601 Attributes.Timestamp",
		`[{"Type":"Expiration","Version":"1.0","Attributes":{}}]`:                                                                                                                           "needs an ISO 8601 Attributes.Timestamp",
		`[{"Type":"Expiration","Version":"2.0","Attributes":{"Timestamp":"2030-01-01T00:00:00Z"}}]`:                                                                                         `Version must be "1.0"`,
		`[{"Type":"Expiration","Version":"1.0","Attributes":"x"}]`:                                                                                                                          "Attributes must be an object",
		`[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2030-01-01T00:00:00Z"}},{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2031-01-01T00:00:00Z"}}]`: "more than one Expiration",
	} {
		wantRefused(t, pol, findingsText(try(pol)), needle)
	}
	m, fs := translateSSMParameter("P", map[string]any{"Name": "/app/x", "Value": "v",
		"Policies": `[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2030-01-01T00:00:00.000Z"}},{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"30","Unit":"Days"}}]`}, nil)
	if len(fs) != 0 || m.Spec["expiresAt"] != "2030-01-01T00:00:00.000Z" {
		t.Fatalf("an Expiration policy must map: %v / %s", m, findingsText(fs))
	}
}

// ---- AWS::AppSync::* ----

// appsyncStack is a minimal API with one NONE data source D and the given resolver Q (and extras).
func lenientAppSync(dsProps, resolverProps, extra string) string {
	return `Resources:
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  D:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt A.ApiId, Name: none, Type: NONE` + dsProps + ` }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x` + resolverProps + ` }
` + extra
}

const vtlUnit = `, DataSourceName: none, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)"`

func TestLenient_AppSyncDataSourceMetricsConfig(t *testing.T) {
	f, _ := lenientRun(t, lenientAppSync(`, MetricsConfig: "x"`, vtlUnit, ""))
	wantRefused(t, "MetricsConfig x", f, "MetricsConfig must be ENABLED or DISABLED")
	f, out := lenientRun(t, lenientAppSync(`, MetricsConfig: ENABLED`, vtlUnit, ""))
	wantClean(t, "MetricsConfig ENABLED", f)
	if !strings.Contains(out, "data source D: MetricsConfig ENABLED asks for enhanced metrics") {
		t.Fatalf("MetricsConfig ENABLED must be reported: %s", out)
	}
	f, _ = lenientRun(t, lenientAppSync(`, MetricsConfig: DISABLED`, vtlUnit, ""))
	wantClean(t, "MetricsConfig DISABLED", f)
}

func TestLenient_AppSyncDataSourceServiceRoleArn(t *testing.T) {
	// A role ARN (here a parameter's value) translates — and the translation says the role is not assumed.
	stack := strings.Replace(lenientAppSync(`, ServiceRoleArn: !Ref RoleArn`, vtlUnit, ""), "Resources:",
		"Parameters:\n  RoleArn: { Type: String, Default: \"arn:aws:iam::123456789012:role/appsync-ds\" }\nResources:", 1)
	f, out := lenientRun(t, stack)
	wantClean(t, "a ServiceRoleArn", f)
	if !strings.Contains(out, "data source D: its ServiceRoleArn is not assumed") {
		t.Fatalf("ServiceRoleArn must be reported: %s", out)
	}
	f, _ = lenientRun(t, lenientAppSync(`, ServiceRoleArn: [ x ]`, vtlUnit, ""))
	wantRefused(t, "a ServiceRoleArn that is not an ARN", f, "ServiceRoleArn must be a role ARN")
}

func TestLenient_AppSyncResolverCachingConfig(t *testing.T) {
	for props, needle := range map[string]string{
		`, CachingConfig: "x"`:                                            "CachingConfig must be an object",
		`, CachingConfig: { Ttl: 0 }`:                                     "Ttl must be a whole number of seconds from 1 to 3600",
		`, CachingConfig: { Ttl: 60, CachingKeys: [ arguments.id ] }`:     "must be a $context path",
		`, CachingConfig: { Ttl: 60, Keys: [ "$context.arguments.id" ] }`: "property Keys is not translatable",
	} {
		f, _ := lenientRun(t, lenientAppSync("", vtlUnit+props, ""))
		wantRefused(t, props, f, needle)
	}
	f, out := lenientRun(t, lenientAppSync("", vtlUnit+`, CachingConfig: { Ttl: 60, CachingKeys: [ "$context.arguments.id" ] }`, ""))
	wantClean(t, "a CachingConfig", f)
	if !strings.Contains(out, "resolver Q: CachingConfig takes effect only with an API cache") || strings.Contains(out, `"caching"`) {
		t.Fatalf("CachingConfig must be reported and not cache (no API cache, as on AWS): %s", out)
	}
}

func TestLenient_AppSyncResolverCode(t *testing.T) {
	// Code on a VTL resolver (no Runtime) used to be skipped: AWS runs no code there, so it refuses.
	f, _ := lenientRun(t, lenientAppSync("", vtlUnit+`, Code: "export function request(ctx) { return {}; }"`, ""))
	wantRefused(t, "Code without an APPSYNC_JS Runtime", f, "Code needs Runtime")
	f, _ = lenientRun(t, lenientAppSync("", `, DataSourceName: none, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 1.0.0 }`, ""))
	wantRefused(t, "an APPSYNC_JS resolver without Code", f, "needs its Code inline")
	f, _ = lenientRun(t, lenientAppSync("", `, DataSourceName: none, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 1.0.0 }, Code: "export function request(ctx){return {}} export function response(ctx){return ctx.result}", RequestMappingTemplate: "{}"`, ""))
	wantRefused(t, "an APPSYNC_JS resolver with a mapping template", f, "does not go with an APPSYNC_JS Runtime")
	f, out := lenientRun(t, lenientAppSync("", `, DataSourceName: none, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 1.0.0 }, Code: "export function request(ctx){return {}} export function response(ctx){return ctx.result}"`, ""))
	wantClean(t, "a JS unit resolver", f)
	if !strings.Contains(out, `"runtime":"appsync-js"`) || !strings.Contains(out, `"request":"export function request(ctx){return {}}`) {
		t.Fatalf("a JS unit resolver must map its code: %s", out)
	}
}

func TestLenient_AppSyncResolverKind(t *testing.T) {
	// A Kind outside the AWS enum used to be taken as UNIT.
	f, _ := lenientRun(t, lenientAppSync("", vtlUnit+`, Kind: PIPELINES`, ""))
	wantRefused(t, "Kind PIPELINES", f, "Kind must be UNIT or PIPELINE")
	f, _ = lenientRun(t, lenientAppSync("", vtlUnit+`, Kind: UNIT`, ""))
	wantClean(t, "Kind UNIT", f)
}

func TestLenient_AppSyncResolverMaxBatchSize(t *testing.T) {
	// Batching is a Lambda data source's: on the NONE source it refuses (see the Lambda tests below).
	f, _ := lenientRun(t, lenientAppSync("", vtlUnit+`, MaxBatchSize: 10`, ""))
	wantRefused(t, "MaxBatchSize 10", f, "it needs an AWS_LAMBDA data source")
	f, _ = lenientRun(t, lenientAppSync("", vtlUnit+`, MaxBatchSize: many`, ""))
	wantRefused(t, "MaxBatchSize many", f, "MaxBatchSize must be a whole number")
	f, _ = lenientRun(t, lenientAppSync("", vtlUnit+`, MaxBatchSize: 0`, ""))
	wantClean(t, "MaxBatchSize 0", f)
}

func TestLenient_AppSyncResolverMetricsConfig(t *testing.T) {
	f, _ := lenientRun(t, lenientAppSync("", vtlUnit+`, MetricsConfig: true`, ""))
	wantRefused(t, "MetricsConfig true", f, "MetricsConfig must be ENABLED or DISABLED")
	f, out := lenientRun(t, lenientAppSync("", vtlUnit+`, MetricsConfig: ENABLED`, ""))
	wantClean(t, "resolver MetricsConfig ENABLED", f)
	if !strings.Contains(out, "resolver Q: MetricsConfig ENABLED") {
		t.Fatalf("resolver MetricsConfig ENABLED must be reported: %s", out)
	}
}

// fnStack is a pipeline resolver Q over one function F (with fnProps) on data source D.
func lenientPipeline(resolverProps, fnProps string) string {
	return lenientAppSync("", `, Kind: PIPELINE, PipelineConfig: { Functions: [ !GetAtt F.FunctionId ] }`+resolverProps, `
  F:
    Type: AWS::AppSync::FunctionConfiguration
    Properties: { ApiId: !GetAtt A.ApiId, Name: f, DataSourceName: none`+fnProps+` }
`)
}

const vtlFn = `, FunctionVersion: "2018-05-29", RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)"`
const jsMod = `"export function request(ctx){ return {}; } export function response(ctx){ return ctx.prev.result; }"`

func TestLenient_AppSyncResolverPipelineConfig(t *testing.T) {
	// PipelineConfig on a UNIT resolver used to be skipped: its functions never ran.
	f, _ := lenientRun(t, lenientAppSync("", vtlUnit+`, PipelineConfig: { Functions: [ x ] }`, ""))
	wantRefused(t, "PipelineConfig on a UNIT resolver", f, "PipelineConfig belongs to a PIPELINE resolver")
	f, _ = lenientRun(t, lenientAppSync("", `, Kind: PIPELINE, PipelineConfig: "x"`, ""))
	wantRefused(t, "a PipelineConfig that is not an object", f, "needs a PipelineConfig with its Functions")
	f, _ = lenientRun(t, lenientAppSync("", `, Kind: PIPELINE, PipelineConfig: { Functions: [] }`, ""))
	wantRefused(t, "an empty PipelineConfig", f, "PipelineConfig.Functions must list")
	f, _ = lenientRun(t, lenientPipeline("", vtlFn))
	wantClean(t, "a VTL pipeline resolver", f)
}

func TestLenient_AppSyncResolverRuntime(t *testing.T) {
	for props, needle := range map[string]string{
		`, Runtime: APPSYNC_JS, Code: ` + jsMod:                                            "Runtime must be {Name: APPSYNC_JS",
		`, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 2.0.0 }, Code: ` + jsMod:           "is not served",
		`, Runtime: { Name: APPSYNC_JS }, Code: ` + jsMod:                                  "is not served",
		`, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 1.0.0, Extra: 1 }, Code: ` + jsMod: "property Extra is not translatable",
	} {
		f, _ := lenientRun(t, lenientAppSync("", `, DataSourceName: none`+props, ""))
		wantRefused(t, props, f, needle)
	}
	// A JavaScript PIPELINE resolver used to run with its Code dropped; its module is now its before and
	// after step, and the engine runs them as JavaScript.
	f, out := lenientRun(t, lenientPipeline(`, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 1.0.0 }, Code: `+jsMod, vtlFn))
	wantClean(t, "a JS pipeline resolver", f)
	for _, want := range []string{`"runtime":"appsync-js"`, `"before":"export function request(ctx){ return {}; }`, `"after":"export function request(ctx){ return {}; }`} {
		if !strings.Contains(out, want) {
			t.Fatalf("a JS pipeline resolver must carry its module as before and after (%s): %s", want, out)
		}
	}
}

func TestLenient_AppSyncResolverSyncConfig(t *testing.T) {
	for props, needle := range map[string]string{
		`, SyncConfig: "x"`: "SyncConfig must be an object",
		`, SyncConfig: { ConflictDetection: VERSION, ConflictHandler: AUTOMERGE }`: "ConflictDetection VERSION",
		`, SyncConfig: { ConflictDetection: SOMETIMES }`:                           "must be VERSION or NONE",
		`, SyncConfig: { ConflictDetection: NONE, Extra: 1 }`:                      "property Extra is not translatable",
	} {
		f, _ := lenientRun(t, lenientAppSync("", vtlUnit+props, ""))
		wantRefused(t, props, f, needle)
	}
	f, _ := lenientRun(t, lenientAppSync("", vtlUnit+`, SyncConfig: { ConflictDetection: NONE }`, ""))
	wantClean(t, "SyncConfig NONE", f)
}

func TestLenient_AppSyncFunctionCode(t *testing.T) {
	f, _ := lenientRun(t, lenientPipeline("", vtlFn+`, Code: `+jsMod))
	wantRefused(t, "Code on a VTL function", f, "Code needs Runtime")
	// A JavaScript function used to run as VTL with its Code dropped; it now runs its module.
	f, out := lenientRun(t, lenientPipeline("", `, Runtime: { Name: APPSYNC_JS, RuntimeVersion: 1.0.0 }, Code: `+jsMod))
	wantClean(t, "a JS function", f)
	if !strings.Contains(out, `"functions":[{"dataSource":"none","request":"export function request`) || !strings.Contains(out, `"runtime":"appsync-js"}]`) {
		t.Fatalf("a JS function must map its module and runtime: %s", out)
	}
}

func TestLenient_AppSyncFunctionS3Locations(t *testing.T) {
	for _, k := range []string{"CodeS3Location", "RequestMappingTemplateS3Location", "ResponseMappingTemplateS3Location"} {
		f, _ := lenientRun(t, lenientPipeline("", vtlFn+`, `+k+`: "s3://bucket/key"`))
		wantRefused(t, "a function's "+k, f, k+" is not translatable")
	}
}

func TestLenient_AppSyncFunctionMaxBatchSize(t *testing.T) {
	f, _ := lenientRun(t, lenientPipeline("", vtlFn+`, MaxBatchSize: 5`))
	wantRefused(t, "a function's MaxBatchSize 5 on a NONE source", f, "it needs an AWS_LAMBDA data source")
}

// lenientLambdaAppSync is an API whose data source L invokes the stack's own function Fn (AWS_LAMBDA,
// LambdaFunctionArn !GetAtt Fn.Arn), with the resolver Q (and extras).
func lenientLambdaAppSync(resolverProps, extra string) string {
	return `Resources:
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, FunctionName: posts-fn }
  L:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt A.ApiId, Name: fn, Type: AWS_LAMBDA, LambdaConfig: { LambdaFunctionArn: !GetAtt Fn.Arn } }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x, DataSourceName: !GetAtt L.Name` + resolverProps + ` }
` + extra
}

// A Direct Lambda Resolver — no mapping templates — on a data source invoking the stack's own function
// translates, with its MaxBatchSize; the data source names the function it becomes.
func TestLenient_AppSyncDirectLambdaResolver(t *testing.T) {
	f, out := lenientRun(t, lenientLambdaAppSync(`, MaxBatchSize: 10`, ""))
	wantClean(t, "a Direct Lambda Resolver with MaxBatchSize", f)
	for _, want := range []string{`{"function":"posts-fn","name":"fn","type":"lambda"}`, `"maxBatchSize":10`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s: %s", want, out)
		}
	}
	if strings.Contains(out, `"request"`) || strings.Contains(out, `"response"`) {
		t.Fatalf("a Direct Lambda Resolver carries no templates: %s", out)
	}
	f, out = lenientRun(t, lenientLambdaAppSync(`, ResponseMappingTemplate: "$util.toJson($ctx.result.data)"`, ""))
	wantClean(t, "a Lambda resolver with only a response template", f)
	if !strings.Contains(out, `"response":"$util.toJson($ctx.result.data)"`) || strings.Contains(out, `"request"`) {
		t.Fatalf("only the response template is carried: %s", out)
	}
	f, _ = lenientRun(t, lenientLambdaAppSync(`, MaxBatchSize: 2001`, ""))
	wantRefused(t, "MaxBatchSize 2001", f, "MaxBatchSize must be a whole number from 0 to 2000")
}

// A direct Lambda pipeline function translates with its MaxBatchSize; a PIPELINE resolver's own
// MaxBatchSize refuses (a pipeline batches in its functions).
func TestLenient_AppSyncDirectLambdaFunction(t *testing.T) {
	pipeline := func(resolverProps string) string {
		return strings.Replace(lenientLambdaAppSync("", `
  F:
    Type: AWS::AppSync::FunctionConfiguration
    Properties: { ApiId: !GetAtt A.ApiId, Name: f, FunctionVersion: "2018-05-29", DataSourceName: !GetAtt L.Name, MaxBatchSize: 3 }
`), `DataSourceName: !GetAtt L.Name }`, `Kind: PIPELINE, PipelineConfig: { Functions: [ !GetAtt F.FunctionId ] }`+resolverProps+` }`, 1)
	}
	f, out := lenientRun(t, pipeline(""))
	wantClean(t, "a direct Lambda pipeline function", f)
	if !strings.Contains(out, `"functions":[{"dataSource":"fn","maxBatchSize":3,"runtime":"appsync-vtl"}]`) {
		t.Fatalf("the function must carry its MaxBatchSize and no templates: %s", out)
	}
	f, _ = lenientRun(t, pipeline(`, MaxBatchSize: 4`))
	wantRefused(t, "MaxBatchSize on a PIPELINE resolver", f, "a pipeline batches in its functions")
}

// Templates may be left out on an AWS_LAMBDA source only; a Lambda data source must invoke the stack's
// own function.
func TestLenient_AppSyncDirectLambdaRefusals(t *testing.T) {
	f, _ := lenientRun(t, lenientAppSync("", `, DataSourceName: none`, ""))
	wantRefused(t, "a NONE resolver with no templates", f, "may be left out only on a Lambda data source")
	f, _ = lenientRun(t, lenientAppSync("", `, DataSourceName: none, RequestMappingTemplate: "{}"`, ""))
	wantRefused(t, "a NONE resolver with no response template", f, "may be left out only on a Lambda data source")
	f, _ = lenientRun(t, strings.Replace(lenientLambdaAppSync("", ""), "!GetAtt Fn.Arn", `"arn:aws:lambda:us-east-1:111111111111:function:elsewhere"`, 1))
	wantRefused(t, "a Lambda data source naming an out-of-stack function", f, "references an AWS::Lambda::Function in this stack")
}

func TestLenient_AppSyncFunctionRuntime(t *testing.T) {
	f, _ := lenientRun(t, lenientPipeline("", vtlFn+`, Runtime: { Name: VTL }`))
	wantRefused(t, "a function's Runtime VTL", f, "is not served")
}

func TestLenient_AppSyncFunctionSyncConfig(t *testing.T) {
	f, _ := lenientRun(t, lenientPipeline("", vtlFn+`, SyncConfig: { ConflictDetection: VERSION }`))
	wantRefused(t, "a function's SyncConfig VERSION", f, "ConflictDetection VERSION")
}

// The two collated types the guard did not check property by property now report their accepted set.
func TestLenient_CollatedTypesReportTheirProperties(t *testing.T) {
	f, _ := lenientRun(t, `Resources:
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }", Schema: x }
  D: { Type: AWS::AppSync::DataSource, Properties: { ApiId: !GetAtt A.ApiId, Name: none, Type: NONE } }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x`+vtlUnit+` }
`)
	wantRefused(t, "a GraphQLSchema property AppSync does not define", f, "property Schema is not translatable")
	f, _ = lenientRun(t, `Resources:
  B: { Type: AWS::S3::Bucket, Properties: { BucketName: b } }
  P:
    Type: AWS::S3::BucketPolicy
    Properties: { Bucket: !Ref B, PolicyDocument: [ x ] }
`)
	wantRefused(t, "a BucketPolicy PolicyDocument that is not a document", f, "PolicyDocument must be a policy document")
	f, out := lenientRun(t, `Resources:
  B: { Type: AWS::S3::Bucket, Properties: { BucketName: b } }
  P:
    Type: AWS::S3::BucketPolicy
    Properties: { Bucket: !Ref B, PolicyDocument: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::b/*\"}]}" }
`)
	wantClean(t, "a BucketPolicy given as a JSON string", f)
	if !strings.Contains(out, `s3:GetObject`) {
		t.Fatalf("a JSON-string PolicyDocument must be stored as the document: %s", out)
	}
}

func TestLenient_AppSyncQueryDepthLimit(t *testing.T) {
	stack := func(v string) string {
		return strings.Replace(lenientAppSync("", vtlUnit, ""), "AuthenticationType: API_KEY }", "AuthenticationType: API_KEY, QueryDepthLimit: "+v+" }", 1)
	}
	f, _ := lenientRun(t, stack("deep"))
	wantRefused(t, "QueryDepthLimit deep", f, "QueryDepthLimit must be a whole number from 0 to 75")
	f, _ = lenientRun(t, stack("76"))
	wantRefused(t, "QueryDepthLimit 76", f, "QueryDepthLimit must be a whole number from 0 to 75")
	f, out := lenientRun(t, stack("6"))
	wantClean(t, "QueryDepthLimit 6", f)
	if !strings.Contains(out, `"maxDepth":6`) {
		t.Fatalf("QueryDepthLimit not mapped: %s", out)
	}
	f, _ = lenientRun(t, stack("0"))
	wantClean(t, "QueryDepthLimit 0", f)
}
