package cfn

import (
	"encoding/json"
	"regexp"
	"strings"
)

// A Lambda function's environment variables, as Lambda takes them, for every door that writes a Function:
// the Lambda API (aws-shim) and an AWS::Lambda::Function in a stack. A value is any string: the function's
// template renders it escaped (#405).

// LambdaEnvLimit is Lambda's limit on a function's environment variables: 4 KB, measured as their JSON.
const LambdaEnvLimit = 4096

// lambdaEnvNameRe is Lambda's pattern for an environment variable's name.
var lambdaEnvNameRe = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9_])+$`)

// LambdaEnvNamePattern is lambdaEnvNameRe as Lambda's validation message names it.
const LambdaEnvNamePattern = `[a-zA-Z]([a-zA-Z0-9_])+`

// LambdaEnvNameOK reports whether name is a name Lambda takes.
func LambdaEnvNameOK(name string) bool { return lambdaEnvNameRe.MatchString(name) }

// lambdaReservedEnv are the environment variables a function's own configuration may not set: Lambda's
// reserved keys, and the ones the platform sets for the function's runtime, role and code (an endpoint or
// token file named by the caller would send the function's identity elsewhere).
var lambdaReservedEnv = map[string]bool{
	"_HANDLER": true, "_X_AMZN_TRACE_ID": true, "AWS_DEFAULT_REGION": true, "AWS_REGION": true,
	"AWS_EXECUTION_ENV": true, "AWS_LAMBDA_FUNCTION_NAME": true, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": true,
	"AWS_LAMBDA_FUNCTION_VERSION": true, "AWS_LAMBDA_INITIALIZATION_TYPE": true, "AWS_LAMBDA_LOG_GROUP_NAME": true,
	"AWS_LAMBDA_LOG_STREAM_NAME": true, "AWS_ACCESS_KEY": true, "AWS_ACCESS_KEY_ID": true,
	"AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_LAMBDA_RUNTIME_API": true,
	"LAMBDA_TASK_ROOT": true, "LAMBDA_RUNTIME_DIR": true,
	"AWS_ROLE_ARN": true, "AWS_ROLE_SESSION_NAME": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true, "NATS_URL": true,
}

// LambdaEnvReserved reports whether a function's configuration may not set name.
func LambdaEnvReserved(name string) bool {
	return lambdaReservedEnv[name] || strings.HasPrefix(name, "OPENINFRA_") || name == "AWS_ENDPOINT_URL" ||
		strings.HasPrefix(name, "AWS_ENDPOINT_URL_")
}

// LambdaReservedEnvMessage is Lambda's refusal of reserved keys.
func LambdaReservedEnvMessage(names []string) string {
	return "Lambda was unable to configure your environment variables because the environment variables you have provided contains reserved keys that are currently not supported for modification. Reserved keys used in this request: " + strings.Join(names, ", ")
}

// LambdaEnvOverLimit answers Lambda's refusal when vars measure more than LambdaEnvLimit as JSON, or "".
func LambdaEnvOverLimit(vars map[string]any) string {
	measured, _ := json.Marshal(vars)
	if len(measured) <= LambdaEnvLimit {
		return ""
	}
	return "Lambda was unable to configure your environment variables because the environment variables you have provided exceeded the 4KB limit. String measured: " + string(measured)
}
