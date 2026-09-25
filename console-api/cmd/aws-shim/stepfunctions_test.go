package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateAndTranslateDefinition_Accepts(t *testing.T) {
	cases := map[string]string{
		"native function": `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"function:echo","End":true}}}`,
		"http escape":     `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"http://echo.default.svc/","End":true}}}`,
		"choice+wait+pass": `{"StartAt":"C","States":{
			"C":{"Type":"Choice","Choices":[{"Variable":"$.x","NumericEquals":1,"Next":"W"}],"Default":"P"},
			"W":{"Type":"Wait","Seconds":1,"Next":"P"},
			"P":{"Type":"Pass","Next":"D"},
			"D":{"Type":"Succeed"}}}`,
	}
	for name, def := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAndTranslateDefinition(def); err != nil {
				t.Fatalf("expected accept, got: %v", err)
			}
		})
	}
}

func TestValidateAndTranslateDefinition_TranslatesLambdaArn(t *testing.T) {
	def := `{"StartAt":"A","States":{"A":{"Type":"Task",
		"Resource":"arn:aws:lambda:us-east-1:open-infra:function:my-fn","End":true}}}`
	out, err := validateAndTranslateDefinition(def)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(out), &doc)
	got := doc["States"].(map[string]any)["A"].(map[string]any)["Resource"]
	if got != "function:my-fn" {
		t.Fatalf("Lambda ARN not translated: got %v", got)
	}
}

func TestValidateAndTranslateDefinition_TranslatesOptimizedLambdaInvoke(t *testing.T) {
	def := `{"StartAt":"A","States":{"A":{"Type":"Task",
		"Resource":"arn:aws:states:::lambda:invoke",
		"Parameters":{"FunctionName":"arn:aws:lambda:us-east-1:open-infra:function:my-fn","Payload":{"k":"v"}},
		"End":true}}}`
	out, err := validateAndTranslateDefinition(def)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(out), &doc)
	a := doc["States"].(map[string]any)["A"].(map[string]any)
	if a["Resource"] != "function:my-fn" {
		t.Fatalf("Resource not rewritten: %v", a["Resource"])
	}
	// Payload is folded up to Parameters so the engine passes {"k":"v"} to the function.
	params, ok := a["Parameters"].(map[string]any)
	if !ok || params["k"] != "v" {
		t.Fatalf("Payload not folded into Parameters: %v", a["Parameters"])
	}
}

func TestValidateAndTranslateDefinition_Refuses(t *testing.T) {
	cases := map[string]string{
		"parallel":         `{"StartAt":"A","States":{"A":{"Type":"Parallel","End":true}}}`,
		"map":              `{"StartAt":"A","States":{"A":{"Type":"Map","End":true}}}`,
		"waitForTaskToken": `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::lambda:invoke.waitForTaskToken","End":true}}}`,
		"sync":             `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::ecs:runTask.sync","End":true}}}`,
		"non-lambda svc":   `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::sns:publish","End":true}}}`,
		"unknown type":     `{"StartAt":"A","States":{"A":{"Type":"Frobnicate","End":true}}}`,
		"no StartAt":       `{"States":{"A":{"Type":"Succeed"}}}`,
		"empty States":     `{"StartAt":"A","States":{}}`,
		"bad json":         `{not json`,
	}
	for name, def := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAndTranslateDefinition(def); err == nil {
				t.Fatalf("expected refusal for %s, got accept", name)
			}
		})
	}
}

func TestExecParts(t *testing.T) {
	sm, name := execParts("arn:aws:states:us-east-1:open-infra:execution:my-sm:run-1")
	if sm != "my-sm" || name != "run-1" {
		t.Fatalf("execParts: sm=%q name=%q", sm, name)
	}
}

func TestSMNameFromArn(t *testing.T) {
	if got := smNameFromArn("arn:aws:states:us-east-1:open-infra:stateMachine:my-sm"); got != "my-sm" {
		t.Fatalf("smNameFromArn=%q", got)
	}
	if got := smNameFromArn("my-sm"); got != "my-sm" { // bare name passthrough
		t.Fatalf("smNameFromArn bare=%q", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"MyExec_1":  "myexec-1",
		"a.b-c":     "a.b-c",
		"__weird__": "weird",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAWSExecStatus(t *testing.T) {
	for phase, want := range map[string]string{
		"Succeeded": "SUCCEEDED", "Failed": "FAILED", "TimedOut": "TIMED_OUT",
		"Aborted": "ABORTED", "Running": "RUNNING", "": "RUNNING",
	} {
		if got := awsExecStatus(phase); got != want {
			t.Errorf("awsExecStatus(%q)=%q want %q", phase, got, want)
		}
	}
}

func TestVerbForSFNOp(t *testing.T) {
	for op, wantRes := range map[string]string{
		"CreateStateMachine": "statemachines",
		"StartExecution":     "executions",
		"StopExecution":      "executions",
		"DescribeExecution":  "executions",
	} {
		_, res, ok := verbForSFNOp(op)
		if !ok || res != wantRes {
			t.Errorf("verbForSFNOp(%q)=%q,%v want %q", op, res, ok, wantRes)
		}
	}
	if _, _, ok := verbForSFNOp("NopeOp"); ok {
		t.Error("unknown op should not be known")
	}
	_ = strings.TrimSpace("")
}
