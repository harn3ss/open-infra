package cfn

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every runtime open-infra runs has AWS's lifecycle dates, in order.
func TestLambdaRuntimes_EachHasAWSsLifecycle(t *testing.T) {
	for rt := range lambdaRuntimes {
		l, ok := LambdaRuntimeLifecycleOf(rt)
		if !ok {
			t.Errorf("%s has no lifecycle: add AWS's dates to lambdaRuntimeLifecycles", rt)
			continue
		}
		if !l.Deprecated.Before(l.BlockCreate) || !l.BlockCreate.Before(l.BlockUpdate) {
			t.Errorf("%s: deprecation %v, block create %v and block update %v are out of order", rt, l.Deprecated, l.BlockCreate, l.BlockUpdate)
		}
	}
	for rt := range lambdaRuntimeLifecycles {
		if _, ok := lambdaRuntimes[rt]; !ok {
			t.Errorf("%s has a lifecycle but is not a runtime open-infra runs", rt)
		}
	}
}

// Lambda refuses a create from the block-create date and a change from the block-update date, naming the
// newest runtime of the language it still creates functions on.
func TestLambdaRuntimeRefusal_FollowsAWSsDates(t *testing.T) {
	at := func(s string) time.Time { return day(s) }
	if LambdaRuntimeRefusal("nodejs20.x", false, at("2026-11-08")) != "" || LambdaRuntimeRefusal("nodejs20.x", true, at("2026-11-08")) != "" {
		t.Error("deprecated nodejs20.x is still created and updated through the API until its block dates, as on AWS")
	}
	if !LambdaRuntimeDeprecated("nodejs20.x", at("2026-11-08")) || LambdaRuntimeDeprecated("nodejs22.x", at("2026-11-08")) {
		t.Error("nodejs20.x is deprecated on 2026-11-08, nodejs22.x is not")
	}
	msg := LambdaRuntimeRefusal("nodejs20.x", false, at("2027-07-29"))
	if msg != "The runtime parameter of nodejs20.x is no longer supported for creating or updating AWS Lambda functions. We recommend you use the new runtime (nodejs24.x) while creating or updating functions." {
		t.Errorf("create on the block-create date: %q", msg)
	}
	if LambdaRuntimeRefusal("nodejs20.x", true, at("2027-08-30")) != "" {
		t.Error("an update before the block-update date is taken")
	}
	if LambdaRuntimeRefusal("nodejs20.x", true, at("2027-08-31")) == "" {
		t.Error("an update on the block-update date is refused")
	}
	// dotnet8 has no successor open-infra runs: no runtime is recommended.
	if m := LambdaRuntimeRefusal("dotnet8", false, at("2027-08-01")); !strings.HasSuffix(m, "functions.") || strings.Contains(m, "recommend") {
		t.Errorf("dotnet8: %q", m)
	}
	// Of two runtimes AWS deprecates on one day, the newer version is the one recommended.
	if m := LambdaRuntimeRefusal("python3.8", false, at("2027-08-01")); !strings.Contains(m, "(python3.14)") {
		t.Errorf("python3.8: %q", m)
	}
	if LambdaRuntimeRefusal("ruby3.4", false, at("2030-01-01")) != "" {
		t.Error("a runtime open-infra does not run is refused elsewhere, not here")
	}
}

// A stack's zip Lambda follows the dates: a new function on a runtime past its block-create date is
// refused; one the stack already has may change until the block-update date.
func TestLambdaZip_RuntimePastAWSsDates(t *testing.T) {
	defer func(c func() time.Time) { lambdaClock = c }(lambdaClock)
	lambdaClock = func() time.Time { return day("2027-08-01") }
	plan, err := BuildPlanForStack(zipTemplate(inlineNodeFn), nil, nil, "s", "", Capabilities{LambdaPackageStore: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != Rejected || !strings.Contains(strings.Join(plan.Blockers, "\n"), "The runtime parameter of nodejs22.x is no longer supported") {
		t.Errorf("a new nodejs22.x function after its block-create date: %s %v", plan.Verdict, plan.Blockers)
	}
	props := map[string]any{"Runtime": "nodejs22.x", "Handler": "index.handler"}
	code := map[string]any{"ZipFile": "exports.handler = async () => 1;"}
	existing := &stackCtx{caps: Capabilities{LambdaPackageStore: true},
		namer: newPhysNamer("s", []StackResource{{LogicalID: "Hello", Kind: "Function", Name: "s-hello"}})}
	if _, _, _, f := lambdaZipCode("Hello", props, code, existing); len(f) != 0 {
		t.Errorf("the stack's own nodejs22.x function before the block-update date: %v", f)
	}
	lambdaClock = func() time.Time { return day("2027-09-01") }
	if _, _, _, f := lambdaZipCode("Hello", props, code, existing); len(f) == 0 {
		t.Error("the stack's own nodejs22.x function after the block-update date must be refused")
	}
}

// The console offers a deprecated runtime disabled from AWS's deprecation date
// (ui/src/lib/lambda-runtimes.ts): its dates are this table's.
func TestLambdaRuntimes_TheConsoleHasTheSameDates(t *testing.T) {
	src, err := os.ReadFile("../ui/src/lib/lambda-runtimes.ts")
	if err != nil {
		t.Fatal(err)
	}
	ui := map[string]string{}
	for _, m := range regexp.MustCompile(`"([a-z0-9.]+)": "(\d{4}-\d{2}-\d{2})"`).FindAllStringSubmatch(string(src), -1) {
		ui[m[1]] = m[2]
	}
	for rt, spec := range lambdaRuntimes {
		want := lambdaRuntimeLifecycles[rt].Deprecated.Format("2006-01-02")
		if ui[spec] != want {
			t.Errorf("console's %s deprecation = %q, want %s (cfn/lambda_runtimes.go)", spec, ui[spec], want)
		}
		delete(ui, spec)
	}
	for spec := range ui {
		t.Errorf("console lists %s, which is not a runtime open-infra runs", spec)
	}
}

// A runtime AWS has deprecated but still creates functions on deploys from a stack, as on AWS (here
// nodejs18.x and python3.9 on 2026-11-08), on its own runtime image.
func TestLambdaZip_DeprecatedRuntimesAWSStillCreatesDeploy(t *testing.T) {
	defer func(c func() time.Time) { lambdaClock = c }(lambdaClock)
	lambdaClock = func() time.Time { return day("2026-11-08") }
	for rt, spec := range map[string]string{"nodejs18.x": "nodejs18", "nodejs16.x": "nodejs16", "python3.9": "python3.9", "python3.8": "python3.8"} {
		fn := strings.Replace(inlineNodeFn, "nodejs22.x", rt, 1)
		if strings.HasPrefix(rt, "python") {
			fn = strings.NewReplacer("nodejs22.x", rt, "exports.handler = async (event) => ({ hello: event.name });", "def handler(event, context):\n            return {'hello': event['name']}").Replace(inlineNodeFn)
		}
		plan, err := BuildPlanForStack(zipTemplate(fn), nil, nil, "s", "", Capabilities{LambdaPackageStore: true})
		if err != nil {
			t.Fatal(err)
		}
		if plan.Verdict == Rejected {
			t.Errorf("%s: a runtime AWS still creates functions on must deploy, got %v", rt, plan.Blockers)
		}
		if got, _ := LambdaRuntime(rt); got != spec {
			t.Errorf("%s runs as %q", rt, got)
		}
	}
}
