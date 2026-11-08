package cfn

import (
	"fmt"
	"strings"
	"time"
)

// LambdaRuntimeLifecycle is a Lambda runtime's place in AWS's deprecation policy: from Deprecated, the
// Lambda console no longer creates or updates functions on it; from BlockCreate, Lambda refuses to create
// one (the API, the CLI and CloudFormation alike); from BlockUpdate, it also refuses to change the code or
// configuration of one, except to move it to a supported runtime. A function on it is invoked as before,
// indefinitely.
type LambdaRuntimeLifecycle struct {
	Deprecated, BlockCreate, BlockUpdate time.Time
}

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// lambdaRuntimeLifecycles are AWS's dates for the runtimes open-infra runs, as Lambda's runtime page gives
// them (docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html, read 2026-11-08). AWS may move them;
// when it does, this table follows.
var lambdaRuntimeLifecycles = map[string]LambdaRuntimeLifecycle{
	"nodejs16.x": {day("2024-06-12"), day("2027-07-29"), day("2027-08-31")},
	"nodejs18.x": {day("2025-09-01"), day("2027-07-29"), day("2027-08-31")},
	"nodejs20.x": {day("2026-04-30"), day("2027-07-29"), day("2027-08-31")},
	"nodejs22.x": {day("2027-04-30"), day("2027-07-29"), day("2027-08-31")},
	"nodejs24.x": {day("2028-04-30"), day("2028-06-01"), day("2028-07-01")},
	"python3.8":  {day("2024-10-14"), day("2027-07-29"), day("2027-08-31")},
	"python3.9":  {day("2025-12-15"), day("2027-07-29"), day("2027-08-31")},
	"python3.10": {day("2026-10-31"), day("2027-07-29"), day("2027-08-31")},
	"python3.11": {day("2027-06-30"), day("2027-07-29"), day("2027-08-31")},
	"python3.12": {day("2028-10-31"), day("2028-11-30"), day("2029-01-10")},
	"python3.13": {day("2029-06-30"), day("2029-07-31"), day("2029-08-31")},
	"python3.14": {day("2029-06-30"), day("2029-07-31"), day("2029-08-31")},
	"dotnet8":    {day("2026-11-10"), day("2027-07-29"), day("2027-08-31")},
}

// LambdaRuntimeLifecycleOf is rt's lifecycle; ok is false for a runtime open-infra does not run.
func LambdaRuntimeLifecycleOf(rt string) (LambdaRuntimeLifecycle, bool) {
	l, ok := lambdaRuntimeLifecycles[rt]
	return l, ok
}

// LambdaRuntimeDeprecated reports whether rt is deprecated at now (the console no longer offers it).
func LambdaRuntimeDeprecated(rt string, now time.Time) bool {
	l, ok := lambdaRuntimeLifecycles[rt]
	return ok && !now.Before(l.Deprecated)
}

// LambdaRuntimeRefusal is Lambda's refusal of a function on rt at now: creating one (update false) from
// its BlockCreate date, changing one (update true) from its BlockUpdate date; "" when Lambda takes it.
func LambdaRuntimeRefusal(rt string, update bool, now time.Time) string {
	l, ok := lambdaRuntimeLifecycles[rt]
	if !ok {
		return ""
	}
	from := l.BlockCreate
	if update {
		from = l.BlockUpdate
	}
	if now.Before(from) {
		return ""
	}
	msg := fmt.Sprintf("The runtime parameter of %s is no longer supported for creating or updating AWS Lambda functions.", rt)
	if next := newestLambdaRuntime(rt, now); next != "" {
		msg += fmt.Sprintf(" We recommend you use the new runtime (%s) while creating or updating functions.", next)
	}
	return msg
}

// newestLambdaRuntime is the newest runtime of rt's language open-infra runs and Lambda still creates
// functions on at now ("" when there is none).
func newestLambdaRuntime(rt string, now time.Time) string {
	family := strings.TrimRight(rt, "0123456789.x")
	best := ""
	var bestDep time.Time
	for id, l := range lambdaRuntimeLifecycles {
		if id == rt || strings.TrimRight(id, "0123456789.x") != family || !now.Before(l.BlockCreate) {
			continue
		}
		if best == "" || l.Deprecated.After(bestDep) || l.Deprecated.Equal(bestDep) && newerVersion(id, best) {
			best, bestDep = id, l.Deprecated
		}
	}
	return best
}

// newerVersion reports whether runtime a is a newer version of its language than b (python3.14 is newer
// than python3.9).
func newerVersion(a, b string) bool {
	num := func(s string) []int {
		var out []int
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
			n := 0
			for _, c := range part {
				n = n*10 + int(c-'0')
			}
			out = append(out, n)
		}
		return out
	}
	x, y := num(a), num(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return len(x) > len(y)
}
