package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// A front door counts as landed only when its IAM actions are decided by the one evaluator and a denial
// is tested. Every service the router serves (probe/registry/shim-router.json, which
// TestCoverageRegistryShimRouter keeps in step with main.go) must be driven by a roleDoorCase, which
// TestEnforce_EveryFrontDoorIsIAMPolicyAlone, TestLegacy_UserWithNoPolicyKeepsItsRBACGrant and
// TestAssumedRoleDefaultDeny_EveryFrontDoor all run: no policy is denied, the exact grant allows, an
// explicit Deny wins. A door whose operations do not fit that shape names, in denyCaseExceptions, the test
// that proves it denies and why. A new service with neither fails here.

// denyCaseException is a front door proved by a test of its own instead of a roleDoorCase.
type denyCaseException struct {
	test string // a Test function in this package that shows the door's access-denied
	why  string // why the door does not fit roleDoorCase's shape
}

// denyCaseExceptions, by SigV4 signing name. Keep it short: a door that can be a roleDoorCase is one.
var denyCaseExceptions = map[string]denyCaseException{
	"sts": {test: "TestAssumeRole_UntrustedCallerDenied",
		why: "AssumeRole is decided by the target role's trust policy in every mode (the door has no RBAC or " +
			"identity-policy check to switch), and GetCallerIdentity needs no permission at all, as on AWS"},
}

// doorSigningName is the signing name a roleDoorCase's door is served under: the door's own name, but for
// API Gateway, whose REST (v1) and HTTP (v2) APIs are two doors behind one signing name.
func doorSigningName(door string) string {
	switch door {
	case "apigateway-v1", "apigateway-v2":
		return "apigateway"
	}
	return door
}

// denyCaseGaps is the gate: every router signing name has a roleDoorCase door or an exception; every
// exception names a service the router still serves, a Test function that exists, and a reason, and is
// not beside a roleDoorCase that already covers its door; every door is a service the router serves (a
// misnamed door would cover nothing).
func denyCaseGaps(routerKeys, doors []string, exceptions map[string]denyCaseException, tests map[string]bool) []error {
	served := map[string]bool{}
	for _, k := range routerKeys {
		served[k] = true
	}
	covered := map[string]bool{}
	var errs []error
	seenDoor := map[string]bool{}
	for _, d := range doors {
		if seenDoor[d] {
			continue
		}
		seenDoor[d] = true
		name := doorSigningName(d)
		if !served[name] {
			errs = append(errs, fmt.Errorf("roleDoorCase door %q is not a service the router serves (signing name %q): its cases cover no front door", d, name))
			continue
		}
		covered[name] = true
	}
	for _, k := range namesOf(served) {
		exc, isException := exceptions[k]
		switch {
		case !covered[k] && !isException:
			errs = append(errs, fmt.Errorf("%s: the router serves it, but no roleDoorCase drives it and no entry in denyCaseExceptions "+
				"names a test that proves it denies: add a roleDoorCase (or, if its operations cannot fit one, an exception)", k))
		case covered[k] && isException:
			errs = append(errs, fmt.Errorf("%s: roleDoorCases cover it, so its exception (%s) is redundant: remove it", k, exc.test))
		}
	}
	for _, k := range namesOf(exceptions) {
		exc := exceptions[k]
		if !served[k] {
			errs = append(errs, fmt.Errorf("denyCaseExceptions[%q]: the router does not serve %q (stale: remove it)", k, k))
		}
		if !tests[exc.test] {
			errs = append(errs, fmt.Errorf("denyCaseExceptions[%q] names %q, which is not a Test function in this package", k, exc.test))
		}
		if strings.TrimSpace(exc.why) == "" {
			errs = append(errs, fmt.Errorf("denyCaseExceptions[%q] gives no reason why %s is not a roleDoorCase", k, k))
		}
	}
	return errs
}

// namesOf is m's keys, sorted.
func namesOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// routerSigningNames is the signing names the router serves, from the committed registry.
func routerSigningNames(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(shimRegistryPath)
	if err != nil {
		t.Fatal(err)
	}
	var reg shimRegistry
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("%s: %v", shimRegistryPath, err)
	}
	if len(reg.Services) == 0 {
		t.Fatalf("%s lists no services", shimRegistryPath)
	}
	return namesOf(reg.Services)
}

// roleDoorDoors is the door of every roleDoorCase.
func roleDoorDoors() []string {
	var doors []string
	for _, tc := range roleDoorCases() {
		doors = append(doors, tc.door)
	}
	return doors
}

// packageTestFuncs is the Test functions (func TestX(t *testing.T)) of this package's _test.go files.
func packageTestFuncs(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || !takesTestingT(fn) {
				continue
			}
			out[fn.Name.Name] = true
		}
	}
	return out
}

func takesTestingT(fn *ast.FuncDecl) bool {
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) > 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "T"
}

func TestEveryFrontDoorHasADenyCase(t *testing.T) {
	for _, err := range denyCaseGaps(routerSigningNames(t), roleDoorDoors(), denyCaseExceptions, packageTestFuncs(t)) {
		t.Error(err)
	}
}

// The gate fails on each thing it guards against, naming it.
func TestDenyCaseGate_ProvesRed(t *testing.T) {
	keys, doors, tests := routerSigningNames(t), roleDoorDoors(), packageTestFuncs(t)
	withExceptions := func(extra map[string]denyCaseException) map[string]denyCaseException {
		out := map[string]denyCaseException{}
		for k, v := range denyCaseExceptions {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	wantGap := func(name string, errs []error, mention string) {
		t.Helper()
		for _, err := range errs {
			if strings.Contains(err.Error(), mention) {
				return
			}
		}
		t.Errorf("%s: the gate did not fail naming %q (errors: %v)", name, mention, errs)
	}
	served := append(append([]string{}, keys...), "widgets")

	if errs := denyCaseGaps(keys, doors, denyCaseExceptions, tests); len(errs) != 0 {
		t.Fatalf("the real inputs must pass the gate: %v", errs)
	}
	wantGap("a new service with no case and no exception",
		denyCaseGaps(served, doors, denyCaseExceptions, tests), "widgets")
	wantGap("an exception naming a test that does not exist",
		denyCaseGaps(served, doors, withExceptions(map[string]denyCaseException{
			"widgets": {test: "TestWidgets_NoSuchTest", why: "widgets are decided elsewhere"}}), tests), "TestWidgets_NoSuchTest")
	wantGap("a stale exception (a service the router does not serve)",
		denyCaseGaps(keys, doors, withExceptions(map[string]denyCaseException{
			"gadgets": {test: "TestAssumeRole_UntrustedCallerDenied", why: "gadgets are decided elsewhere"}}), tests), "gadgets")
	wantGap("an exception with no reason",
		denyCaseGaps(served, doors, withExceptions(map[string]denyCaseException{
			"widgets": {test: "TestAssumeRole_UntrustedCallerDenied"}}), tests), "no reason")
	wantGap("an exception beside the roleDoorCases that cover its door",
		denyCaseGaps(keys, doors, withExceptions(map[string]denyCaseException{
			"sqs": {test: "TestAssumeRole_UntrustedCallerDenied", why: "x"}}), tests), "sqs")
	wantGap("a roleDoorCase door the router does not serve",
		denyCaseGaps(keys, append(append([]string{}, doors...), "cognito"), denyCaseExceptions, tests), "cognito")
	// An exception that names a real test, with a reason, covers its service.
	if errs := denyCaseGaps(served, doors, withExceptions(map[string]denyCaseException{
		"widgets": {test: "TestAssumeRole_UntrustedCallerDenied", why: "widgets are decided elsewhere"}}), tests); len(errs) != 0 {
		t.Errorf("a well-formed exception must cover its service: %v", errs)
	}
	// A door with no roleDoorCase is a gap: dropping a door's cases fails the gate.
	var withoutLambda []string
	for _, d := range doors {
		if d != "lambda" {
			withoutLambda = append(withoutLambda, d)
		}
	}
	wantGap("a door whose cases are removed", denyCaseGaps(keys, withoutLambda, denyCaseExceptions, tests), "lambda")
	// The test-function scan finds this package's tests and nothing that is not one.
	for name, want := range map[string]bool{"TestEveryFrontDoorHasADenyCase": true, "TestAssumeRole_UntrustedCallerDenied": true,
		"roleDoorCases": false, "TestNoSuchTest": false} {
		if tests[name] != want {
			t.Errorf("packageTestFuncs()[%q] = %v, want %v", name, tests[name], want)
		}
	}
}
