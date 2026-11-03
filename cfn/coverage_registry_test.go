package cfn

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// The CloudFormation half of the AWS coverage registry that probe/shimgen.py joins with the aws-shim's
// half (console-api/cmd/aws-shim/coverage_registry_test.go): every resource type the engine knows, read
// from the mapping table and the translator dispatch themselves (including what other files' init()
// add), so a new type reaches the registry, the CI gate and the docs without anyone writing it down.
// Deployable is the same fact `cfn plan` reports: the type maps (supported or partial) AND has a create
// translator. The committed probe/registry/cfn-types.json must match; UPDATE_REGISTRY=1 rewrites it
// (probe/shimgen.py does that when Go is on PATH).
const cfnRegistryPath = "../probe/registry/cfn-types.json"

type cfnRegistryType struct {
	Status     Status `json:"status"`
	Kind       string `json:"kind,omitempty"`
	Translator bool   `json:"translator"`
	Deployable bool   `json:"deployable"`
	// Flattened: a nested stack, inlined into its parent by FlattenNested before the engine plans it —
	// its resources are what a stack creates, not the Stack itself.
	Flattened bool `json:"flattened,omitempty"`
}

type cfnRegistry struct {
	GeneratedBy string                     `json:"generatedBy"`
	Types       map[string]cfnRegistryType `json:"types"`
}

func buildCFNRegistry() cfnRegistry {
	names := map[string]bool{"AWS::CloudFormation::CustomResource": true} // Custom::* resolve to this entry
	for t := range mappingTable {
		names[t] = true
	}
	for t := range translators {
		names[t] = true
	}
	sorted := make([]string, 0, len(names))
	for t := range names {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	reg := cfnRegistry{GeneratedBy: "cfn/coverage_registry_test.go", Types: map[string]cfnRegistryType{}}
	for _, t := range sorted {
		e := Lookup(t)
		reg.Types[t] = cfnRegistryType{Status: e.Status, Kind: e.Kind, Translator: hasTranslator(t),
			Deployable: e.mappable() && hasTranslator(t), Flattened: t == StackTypeName}
	}
	return reg
}

func TestCoverageRegistryCFNTypes(t *testing.T) {
	reg := buildCFNRegistry()
	got, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_REGISTRY") != "" {
		if err := os.WriteFile(cfnRegistryPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(cfnRegistryPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("probe/registry/cfn-types.json is stale (the mapping table or translator dispatch changed): run "+
			"probe/shimgen.py (or UPDATE_REGISTRY=1 go test ./ -run TestCoverageRegistry in cfn/) and commit the "+
			"result (read error: %v)", err)
	}
}

// The registry must say what `cfn plan` says: for a template holding just that type, plan's Deployable,
// Status and Kind are the registry's.
func TestCoverageRegistryMatchesPlan(t *testing.T) {
	for typ, want := range buildCFNRegistry().Types {
		tpl := []byte(`{"Resources":{"R":{"Type":"` + typ + `","Properties":{}}}}`)
		p, err := BuildPlanWithCaps(tpl, nil, nil, "registry", Capabilities{})
		if err != nil {
			t.Fatalf("%s: plan: %v", typ, err)
		}
		if len(p.Resources) != 1 {
			t.Fatalf("%s: plan has %d resources", typ, len(p.Resources))
		}
		got := p.Resources[0]
		if got.Deployable != want.Deployable || got.Status != want.Status || got.Kind != want.Kind {
			t.Errorf("%s: plan says deployable=%v status=%s kind=%q, the registry deployable=%v status=%s kind=%q",
				typ, got.Deployable, got.Status, got.Kind, want.Deployable, want.Status, want.Kind)
		}
	}
}
