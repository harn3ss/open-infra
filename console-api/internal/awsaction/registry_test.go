package awsaction

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// The committed probe/registry/iam-actions.json is this table, rendered: every kind's AWS service,
// resource type, ARN template and the action each verb is, the operator prefix, and the IAM actions
// the aws-shim's own front doors check (from probe/registry/shim-router.json). The managed-policy set,
// the IAM→RBAC compiler and the docs read it. A stale file fails go test; UPDATE_REGISTRY=1 rewrites it.
const iamActionsPath = "../../../probe/registry/iam-actions.json"

type registryKind struct {
	Entry
	Variants []registryVariant `json:"variants,omitempty"`
}

type registryVariant struct {
	Name    string `json:"name"`
	Replace bool   `json:"replace,omitempty"`
	Entry   Entry  `json:"entry"`
}

type iamActionsRegistry struct {
	GeneratedBy string                  `json:"generatedBy"`
	Kinds       map[string]registryKind `json:"kinds"`
	Operator    map[string]string       `json:"operator"`
	ShimActions map[string][]string     `json:"shimActions"`
	Actions     []string                `json:"actions"`
}

func buildIAMActionsRegistry(t *testing.T) iamActionsRegistry {
	t.Helper()
	reg := iamActionsRegistry{
		GeneratedBy: "console-api/internal/awsaction (go test; UPDATE_REGISTRY=1 rewrites)",
		Kinds:       map[string]registryKind{},
		Operator: map[string]string{
			"prefix": OperatorPrefix,
			"action": OperatorPrefix + ":<Verb><Kind>[<Subresource>]",
			"arn":    "arn:{partition}:" + OperatorPrefix + ":{region}:{account}:<resource>/[<namespace>/]<name>",
		},
		ShimActions: map[string][]string{},
	}
	all := map[string]bool{}
	for k, acts := range allActions() {
		e, _ := Lookup(k)
		rk := registryKind{Entry: e}
		rk.Entry.Variants = nil
		for _, vr := range e.Variants {
			rk.Variants = append(rk.Variants, registryVariant{Name: vr.Name, Replace: vr.Replace, Entry: *vr.Entry})
		}
		reg.Kinds[k] = rk
		for _, a := range acts {
			all[a] = true
		}
	}
	raw, err := os.ReadFile("../../../probe/registry/shim-router.json")
	if err != nil {
		t.Fatal(err)
	}
	var shim struct {
		Services map[string]struct {
			Actions []string `json:"actions"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &shim); err != nil {
		t.Fatal(err)
	}
	for svc, s := range shim.Services {
		if len(s.Actions) == 0 {
			continue
		}
		acts := append([]string(nil), s.Actions...)
		sort.Strings(acts)
		reg.ShimActions[svc] = acts
		for _, a := range acts {
			all[a] = true
		}
	}
	for a := range all {
		reg.Actions = append(reg.Actions, a)
	}
	sort.Strings(reg.Actions)
	return reg
}

func TestIAMActionsRegistryIsCurrent(t *testing.T) {
	reg := buildIAMActionsRegistry(t)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(reg); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_REGISTRY") == "1" {
		if err := os.WriteFile(iamActionsPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	cur, err := os.ReadFile(iamActionsPath)
	if err != nil || !bytes.Equal(cur, buf.Bytes()) {
		t.Fatalf("%s is stale: run UPDATE_REGISTRY=1 go test ./internal/awsaction/ and commit it", iamActionsPath)
	}
}

// Every IAM action an aws-shim front door checks is in the registry, with its service's prefix.
func TestEveryShimActionIsListed(t *testing.T) {
	reg := buildIAMActionsRegistry(t)
	listed := map[string]bool{}
	for _, a := range reg.Actions {
		listed[a] = true
	}
	if len(reg.ShimActions) < 10 {
		t.Fatalf("only %d shim services with actions: shim-router.json is not being read", len(reg.ShimActions))
	}
	for svc, acts := range reg.ShimActions {
		for _, a := range acts {
			if !listed[a] || !actionRe.MatchString(a) {
				t.Errorf("shim %s: %q missing or malformed", svc, a)
			}
		}
	}
}
