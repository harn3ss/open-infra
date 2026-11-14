package render

import (
	"os"
	"strings"
	"testing"
)

// kind: Account spec.capacity: the operator's ceiling on what an account may reserve in each of its
// namespaces. The composition labels every namespace with each limit set; the compliance component's
// account-capacity policy turns each label into a ResourceQuota.

// Each label the composition writes, the ResourceQuota key the policy must turn it into.
var capacityLabels = map[string]string{
	"openinfra.dev/capacity-cpu":     "requests.cpu",
	"openinfra.dev/capacity-memory":  "requests.memory",
	"openinfra.dev/capacity-gpu":     "requests.nvidia.com/gpu",
	"openinfra.dev/capacity-storage": "requests.storage",
	"openinfra.dev/capacity-pods":    "count/pods",
}

func TestAccount_CapacityLabelsEveryNamespace(t *testing.T) {
	k := byKind(accountDocs(t, map[string]any{"accountId": "912345678901",
		"namespaces": []any{"team-a", "team-a-data"},
		"capacity":   map[string]any{"cpu": "16", "memory": "64Gi", "gpus": 1, "storage": "500Gi", "pods": 200}}, "000000000000"))
	if len(k["Namespace"]) != 2 {
		t.Fatalf("want both namespaces, got %d", len(k["Namespace"]))
	}
	want := map[string]string{
		"openinfra.dev/capacity-cpu": "16", "openinfra.dev/capacity-memory": "64Gi",
		"openinfra.dev/capacity-gpu": "1", "openinfra.dev/capacity-storage": "500Gi",
		"openinfra.dev/capacity-pods": "200",
	}
	for _, ns := range k["Namespace"] {
		for l, v := range want {
			if got := mstr(ns, "metadata", "labels", l); got != v {
				t.Errorf("%s: label %s = %q, want %q", mstr(ns, "metadata", "name"), l, got, v)
			}
		}
	}
}

// Every capacity label is always written, "none" for an unset limit: provider-kubernetes never removes a
// label it stops rendering, so "none" is how removing a limit reaches the namespace. gpus: 0 is a limit
// (none allowed), not "unset". A hand-set pod budget is not the composition's to write.
func TestAccount_CapacityUnsetIsNone(t *testing.T) {
	k := byKind(accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"}}, "000000000000"))
	for l := range capacityLabels {
		if got := mstr(k["Namespace"][0], "metadata", "labels", l); got != "none" {
			t.Errorf("no capacity: label %s = %q, want none", l, got)
		}
	}
	if got := mstr(k["Namespace"][0], "metadata", "labels", "openinfra.dev/pod-budget"); got != "" {
		t.Errorf("the composition must not write the hand-set pod budget, got %q", got)
	}

	k = byKind(accountDocs(t, map[string]any{"accountId": "912345678901", "namespaces": []any{"team-a"},
		"capacity": map[string]any{"gpus": 0, "memory": "8Gi"}}, "000000000000"))
	want := map[string]string{"openinfra.dev/capacity-gpu": "0", "openinfra.dev/capacity-memory": "8Gi",
		"openinfra.dev/capacity-cpu": "none", "openinfra.dev/capacity-storage": "none", "openinfra.dev/capacity-pods": "none"}
	for l, v := range want {
		if got := mstr(k["Namespace"][0], "metadata", "labels", l); got != v {
			t.Errorf("label %s = %q, want %q", l, got, v)
		}
	}
}

// The policy turns every label the composition writes into the right ResourceQuota key, only generates
// (never validates or blocks admission), fails open on a Kyverno outage, keeps quotas in step with the
// labels, and gives request-less containers a default request whenever cpu or memory is limited.
func TestAccountCapacityPolicy_MatchesTheComposition(t *testing.T) {
	raw, err := os.ReadFile("../../platform/compliance/account-capacity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := parseYAMLDocs(string(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var policy map[string]any
	var limitRangeRole bool
	for _, d := range docs {
		switch d["kind"] {
		case "ClusterPolicy":
			policy = d
		case "ClusterRole":
			for _, r := range mget(d, "rules").([]any) {
				if strings.Contains(strings.Join(toStrings(mget(r.(map[string]any), "resources")), ","), "limitranges") {
					limitRangeRole = mstr(d, "metadata", "labels", "rbac.kyverno.io/aggregate-to-background-controller") == "true"
				}
			}
		}
	}
	if policy == nil {
		t.Fatal("no ClusterPolicy")
	}
	if !limitRangeRole {
		t.Error("Kyverno's background controller needs a limitranges grant, aggregated into its role")
	}
	if mstr(policy, "spec", "failurePolicy") != "Ignore" {
		t.Error("failurePolicy must be Ignore: a generate policy must never fail admission closed")
	}
	quotas := map[string]string{} // label -> quota key generated for it
	defaults := map[string]bool{} // labels that trigger the default-requests LimitRange
	for _, r := range mget(policy, "spec", "rules").([]any) {
		rule := r.(map[string]any)
		if mget(rule, "validate") != nil || mget(rule, "mutate") != nil {
			t.Errorf("rule %s must only generate", mstr(rule, "name"))
		}
		gen, _ := mget(rule, "generate").(map[string]any)
		if gen == nil {
			t.Fatalf("rule %s generates nothing", mstr(rule, "name"))
		}
		if v := mget(gen, "synchronize"); v != true && v != "true" {
			t.Errorf("rule %s must synchronize, so the quota follows the label", mstr(rule, "name"))
		}
		// Each selector names one label: it must exist and not be "none" (an unset limit).
		var keys []string
		for _, a := range mget(rule, "match", "any").([]any) {
			exists, notNone, key := false, false, ""
			for _, e := range mget(a.(map[string]any), "resources", "selector", "matchExpressions").([]any) {
				ex := e.(map[string]any)
				if key != "" && mstr(ex, "key") != key {
					t.Errorf("rule %s: one selector must name one label", mstr(rule, "name"))
				}
				key = mstr(ex, "key")
				switch mstr(ex, "operator") {
				case "Exists":
					exists = true
				case "NotIn":
					notNone = strings.Join(toStrings(mget(ex, "values")), ",") == "none"
				}
			}
			if !exists || !notNone {
				t.Errorf("rule %s: label %s must be matched as Exists and NotIn [none]", mstr(rule, "name"), key)
			}
			keys = append(keys, key)
		}
		switch mstr(gen, "kind") {
		case "ResourceQuota":
			hard, _ := mget(gen, "data", "spec", "hard").(map[string]any)
			if len(keys) != 1 || len(hard) != 1 {
				t.Fatalf("rule %s: one label, one quota key; got %v %v", mstr(rule, "name"), keys, hard)
			}
			for q, v := range hard {
				quotas[keys[0]] = q
				if !strings.Contains(v.(string), keys[0]) {
					t.Errorf("rule %s: %s must take its value from label %s, got %v", mstr(rule, "name"), q, keys[0], v)
				}
			}
		case "LimitRange":
			for _, k := range keys {
				defaults[k] = true
			}
		}
	}
	for l, q := range capacityLabels {
		if quotas[l] != q {
			t.Errorf("label %s must generate quota %s, got %q", l, q, quotas[l])
		}
	}
	for l := range quotas {
		if _, ok := capacityLabels[l]; !ok {
			t.Errorf("policy matches label %s that the composition never writes", l)
		}
	}
	if !defaults["openinfra.dev/capacity-cpu"] || !defaults["openinfra.dev/capacity-memory"] || len(defaults) != 2 {
		t.Errorf("default requests must follow a cpu or memory limit (and only those), got %v", defaults)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
