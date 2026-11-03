package render

// Knative's data path is shared by every tenant and routes by header: the Kourier gateway by Host, the
// activator by Knative-Serving-*. Without a policy on them, any pod could invoke any Function through
// them, skipping Invoke's authorization. platform/serverless/function-gateway-isolation.yaml admits only
// the platform's invokers to the gateway's internal listener, and only the gateway to the activator.

import (
	"os"
	"sort"
	"strings"
	"testing"
)

const gatewayPolicyFile = "../../platform/serverless/function-gateway-isolation.yaml"

func gatewayPolicies(t *testing.T) map[string]map[string]any {
	t.Helper()
	b, err := os.ReadFile(gatewayPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := parseYAMLDocs(string(b))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, d := range docs {
		if mstr(d, "kind") == "NetworkPolicy" {
			out[mstr(d, "metadata", "name")] = d
		}
	}
	return out
}

func rulePorts(r any) map[string]bool {
	out := map[string]bool{}
	ps, _ := mget(r, "ports").([]any)
	for _, p := range ps {
		out[mstr(p, "port")] = true
	}
	return out
}

// gatewayInvokerValues returns the openinfra.dev/function-invoker values a cross-namespace peer admits.
func gatewayInvokerValues(peer any) []string {
	exprs, _ := mget(peer, "podSelector", "matchExpressions").([]any)
	var vals []string
	for _, e := range exprs {
		if mstr(e, "key") != "openinfra.dev/function-invoker" || mstr(e, "operator") != "In" {
			return nil
		}
		vs, _ := mget(e, "values").([]any)
		for _, v := range vs {
			vals = append(vals, v.(string))
		}
	}
	sort.Strings(vals)
	return vals
}

func TestFunctionGateway_InternalListenerAdmitsOnlyInvokers(t *testing.T) {
	gw := gatewayPolicies(t)["kourier-gateway-isolation"]
	if gw == nil {
		t.Fatal("no kourier-gateway-isolation policy")
	}
	if mstr(gw, "metadata", "namespace") != "knative-serving" || mstr(gw, "spec", "podSelector", "matchLabels", "app") != "3scale-kourier-gateway" {
		t.Fatalf("the policy must select the Kourier gateway in knative-serving")
	}
	// Platform namespaces that may reach the internal listener, and the pod each must name (blank: the
	// whole namespace, Knative's own components).
	platform := map[string]string{"open-infra-aws-shim": "aws-shim", "crossplane-system": "openinfra-statemachine",
		"open-infra-console": "console", "knative-serving": ""}
	covered := false
	rules, _ := mget(gw, "spec", "ingress").([]any)
	for _, r := range rules {
		ports := rulePorts(r)
		if !ports["8081"] && !ports["8444"] {
			continue
		}
		covered = true
		from, _ := mget(r, "from").([]any)
		if len(from) == 0 {
			t.Fatalf("a from-less rule opens the internal listener to every pod")
		}
		for _, peer := range from {
			pm, _ := peer.(map[string]any)
			if ib, ok := pm["ipBlock"]; ok {
				if mstr(ib, "cidr") != isoJoinCIDR || mget(ib, "except") != nil {
					t.Errorf("ipBlock %s on the internal listener (only the join subnet, i.e. the host network)", mstr(ib, "cidr"))
				}
				continue
			}
			nsm, _ := pm["namespaceSelector"].(map[string]any)
			if nsm == nil {
				t.Errorf("a peer without a namespaceSelector (this would be knative-serving's own pods; name the namespace)")
				continue
			}
			if len(nsm) == 0 {
				if v := gatewayInvokerValues(peer); strings.Join(v, ",") != "graphqlapi,pump" {
					t.Errorf("an all-namespaces peer must select only the function-invoker label (pump, graphqlapi); got %v", v)
				}
				continue
			}
			n := strMap(nsm["matchLabels"])["kubernetes.io/metadata.name"]
			want, ok := platform[n]
			if !ok {
				t.Errorf("the internal listener admits namespace %q", n)
				continue
			}
			if got := mstr(pm, "podSelector", "matchLabels", "app"); got != want {
				t.Errorf("namespace %s: peer selects app=%q, want %q", n, got, want)
			}
		}
	}
	if !covered {
		t.Fatal("no rule covers the internal listener (8081/8444)")
	}
}

// The activator's data ports admit the gateway, which forwards requests, and Knative's own autoscaler,
// which probes each revision's public Service before scale-to-zero (blocking it stalls every
// PodAutoscaler). Both are pods in knative-serving itself; no other peer.
func TestFunctionGateway_ActivatorAdmitsOnlyTheGatewayAndAutoscaler(t *testing.T) {
	act := gatewayPolicies(t)["activator-isolation"]
	if act == nil {
		t.Fatal("no activator-isolation policy")
	}
	rules, _ := mget(act, "spec", "ingress").([]any)
	autoscalerProbes := false
	for _, r := range rules {
		from, _ := mget(r, "from").([]any)
		if len(from) == 0 {
			t.Fatal("a from-less rule opens the activator to every pod")
		}
		ports := rulePorts(r)
		if !ports["8012"] && !ports["8013"] {
			continue
		}
		for _, peer := range from {
			pm, _ := peer.(map[string]any)
			app := mstr(pm, "podSelector", "matchLabels", "app")
			if _, hasNS := pm["namespaceSelector"]; hasNS || (app != "3scale-kourier-gateway" && app != "autoscaler") {
				t.Errorf("the activator's data ports admit a peer other than the gateway or the autoscaler: %v", pm)
			}
			if app == "autoscaler" {
				if ports["8013"] || ports["8112"] {
					t.Errorf("the autoscaler needs only the probe port 8012: %v", ports)
				}
				autoscalerProbes = ports["8012"]
			}
		}
	}
	if !autoscalerProbes {
		t.Error("the autoscaler cannot probe the activator on 8012: every PodAutoscaler reconcile would time out")
	}
}

// The compositions set the function-invoker label the gateway admits: the trigger pump always, a
// GraphQLApi only when it has a lambda data source.
func TestFunctionGateway_InvokerLabels(t *testing.T) {
	podLabels := func(file string, spec map[string]any, kind string) []map[string]string {
		tmpl := extractInlineTemplate(t, "../../platform/abstraction/"+file)
		wl, _ := isoCollect(t, render(t, tmpl, isoCtx(spec)))
		var out []map[string]string
		for _, w := range wl {
			if w.kind == kind {
				out = append(out, w.labels)
			}
		}
		return out
	}
	pump := false
	for _, l := range podLabels("function-composition.yaml", map[string]any{"image": "ghcr.io/x/fn:1", "trigger": map[string]any{"stream": "orders"}}, "Deployment") {
		if l["openinfra.dev/function-invoker"] == "pump" {
			pump = true
		}
	}
	if !pump {
		t.Error("the trigger pump's pods do not carry openinfra.dev/function-invoker: pump")
	}
	gql := func(dsType string) string {
		for _, l := range podLabels("graphqlapi-composition.yaml", map[string]any{"schema": "type Query { a: String }",
			"dataSources": []any{map[string]any{"name": "d", "type": dsType, "endpoint": "http://fn.tenant-a.svc.cluster.local"}}}, "Deployment") {
			return l["openinfra.dev/function-invoker"]
		}
		t.Fatal("no GraphQLApi engine Deployment rendered")
		return ""
	}
	if got := gql("lambda"); got != "graphqlapi" {
		t.Errorf("a GraphQLApi with a lambda data source: function-invoker=%q, want graphqlapi", got)
	}
	if got := gql("http"); got != "" {
		t.Errorf("a GraphQLApi without a lambda data source must not carry function-invoker (got %q)", got)
	}
}
