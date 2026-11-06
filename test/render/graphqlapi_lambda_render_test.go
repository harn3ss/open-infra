package render

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// #341: a GraphQLApi declares direct Lambda resolvers and BatchInvoke batching the AWS way — a resolver
// on a lambda data source with no request/response mapping template, maxBatchSize on the resolver or a
// pipeline function, and a lambda data source that names its function (as AppSync's LambdaConfig does)
// rather than a URL. The composition carries all of it into the engine's config.json.

const graphqlComposition = "../../platform/abstraction/graphqlapi-composition.yaml"

func graphqlLambdaCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{"uid": "u", "labels": map[string]any{
			"crossplane.io/claim-name": "blog", "crossplane.io/claim-namespace": "team-a"}},
	}}}}
}

func directLambdaSpec() map[string]any {
	return map[string]any{
		"schema":      "type Post { id: ID! author: String } type Query { posts: [Post] getPost(id: ID!): Post }",
		"dataSources": []any{map[string]any{"name": "fn", "type": "lambda", "function": "blog-fn"}},
		"resolvers": []any{
			map[string]any{"type": "Query", "field": "posts", "dataSource": "fn"},
			map[string]any{"type": "Post", "field": "author", "dataSource": "fn", "maxBatchSize": int64(10)},
			map[string]any{"type": "Query", "field": "getPost", "before": "{}", "after": "$util.toJson($ctx.prev.result)",
				"functions": []any{map[string]any{"dataSource": "fn", "maxBatchSize": int64(3)}}},
		},
	}
}

// engineConfig is the rendered config.json, parsed.
func engineConfig(t *testing.T, out string) map[string]any {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("render is not YAML: %v", err)
	}
	for _, d := range docs {
		m, _ := dig(d, "spec", "forProvider", "manifest").(map[string]any)
		if m["kind"] != "ConfigMap" {
			continue
		}
		raw, _ := dig(m, "data", "config.json").(string)
		var cfg map[string]any
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatalf("config.json is not JSON: %v\n%s", err, raw)
		}
		return cfg
	}
	t.Fatal("no engine ConfigMap rendered")
	return nil
}

func TestGraphQLApi_DirectLambdaAndBatching(t *testing.T) {
	tmpl := extractInlineTemplate(t, graphqlComposition)
	out := render(t, tmpl, graphqlLambdaCtx(directLambdaSpec()))
	cfg := engineConfig(t, out)

	ds := cfg["dataSources"].([]any)[0].(map[string]any)
	if ds["endpoint"] != "http://blog-fn.team-a.svc.cluster.local/" || ds["type"] != "lambda" {
		t.Errorf("a lambda source naming its function invokes it at its cluster-local URL; got %v", ds)
	}
	res := cfg["resolvers"].([]any)
	posts, author, getPost := res[0].(map[string]any), res[1].(map[string]any), res[2].(map[string]any)
	if posts["request"] != "" || posts["response"] != "" {
		t.Errorf("a direct Lambda resolver names no template files; got %v", posts)
	}
	if _, set := posts["maxBatchSize"]; set {
		t.Errorf("an unbatched resolver carries no maxBatchSize; got %v", posts)
	}
	if author["maxBatchSize"] != float64(10) {
		t.Errorf("Post.author maxBatchSize = %v, want 10", author["maxBatchSize"])
	}
	fn := getPost["functions"].([]any)[0].(map[string]any)
	if fn["maxBatchSize"] != float64(3) || fn["request"] != "" || fn["response"] != "" {
		t.Errorf("a direct pipeline function carries its maxBatchSize and no templates; got %v", fn)
	}
	for _, key := range []string{"Query.posts.request.vtl:", "Query.posts.response.vtl:", "Query.getPost.fn0.request.vtl:"} {
		if strings.Contains(out, key) {
			t.Errorf("no template file is written for a template left out (%s)", key)
		}
	}
	// It invokes a Function, so it passes the function gateway (function-invoker label).
	if !strings.Contains(out, "openinfra.dev/function-invoker: graphqlapi") {
		t.Errorf("a GraphQLApi with a lambda data source must carry the function-invoker label")
	}
}

// Setting maxBatchSize is a config change, so it rolls the engine (the checksum moves).
func TestGraphQLApi_MaxBatchSizeRollsTheEngine(t *testing.T) {
	tmpl := extractInlineTemplate(t, graphqlComposition)
	sum := regexp.MustCompile(`openinfra.dev/config-checksum: "([0-9a-f]+)"`)
	base := sum.FindStringSubmatch(render(t, tmpl, graphqlLambdaCtx(directLambdaSpec())))
	spec := directLambdaSpec()
	spec["resolvers"].([]any)[1].(map[string]any)["maxBatchSize"] = int64(20)
	changed := sum.FindStringSubmatch(render(t, tmpl, graphqlLambdaCtx(spec)))
	if base == nil || changed == nil || base[1] == changed[1] {
		t.Errorf("changing maxBatchSize must change the config checksum (%v vs %v)", base, changed)
	}
}

// Shapes the composition refuses, each naming what is wrong in AppSync's terms.
func TestGraphQLApi_LambdaRefusals(t *testing.T) {
	tmpl := extractInlineTemplate(t, graphqlComposition)
	cases := map[string]struct {
		mutate func(spec map[string]any)
		want   string
	}{
		"function on a non-lambda source": {func(s map[string]any) {
			s["dataSources"] = []any{map[string]any{"name": "fn", "type": "http", "function": "blog-fn"}}
		}, "in place of its endpoint"},
		"function and endpoint": {func(s map[string]any) {
			s["dataSources"] = []any{map[string]any{"name": "fn", "type": "lambda", "function": "blog-fn", "endpoint": "http://x/"}}
		}, "in place of its endpoint"},
		"function that is not a name": {func(s map[string]any) {
			s["dataSources"] = []any{map[string]any{"name": "fn", "type": "lambda", "function": "evil.example.com/#"}}
		}, "must be the name of a Lambda function"},
		"maxBatchSize on a pipeline resolver": {func(s map[string]any) {
			s["resolvers"].([]any)[2].(map[string]any)["maxBatchSize"] = int64(4)
		}, "its batching is configured on its functions"},
	}
	for name, c := range cases {
		spec := directLambdaSpec()
		c.mutate(spec)
		err := renderErr(tmpl, graphqlLambdaCtx(spec))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: render err = %v, want a refusal containing %q", name, err, c.want)
		}
	}

	// Admission rejects the same function/endpoint/type mismatch, and bounds maxBatchSize as AWS does.
	xrd := mustRead(t, "../../platform/abstraction/graphqlapi-xrd.yaml")
	if !strings.Contains(xrd, `rule: "!has(self.function) || (has(self.type) && self.type == 'lambda' && !has(self.endpoint))"`) {
		t.Error("graphqlapi-xrd.yaml must reject a data source function that is not a lambda source's, or that comes with an endpoint")
	}
	if n := strings.Count(xrd, "maxBatchSize:\n"); n != 2 {
		t.Errorf("maxBatchSize must be declared on resolvers and pipeline functions (found %d)", n)
	}
	if strings.Count(xrd, "maximum: 2000") != 2 {
		t.Error("maxBatchSize must be bounded at AWS's 2000")
	}
}
