package graphql

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/cache"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

const batchSDL = `
interface Node { id: ID! }
type Author implements Node { id: ID! name: String }
type Post implements Node { id: ID! title: String author: Author }
type Query { posts: [Post] node(id: ID!): Node }
`

// batchSource can batch: each batch answers {id: "a-" + source id} per op, and records its sizes.
type batchSource struct{ sizes []int }

func (s *batchSource) Execute(_ context.Context, op runtime.Operation) (any, error) {
	return nil, fmt.Errorf("batchSource: a BatchInvoke must not run on its own")
}

func (s *batchSource) ExecuteBatch(_ context.Context, ops []runtime.Operation) ([]any, error) {
	s.sizes = append(s.sizes, len(ops))
	out := make([]any, len(ops))
	for i, op := range ops {
		out[i] = map[string]any{"id": "a-" + op["payload"].(string)}
	}
	return out, nil
}

// batchRuntime emits a BatchInvoke with its source's id as the payload and passes the item through.
type batchRuntime struct{}

func (batchRuntime) RenderRequest(ctx map[string]any) (runtime.Operation, error) {
	return runtime.Operation{"operation": "BatchInvoke", "payload": ctx["source"].(map[string]any)["id"]}, nil
}
func (batchRuntime) RenderResponse(ctx map[string]any) (any, error) { return ctx["result"], nil }

func postsResolver(n int) resolver.Resolver {
	posts := make([]any, n)
	for i := range posts {
		posts[i] = map[string]any{"id": fmt.Sprintf("p%d", i)}
	}
	return resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: posts}}
}

func batchEngine(t *testing.T, n int, author resolver.Resolver, opts ...Option) *Engine {
	t.Helper()
	s, err := ParseSchema(batchSDL)
	if err != nil {
		t.Fatal(err)
	}
	return New(map[string]resolver.Resolver{"Query.posts": postsResolver(n), "Post.author": author}, append([]Option{WithSchema(s)}, opts...)...)
}

// A cached item is served from the cache and stays out of the batch; the rest are batched together.
func TestBatch_CachedItemsStayOutOfTheBatch(t *testing.T) {
	src := &batchSource{}
	author := resolver.Resolver{Runtime: batchRuntime{}, Source: src, MaxBatchSize: 10,
		Caching: &resolver.CachingConfig{TTL: time.Minute, Keys: []string{"source.id"}}}
	mem := cache.NewMem()
	e := batchEngine(t, 3, author, WithCache(mem))
	if res := e.Execute(context.Background(), `{ posts { author { id } } }`, nil); len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	e2 := batchEngine(t, 4, author, WithCache(mem))
	res := e2.Execute(context.Background(), `{ posts { author { id } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if got := fmt.Sprint(src.sizes); got != "[3 1]" {
		t.Errorf("batches = %s, want [3 1] (p0–p2 cached, only p3 batched)", got)
	}
	if id := res.Data["posts"].([]any)[3].(map[string]any)["author"].(map[string]any)["id"]; id != "a-p3" {
		t.Errorf("posts[3].author.id = %v", id)
	}
}

// A field the caller may not read is never sent to the function; each object reports the denial.
func TestBatch_DeniedFieldIsNotInvoked(t *testing.T) {
	src := &batchSource{}
	author := resolver.Resolver{Runtime: batchRuntime{}, Source: src, Auth: authz.Requirement{Resource: "posts", Verb: "get"}}
	e := batchEngine(t, 2, author, WithAuthorizer(denyAll{}))
	res := e.Execute(context.Background(), `{ posts { author { id } } }`, nil)
	if len(src.sizes) != 0 {
		t.Errorf("a denied field reached the function: batches %v", src.sizes)
	}
	if len(res.Errors) != 2 || res.Errors[0].ErrorType != "Unauthorized" || fmt.Sprint(res.Errors[1].Path) != "[posts 1 author]" {
		t.Errorf("errors = %+v, want Unauthorized on each object", res.Errors)
	}
}

// Aliased selections of the same field are separate resolutions: each batches across the list.
func TestBatch_AliasesBatchSeparately(t *testing.T) {
	src := &batchSource{}
	e := batchEngine(t, 3, resolver.Resolver{Runtime: batchRuntime{}, Source: src, MaxBatchSize: 10})
	res := e.Execute(context.Background(), `{ posts { a: author { id } b: author { id } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if got := fmt.Sprint(src.sizes); got != "[3 3]" {
		t.Errorf("batches = %s, want [3 3]", got)
	}
}

// $ctx.info: selectionSetList lists each selected field by its response key (nested as parent/child),
// expanding fragments that apply to the field's type; selectionSetGraphQL is the selection set as written.
func TestFieldInfo_SelectionSet(t *testing.T) {
	var seen map[string]any
	capture := resolver.Resolver{Runtime: fnRuntime{fn: func(ctx map[string]any) (any, error) {
		seen = ctx["info"].(map[string]any)
		return map[string]any{"__typename": "Post", "id": "p1"}, nil
	}}, Source: stubStore{}}
	s, err := ParseSchema(batchSDL)
	if err != nil {
		t.Fatal(err)
	}
	e := New(map[string]resolver.Resolver{"Query.node": capture}, WithSchema(s))
	res := e.Execute(context.Background(), `query Q($x: Boolean!) {
	  node(id: "p1") {
	    id
	    ... on Post { title }
	    ...F
	    gone: id @skip(if: $x)
	    __typename
	  }
	}
	fragment F on Node { nid: id }`, map[string]any{"x": true})
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if seen["fieldName"] != "node" || seen["parentTypeName"] != "Query" || !reflect.DeepEqual(seen["variables"], map[string]any{"x": true}) {
		t.Errorf("info = %v", seen)
	}
	// Node is an interface: the Post-only fragment is not the field's type's, so it is not listed.
	if got := seen["selectionSetList"]; !reflect.DeepEqual(got, []any{"id", "nid"}) {
		t.Errorf("selectionSetList = %v, want [id nid]", got)
	}
	want := "{\n  id\n  ... on Post {\n    title\n  }\n  ... F\n  gone: id @skip(if: $x)\n  __typename\n}"
	if got := seen["selectionSetGraphQL"]; got != want {
		t.Errorf("selectionSetGraphQL =\n%q\nwant\n%q", got, want)
	}
}

// Arguments print as GraphQL (in name order): strings quoted, variables as $name, lists and objects.
func TestPrintSelectionSet_Arguments(t *testing.T) {
	op, err := parseQuery(`{ f { a(s: "x\"y", n: 3, v: $v, l: [1, 2.5], o: {k: true, e: RED, z: null}) { b } } }`)
	if err != nil {
		t.Fatal(err)
	}
	got := printSelectionSet(op.selections[0].selections)
	want := "{\n  a(l: [1, 2.5], n: 3, o: {e: RED, k: true, z: null}, s: \"x\\\"y\", v: $v) {\n    b\n  }\n}"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if printSelectionSet(nil) != "" {
		t.Error("a scalar field's selection set is empty")
	}
}
