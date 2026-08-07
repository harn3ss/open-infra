package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/httpsource"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// The data-source neutrality proof (forward-map §5): an HTTP data source has a totally different
// Operation shape ({"method":…,"resourcePath":…}) from DynamoDB ({"operation":"GetItem",…}), yet a
// resolver targets it through the EXACT same resolver lifecycle and executor, with no code path
// branching on data-source type. If the neutral Operation were "a DynamoDB op in a trench coat" this
// could not work. It also confirms the second call-source is cheap now that DataSource is first-class.

// Compile-time: the HTTP source satisfies the same neutral contract as the DynamoDB stores.
var _ datasource.Store = (*httpsource.Store)(nil)

func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/users/123", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "123", "name": "Ada", "role": "admin"})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		_ = json.NewEncoder(w).Encode(map[string]any{"got": in, "method": r.Method})
	})
	return httptest.NewServer(mux)
}

// A GET resolver reads a user from the HTTP endpoint, through the same VTL runtime + lifecycle as any
// DynamoDB resolver — only the data source (and the operation it renders) differs.
func TestHTTPProbe_GetThroughSameLifecycle(t *testing.T) {
	ts := fakeAPI(t)
	defer ts.Close()

	getUser := resolver.Resolver{
		Runtime: vtlruntime.New(engine(),
			`{"method":"GET","resourcePath":"/users/$ctx.args.id"}`,
			`$util.toJson($ctx.result.body)`),
		Source: httpsource.New(ts.URL),
	}
	e := graphql.New(map[string]resolver.Resolver{"Query.getUser": getUser})

	res := e.Execute(context.Background(), `query { getUser(id:"123") { id name } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("http resolver errors: %+v", res.Errors)
	}
	want := map[string]any{"getUser": map[string]any{"id": "123", "name": "Ada"}}
	if !reflect.DeepEqual(res.Data, want) {
		t.Fatalf("http GET not faithful:\n got %v\nwant %v", res.Data, want)
	}
}

// A POST resolver sends a JSON body (params.body) and reads it back — exercising the request-shaping
// half of the HTTP operation.
func TestHTTPProbe_PostBody(t *testing.T) {
	ts := fakeAPI(t)
	defer ts.Close()

	echo := resolver.Resolver{
		Runtime: vtlruntime.New(engine(),
			`{"method":"POST","resourcePath":"/echo","params":{"body":{"name":$util.toJson($ctx.args.name)}}}`,
			`$util.toJson($ctx.result.body.got)`),
		Source: httpsource.New(ts.URL),
	}
	e := graphql.New(map[string]resolver.Resolver{"Mutation.echo": echo})
	res := e.Execute(context.Background(), `mutation { echo(name:"Ada") { name } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("http POST errors: %+v", res.Errors)
	}
	want := map[string]any{"echo": map[string]any{"name": "Ada"}}
	if !reflect.DeepEqual(res.Data, want) {
		t.Fatalf("http POST body not faithful:\n got %v\nwant %v", res.Data, want)
	}
}

// The clinching neutrality test: an HTTP resolver and a DynamoDB (memory) resolver live in ONE engine
// and both resolve. The lifecycle/executor never learns which is which.
func TestHTTPProbe_CoexistsWithDynamoDB(t *testing.T) {
	ts := fakeAPI(t)
	defer ts.Close()
	store := dynamodb.NewMemStore()

	e := graphql.New(map[string]resolver.Resolver{
		"Query.getUser": { // HTTP source
			Runtime: vtlruntime.New(engine(), `{"method":"GET","resourcePath":"/users/$ctx.args.id"}`, `$util.toJson($ctx.result.body)`),
			Source:  httpsource.New(ts.URL),
		},
		"Mutation.createTodo": { // DynamoDB source, different op shape entirely
			Runtime: vtlruntime.New(engine(), mustCorpus("putitem.request.vtl"), "$util.toJson($ctx.result)"),
			Source:  store,
		},
	})
	if r := e.Execute(context.Background(), `mutation { createTodo(input:{name:"x"}) { id } }`, nil); len(r.Errors) != 0 {
		t.Fatalf("dynamodb resolver errors: %+v", r.Errors)
	}
	if r := e.Execute(context.Background(), `query { getUser(id:"123") { role } }`, nil); len(r.Errors) != 0 {
		t.Fatalf("http resolver errors: %+v", r.Errors)
	}
}
