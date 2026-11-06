package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Engine-level tests of direct Lambda resolvers and BatchInvoke: the config is loaded the way the
// deployed engine loads it, GraphQL runs over the HTTP handler, and a fake Lambda (an httptest server
// speaking the runtime's direct-invoke contract) records every event it is invoked with.

const lambdaSDL = `
type Author { id: ID! name: String }
type Post { id: ID! title: String author: Author }
type Query { getPost(id: ID!): Post posts(n: Int): [Post] }
type Mutation { addPost(title: String): Post }
`

// fakeLambda is a function behind the direct-invoke contract: it answers each event with handle(event),
// or — when handle returns a thrownError — signals a thrown error the way the runtimes do (HTTP 200 with
// X-Amz-Function-Error and Lambda's error payload).
type fakeLambda struct {
	mu     sync.Mutex
	events []any
	srv    *httptest.Server
}

type thrownError struct{ errorType, errorMessage string }

func newFakeLambda(t *testing.T, handle func(event any) any) *fakeLambda {
	t.Helper()
	f := &fakeLambda{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Openinfra-Invoke") != "direct" {
			t.Errorf("the engine must invoke AWS-Invoke style (X-Openinfra-Invoke=%q)", r.Header.Get("X-Openinfra-Invoke"))
		}
		b, _ := io.ReadAll(r.Body)
		var ev any
		if err := json.Unmarshal(b, &ev); err != nil {
			t.Errorf("event is not JSON: %s", b)
		}
		f.mu.Lock()
		f.events = append(f.events, ev)
		f.mu.Unlock()
		out := handle(ev)
		if te, ok := out.(thrownError); ok {
			w.Header().Set("X-Amz-Function-Error", "Unhandled")
			out = map[string]any{"errorType": te.errorType, "errorMessage": te.errorMessage}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// batches is the size of each BatchInvoke the function received (an event that is a list).
func (f *fakeLambda) batches() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sizes []int
	for _, ev := range f.events {
		if l, ok := ev.([]any); ok {
			sizes = append(sizes, len(l))
		}
	}
	return sizes
}

// loadLambdaAPI writes config.json (dataSources = one lambda source "fn" at the fake's URL), the schema
// and any template files, and loads the engine.
func loadLambdaAPI(t *testing.T, fnURL, resolvers string, files map[string]string) http.HandlerFunc {
	t.Helper()
	dir := t.TempDir()
	write := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", `{"dataSources":[{"name":"fn","type":"lambda","endpoint":"`+fnURL+`"}],"resolvers":`+resolvers+`}`)
	write("schema.graphql", lambdaSDL)
	for n, c := range files {
		write(n, c)
	}
	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return Handler(engine)
}

type gqlResult struct {
	Data   map[string]any   `json:"data"`
	Errors []map[string]any `json:"errors"`
}

func postGraphQL(t *testing.T, h http.HandlerFunc, query string, vars map[string]any, headers map[string]string) gqlResult {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	var out gqlResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, rec.Body.String())
	}
	return out
}

// postsFn answers Query.posts with n posts p0…p(n-1), and a BatchInvoke for Post.author with authorItem
// per Context, in order. It fails the test on any other event.
func postsFn(t *testing.T, authorItems func(ctxs []any) any) func(any) any {
	return func(ev any) any {
		if list, ok := ev.([]any); ok {
			return authorItems(list)
		}
		m, _ := ev.(map[string]any)
		info, _ := m["info"].(map[string]any)
		if info["fieldName"] != "posts" {
			t.Errorf("unexpected single event %v", ev)
			return nil
		}
		n := 3
		if args, _ := m["arguments"].(map[string]any); args["n"] != nil {
			n = int(args["n"].(float64))
		}
		posts := make([]any, n)
		for i := range posts {
			posts[i] = map[string]any{"id": fmt.Sprintf("p%d", i), "title": fmt.Sprintf("T%d", i)}
		}
		return posts
	}
}

// authorData is the batched answer that resolves every post's author: {data: {id: a<i>}} per Context, read
// back from the Context's source (so the order is the function's own proof).
func authorData(ctxs []any) any {
	out := make([]any, len(ctxs))
	for i, c := range ctxs {
		src := c.(map[string]any)["source"].(map[string]any)
		out[i] = map[string]any{"data": map[string]any{"id": "a-" + src["id"].(string), "name": "N"}}
	}
	return out
}

// A direct Lambda resolver — no request and no response mapping template — sends AWS's Context as the
// event and the function's return value is the field's data.
func TestDirectLambda_SendsAWSContextAndReturnsData(t *testing.T) {
	fn := newFakeLambda(t, func(any) any {
		return map[string]any{"id": "p1", "title": "Hello", "author": map[string]any{"id": "a1", "name": "Ada"}}
	})
	h := loadLambdaAPI(t, fn.srv.URL, `[{"type":"Query","field":"getPost","dataSource":"fn"}]`, nil)

	res := postGraphQL(t, h, `query Q($id: ID!) { getPost(id: $id) { id t: title author { id name } } }`,
		map[string]any{"id": "p1"},
		map[string]string{"X-Custom": "hello", "Cookie": "session=secret", "X-OpenInfra-User": "ada", "X-OpenInfra-Groups": "readers"})
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	want := map[string]any{"id": "p1", "t": "Hello", "author": map[string]any{"id": "a1", "name": "Ada"}}
	if !reflect.DeepEqual(res.Data["getPost"], want) {
		t.Errorf("getPost = %v, want %v", res.Data["getPost"], want)
	}

	if len(fn.events) != 1 {
		t.Fatalf("want one invocation, got %d", len(fn.events))
	}
	ev := fn.events[0].(map[string]any)
	if fmt.Sprint(sortedKeys(ev)) != "[arguments identity info prev request source stash]" {
		t.Errorf("event keys = %v, want AWS's Context: arguments identity info prev request source stash", sortedKeys(ev))
	}
	if !reflect.DeepEqual(ev["arguments"], map[string]any{"id": "p1"}) {
		t.Errorf("arguments = %v", ev["arguments"])
	}
	if !reflect.DeepEqual(ev["identity"], map[string]any{"username": "ada", "groups": []any{"readers"}}) {
		t.Errorf("identity = %v", ev["identity"])
	}
	if ev["source"] != nil || ev["prev"] != nil {
		t.Errorf("a root field has a null source and prev: source=%v prev=%v", ev["source"], ev["prev"])
	}
	if !reflect.DeepEqual(ev["stash"], map[string]any{}) {
		t.Errorf("stash = %v, want {}", ev["stash"])
	}
	headers := ev["request"].(map[string]any)["headers"].(map[string]any)
	if headers["x-custom"] != "hello" {
		t.Errorf("request.headers = %v, want x-custom: hello", headers)
	}
	if _, ok := headers["cookie"]; ok {
		t.Error("AppSync leaves the cookie header out of request.headers")
	}
	if _, ok := headers["x-openinfra-user"]; ok {
		t.Error("the platform's identity headers are not the client's headers")
	}
	info := ev["info"].(map[string]any)
	wantInfo := map[string]any{
		"fieldName":           "getPost",
		"parentTypeName":      "Query",
		"variables":           map[string]any{"id": "p1"},
		"selectionSetList":    []any{"id", "t", "author", "author/id", "author/name"},
		"selectionSetGraphQL": "{\n  id\n  t: title\n  author {\n    id\n    name\n  }\n}",
	}
	if !reflect.DeepEqual(info, wantInfo) {
		t.Errorf("info =\n %#v\nwant\n %#v", info, wantInfo)
	}
}

func sortedKeys(m map[string]any) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A thrown error is the field's GraphQL error, with the thrown error's errorType and message, and the
// field is null.
func TestDirectLambda_ThrownErrorIsTheFieldsError(t *testing.T) {
	fn := newFakeLambda(t, func(any) any { return thrownError{"CustomException", "Custom message"} })
	h := loadLambdaAPI(t, fn.srv.URL, `[{"type":"Query","field":"getPost","dataSource":"fn"}]`, nil)
	res := postGraphQL(t, h, `{ getPost(id: "p1") { id } }`, nil, nil)
	if res.Data["getPost"] != nil {
		t.Errorf("getPost = %v, want null", res.Data["getPost"])
	}
	if len(res.Errors) != 1 || res.Errors[0]["errorType"] != "CustomException" || res.Errors[0]["message"] != "Custom message" ||
		fmt.Sprint(res.Errors[0]["path"]) != "[getPost]" {
		t.Errorf("errors = %v, want one CustomException \"Custom message\" at [getPost]", res.Errors)
	}
}

// A batched list field: Post.author on a direct resolver with maxBatchSize is ONE invocation for the
// whole list — a list of Contexts, each with its post as source — the results land in order, and an
// item's errorMessage/errorType is the error of exactly that item's path.
func TestDirectLambda_BatchedListFieldIsOneInvocation(t *testing.T) {
	fn := newFakeLambda(t, postsFn(t, func(ctxs []any) any {
		items := authorData(ctxs).([]any)
		items[1] = map[string]any{"data": nil, "errorMessage": "Not found", "errorType": "NotFound"}
		return items
	}))
	h := loadLambdaAPI(t, fn.srv.URL, `[
	  {"type":"Query","field":"posts","dataSource":"fn"},
	  {"type":"Post","field":"author","dataSource":"fn","maxBatchSize":10}]`, nil)

	res := postGraphQL(t, h, `{ posts { id author { id } } }`, nil, nil)

	if got := fmt.Sprint(fn.batches()); got != "[3]" {
		t.Fatalf("author batches = %s, want one batch of 3", got)
	}
	if len(fn.events) != 2 {
		t.Errorf("invocations = %d, want 2 (posts, then one batch for the authors)", len(fn.events))
	}
	for i, c := range fn.events[1].([]any) {
		ctx := c.(map[string]any)
		if ctx["source"].(map[string]any)["id"] != fmt.Sprintf("p%d", i) {
			t.Errorf("batch item %d source = %v, want post p%d", i, ctx["source"], i)
		}
		info := ctx["info"].(map[string]any)
		if info["fieldName"] != "author" || info["parentTypeName"] != "Post" {
			t.Errorf("batch item %d info = %v", i, info)
		}
	}
	posts := res.Data["posts"].([]any)
	if a := posts[0].(map[string]any)["author"].(map[string]any); a["id"] != "a-p0" {
		t.Errorf("posts[0].author = %v, want a-p0", a)
	}
	if posts[1].(map[string]any)["author"] != nil {
		t.Errorf("posts[1].author = %v, want null (its item errored)", posts[1].(map[string]any)["author"])
	}
	if a := posts[2].(map[string]any)["author"].(map[string]any); a["id"] != "a-p2" {
		t.Errorf("posts[2].author = %v, want a-p2", a)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("errors = %v, want exactly one", res.Errors)
	}
	e := res.Errors[0]
	if fmt.Sprint(e["path"]) != "[posts 1 author]" || e["errorType"] != "NotFound" || e["message"] != "Not found" {
		t.Errorf("error = %v, want NotFound \"Not found\" at [posts 1 author]", e)
	}
}

// maxBatchSize splits the siblings into batches of at most that many, and the results stay in order
// across the batches.
func TestDirectLambda_MaxBatchSizeSplits(t *testing.T) {
	fn := newFakeLambda(t, postsFn(t, authorData))
	h := loadLambdaAPI(t, fn.srv.URL, `[
	  {"type":"Query","field":"posts","dataSource":"fn"},
	  {"type":"Post","field":"author","dataSource":"fn","maxBatchSize":2}]`, nil)
	res := postGraphQL(t, h, `{ posts(n: 5) { author { id } } }`, nil, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if got := fmt.Sprint(fn.batches()); got != "[2 2 1]" {
		t.Errorf("batches = %s, want [2 2 1]", got)
	}
	for i, p := range res.Data["posts"].([]any) {
		if id := p.(map[string]any)["author"].(map[string]any)["id"]; id != fmt.Sprintf("a-p%d", i) {
			t.Errorf("posts[%d].author.id = %v, want a-p%d", i, id, i)
		}
	}
}

// A batch response of the wrong length cannot be matched back to the batch: every item of it fails, on
// its own path, and the function's partial answer is not used.
func TestDirectLambda_BatchLengthMismatchFailsEveryItem(t *testing.T) {
	fn := newFakeLambda(t, postsFn(t, func(ctxs []any) any { return authorData(ctxs).([]any)[:2] }))
	h := loadLambdaAPI(t, fn.srv.URL, `[
	  {"type":"Query","field":"posts","dataSource":"fn"},
	  {"type":"Post","field":"author","dataSource":"fn","maxBatchSize":10}]`, nil)
	res := postGraphQL(t, h, `{ posts { id author { id } } }`, nil, nil)
	if len(res.Errors) != 3 {
		t.Fatalf("errors = %v, want one per item (3)", res.Errors)
	}
	for i, e := range res.Errors {
		if fmt.Sprint(e["path"]) != fmt.Sprintf("[posts %d author]", i) || e["errorType"] != "BatchInvokeResponseMismatch" ||
			!strings.Contains(e["message"].(string), "returned 2 results for a batch of 3") {
			t.Errorf("error %d = %v", i, e)
		}
	}
	for i, p := range res.Data["posts"].([]any) {
		if p.(map[string]any)["author"] != nil {
			t.Errorf("posts[%d].author = %v, want null", i, p.(map[string]any)["author"])
		}
	}
}

// A thrown error fails the whole batch: every item carries it.
func TestDirectLambda_BatchThrownErrorFailsEveryItem(t *testing.T) {
	fn := newFakeLambda(t, postsFn(t, func([]any) any { return thrownError{"DBDown", "no connection"} }))
	h := loadLambdaAPI(t, fn.srv.URL, `[
	  {"type":"Query","field":"posts","dataSource":"fn"},
	  {"type":"Post","field":"author","dataSource":"fn","maxBatchSize":10}]`, nil)
	res := postGraphQL(t, h, `{ posts { author { id } } }`, nil, nil)
	if len(res.Errors) != 3 {
		t.Fatalf("errors = %v, want 3", res.Errors)
	}
	for _, e := range res.Errors {
		if e["errorType"] != "DBDown" || e["message"] != "no connection" {
			t.Errorf("error = %v, want DBDown \"no connection\"", e)
		}
	}
}

// A VTL resolver whose request template emits BatchInvoke: the template runs per item, the payloads are
// merged into one list per batch (AppSync's default of 5 per batch with no maxBatchSize), each item's
// $ctx.result is its element, and the response template raises the per-item error with $util.error.
func TestVTLBatchInvoke_PayloadListAndResponseTemplatePerItem(t *testing.T) {
	fn := newFakeLambda(t, func(ev any) any {
		if list, ok := ev.([]any); ok {
			out := make([]any, len(list))
			for i, p := range list {
				id := p.(map[string]any)["postId"].(string)
				out[i] = map[string]any{"data": map[string]any{"id": "a-" + id}}
				if id == "p6" {
					out[i] = map[string]any{"data": map[string]any{"id": "partial"}, "errorMessage": "Error Happened", "errorType": "ERROR"}
				}
			}
			return out
		}
		posts := make([]any, 7)
		for i := range posts {
			posts[i] = map[string]any{"id": fmt.Sprintf("p%d", i)}
		}
		return posts
	})
	h := loadLambdaAPI(t, fn.srv.URL, `[
	  {"type":"Query","field":"posts","dataSource":"fn","request":"posts.req.vtl","response":"posts.resp.vtl"},
	  {"type":"Post","field":"author","dataSource":"fn","request":"author.req.vtl","response":"author.resp.vtl"}]`,
		map[string]string{
			"posts.req.vtl":  `{"version":"2018-05-29","operation":"Invoke","payload":{"field":"posts"}}`,
			"posts.resp.vtl": `$util.toJson($ctx.result)`,
			"author.req.vtl": `{"version":"2018-05-29","operation":"BatchInvoke","payload":{"postId":$util.toJson($ctx.source.id)}}`,
			"author.resp.vtl": `#if($ctx.result && $ctx.result.errorMessage)
$util.error($ctx.result.errorMessage, $ctx.result.errorType, $ctx.result.data)
#else
$util.toJson($ctx.result.data)
#end`,
		})
	res := postGraphQL(t, h, `{ posts { id author { id } } }`, nil, nil)

	if got := fmt.Sprint(fn.batches()); got != "[5 2]" {
		t.Errorf("batches = %s, want [5 2] (AppSync's default batch size)", got)
	}
	if first := fn.events[1].([]any)[0]; !reflect.DeepEqual(first, map[string]any{"postId": "p0"}) {
		t.Errorf("batch item 0 = %v, want the rendered payload {postId: p0}", first)
	}
	posts := res.Data["posts"].([]any)
	for i := 0; i < 6; i++ {
		if id := posts[i].(map[string]any)["author"].(map[string]any)["id"]; id != fmt.Sprintf("a-p%d", i) {
			t.Errorf("posts[%d].author.id = %v", i, id)
		}
	}
	if posts[6].(map[string]any)["author"] != nil {
		t.Errorf("posts[6].author = %v, want null", posts[6].(map[string]any)["author"])
	}
	if len(res.Errors) != 1 || fmt.Sprint(res.Errors[0]["path"]) != "[posts 6 author]" || res.Errors[0]["errorType"] != "ERROR" ||
		res.Errors[0]["message"] != "Error Happened" || !reflect.DeepEqual(res.Errors[0]["data"], map[string]any{"id": "partial"}) {
		t.Errorf("errors = %v, want ERROR \"Error Happened\" with its data at [posts 6 author]", res.Errors)
	}
}

// A root field of a batching resolver is a batch of one — the function still receives a list; a
// mutation is never batched with another (AppSync runs mutations one after another).
func TestDirectLambda_RootBatchingIsABatchOfOne(t *testing.T) {
	fn := newFakeLambda(t, func(ev any) any {
		list := ev.([]any)
		return []any{map[string]any{"data": map[string]any{"id": "new", "title": list[0].(map[string]any)["arguments"].(map[string]any)["title"]}}}
	})
	h := loadLambdaAPI(t, fn.srv.URL, `[{"type":"Mutation","field":"addPost","dataSource":"fn","maxBatchSize":5}]`, nil)
	res := postGraphQL(t, h, `mutation { a: addPost(title: "x") { id title } b: addPost(title: "y") { title } }`, nil, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if got := fmt.Sprint(fn.batches()); got != "[1 1]" {
		t.Errorf("batches = %s, want [1 1]", got)
	}
	if res.Data["a"].(map[string]any)["title"] != "x" || res.Data["b"].(map[string]any)["title"] != "y" {
		t.Errorf("data = %v", res.Data)
	}
}

// A direct Lambda function in a pipeline batches across the siblings with its own maxBatchSize, and its
// Context carries the pipeline's stash.
func TestDirectLambda_PipelineFunctionBatches(t *testing.T) {
	fn := newFakeLambda(t, postsFn(t, func(ctxs []any) any {
		for i, c := range ctxs {
			if c.(map[string]any)["stash"].(map[string]any)["tag"] != "set-by-before" {
				t.Errorf("batch item %d stash = %v", i, c.(map[string]any)["stash"])
			}
		}
		return authorData(ctxs)
	}))
	h := loadLambdaAPI(t, fn.srv.URL, `[
	  {"type":"Query","field":"posts","dataSource":"fn"},
	  {"type":"Post","field":"author","before":"before.vtl","after":"after.vtl",
	   "functions":[{"dataSource":"fn","maxBatchSize":2}]}]`,
		map[string]string{
			"before.vtl": `#set($d = $ctx.stash.put("tag", "set-by-before"))`,
			"after.vtl":  `$util.toJson($ctx.prev.result)`,
		})
	res := postGraphQL(t, h, `{ posts { author { id } } }`, nil, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if got := fmt.Sprint(fn.batches()); got != "[2 1]" {
		t.Errorf("batches = %s, want [2 1]", got)
	}
	if id := res.Data["posts"].([]any)[2].(map[string]any)["author"].(map[string]any)["id"]; id != "a-p2" {
		t.Errorf("posts[2].author.id = %v", id)
	}
}

// An asynchronous invoke (invocationType Event) is not served: the field fails with an error naming it,
// never a silent null, and the function is not called.
func TestLambda_EventInvocationFailsClosed(t *testing.T) {
	fn := newFakeLambda(t, func(any) any { return map[string]any{"id": "x"} })
	h := loadLambdaAPI(t, fn.srv.URL, `[{"type":"Query","field":"getPost","dataSource":"fn","request":"req.vtl","response":"resp.vtl"}]`,
		map[string]string{
			"req.vtl":  `{"version":"2018-05-29","operation":"Invoke","invocationType":"Event","payload":{}}`,
			"resp.vtl": `$util.toJson($ctx.result)`,
		})
	res := postGraphQL(t, h, `{ getPost(id: "1") { id } }`, nil, nil)
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0]["message"].(string), "invocationType Event") {
		t.Errorf("errors = %v, want one naming invocationType Event", res.Errors)
	}
	if len(fn.events) != 0 {
		t.Errorf("the function must not be invoked (%d events)", len(fn.events))
	}
}

// Shapes open-appsync does not serve refuse to load, naming the feature — never a resolver that would
// silently resolve to null.
func TestLoad_UnsupportedLambdaShapesFailClosed(t *testing.T) {
	cases := map[string]struct {
		dataSources, resolvers string
		files                  map[string]string
		want                   string
	}{
		"no templates on a non-Lambda source": {
			`[{"name":"m","type":"memory"}]`, `[{"type":"Query","field":"getPost","dataSource":"m"}]`, nil,
			"only a resolver on a lambda data source may leave its mapping templates out",
		},
		"maxBatchSize on a non-Lambda source": {
			`[{"name":"m","type":"memory"}]`, `[{"type":"Query","field":"getPost","dataSource":"m","request":"q","response":"r","maxBatchSize":5}]`,
			map[string]string{"q": `{"operation":"Scan"}`, "r": `$util.toJson($ctx.result)`},
			"needs a lambda data source",
		},
		"maxBatchSize over AWS's limit": {
			`[{"name":"fn","type":"lambda","endpoint":"http://unused"}]`, `[{"type":"Query","field":"getPost","dataSource":"fn","maxBatchSize":2001}]`, nil,
			"maxBatchSize must be from 0 to 2000",
		},
		"maxBatchSize on a pipeline resolver": {
			`[{"name":"fn","type":"lambda","endpoint":"http://unused"}]`, `[{"type":"Query","field":"getPost","maxBatchSize":3,"functions":[{"dataSource":"fn"}]}]`, nil,
			"batching is configured on its Lambda functions",
		},
		"APPSYNC_JS with no code": {
			`[{"name":"fn","type":"lambda","endpoint":"http://unused"}]`, `[{"type":"Query","field":"getPost","dataSource":"fn","runtime":"appsync-js"}]`, nil,
			"needs its code",
		},
	}
	for name, c := range cases {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"dataSources":`+c.dataSources+`,"resolvers":`+c.resolvers+`}`), 0o644)
		for n, body := range c.files {
			_ = os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644)
		}
		_, err := Load(dir, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load err = %v, want one containing %q", name, err, c.want)
		}
	}
}

// BatchInvoke on a data source that cannot batch fails the field with an error naming the feature.
func TestBatchInvoke_OnANonLambdaSourceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"dataSources":[{"name":"n","type":"none"}],
	  "resolvers":[{"type":"Query","field":"getPost","dataSource":"n","request":"q","response":"r"}]}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "q"), []byte(`{"version":"2018-05-29","operation":"BatchInvoke","payload":{}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "r"), []byte(`$util.toJson($ctx.result)`), 0o644)
	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := postGraphQL(t, Handler(engine), `{ getPost(id: "1") { id } }`, nil, nil)
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0]["message"].(string), "BatchInvoke is supported only on a Lambda data source") {
		t.Errorf("errors = %v", res.Errors)
	}
}
