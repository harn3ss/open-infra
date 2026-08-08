package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
)

// A subscription trigger declared ONLY via SDL @aws_subscribe (no config triggeredBy) must still fire:
// a createTodo mutation reaches the onCreateTodo subscriber. Proves LoadSubscriptions merges SDL triggers.
func TestLoadSubscriptions_AwsSubscribeFromSDL(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// config.json declares the subscription but deliberately omits triggeredBy — the trigger comes from SDL.
	w("config.json", `{
	  "dataSources": [{"name":"todos","type":"memory"}],
	  "resolvers": [{"type":"Mutation","field":"createTodo","dataSource":"todos","request":"put.vtl","response":"resp.vtl"}],
	  "subscriptions": [{"field":"onCreateTodo","response":"onCreateTodo.subscription.response.vtl"}]
	}`)
	w("put.vtl", `{"version":"2018-05-29","operation":"PutItem","key":{"id":$util.dynamodb.toDynamoDBJson($util.autoId())},"attributeValues":$util.dynamodb.toMapValuesJson($ctx.args.input)}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)
	w("onCreateTodo.subscription.response.vtl", `$util.toJson($ctx.result)`)
	w("schema.graphql", `
type Todo { id: ID! name: String! }
type Mutation { createTodo(input: CreateTodoInput!): Todo }
input CreateTodoInput { name: String! }
type Subscription { onCreateTodo: Todo @aws_subscribe(mutations: ["createTodo"]) }
`)

	mgr, pub, err := LoadSubscriptions(dir, subscription.NewMemBus(), authz.AllowAll{})
	if err != nil {
		t.Fatalf("LoadSubscriptions: %v", err)
	}
	if mgr == nil || pub == nil {
		t.Fatal("expected a manager + publisher")
	}
	ctx := context.Background()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	got := make(chan any, 1)
	unsub, err := mgr.Subscribe(ctx, "conn1", "onCreateTodo", subscription.FilterGroup{}, func(v any) { got <- v })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	// A createTodo success — the mutation named by @aws_subscribe — must reach the subscriber.
	pub.PublishForMutation(ctx, "createTodo", map[string]any{"id": "t1", "name": "Ada"})

	select {
	case <-got:
		// delivered — the SDL-declared trigger wired createTodo → onCreateTodo
	case <-time.After(2 * time.Second):
		t.Fatal("no delivery: @aws_subscribe trigger was not wired from the SDL")
	}
}
