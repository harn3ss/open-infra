package probe

import (
	"context"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// The executor notifies the Publisher after a MUTATION field resolves successfully (the hook the
// subscription layer uses to push results), and never for a query — so a subscription only fires on the
// mutations that should trigger it.
type recordingPublisher struct {
	mu    sync.Mutex
	calls []string
}

func (p *recordingPublisher) PublishForMutation(_ context.Context, field string, _ any) {
	p.mu.Lock()
	p.calls = append(p.calls, field)
	p.mu.Unlock()
}

func TestPublisher_FiresOnMutationNotQuery(t *testing.T) {
	store := dynamodb.NewMemStore()
	pub := &recordingPublisher{}
	e := graphql.New(map[string]resolver.Resolver{
		"Mutation.createTodo": {Runtime: vtlruntime.New(engine(), mustCorpus("putitem.request.vtl"), "$util.toJson($ctx.result)"), Source: store},
		"Query.getTodo":       {Runtime: vtlruntime.New(engine(), mustCorpus("getitem.request.vtl"), "$util.toJson($ctx.result)"), Source: store},
	}, graphql.WithPublisher(pub))

	id := "11111111-2222-4333-8444-555555555555"
	if r := e.Execute(context.Background(), `mutation { createTodo(input:{name:"Ada"}) { id } }`, nil); len(r.Errors) != 0 {
		t.Fatalf("mutation errored: %+v", r.Errors)
	}
	if r := e.Execute(context.Background(), `query { getTodo(id:"`+id+`") { id } }`, nil); len(r.Errors) != 0 {
		t.Fatalf("query errored: %+v", r.Errors)
	}

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.calls) != 1 || pub.calls[0] != "createTodo" {
		t.Fatalf("publisher should fire once, for the mutation createTodo; got %v", pub.calls)
	}
}
