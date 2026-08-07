package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// Hostile-load guards (drop-33 §7): a pathological query must be REJECTED before any resolver runs,
// and the rejection must be proven (prove the "no", not just the "yes"). These are the negatives that
// make open-appsync safe to expose to untrusted clients.

func hostileEngine(limits graphql.Limits) *graphql.Engine {
	store := dynamodb.NewMemStore()
	r := resolver.Resolver{
		Runtime: vtlruntime.New(engine(), mustCorpus("getitem.request.vtl"), "$util.toJson($ctx.result)"),
		Source:  store,
	}
	return graphql.NewWithLimits(map[string]resolver.Resolver{"Query.getTodo": r}, limits)
}

// A query nested past MaxDepth is rejected with MaxDepthExceeded.
func TestHostileLoad_DepthRejected(t *testing.T) {
	e := hostileEngine(graphql.Limits{MaxDepth: 3})
	deep := "query { getTodo(id: \"1\") { a { b { c { d { e } } } } } }"
	res := e.Execute(context.Background(), deep, nil)
	if len(res.Errors) != 1 || res.Errors[0].ErrorType != "MaxDepthExceeded" {
		t.Fatalf("deep query must be rejected, got %+v", res.Errors)
	}
	if res.Data != nil {
		t.Fatalf("a rejected query must not return data, got %v", res.Data)
	}
}

// A query with more fields than MaxCost is rejected with MaxCostExceeded, before the resolver runs.
func TestHostileLoad_CostRejected(t *testing.T) {
	e := hostileEngine(graphql.Limits{MaxCost: 3})
	wide := "query { getTodo(id: \"1\") { a b c d e f g h } }"
	res := e.Execute(context.Background(), wide, nil)
	if len(res.Errors) != 1 || res.Errors[0].ErrorType != "MaxCostExceeded" {
		t.Fatalf("wide query must be rejected, got %+v", res.Errors)
	}
}

// PersistedOnly mode refuses an unregistered document and admits a registered one.
func TestHostileLoad_PersistedOnly(t *testing.T) {
	allowed := `query { getTodo(id: "1") { id } }`
	sum := sha256.Sum256([]byte(allowed))
	e := hostileEngine(graphql.Limits{PersistedOnly: true, Persisted: map[string]bool{hex.EncodeToString(sum[:]): true}})

	// Unregistered document → refused.
	res := e.Execute(context.Background(), `query { getTodo(id: "1") { id name } }`, nil)
	if len(res.Errors) != 1 || res.Errors[0].ErrorType != "PersistedQueryRequired" {
		t.Fatalf("unregistered query must be refused, got %+v", res.Errors)
	}
	// Registered document → runs (no limit error; getTodo miss returns null, not an error).
	res = e.Execute(context.Background(), allowed, nil)
	for _, ge := range res.Errors {
		if strings.Contains(ge.ErrorType, "Persisted") {
			t.Fatalf("registered query must be admitted, got %+v", res.Errors)
		}
	}
}

// Default limits admit an ordinary small query — the guards protect without blocking normal use.
func TestHostileLoad_DefaultsAdmitNormalQueries(t *testing.T) {
	e := hostileEngine(graphql.DefaultLimits())
	res := e.Execute(context.Background(), `query { getTodo(id: "1") { id name age } }`, nil)
	for _, ge := range res.Errors {
		if strings.HasSuffix(ge.ErrorType, "Exceeded") {
			t.Fatalf("a normal query must pass default limits, got %+v", res.Errors)
		}
	}
}
