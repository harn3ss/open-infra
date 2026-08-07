// Package datasource is the first-class, vendor-neutral data-source contract. It is
// deliberately its OWN package — not part of internal/dynamodb — so the contract owes nothing to any
// one source's shape: a resolver can target a DynamoDB-style store, an HTTP endpoint, or a Lambda
// without the engine or the resolver lifecycle ever branching on which. Only a Store implementation
// knows its own operation shape.
//
// Store is the CALL-source contract (the the call-vs-stream split distinction): a synchronous "give me this Operation, hand
// back a result". It fits DynamoDB, HTTP, Lambda, RDS — everything you *call*. A subscription's push
// source (a stream of events that call YOU) is a different kind of thing entirely and is NOT a Store.
package datasource

import (
	"context"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Store executes a neutral runtime.Operation and returns the plain-value result the response phase
// sees as $ctx.result. The Operation's shape is whatever the runtime rendered and this particular
// store understands — a DynamoDB op ({"operation":"GetItem",…}), an HTTP op ({"method":"POST",…}),
// etc. The context carries the request deadline/cancellation.
type Store interface {
	Execute(ctx context.Context, op runtime.Operation) (any, error)
}
