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

// BatchStore is an OPTIONAL capability of a Store: execute several operations as ONE call and return
// one result per operation, in order. It is AppSync's BatchInvoke — the Lambda source implements it
// (the payloads of N sibling resolutions go to the function as one list, and the function answers one
// list). It is separate from Store on purpose, like runtime.Validator: a source that cannot batch
// simply does not implement it, and a resolver that asks it to batch fails closed rather than being
// silently resolved one call at a time.
type BatchStore interface {
	Store
	// ExecuteBatch runs ops as one call. On success it returns exactly len(ops) results, in order; a
	// failure of the whole call (or a response that cannot be matched back to the ops) is an error that
	// every op in the batch shares.
	ExecuteBatch(ctx context.Context, ops []runtime.Operation) ([]any, error)
}
