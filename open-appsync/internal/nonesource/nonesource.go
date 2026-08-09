// Package nonesource is the "NONE" data source: a resolver with no backend, resolved entirely in the
// mapping templates. It mirrors AppSync's NONE data source — the request template returns
// {"version":"2018-05-29","payload": <any>} and that payload becomes $ctx.result for the response
// template. Useful for pub/sub-only fields (a mutation that only fans out to subscriptions), local
// computation, and stitching, without wiring a real store.
//
// It implements the same neutral datasource.Store contract as every other source; "no backend" is just
// a Store that echoes the request's payload back as the result.
package nonesource

import (
	"context"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Store resolves a field with no backend by returning the request operation's payload.
type Store struct{}

var _ datasource.Store = (*Store)(nil)

func New() *Store { return &Store{} }

// Execute returns op["payload"] (the AppSync NONE convention) as the result the response template sees.
// If no payload is present, it returns nil — the response template runs against an empty result.
func (Store) Execute(_ context.Context, op runtime.Operation) (any, error) {
	if p, ok := op["payload"]; ok {
		return p, nil
	}
	return nil, nil
}
