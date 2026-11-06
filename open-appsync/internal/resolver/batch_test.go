package resolver_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// fakeBatchStore records each call: Execute (one op) and ExecuteBatch (one list of ops). Its batch answer
// is each op's payload "id" upper-cased; fail makes every batch call fail.
type fakeBatchStore struct {
	singles []runtime.Operation
	batches [][]runtime.Operation
	fail    error
}

func (s *fakeBatchStore) Execute(_ context.Context, op runtime.Operation) (any, error) {
	s.singles = append(s.singles, op)
	return map[string]any{"single": op["payload"]}, nil
}

func (s *fakeBatchStore) ExecuteBatch(_ context.Context, ops []runtime.Operation) ([]any, error) {
	s.batches = append(s.batches, ops)
	if s.fail != nil {
		return nil, s.fail
	}
	out := make([]any, len(ops))
	for i, op := range ops {
		out[i] = fmt.Sprintf("R-%v", op["payload"])
	}
	return out, nil
}

// plainStore is a source that cannot batch.
type plainStore struct{}

func (plainStore) Execute(context.Context, runtime.Operation) (any, error) { return "plain", nil }

// opRuntime emits the operation it is told to for each context (its "op" key), with the context's "id"
// as the payload, and passes the result through.
type opRuntime struct{}

func (opRuntime) RenderRequest(ctx map[string]any) (runtime.Operation, error) {
	return runtime.Operation{"operation": ctx["op"], "payload": ctx["id"]}, nil
}
func (opRuntime) RenderResponse(ctx map[string]any) (any, error) { return ctx["result"], nil }

func siblings(n int, op string) []map[string]any {
	ctxs := make([]map[string]any, n)
	for i := range ctxs {
		ctxs[i] = map[string]any{"op": op, "id": i}
	}
	return ctxs
}

func batchSizes(s *fakeBatchStore) []int {
	var sizes []int
	for _, b := range s.batches {
		sizes = append(sizes, len(b))
	}
	return sizes
}

// Sibling requests that are BatchInvokes go to the source together, maxBatchSize per call, and each
// sibling gets ITS item back, in order.
func TestResolveAll_BatchesSiblingsUpToMaxBatchSize(t *testing.T) {
	src := &fakeBatchStore{}
	r := resolver.Resolver{Runtime: opRuntime{}, Source: src, MaxBatchSize: 2}
	out := r.ResolveAll(context.Background(), siblings(5, "BatchInvoke"))
	if got := fmt.Sprint(batchSizes(src)); got != "[2 2 1]" {
		t.Errorf("batch sizes = %s, want [2 2 1]", got)
	}
	for i, o := range out {
		if o.Err != nil || o.Value != fmt.Sprintf("R-%d", i) {
			t.Errorf("sibling %d = %v / %v, want R-%d", i, o.Value, o.Err, i)
		}
	}
	if len(src.singles) != 0 {
		t.Errorf("no sibling may be invoked on its own (%d singles)", len(src.singles))
	}
}

// With no maxBatchSize a BatchInvoke carries AppSync's default of 5.
func TestResolveAll_DefaultBatchSizeIsFive(t *testing.T) {
	src := &fakeBatchStore{}
	resolver.Resolver{Runtime: opRuntime{}, Source: src}.ResolveAll(context.Background(), siblings(7, "BatchInvoke"))
	if got := fmt.Sprint(batchSizes(src)); got != "[5 2]" {
		t.Errorf("batch sizes = %s, want [5 2]", got)
	}
}

// An Invoke request is never batched, even on a source that could batch.
func TestResolveAll_InvokeRunsPerSibling(t *testing.T) {
	src := &fakeBatchStore{}
	out := resolver.Resolver{Runtime: opRuntime{}, Source: src, MaxBatchSize: 10}.ResolveAll(context.Background(), siblings(3, "Invoke"))
	if len(src.batches) != 0 || len(src.singles) != 3 {
		t.Errorf("Invoke: %d batches, %d singles; want 0 and 3", len(src.batches), len(src.singles))
	}
	if out[2].Value.(map[string]any)["single"] != 2 {
		t.Errorf("sibling 2 = %v", out[2].Value)
	}
}

// A failed batch call fails each of its items with the same error.
func TestResolveAll_FailedBatchFailsEveryItem(t *testing.T) {
	boom := errors.New("boom")
	src := &fakeBatchStore{fail: boom}
	for i, o := range (resolver.Resolver{Runtime: opRuntime{}, Source: src}).ResolveAll(context.Background(), siblings(3, "BatchInvoke")) {
		if !errors.Is(o.Err, boom) {
			t.Errorf("sibling %d err = %v, want the batch's error", i, o.Err)
		}
	}
}

// BatchInvoke on a source that cannot batch fails closed, naming the feature.
func TestResolveAll_BatchInvokeOnANonBatchSourceFailsClosed(t *testing.T) {
	_, err := resolver.Resolver{Runtime: opRuntime{}, Source: plainStore{}}.Resolve(context.Background(), map[string]any{"op": "BatchInvoke", "id": 1})
	if err == nil || err.Error() != "BatchInvoke is supported only on a Lambda data source" {
		t.Errorf("err = %v, want the unsupported-batch error", err)
	}
}

// Resolve of one context is a batch of one for a BatchInvoke request.
func TestResolve_BatchInvokeIsABatchOfOne(t *testing.T) {
	src := &fakeBatchStore{}
	v, err := resolver.Resolver{Runtime: opRuntime{}, Source: src}.Resolve(context.Background(), map[string]any{"op": "BatchInvoke", "id": 7})
	if err != nil || v != "R-7" || fmt.Sprint(batchSizes(src)) != "[1]" {
		t.Errorf("got %v, %v, batches %v; want R-7 in one batch of 1", v, err, batchSizes(src))
	}
}

// In a pipeline the siblings move through the functions together, so a function whose request is a
// BatchInvoke batches across them (its own maxBatchSize), and each sibling's result threads into
// $ctx.prev.result.
func TestPipelineResolveAll_FunctionBatchesAcrossSiblings(t *testing.T) {
	src := &fakeBatchStore{}
	p := &resolver.Pipeline{Functions: []resolver.Function{{Runtime: opRuntime{}, Source: src, MaxBatchSize: 3}}}
	out := resolver.Resolver{Pipeline: p, MaxBatchSize: 0}.ResolveAll(context.Background(), siblings(4, "BatchInvoke"))
	if got := fmt.Sprint(batchSizes(src)); got != "[3 1]" {
		t.Errorf("batch sizes = %s, want [3 1]", got)
	}
	for i, o := range out {
		if o.Err != nil || o.Value != fmt.Sprintf("R-%d", i) {
			t.Errorf("sibling %d = %v / %v, want R-%d", i, o.Value, o.Err, i)
		}
	}
}

// CanBatch: only a resolver with a step over a source that can batch gathers its siblings.
func TestCanBatch(t *testing.T) {
	if !(resolver.Resolver{Source: &fakeBatchStore{}}).CanBatch() {
		t.Error("a unit resolver over a batch source can batch")
	}
	if (resolver.Resolver{Source: plainStore{}}).CanBatch() {
		t.Error("a unit resolver over a plain source cannot batch")
	}
	p := &resolver.Pipeline{Functions: []resolver.Function{{Source: plainStore{}}, {Source: &fakeBatchStore{}}}}
	if !(resolver.Resolver{Pipeline: p}).CanBatch() {
		t.Error("a pipeline with a batch-source function can batch")
	}
}
