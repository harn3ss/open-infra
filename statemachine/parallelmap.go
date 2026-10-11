// ASL Parallel and Map states.
//
// Parallel runs each of its Branches concurrently over the same effective input; the state's result is
// the array of branch outputs in branch order. Map runs its Iterator/ItemProcessor over each element of
// an input array (ItemsPath), bounded by MaxConcurrency; the result is the array of per-item outputs in
// item order. Both honor Retry/Catch at the state level (via runRetryCatch) and shape through
// ResultPath/OutputPath like any other state.
//
// Sub-executions run as nested in-memory engines (subEngine). On a first sub-failure the state fails with
// that branch/item's error (by order); v1 lets the other sub-executions run to completion rather than
// aborting them — the RESULT is identical (the state fails), only some extra work is done.
package main

import (
	"context"
	"fmt"
	"sync"
)

func (e *Engine) runParallel(ctx context.Context, name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	if len(s.Branches) == 0 {
		return failRuntime("Parallel state has no Branches")
	}
	return e.runRetryCatch(ctx, name, s, effInput, func(ctx context.Context) (any, *taskError) {
		return e.runBranches(ctx, s.Branches, effInput)
	})
}

// runBranches runs every branch concurrently over the same input and returns the array of branch outputs
// in branch order, or the first failing branch's error (by order).
func (e *Engine) runBranches(ctx context.Context, branches []Definition, input any) (any, *taskError) {
	outs := make([]any, len(branches))
	errs := make([]*taskError, len(branches))
	var wg sync.WaitGroup
	for i := range branches {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := branches[i]
			se := e.subEngine(&b, copyCtx(e.ctxObj))
			res := se.Run(ctx, b.StartAt, input)
			if res.Phase == "Succeeded" {
				outs[i] = res.Output
			} else {
				errs[i] = &taskError{res.Error, res.Cause}
			}
		}(i)
	}
	wg.Wait()
	for _, er := range errs {
		if er != nil {
			return nil, er
		}
	}
	return outs, nil
}

func (e *Engine) runMap(ctx context.Context, name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	iter := s.iteratorDef()
	if iter == nil {
		return failRuntime("Map state has no Iterator/ItemProcessor")
	}
	// Select the input array via ItemsPath (default "$" = the whole input is the array).
	itemsVal, err := applyInputPath(effInput, e.ctxObj, s.ItemsPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	items, ok := itemsVal.([]any)
	if !ok {
		return failRuntime(fmt.Sprintf("Map ItemsPath %q did not resolve to an array", s.ItemsPath.orDefault("$")))
	}
	return e.runRetryCatch(ctx, name, s, effInput, func(ctx context.Context) (any, *taskError) {
		return e.runMapItems(ctx, s, iter, items)
	})
}

// runMapItems runs the iterator over each item (MaxConcurrency-bounded) and returns the array of per-item
// outputs in item order, or the first failing item's error (by order). Each item's iterator input is the
// item shaped through ItemSelector/Parameters (if set), with $$.Map.Item.{Index,Value} available.
func (e *Engine) runMapItems(ctx context.Context, s State, iter *Definition, items []any) (any, *taskError) {
	outs := make([]any, len(items))
	errs := make([]*taskError, len(items))

	conc := s.MaxConcurrency
	if conc <= 0 || conc > len(items) {
		conc = len(items)
	}
	if conc == 0 { // empty items array
		return []any{}, nil
	}
	sem := make(chan struct{}, conc)
	tmpl := s.itemTemplate()
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			mapCtx := copyCtx(e.ctxObj)
			// Index is a number in the engine's data model (float64, like every JSON number).
			mapCtx["Map"] = map[string]any{"Item": map[string]any{"Index": float64(i), "Value": items[i]}}
			itemInput := items[i]
			if len(tmpl) > 0 {
				v, perr := resolveParameters(tmpl, items[i], mapCtx)
				if perr != nil {
					errs[i] = &taskError{ErrRuntime, perr.Error()}
					return
				}
				itemInput = v
			}
			se := e.subEngine(iter, mapCtx)
			res := se.Run(ctx, iter.StartAt, itemInput)
			if res.Phase == "Succeeded" {
				outs[i] = res.Output
			} else {
				errs[i] = &taskError{res.Error, res.Cause}
			}
		}(i)
	}
	wg.Wait()
	for _, er := range errs {
		if er != nil {
			return nil, er
		}
	}
	return outs, nil
}
