package main

import (
	"context"
	"reflect"
	"testing"
)

// mathInvoker: function:double -> n*2, function:inc -> n+1, function:boom -> States.TaskFailed, else echo.
func mathInvoker() *fakeInvoker {
	return &fakeInvoker{fn: func(resource string, input any) (any, *taskError) {
		switch resource {
		case "function:double":
			n, _ := toFloat(input)
			return n * 2, nil
		case "function:inc":
			n, _ := toFloat(input)
			return n + 1, nil
		case "function:boom":
			return nil, &taskError{ErrTaskFailed, "boom"}
		}
		return input, nil
	}}
}

func TestParallel_Success(t *testing.T) {
	def := mustDef(t, `{"StartAt":"P","States":{"P":{"Type":"Parallel","End":true,"Branches":[
		{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"function:double","End":true}}},
		{"StartAt":"B","States":{"B":{"Type":"Task","Resource":"function:inc","End":true}}}
	]}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "P", float64(5))
	if res.Phase != "Succeeded" {
		t.Fatalf("expected Succeeded, got %+v", res)
	}
	want := []any{float64(10), float64(6)} // branch order preserved
	if !reflect.DeepEqual(res.Output, want) {
		t.Fatalf("Parallel output = %#v, want %#v", res.Output, want)
	}
}

func TestParallel_BranchFailureFailsState(t *testing.T) {
	def := mustDef(t, `{"StartAt":"P","States":{"P":{"Type":"Parallel","End":true,"Branches":[
		{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"function:double","End":true}}},
		{"StartAt":"B","States":{"B":{"Type":"Task","Resource":"function:boom","End":true}}}
	]}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "P", float64(1))
	if res.Phase != "Failed" || res.Error != ErrTaskFailed {
		t.Fatalf("a failing branch must fail the Parallel with its error, got %+v", res)
	}
}

func TestParallel_Catch(t *testing.T) {
	def := mustDef(t, `{"StartAt":"P","States":{
		"P":{"Type":"Parallel","Catch":[{"ErrorEquals":["States.ALL"],"Next":"Fallback"}],"End":true,"Branches":[
			{"StartAt":"B","States":{"B":{"Type":"Task","Resource":"function:boom","End":true}}}
		]},
		"Fallback":{"Type":"Succeed"}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "P", nil)
	if res.Phase != "Succeeded" {
		t.Fatalf("a Catch on Parallel should route to Fallback and succeed, got %+v", res)
	}
}

func TestMap_Success(t *testing.T) {
	def := mustDef(t, `{"StartAt":"M","States":{"M":{"Type":"Map","End":true,"ItemsPath":"$.items",
		"Iterator":{"StartAt":"D","States":{"D":{"Type":"Task","Resource":"function:double","End":true}}}}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "M",
		map[string]any{"items": []any{float64(1), float64(2), float64(3)}})
	if res.Phase != "Succeeded" {
		t.Fatalf("expected Succeeded, got %+v", res)
	}
	want := []any{float64(2), float64(4), float64(6)} // item order preserved
	if !reflect.DeepEqual(res.Output, want) {
		t.Fatalf("Map output = %#v, want %#v", res.Output, want)
	}
}

// MaxConcurrency=1 still produces the ordered result.
func TestMap_MaxConcurrencyOne(t *testing.T) {
	def := mustDef(t, `{"StartAt":"M","States":{"M":{"Type":"Map","End":true,"MaxConcurrency":1,
		"Iterator":{"StartAt":"I","States":{"I":{"Type":"Task","Resource":"function:inc","End":true}}}}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "M", []any{float64(10), float64(20)})
	if res.Phase != "Succeeded" || !reflect.DeepEqual(res.Output, []any{float64(11), float64(21)}) {
		t.Fatalf("Map(conc=1) = %+v", res)
	}
}

// ItemSelector shapes each item and $$.Map.Item.Index is available.
func TestMap_ItemSelectorAndContext(t *testing.T) {
	def := mustDef(t, `{"StartAt":"M","States":{"M":{"Type":"Map","End":true,
		"ItemSelector":{"idx.$":"$$.Map.Item.Index","val.$":"$"},
		"ItemProcessor":{"StartAt":"P","States":{"P":{"Type":"Pass","End":true}}}}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "M", []any{"a", "b"})
	if res.Phase != "Succeeded" {
		t.Fatalf("expected Succeeded, got %+v", res)
	}
	want := []any{
		map[string]any{"idx": float64(0), "val": "a"},
		map[string]any{"idx": float64(1), "val": "b"},
	}
	if !reflect.DeepEqual(res.Output, want) {
		t.Fatalf("Map ItemSelector output = %#v, want %#v", res.Output, want)
	}
}

func TestMap_EmptyArray(t *testing.T) {
	def := mustDef(t, `{"StartAt":"M","States":{"M":{"Type":"Map","End":true,
		"Iterator":{"StartAt":"D","States":{"D":{"Type":"Task","Resource":"function:double","End":true}}}}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "M", []any{})
	if res.Phase != "Succeeded" || !reflect.DeepEqual(res.Output, []any{}) {
		t.Fatalf("empty Map should succeed with [], got %+v", res)
	}
}

func TestMap_ItemFailureFailsState(t *testing.T) {
	def := mustDef(t, `{"StartAt":"M","States":{"M":{"Type":"Map","End":true,
		"Iterator":{"StartAt":"B","States":{"B":{"Type":"Task","Resource":"function:boom","End":true}}}}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "M", []any{float64(1)})
	if res.Phase != "Failed" || res.Error != ErrTaskFailed {
		t.Fatalf("a failing iteration must fail the Map, got %+v", res)
	}
}

// Map over a non-array input is a loud runtime error, not a silent pass.
func TestMap_NonArrayInput(t *testing.T) {
	def := mustDef(t, `{"StartAt":"M","States":{"M":{"Type":"Map","End":true,"ItemsPath":"$.items",
		"Iterator":{"StartAt":"D","States":{"D":{"Type":"Task","Resource":"function:double","End":true}}}}}}`)
	res := newTestEngine(def, mathInvoker()).Run(context.Background(), "M", map[string]any{"items": "nope"})
	if res.Phase != "Failed" || res.Error != ErrRuntime {
		t.Fatalf("non-array ItemsPath should fail with States.Runtime, got %+v", res)
	}
}
