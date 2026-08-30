// ASL (Amazon States Language) types and parsing for open-infra's kind: StateMachine.
//
// This is a faithful SUBSET of ASL: state types Task, Choice, Wait, Pass, Succeed,
// Fail, with Retry/Catch, TimeoutSeconds, and JSONPath data shaping
// (InputPath/Parameters/ResultPath/OutputPath). Parallel and Map are not parsed here
// (the engine rejects them with States.Runtime so the gap is loud, never silent).
package main

import (
	"encoding/json"
	"fmt"
)

// Definition is a parsed ASL document.
type Definition struct {
	Comment        string           `json:"Comment"`
	StartAt        string           `json:"StartAt"`
	TimeoutSeconds int              `json:"TimeoutSeconds"`
	States         map[string]State `json:"States"`
}

// State is the union of every ASL state type. Which fields are meaningful depends
// on Type; a single struct keeps parsing simple (ASL has no discriminated-union
// wire form beyond the Type field).
type State struct {
	Type    string `json:"Type"`
	Comment string `json:"Comment"`

	// Transitions (Task, Pass, Wait, Choice-branches use their own Next).
	Next string `json:"Next"`
	End  bool   `json:"End"`

	// Data shaping (Task, Pass; InputPath/OutputPath also on Wait/Choice).
	InputPath  Path            `json:"InputPath"`
	OutputPath Path            `json:"OutputPath"`
	ResultPath Path            `json:"ResultPath"`
	Parameters json.RawMessage `json:"Parameters"`

	// Task.
	Resource       string    `json:"Resource"`
	TimeoutSeconds int       `json:"TimeoutSeconds"`
	Retry          []Retrier `json:"Retry"`
	Catch          []Catcher `json:"Catch"`

	// Pass.
	Result json.RawMessage `json:"Result"`

	// Wait.
	Seconds       *int   `json:"Seconds"`
	SecondsPath   string `json:"SecondsPath"`
	Timestamp     string `json:"Timestamp"`
	TimestampPath string `json:"TimestampPath"`

	// Choice.
	Choices []ChoiceRule `json:"Choices"`
	Default string       `json:"Default"`

	// Fail.
	Error string `json:"Error"`
	Cause string `json:"Cause"`
}

// Retrier retries a failed Task on matching errors with exponential backoff.
type Retrier struct {
	ErrorEquals     []string `json:"ErrorEquals"`
	IntervalSeconds int      `json:"IntervalSeconds"`
	MaxAttempts     *int     `json:"MaxAttempts"`
	BackoffRate     float64  `json:"BackoffRate"`
	MaxDelaySeconds int      `json:"MaxDelaySeconds"`
}

func (r Retrier) interval() int {
	if r.IntervalSeconds > 0 {
		return r.IntervalSeconds
	}
	return 1
}
func (r Retrier) maxAttempts() int {
	if r.MaxAttempts != nil {
		return *r.MaxAttempts
	}
	return 3
}
func (r Retrier) backoff() float64 {
	if r.BackoffRate >= 1.0 {
		return r.BackoffRate
	}
	return 2.0
}

// Catcher routes a matching Task error to a fallback state.
type Catcher struct {
	ErrorEquals []string `json:"ErrorEquals"`
	Next        string   `json:"Next"`
	ResultPath  Path     `json:"ResultPath"`
}

// Standard ASL error names the engine produces.
const (
	ErrTaskFailed = "States.TaskFailed"
	ErrTimeout    = "States.Timeout"
	ErrRuntime    = "States.Runtime"
	ErrAll        = "States.ALL"
)

// matchesError reports whether an ErrorEquals set matches a produced error name.
// "States.ALL" matches anything (ASL requires it to be the sole element; we don't
// enforce that, we just treat it as a wildcard).
func matchesError(errorEquals []string, name string) bool {
	for _, e := range errorEquals {
		if e == ErrAll || e == name {
			return true
		}
	}
	return false
}

// Path models an ASL reference path field that must distinguish three states:
// absent (use the ASL default, "$"), explicit JSON null (discard), or a path string.
type Path struct {
	Set   bool
	Null  bool
	Value string
}

func (p *Path) UnmarshalJSON(b []byte) error {
	p.Set = true
	if string(b) == "null" {
		p.Null = true
		return nil
	}
	return json.Unmarshal(b, &p.Value)
}

// orDefault returns the path to use, treating absent as def and null as "" (discard).
func (p Path) orDefault(def string) string {
	if !p.Set {
		return def
	}
	if p.Null {
		return ""
	}
	return p.Value
}

// ParseDefinition parses an ASL JSON document and validates the reachable state graph.
func ParseDefinition(raw []byte) (*Definition, error) {
	var d Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("definition is not valid JSON: %w", err)
	}
	if d.StartAt == "" {
		return nil, fmt.Errorf("definition missing StartAt")
	}
	if len(d.States) == 0 {
		return nil, fmt.Errorf("definition has no States")
	}
	if _, ok := d.States[d.StartAt]; !ok {
		return nil, fmt.Errorf("StartAt %q is not a defined state", d.StartAt)
	}
	// Validate every Next/Default/Catch target resolves — a dangling transition
	// should fail at create time, not surface mid-execution.
	check := func(from, to string) error {
		if to == "" {
			return nil
		}
		if _, ok := d.States[to]; !ok {
			return fmt.Errorf("state %q transitions to undefined state %q", from, to)
		}
		return nil
	}
	for name, s := range d.States {
		if err := check(name, s.Next); err != nil {
			return nil, err
		}
		if err := check(name, s.Default); err != nil {
			return nil, err
		}
		for _, c := range s.Catch {
			if err := check(name, c.Next); err != nil {
				return nil, err
			}
		}
		for _, ch := range s.Choices {
			if err := check(name, ch.Next()); err != nil {
				return nil, err
			}
		}
	}
	return &d, nil
}
