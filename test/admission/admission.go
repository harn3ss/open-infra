// Package admission evaluates the platform's ValidatingAdmissionPolicies offline: each policy's CEL
// (matchConditions, variables, validations) runs against admission requests the way the API server runs
// it, so a rule that lets the wrong write through, or refuses the right one, fails a test rather than
// a live cluster. Objects are untyped (dyn); the API server also type-checks each expression against
// the resource's schema when the policy is applied (status.typeChecking).
package admission

import (
	"fmt"
	"os"

	"cel.dev/cel-go/cel"
	"gopkg.in/yaml.v3"
)

// Policy is the part of a ValidatingAdmissionPolicy the evaluator needs.
type Policy struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		FailurePolicy    string `yaml:"failurePolicy"`
		MatchConstraints struct {
			ResourceRules []struct {
				APIGroups   []string `yaml:"apiGroups"`
				APIVersions []string `yaml:"apiVersions"`
				Operations  []string `yaml:"operations"`
				Resources   []string `yaml:"resources"`
			} `yaml:"resourceRules"`
		} `yaml:"matchConstraints"`
		MatchConditions []Named `yaml:"matchConditions"`
		Variables       []Named `yaml:"variables"`
		Validations     []struct {
			Expression string `yaml:"expression"`
			Message    string `yaml:"message"`
			Reason     string `yaml:"reason"`
		} `yaml:"validations"`
	} `yaml:"spec"`
}

// Named is a matchCondition or a variable.
type Named struct {
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
}

// Load returns the ValidatingAdmissionPolicy named name from a multi-document manifest.
func Load(path, name string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	for {
		var p Policy
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%s: no ValidatingAdmissionPolicy %s (%v)", path, name, err)
		}
		if p.Kind == "ValidatingAdmissionPolicy" && p.Metadata.Name == name {
			return &p, nil
		}
	}
}

// Request is one admission request: the operation, where, who, and the object before and after.
type Request struct {
	Operation string // CREATE, UPDATE, DELETE
	Namespace string
	Username  string
	Groups    []string
	Object    map[string]any // nil on DELETE
	OldObject map[string]any // nil on CREATE
}

// Verdict is the policy's answer: Matched is false when a matchCondition excluded the request (it is
// then admitted without validation); Denied names the first failing validation's message.
type Verdict struct {
	Matched bool
	Denied  string
}

// Allowed reports whether the request is admitted.
func (v Verdict) Allowed() bool { return v.Denied == "" }

var env = func() *cel.Env {
	e, err := cel.NewEnv(
		cel.Variable("request", cel.DynType),
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		panic(err)
	}
	return e
}()

func eval(expr string, act map[string]any) (any, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile %q: %w", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program %q: %w", expr, err)
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("eval %q: %w", expr, err)
	}
	return out.Value(), nil
}

// Admit runs the policy against r. An expression that fails to compile or evaluate is an error (the
// API server would refuse the request under failurePolicy: Fail); a test treats it as a bug.
func (p *Policy) Admit(r Request) (Verdict, error) {
	groups := make([]any, len(r.Groups))
	for i, g := range r.Groups {
		groups[i] = g
	}
	vars := map[string]any{}
	act := map[string]any{
		"request": map[string]any{
			"operation": r.Operation,
			"namespace": r.Namespace,
			"userInfo":  map[string]any{"username": r.Username, "groups": groups},
		},
		"object":    nilable(r.Object),
		"oldObject": nilable(r.OldObject),
		"variables": vars,
	}
	for _, m := range p.Spec.MatchConditions {
		v, err := eval(m.Expression, act)
		if err != nil {
			return Verdict{}, fmt.Errorf("matchCondition %s: %w", m.Name, err)
		}
		if b, ok := v.(bool); !ok {
			return Verdict{}, fmt.Errorf("matchCondition %s: not a bool: %v", m.Name, v)
		} else if !b {
			return Verdict{Matched: false}, nil
		}
	}
	// Variables are evaluated in order, each seeing the ones before it (the API server evaluates them
	// lazily; evaluating every one here is stricter, catching a variable that errors on some request).
	for _, n := range p.Spec.Variables {
		v, err := eval(n.Expression, act)
		if err != nil {
			return Verdict{}, fmt.Errorf("variable %s: %w", n.Name, err)
		}
		vars[n.Name] = v
	}
	for _, val := range p.Spec.Validations {
		v, err := eval(val.Expression, act)
		if err != nil {
			return Verdict{}, err
		}
		if b, ok := v.(bool); !ok {
			return Verdict{}, fmt.Errorf("validation %q: not a bool: %v", val.Expression, v)
		} else if !b {
			return Verdict{Matched: true, Denied: val.Message}, nil
		}
	}
	return Verdict{Matched: true}, nil
}

// nilable turns a nil map into CEL's null, as the API server presents an absent object.
func nilable(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}
