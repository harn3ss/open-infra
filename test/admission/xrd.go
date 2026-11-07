package admission

import (
	"fmt"
	"os"

	"cel.dev/cel-go/cel"
	"gopkg.in/yaml.v3"
)

// An XRD's validation rules (x-kubernetes-validations on spec) are CRD validation rules: the API server
// evaluates each with self bound to the object's spec, on every create and update of the claim and of its
// composite. These evaluate them offline the same way, so a rule that refuses the right write or lets the
// wrong one through fails a test.

// Rule is one x-kubernetes-validations entry.
type Rule struct {
	Rule    string `yaml:"rule"`
	Message string `yaml:"message"`
}

// LoadXRDSpecRules returns the validation rules on spec in an XRD's first version.
func LoadXRDSpecRules(path string) ([]Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var xrd struct {
		Kind string `yaml:"kind"`
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Rules []Rule `yaml:"x-kubernetes-validations"`
							} `yaml:"spec"`
						} `yaml:"properties"`
					} `yaml:"openAPIV3Schema"`
				} `yaml:"schema"`
			} `yaml:"versions"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &xrd); err != nil {
		return nil, err
	}
	if xrd.Kind != "CompositeResourceDefinition" || len(xrd.Spec.Versions) == 0 {
		return nil, fmt.Errorf("%s: not an XRD", path)
	}
	rules := xrd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Rules
	if len(rules) == 0 {
		return nil, fmt.Errorf("%s: no validation rules on spec", path)
	}
	return rules, nil
}

var selfEnv = func() *cel.Env {
	e, err := cel.NewEnv(cel.Variable("self", cel.DynType))
	if err != nil {
		panic(err)
	}
	return e
}()

// Validate evaluates the rules against a spec (as self) and returns the first refusal's message, "" when
// every rule holds. A rule that fails to compile is an error; one that errors on this spec refuses it, as
// the API server does.
func Validate(rules []Rule, spec map[string]any) (string, error) {
	for _, r := range rules {
		ast, iss := selfEnv.Compile(r.Rule)
		if iss.Err() != nil {
			return "", fmt.Errorf("compile %q: %w", r.Rule, iss.Err())
		}
		prg, err := selfEnv.Program(ast)
		if err != nil {
			return "", fmt.Errorf("program %q: %w", r.Rule, err)
		}
		out, _, err := prg.Eval(map[string]any{"self": spec})
		if err != nil {
			return r.Message, nil
		}
		if b, ok := out.Value().(bool); !ok || !b {
			return r.Message, nil
		}
	}
	return "", nil
}
