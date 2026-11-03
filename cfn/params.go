// Parameter validation, as CloudFormation does it before a stack operation creates anything: a value for
// a parameter the template does not declare is refused, a parameter with no value and no Default is
// refused, a value is checked against its type and its constraints (AllowedValues, AllowedPattern,
// MinLength / MaxLength, MinValue / MaxValue), and the value of an AWS-specific parameter type (a subnet,
// security group or VPC) must name one that exists. The errors are AWS's own words, so a deploy script
// that matches on them behaves as it does against AWS.
package cfn

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// parseParamConstraints reads a parameter declaration's constraints into p. A constraint that is not of
// the type CloudFormation takes (MinLength: "x") is left unset; ValidateTemplate reports a template whose
// constraints are malformed (paramDeclBlockers).
func parseParamConstraints(pm map[string]any, p *Parameter) {
	if av, ok := pm["AllowedValues"].([]any); ok {
		for _, v := range av {
			p.AllowedValues = append(p.AllowedValues, scalarString(v))
		}
	}
	if s, ok := pm["AllowedPattern"].(string); ok {
		p.AllowedPattern = s
	}
	p.MinLength, p.MaxLength = intConstraint(pm["MinLength"]), intConstraint(pm["MaxLength"])
	p.MinValue, p.MaxValue = numConstraint(pm["MinValue"]), numConstraint(pm["MaxValue"])
	if s, ok := pm["ConstraintDescription"].(string); ok {
		p.ConstraintDescription = s
	}
}

// scalarString renders a template scalar as CloudFormation compares it: a number as it is written (1, 1.5,
// not 1.000000), a boolean as true / false.
func scalarString(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case int:
		return strconv.Itoa(n)
	}
	return fmt.Sprint(v)
}

func numConstraint(v any) *float64 {
	switch n := v.(type) {
	case float64:
		return &n
	case int:
		f := float64(n)
		return &f
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
			return &f
		}
	}
	return nil
}

func intConstraint(v any) *int {
	f := numConstraint(v)
	if f == nil || *f != float64(int(*f)) {
		return nil
	}
	i := int(*f)
	return &i
}

// ParameterError is a parameter value CloudFormation refuses: Message is AWS's text for it.
type ParameterError struct{ Message string }

func (e *ParameterError) Error() string { return e.Message }

// existenceKinds maps each AWS-specific parameter type whose value CloudFormation looks up to the
// open-infra kind that value names. (AWS::EC2::KeyPair::KeyName is not checked: open-infra has no key
// pairs — an instance's KeyName is a caveat — so there is nothing to look a name up in.)
var existenceKinds = map[string]string{
	"AWS::EC2::Subnet::Id":               "Subnet",
	"AWS::EC2::SecurityGroup::Id":        "SecurityGroup",
	"AWS::EC2::SecurityGroup::GroupName": "SecurityGroup",
	"AWS::EC2::VPC::Id":                  "Vpc",
}

// paramElemType is the element type of a list parameter type (List<Number> -> Number, CommaDelimitedList
// -> String) and list=true; a scalar type is returned as it is with list=false.
func paramElemType(ty string) (elem string, list bool) {
	if ty == "CommaDelimitedList" {
		return "String", true
	}
	if strings.HasPrefix(ty, "List<") && strings.HasSuffix(ty, ">") {
		return strings.TrimSuffix(strings.TrimPrefix(ty, "List<"), ">"), true
	}
	return ty, false
}

// effectiveParams returns each declared parameter's value — supplied, else its Default — and the names
// of those with neither (sorted).
func effectiveParams(t *Template, given map[string]string) (vals map[string]string, missing []string) {
	vals = map[string]string{}
	defaults := map[string]string{}
	for name, p := range t.Parameters {
		if p.hasDef {
			defaults[name] = defaultString(p.Default)
		}
	}
	for name := range t.Parameters {
		if v, ok := given[name]; ok {
			vals[name] = v
		} else if d, ok := defaults[name]; ok {
			vals[name] = d
		} else {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return vals, missing
}

// defaultString renders a parameter Default as the value it stands for (a list Default as its
// comma-separated value).
func defaultString(v any) string {
	if l, ok := v.([]any); ok {
		parts := make([]string, 0, len(l))
		for _, e := range l {
			parts = append(parts, scalarString(e))
		}
		return strings.Join(parts, ",")
	}
	return scalarString(v)
}

// unknownParams returns the keys in given (and in extra — the UsePreviousValue keys of an update) that
// the template does not declare, in the order CloudFormation lists them (sorted, deduplicated).
func unknownParams(t *Template, given map[string]string, extra []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if _, ok := t.Parameters[k]; !ok && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for k := range given {
		add(k)
	}
	for _, k := range extra {
		add(k)
	}
	sort.Strings(out)
	return out
}

// staticParamError is the first refusal CloudFormation gives for these values that needs no lookup: a
// parameter the template does not declare, then one with no value, then a value that breaks its type or
// a constraint (parameters in name order). "" when there is none.
func staticParamError(t *Template, given map[string]string, extra []string) string {
	if unk := unknownParams(t, given, extra); len(unk) > 0 {
		return "Parameters: [" + strings.Join(unk, ", ") + "] do not exist in the template"
	}
	vals, missing := effectiveParams(t, given)
	if len(missing) > 0 {
		return "Parameters: [" + strings.Join(missing, ", ") + "] must have values"
	}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if msg := constraintError(n, t.Parameters[n], vals[n]); msg != "" {
			return msg
		}
	}
	return ""
}

// constraintError checks one parameter's value against its type and constraints; "" when it passes. A
// list parameter's constraints apply to each of its elements. A failed constraint reads as the
// parameter's ConstraintDescription when it has one, as on AWS.
func constraintError(name string, p Parameter, value string) string {
	elemType, list := paramElemType(p.Type)
	if strings.HasPrefix(p.Type, "AWS::SSM::Parameter::") {
		return "" // the value is an SSM parameter's name, resolved at deploy; its constraints apply to what it resolves to
	}
	elems := []string{value}
	if list {
		elems = nil
		for _, e := range strings.Split(value, ",") {
			elems = append(elems, strings.TrimSpace(e))
		}
	}
	fail := func(msg string) string {
		if p.ConstraintDescription != "" {
			return "Parameter '" + name + "' failed to satisfy constraint: " + p.ConstraintDescription
		}
		return msg
	}
	for _, e := range elems {
		if elemType == "Number" {
			f, err := strconv.ParseFloat(strings.TrimSpace(e), 64)
			if err != nil {
				return "Parameter '" + name + "' must be a number"
			}
			if p.MinValue != nil && f < *p.MinValue {
				return fail("Parameter '" + name + "' must be a number not less than " + scalarString(*p.MinValue))
			}
			if p.MaxValue != nil && f > *p.MaxValue {
				return fail("Parameter '" + name + "' must be a number not greater than " + scalarString(*p.MaxValue))
			}
		}
		if len(p.AllowedValues) > 0 && !allowedValue(p.AllowedValues, e, elemType == "Number") {
			return fail("Parameter '" + name + "' must be one of AllowedValues")
		}
		if elemType == "Number" {
			continue
		}
		if p.AllowedPattern != "" {
			re, err := regexp.Compile("^(?:" + p.AllowedPattern + ")$")
			if err == nil && !re.MatchString(e) {
				return fail("Parameter '" + name + "' must match pattern " + p.AllowedPattern)
			}
		}
		if n := len([]rune(e)); p.MinLength != nil && n < *p.MinLength {
			return fail("Parameter '" + name + "' must contain at least " + strconv.Itoa(*p.MinLength) + " characters")
		} else if p.MaxLength != nil && n > *p.MaxLength {
			return fail("Parameter '" + name + "' must contain at most " + strconv.Itoa(*p.MaxLength) + " characters")
		}
	}
	return ""
}

// allowedValue reports whether v is one of allowed: equal as written, or (for a Number) equal as a number
// (AllowedValues [1, 2] admits "1.0").
func allowedValue(allowed []string, v string, number bool) bool {
	for _, a := range allowed {
		if a == v {
			return true
		}
		if number {
			af, aerr := strconv.ParseFloat(a, 64)
			vf, verr := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if aerr == nil && verr == nil && af == vf {
				return true
			}
		}
	}
	return false
}

// paramDeclBlockers reports parameter declarations CloudFormation refuses as a template error: an
// AllowedPattern that is not a regular expression, a Default outside its own constraints is NOT among
// them (AWS reports that only when the Default is used, as a parameter error).
func paramDeclBlockers(t *Template) []string {
	var out []string
	for name, p := range t.Parameters {
		if p.AllowedPattern == "" {
			continue
		}
		if _, err := regexp.Compile("^(?:" + p.AllowedPattern + ")$"); err != nil {
			out = append(out, "parameter "+name+": AllowedPattern "+p.AllowedPattern+" is not a valid regular expression")
		}
	}
	sort.Strings(out)
	return out
}

// CheckParameters refuses parameter values as CloudFormation does before a create, an update or a change
// set: (in this order) a key the template does not declare (given, or sent with UsePreviousValue —
// prevKeys), a parameter with no value and no Default, a value that breaks its type or a constraint, and
// the value of an AWS-specific type (a subnet, security group or VPC id, or a list of them) that names
// nothing that exists. ap looks the latter up (nil skips them). The error is a *ParameterError carrying
// AWS's message; nil when the values are accepted. A NoEcho value is never echoed in the message.
func CheckParameters(ctx context.Context, data []byte, given map[string]string, prevKeys []string, ap Applier) error {
	t, err := Parse(data)
	if err != nil {
		return err
	}
	if msg := staticParamError(t, given, prevKeys); msg != "" {
		return &ParameterError{msg}
	}
	if ap == nil {
		return nil
	}
	return existenceError(ctx, t, given, ap)
}

// objectNameRe is a Kubernetes object name (a DNS-1123 subdomain).
var objectNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// existenceError looks up the value of each AWS-specific parameter (subnet / security group / VPC): one
// that names nothing gives AWS's "parameter value … does not exist".
func existenceError(ctx context.Context, t *Template, given map[string]string, ap Applier) error {
	vals, _ := effectiveParams(t, given)
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := t.Parameters[n]
		elemType, list := paramElemType(p.Type)
		kind, checked := existenceKinds[elemType]
		if !checked {
			continue
		}
		elems := []string{vals[n]}
		if list {
			elems = nil
			for _, e := range strings.Split(vals[n], ",") {
				if e = strings.TrimSpace(e); e != "" {
					elems = append(elems, e)
				}
			}
		}
		for _, e := range elems {
			found := false
			if objectNameRe.MatchString(e) && len(e) <= 253 { // anything else cannot name an object: no lookup
				var err error
				if _, found, err = ap.GetSpec(ctx, "openinfra.dev/v1", kind, e); err != nil {
					return fmt.Errorf("checking parameter %s: %w", n, err)
				}
			}
			if !found {
				shown := e
				if p.NoEcho {
					shown = "****"
				}
				return &ParameterError{"Parameter validation failed: parameter value " + shown + " for parameter name " + n + " does not exist"}
			}
		}
	}
	return nil
}

// DeclaredParameters is the set of parameter names a template declares (empty if it does not parse) —
// what an update's UsePreviousValue keys are checked against.
func DeclaredParameters(data []byte) map[string]bool {
	out := map[string]bool{}
	t, err := Parse(data)
	if err != nil {
		return out
	}
	for k := range t.Parameters {
		out[k] = true
	}
	return out
}
