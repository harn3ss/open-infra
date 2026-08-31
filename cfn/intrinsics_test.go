package main

import "testing"

func resolverFor(t *testing.T, tmpl *Template) *resolver {
	t.Helper()
	r := newResolver(tmpl, map[string]any{"Env": "prod"}, pseudoParams("stk"))
	r.evalConditions()
	r.where = "test"
	return r
}

func TestResolve_SupportedIntrinsics(t *testing.T) {
	tmpl := &Template{
		Mappings: map[string]any{
			"Sizes": map[string]any{"prod": map[string]any{"cpu": "4"}},
		},
		Conditions: map[string]any{
			"IsProd": map[string]any{"Fn::Equals": []any{map[string]any{"Ref": "Env"}, "prod"}},
		},
		Resources: map[string]Resource{},
	}
	r := resolverFor(t, tmpl)
	if !r.conds["IsProd"] {
		t.Fatal("IsProd should be true for Env=prod")
	}

	cases := []struct {
		name string
		in   any
		want string
	}{
		{"Join", map[string]any{"Fn::Join": []any{"-", []any{"a", "b", "c"}}}, "a-b-c"},
		{"Sub", map[string]any{"Fn::Sub": "env-${Env}-${AWS::Region}"}, "env-prod-openinfra"},
		{"SubEscape", map[string]any{"Fn::Sub": "${!Literal}-${Env}"}, "${Literal}-prod"},
		{"FindInMap", map[string]any{"Fn::FindInMap": []any{"Sizes", map[string]any{"Ref": "Env"}, "cpu"}}, "4"},
		{"Select", map[string]any{"Fn::Select": []any{1, []any{"x", "y", "z"}}}, "y"},
		{"IfTrue", map[string]any{"Fn::If": []any{"IsProd", "big", "small"}}, "big"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.resolve(c.in)
			if s := toStr(got); s != c.want {
				t.Errorf("resolve(%s) = %q, want %q", c.name, s, c.want)
			}
		})
	}
	if len(r.findings) != 0 {
		t.Fatalf("supported intrinsics produced findings: %+v", r.findings)
	}
}

func TestResolve_UnsupportedIntrinsicFinds(t *testing.T) {
	tmpl := &Template{Resources: map[string]Resource{}}
	r := resolverFor(t, tmpl)
	for _, in := range []any{
		map[string]any{"Fn::ImportValue": "other-stack-out"},
		map[string]any{"Fn::GetAZs": ""},
		map[string]any{"Fn::Cidr": []any{"10.0.0.0/16", 6, 5}},
		map[string]any{"Fn::Bogus": "x"},
	} {
		r.findings = nil
		r.resolve(in)
		if len(r.findings) == 0 {
			t.Errorf("unsupported intrinsic %v produced no finding", in)
		}
	}
}

func TestParse_YAMLShortForms(t *testing.T) {
	tmpl, err := Parse(readFixtureBytes(t, "webapp.yaml"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	api := tmpl.Resources["Api"]
	role, ok := api.Properties["Role"].(map[string]any)
	if !ok || role["Fn::GetAtt"] == nil {
		t.Fatalf("Api.Role should be a GetAtt long-form, got %#v", api.Properties["Role"])
	}
	// !GetAtt AppRole.Arn -> {"Fn::GetAtt": ["AppRole","Arn"]}
	parts, ok := role["Fn::GetAtt"].([]any)
	if !ok || len(parts) != 2 || parts[0] != "AppRole" || parts[1] != "Arn" {
		t.Fatalf("GetAtt should split to [AppRole Arn], got %#v", role["Fn::GetAtt"])
	}
	// DependsOn string/list normalized.
	wf := tmpl.Resources["Workflow"]
	if len(wf.DependsOn) != 1 || wf.DependsOn[0] != "Api" {
		t.Fatalf("Workflow.DependsOn = %v, want [Api]", wf.DependsOn)
	}
}

func toStr(v any) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}

func readFixtureBytes(t *testing.T, name string) []byte { return readFixture(t, name) }
