package cfn

import "testing"

func resolverFor(t *testing.T, tmpl *Template) *resolver {
	t.Helper()
	r := newResolver(tmpl, map[string]any{"Env": "prod"}, nil, pseudoParams("stk"))
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
		map[string]any{"Fn::ImportValue": "other-stack-out"}, // no export supplied -> finding (fail-loud, not faked)
		map[string]any{"Fn::Transform": map[string]any{"Name": "AWS::Include"}},
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

func TestFnCidr(t *testing.T) {
	// 6 /24 subnets from a /16 (the canonical AWS example)
	got, err := fnCidr("10.0.0.0/16", 6, 8)
	if err != nil {
		t.Fatalf("fnCidr: %v", err)
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24", "10.0.5.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %d subnets, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("subnet %d = %v, want %s", i, got[i], w)
		}
	}
	// /28 subnets from a /24
	g2, err := fnCidr("192.168.0.0/24", 4, 4)
	if err != nil || g2[0] != "192.168.0.0/28" || g2[3] != "192.168.0.48/28" {
		t.Errorf("/28 carve wrong: %v (err %v)", g2, err)
	}
	// overflow: can't fit 300 /24s in a /16
	if _, err := fnCidr("10.0.0.0/16", 300, 8); err == nil {
		t.Error("expected overflow error for 300 /24s in a /16")
	}
	// IPv6 rejected
	if _, err := fnCidr("2001:db8::/32", 2, 8); err == nil {
		t.Error("expected IPv6 to be rejected")
	}
	// garbage ipBlock rejected
	if _, err := fnCidr("not-a-cidr", 2, 8); err == nil {
		t.Error("expected parse error for a bad ipBlock")
	}
}

func TestResolve_Cidr_GetAZs_ImportValue(t *testing.T) {
	tmpl := &Template{Resources: map[string]Resource{}}
	r := newResolver(tmpl, map[string]any{}, map[string]any{"SharedVpcId": "vpc-123"}, pseudoParams("stk"))
	r.where = "test"

	// Fn::Cidr resolves to a list (no finding)
	out := r.resolve(map[string]any{"Fn::Cidr": []any{"10.0.0.0/16", float64(2), float64(8)}})
	if l, ok := out.([]any); !ok || len(l) != 2 || l[0] != "10.0.0.0/24" {
		t.Errorf("Fn::Cidr resolve got %v", out)
	}

	// Fn::GetAZs resolves to a 3-element region-derived stand-in
	az := r.resolve(map[string]any{"Fn::GetAZs": "us-west-2"})
	if l, ok := az.([]any); !ok || len(l) != 3 || l[0] != "us-west-2a" {
		t.Errorf("Fn::GetAZs got %v", az)
	}

	// Fn::ImportValue resolves a SUPPLIED export, no finding
	before := len(r.findings)
	iv := r.resolve(map[string]any{"Fn::ImportValue": "SharedVpcId"})
	if iv != "vpc-123" {
		t.Errorf("Fn::ImportValue(SharedVpcId) got %v want vpc-123", iv)
	}
	if len(r.findings) != before {
		t.Errorf("a supplied export must not add a finding")
	}

	// Fn::ImportValue for a MISSING export is a finding (fail-loud, not faked)
	_ = r.resolve(map[string]any{"Fn::ImportValue": "Absent"})
	if len(r.findings) != before+1 {
		t.Errorf("a missing export must add exactly one finding; findings=%v", r.findings)
	}
}

func TestResolve_TransformStillFailsLoud(t *testing.T) {
	tmpl := &Template{Resources: map[string]Resource{}}
	r := newResolver(tmpl, nil, nil, pseudoParams("stk"))
	r.where = "test"
	_ = r.resolve(map[string]any{"Fn::Transform": map[string]any{"Name": "AWS::Include"}})
	if len(r.findings) != 1 {
		t.Errorf("Fn::Transform must still be a finding; got %v", r.findings)
	}
}
