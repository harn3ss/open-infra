package main

import "testing"

func TestEscapeJavaScript(t *testing.T) {
	cases := map[string]string{
		`plain`:        `plain`,
		`he said "hi"`: `he said \"hi\"`,
		"line1\nline2": `line1\nline2`,
		`back\slash`:   `back\\slash`,
		"tab\there":    `tab\there`,
		"ctrl\x01char": `ctrl\u0001char`,
	}
	for in, want := range cases {
		if got := escapeJavaScript(in); got != want {
			t.Errorf("escapeJavaScript(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApigwUtil_Dispatch(t *testing.T) {
	u := apigwUtil{}

	if v, _, ok := u.Invoke("escapeJavaScript", []any{`a"b`}); !ok || v.(string) != `a\"b` {
		t.Errorf("escapeJavaScript dispatch = %v ok=%v", v, ok)
	}
	if v, _, ok := u.Invoke("urlEncode", []any{"a b&c"}); !ok || v.(string) != "a+b%26c" {
		t.Errorf("urlEncode = %v ok=%v", v, ok)
	}
	if v, _, ok := u.Invoke("urlDecode", []any{"a+b%26c"}); !ok || v.(string) != "a b&c" {
		t.Errorf("urlDecode = %v ok=%v", v, ok)
	}
	if v, _, ok := u.Invoke("base64Encode", []any{"hi"}); !ok || v.(string) != "aGk=" {
		t.Errorf("base64Encode = %v ok=%v", v, ok)
	}
	if v, _, ok := u.Invoke("base64Decode", []any{"aGk="}); !ok || v.(string) != "hi" {
		t.Errorf("base64Decode = %v ok=%v", v, ok)
	}
	if v, _, ok := u.Invoke("toJson", []any{map[string]any{"a": float64(1)}}); !ok || v.(string) != `{"a":1}` {
		t.Errorf("toJson = %v ok=%v", v, ok)
	}
	// parseJson round-trips into a navigable value.
	v, _, ok := u.Invoke("parseJson", []any{`{"n":"x"}`})
	if !ok {
		t.Fatalf("parseJson ok=false")
	}
	if m, _ := v.(map[string]any); m["n"] != "x" {
		t.Errorf("parseJson = %v", v)
	}

	// unknown method: Invoke reports ok=false; Call surfaces an error.
	if _, _, ok := u.Invoke("nope", nil); ok {
		t.Errorf("unknown method should be ok=false")
	}
	if _, err := u.Call("nope", nil); err == nil {
		t.Errorf("Call(unknown) should error")
	}
}

func TestRenderMappingTemplate_InputParams(t *testing.T) {
	out, err := renderMappingTemplate(`$input.params('id')`, nil, map[string]string{"id": "42"}, nil, nil)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if out != "42" {
		t.Fatalf("$input.params('id') = %q, want 42", out)
	}
}

func TestRenderMappingTemplate_SetIf(t *testing.T) {
	tmpl := `#set($n = $input.params('n'))#if($n == "big")BIG#{else}small#end`
	if out, _ := renderMappingTemplate(tmpl, nil, map[string]string{"n": "big"}, nil, nil); out != "BIG" {
		t.Errorf("n=big got %q want BIG", out)
	}
	if out, _ := renderMappingTemplate(tmpl, nil, map[string]string{"n": "x"}, nil, nil); out != "small" {
		t.Errorf("n=x got %q want small", out)
	}
}

func TestRenderMappingTemplate_InputJSON(t *testing.T) {
	body := []byte(`{"name":"erin","nested":{"x":1}}`)
	// whole body re-serialized (deterministic key order)
	if out, _ := renderMappingTemplate(`$input.json('$')`, body, nil, nil, nil); out != `{"name":"erin","nested":{"x":1}}` {
		t.Errorf("json('$') = %q", out)
	}
	// top-level field, JSON-encoded (a string keeps its quotes, as AWS returns)
	if out, _ := renderMappingTemplate(`$input.json('$.name')`, body, nil, nil, nil); out != `"erin"` {
		t.Errorf("json('$.name') = %q want \"erin\"", out)
	}
	// dotted object path (honest subset)
	if out, _ := renderMappingTemplate(`$input.json('$.nested.x')`, body, nil, nil, nil); out != `1` {
		t.Errorf("json('$.nested.x') = %q want 1", out)
	}
}

func TestRenderMappingTemplate_UtilAndBody(t *testing.T) {
	// $util.escapeJavaScript($input.body) embedded in a JSON template
	out, err := renderMappingTemplate(`{"b":"$util.escapeJavaScript($input.body)"}`, []byte(`he said "hi"`), nil, nil, nil)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if out != `{"b":"he said \"hi\""}` {
		t.Fatalf("escapeJavaScript($input.body) = %q", out)
	}

	// $util.parseJson then property access
	if out, _ := renderMappingTemplate(`#set($o = $util.parseJson($input.body))$o.name`, []byte(`{"name":"erin"}`), nil, nil, nil); out != "erin" {
		t.Errorf("parseJson+prop = %q want erin", out)
	}
}

func TestRenderMappingTemplate_ContextAndStageVars(t *testing.T) {
	out, err := renderMappingTemplate(
		`$context.httpMethod/$stageVariables.env`,
		nil, nil,
		map[string]string{"env": "prod"},
		map[string]any{"httpMethod": "GET"},
	)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if out != "GET/prod" {
		t.Fatalf("context/stageVars = %q want GET/prod", out)
	}
}

func TestPickMappingTemplate(t *testing.T) {
	m := map[string]string{"application/json": "J", "text/plain": "T"}
	if v, ok := pickMappingTemplate(m, "application/json; charset=utf-8"); !ok || v != "J" {
		t.Errorf("content-type with params should match json; got %q ok=%v", v, ok)
	}
	if v, ok := pickMappingTemplate(m, "text/plain"); !ok || v != "T" {
		t.Errorf("text/plain should match; got %q ok=%v", v, ok)
	}
	// unmatched content-type falls back to application/json
	if v, ok := pickMappingTemplate(m, "application/xml"); !ok || v != "J" {
		t.Errorf("unmatched should fall back to json; got %q ok=%v", v, ok)
	}
	// $default fallback when no json
	if v, ok := pickMappingTemplate(map[string]string{"$default": "D"}, "application/xml"); !ok || v != "D" {
		t.Errorf("should fall back to $default; got %q ok=%v", v, ok)
	}
	// empty map → no template (pass-through)
	if _, ok := pickMappingTemplate(nil, "application/json"); ok {
		t.Errorf("empty map must not match")
	}
}
