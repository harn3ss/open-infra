package render

import (
	"strings"
	"testing"
)

// Every string a function's author writes is rendered with toJson (#405): a JSON string is a YAML
// double-quoted scalar, so a quote, a backslash, a line break or "{{" stays one literal value, and a value
// crafted to add a setting (an env entry reading another Secret through valueFrom) renders as one plain
// string. On Lambda an environment variable's value is any string.

// escapingValues are the characters the issue names, and values legitimately carrying them.
var escapingValues = map[string]string{
	"a double quote":        `say "hi"`,
	"a backslash":           `C:\temp\new\b`,
	"a line break":          "line one\nline two",
	"template delimiters":   `{{ .observed.composite.resource.spec }}`,
	"a JSON document":       `{"region":"us-east-1","retries":3}`,
	"HTML characters":       `<a href="x">&amp;</a>`,
	"a trailing backslash":  `ends with \`,
	"a tab and a carriage":  "a\tb\rc",
	"an empty string":       "",
	"YAML-looking text":     "key: value\n- item\n# comment",
	"a value that is true":  "true",
	"a number-like value":   "0123",
	"unicode":               "naïve — ✓",
	"a flow-mapping closer": `x" } ] }`,
}

// The injection attempts: a value that closes its own string and adds valueFrom to its own entry (which,
// unescaped, the real YAML decoder reads as a Secret reference: the empty value lets Kubernetes take it); one
// that closes its string and starts another entry; and one that relies only on a line break and the
// template's indentation.
var injectionValues = map[string]string{
	"adds valueFrom on one line": `", valueFrom: { secretKeyRef: { name: other-stack, key: password } }, x: "`,
	"closes the quote":           "x\" }\n                              - { name: STOLEN, valueFrom: { secretKeyRef: { name: other-stack, key: password } } }\n                              - { name: PAD, value: \"y",
	"line break only":            "x\n                              - { name: STOLEN, valueFrom: { secretKeyRef: { name: other-stack, key: password } } }",
}

func escapingSpec(env ...map[string]any) map[string]any {
	list := make([]any, 0, len(env))
	for _, e := range env {
		list = append(list, e)
	}
	return map[string]any{
		"code": map[string]any{"runtime": "nodejs22", "handler": "index.handler",
			"source": map[string]any{"configMap": "orders-code"}},
		"env": list,
	}
}

// containerEnv answers the rendered container's env entries in order.
func containerEnv(t *testing.T, ksvc map[string]any) []map[string]any {
	t.Helper()
	cs, _ := mget(ksvc, "spec", "template", "spec", "containers").([]any)
	if len(cs) != 1 {
		t.Fatalf("want one container, got %d", len(cs))
	}
	list, _ := mget(cs[0], "env").([]any)
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		m, _ := e.(map[string]any)
		out = append(out, m)
	}
	return out
}

func TestFunction_EnvValuesRenderLiterally(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	for what, v := range escapingValues {
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", escapingSpec(
			map[string]any{"name": "SETTING", "value": v}, map[string]any{"name": "AFTER", "value": "after"}), nil))
		ksvc := ksvcOf(t, out, "orders")
		env := envOf(ksvc)
		if got, ok := env["SETTING"]; !ok || got != v {
			t.Errorf("%s: SETTING = %q, want %q\n%s", what, got, v, grepCtx(out, "SETTING"))
		}
		if env["AFTER"] != "after" {
			t.Errorf("%s: the entry after it must be untouched, got %q", what, env["AFTER"])
		}
		if n := envCount(ksvc, "SETTING"); n != 1 {
			t.Errorf("%s: SETTING rendered %d times, want once", what, n)
		}
	}
}

func TestFunction_AnInjectedEnvEntryIsOnePlainString(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	for what, v := range injectionValues {
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", escapingSpec(map[string]any{"name": "SETTING", "value": v}), nil))
		ksvc := ksvcOf(t, out, "orders")
		entries := containerEnv(t, ksvc)
		names := map[string]int{}
		for _, e := range entries {
			names[mstr(e, "name")]++
			if _, ok := e["valueFrom"]; ok {
				t.Errorf("%s: env %q reads through valueFrom; a function with no keys has no such entry", what, mstr(e, "name"))
			}
		}
		if names["STOLEN"] != 0 || names["PAD"] != 0 {
			t.Errorf("%s: the value added env entries %v:\n%s", what, names, grepCtx(out, "STOLEN"))
		}
		if got := envOf(ksvc)["SETTING"]; got != v {
			t.Errorf("%s: SETTING = %q, want the whole value as one string", what, got)
		}
		if strings.Contains(out, "\n                              - { name: STOLEN") {
			t.Errorf("%s: the injected entry reached the rendered output as a line of its own", what)
		}
	}
}

// The name is the author's too.
func TestFunction_AnEnvNameRendersLiterally(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	// One line: unescaped, the name's text becomes this entry's own valueFrom.
	oneLine := "SETTING, valueFrom: { secretKeyRef: { name: other-stack, key: password } }"
	out1 := render(t, tmpl, fnRoleCtx("orders", "team-a", escapingSpec(map[string]any{"name": oneLine, "value": ""}), nil))
	for _, e := range containerEnv(t, ksvcOf(t, out1, "orders")) {
		if _, ok := e["valueFrom"]; ok {
			t.Errorf("an env name became a Secret reference on entry %q", mstr(e, "name"))
		}
	}
	if n := envCount(ksvcOf(t, out1, "orders"), oneLine); n != 1 {
		t.Errorf("the one-line crafted name must be one entry's name, as written: %d", n)
	}
	name := "A\", value: \"x\" }\n                              - { name: STOLEN, valueFrom: { secretKeyRef: { name: other-stack, key: k } } }\n                              - { name: \"B"
	out := render(t, tmpl, fnRoleCtx("orders", "team-a", escapingSpec(map[string]any{"name": name, "value": "v"}), nil))
	ksvc := ksvcOf(t, out, "orders")
	if n := envCount(ksvc, "STOLEN"); n != 0 {
		t.Fatalf("an env name added %d entries:\n%s", n, grepCtx(out, "STOLEN"))
	}
	if n := envCount(ksvc, name); n != 1 {
		t.Errorf("the crafted name must be one entry's name, as written (Kubernetes then refuses it): %d", n)
	}
}

// The handler, the code source, the region, the secrets, the queues, the security groups and a trigger's
// subject are the author's strings as well: each renders as one literal value.
func TestFunction_EveryAuthorStringRendersLiterally(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	evil := "x\" }\n                              - { name: STOLEN, valueFrom: { secretKeyRef: { name: other-stack, key: k } } }\n#"
	noStolen := func(t *testing.T, what, out string) {
		t.Helper()
		docs, err := parseYAMLDocs(out)
		if err != nil {
			t.Fatalf("%s: the render no longer parses: %v", what, err)
		}
		for _, d := range docs {
			if strings.Contains(mstr(d, "kind"), "STOLEN") {
				t.Errorf("%s: an object was injected", what)
			}
		}
		if strings.Contains(out, "\n                              - { name: STOLEN") || strings.Contains(out, "\n- { name: STOLEN") {
			t.Errorf("%s: the crafted value became a line of its own:\n%s", what, grepCtx(out, "STOLEN"))
		}
	}

	t.Run("handler", func(t *testing.T) {
		spec := escapingSpec()
		spec["code"].(map[string]any)["handler"] = evil
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		noStolen(t, "handler", out)
		if got := envOf(ksvcOf(t, out, "orders"))["OPENINFRA_HANDLER"]; got != evil {
			t.Errorf("OPENINFRA_HANDLER = %q, want the handler as written", got)
		}
	})
	t.Run("region", func(t *testing.T) {
		spec := escapingSpec()
		spec["code"].(map[string]any)["region"] = evil
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		noStolen(t, "region", out)
		env := envOf(ksvcOf(t, out, "orders"))
		if env["AWS_REGION"] != evil || env["AWS_DEFAULT_REGION"] != evil {
			t.Errorf("AWS_REGION = %q, AWS_DEFAULT_REGION = %q, want the region as written", env["AWS_REGION"], env["AWS_DEFAULT_REGION"])
		}
	})
	t.Run("bucket source", func(t *testing.T) {
		spec := escapingSpec()
		spec["code"].(map[string]any)["source"] = map[string]any{"bucket": evil, "key": evil + "/code.zip", "secret": evil}
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		noStolen(t, "bucket source", out)
		ksvc := ksvcOf(t, out, "orders")
		env := envOf(ksvc)
		if env["OPENINFRA_CODE_BUCKET"] != evil || env["OPENINFRA_CODE_KEY"] != evil+"/code.zip" {
			t.Errorf("bucket %q, key %q, want them as written", env["OPENINFRA_CODE_BUCKET"], env["OPENINFRA_CODE_KEY"])
		}
		for _, e := range containerEnv(t, ksvc) {
			if ref := mget(e, "valueFrom", "secretKeyRef", "name"); ref != nil && ref != evil {
				t.Errorf("env %s reads Secret %q, want the code secret as written", mstr(e, "name"), ref)
			}
		}
	})
	t.Run("ConfigMap source", func(t *testing.T) {
		spec := escapingSpec()
		spec["code"].(map[string]any)["source"] = map[string]any{"configMap": evil}
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		noStolen(t, "ConfigMap source", out)
		vols, _ := mget(ksvcOf(t, out, "orders"), "spec", "template", "spec", "volumes").([]any)
		found := false
		for _, v := range vols {
			if mstr(v, "configMap", "name") == evil {
				found = true
			}
		}
		if !found {
			t.Errorf("the code volume must name the ConfigMap as written:\n%s", grepCtx(out, "configMap:"))
		}
	})
	t.Run("secrets", func(t *testing.T) {
		spec := escapingSpec()
		spec["secrets"] = []any{evil}
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		noStolen(t, "secrets", out)
		cs, _ := mget(ksvcOf(t, out, "orders"), "spec", "template", "spec", "containers").([]any)
		from, _ := mget(cs[0], "envFrom").([]any)
		if len(from) != 1 || mstr(from[0], "secretRef", "name") != evil {
			t.Errorf("envFrom must be one secretRef naming the secret as written: %v", from)
		}
	})
	t.Run("queues", func(t *testing.T) {
		spec := escapingSpec()
		spec["queues"] = []any{evil, "orders"}
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		noStolen(t, "queues", out)
		if got := envOf(ksvcOf(t, out, "orders"))["OPENINFRA_QUEUES"]; got != evil+",orders" {
			t.Errorf("OPENINFRA_QUEUES = %q, want the queues as written", got)
		}
	})
	t.Run("security groups", func(t *testing.T) {
		spec := escapingSpec()
		spec["securityGroups"] = []any{"web\": \"\"\n                          app: injected\n                          x"}
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		labels, _ := mget(ksvcOf(t, out, "orders"), "spec", "template", "metadata", "labels").(map[string]any)
		if _, ok := labels["app"]; ok {
			t.Errorf("a security group name added a label: %v", labels)
		}
		n := 0
		for k := range labels {
			if strings.HasPrefix(k, "openinfra.dev/sg-") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("want one security-group label, as written (Kubernetes then refuses the key): %v", labels)
		}
	})
	t.Run("trigger subject", func(t *testing.T) {
		spec := escapingSpec()
		spec["trigger"] = map[string]any{"stream": "orders", "subject": "cdc.orders\"\n  durable: \"stolen\"\n#"}
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", spec, nil))
		docs, err := parseYAMLDocs(out)
		if err != nil {
			t.Fatalf("the render no longer parses: %v", err)
		}
		cfg := objectFor(docs, "ConfigMap", "orders-pump-cfg")
		if cfg == nil {
			t.Fatalf("no pump config rendered")
		}
		benthos := mstr(mget(cfg, "spec", "forProvider", "manifest"), "data", "benthos.yaml")
		durables := 0
		for _, ln := range strings.Split(benthos, "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "durable:") {
				durables++
			}
		}
		if durables != 1 {
			t.Errorf("the subject added a setting to the pump's config (%d durable lines):\n%s", durables, benthos)
		}
		if !strings.Contains(benthos, `subject: "cdc.orders\"\n  durable: \"stolen\"\n#"`) {
			t.Errorf("the subject must be one JSON string on its line:\n%s", benthos)
		}
	})
}
