package render

import (
	"strings"
	"testing"
)

// An Application's author strings render as one literal value each (#420), as a Function's do (#405): an
// env name crafted to add a valueFrom stays one name, and a mount path, a secret, the queues and a
// sidecar's image and env name render as written. Identifiers (ports, volumes, sidecar names, resources,
// subnet, security groups) are refused at admission by the XRD's patterns instead.

// appSpec is an Application with an image and these fields over it.
func appSpec(over map[string]any) map[string]any {
	spec := map[string]any{"image": "registry.example/app:1"}
	for k, v := range over {
		spec[k] = v
	}
	return spec
}

// podSpec is the rendered Deployment's pod spec.
func podSpec(t *testing.T, out string) map[string]any {
	t.Helper()
	ps, _ := mget(appDeployment(t, out, "myapp"), "spec", "template", "spec").(map[string]any)
	if ps == nil {
		t.Fatalf("no pod spec rendered:\n%s", out)
	}
	return ps
}

func containerNamed(ps map[string]any, name string) map[string]any {
	cs, _ := ps["containers"].([]any)
	for _, c := range cs {
		if mstr(c, "name") == name {
			m, _ := c.(map[string]any)
			return m
		}
	}
	return nil
}

func TestApplication_AnInjectedEnvNameIsOneName(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	crafted := "SETTING, valueFrom: { secretKeyRef: { name: other-stack, key: password } }"
	for what, spec := range map[string]map[string]any{
		"the app's": appSpec(map[string]any{"env": []any{map[string]any{"name": crafted, "value": ""}}}),
		"a sidecar's": appSpec(map[string]any{"sidecars": []any{map[string]any{"name": "proxy", "image": "registry.example/proxy:1",
			"env": []any{map[string]any{"name": crafted, "value": ""}}}}}),
	} {
		out := render(t, tmpl, appCtx(spec))
		ps := podSpec(t, out)
		for _, c := range ps["containers"].([]any) {
			env, _ := mget(c, "env").([]any)
			for _, e := range env {
				if mget(e, "name") == crafted {
					if _, ok := e.(map[string]any)["valueFrom"]; ok {
						t.Errorf("%s env name became a Secret reference", what)
					}
					continue
				}
				if strings.HasPrefix(mstr(e, "name"), "SETTING") {
					t.Errorf("%s env name was split into another entry: %v", what, e)
				}
			}
		}
		if !strings.Contains(out, `"SETTING, valueFrom: { secretKeyRef: { name: other-stack, key: password } }"`) {
			t.Errorf("%s env name must render as one JSON string:\n%s", what, grepCtx(out, "SETTING"))
		}
	}
}

func TestApplication_AuthorStringsRenderLiterally(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	evil := "x\" }\n                              - { name: STOLEN, valueFrom: { secretKeyRef: { name: other-stack, key: k } } }\n#"
	out := render(t, tmpl, appCtx(appSpec(map[string]any{
		"volumes":      []any{map[string]any{"name": "data"}},
		"volumeMounts": []any{map[string]any{"name": "data", "mountPath": evil}},
		"secrets":      []any{evil},
		"queues":       []any{evil, "orders"},
		"sidecars": []any{map[string]any{"name": "proxy", "image": evil,
			"volumeMounts": []any{map[string]any{"name": "data", "mountPath": evil}}}},
	})))
	if strings.Contains(out, "\n                              - { name: STOLEN") {
		t.Fatalf("a crafted value became a line of its own:\n%s", grepCtx(out, "STOLEN"))
	}
	ps := podSpec(t, out)
	app, proxy := containerNamed(ps, "app"), containerNamed(ps, "proxy")
	if app == nil {
		for _, c := range ps["containers"].([]any) {
			if mstr(c, "name") != "proxy" {
				app, _ = c.(map[string]any)
			}
		}
	}
	if app == nil || proxy == nil {
		t.Fatalf("want the app and its sidecar rendered:\n%s", out)
	}
	for _, c := range []map[string]any{app, proxy} {
		env, _ := mget(c, "env").([]any)
		for _, e := range env {
			if mstr(e, "name") == "STOLEN" {
				t.Errorf("container %s got an injected env entry", mstr(c, "name"))
			}
		}
		vms, _ := mget(c, "volumeMounts").([]any)
		found := false
		for _, vm := range vms {
			if mstr(vm, "mountPath") == evil {
				found = true
			}
		}
		if !found {
			t.Errorf("container %s must mount data at the path as written: %v", mstr(c, "name"), vms)
		}
	}
	if mstr(proxy, "image") != evil {
		t.Errorf("the sidecar's image must be as written, got %q", mstr(proxy, "image"))
	}
	from, _ := mget(app, "envFrom").([]any)
	if len(from) != 1 || mstr(from[0], "secretRef", "name") != evil {
		t.Errorf("envFrom must be one secretRef naming the secret as written: %v", from)
	}
	queues := ""
	appEnvList, _ := mget(app, "env").([]any)
	for _, e := range appEnvList {
		if mstr(e, "name") == "OPENINFRA_QUEUES" {
			queues = mstr(e, "value")
		}
	}
	if queues != evil+",orders" {
		t.Errorf("OPENINFRA_QUEUES = %q, want the queues as written", queues)
	}
}
