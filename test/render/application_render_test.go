package render

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// appCtx wraps an Application spec in the observed-composite context the go-templating function
// receives (claim myapp in namespace default).
func appCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{"uid": "00000000-0000-0000-0000-000000000abc", "labels": map[string]any{
			"crossplane.io/claim-name": "myapp", "crossplane.io/claim-namespace": "default"}},
	}}}}
}

// containerBlock returns the rendered lines of the pod container called name: from its
// `- name: <name>` line up to the next sibling container (or the end of the containers list).
func containerBlock(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		// A sidecar's name renders JSON-quoted (#420); the primary's is the app's own.
		if tl := strings.TrimSpace(ln); tl != "- name: "+name && tl != `- name: "`+name+`"` {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		block := []string{ln}
		for _, next := range lines[i+1:] {
			if strings.TrimSpace(next) == "" {
				continue
			}
			if len(next)-len(strings.TrimLeft(next, " ")) <= indent {
				break
			}
			block = append(block, next)
		}
		return strings.Join(block, "\n")
	}
	t.Fatalf("no container %q in the rendered Deployment", name)
	return ""
}

// #347 follow-up: a sidecar receives NO app secrets unless it opts in via its own `secrets` list.
// A logging agent or proxy must not inherit the app's database/API credentials (spec.secrets) or its
// bucket credentials (<name>-minio); a sidecar that does need one names it explicitly.
func TestApplication_SidecarSecretsOptIn(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, appCtx(map[string]any{
		"image":   "ghcr.io/x/app:latest",
		"port":    8080,
		"secrets": []any{"app-db", "app-api"},
		"storage": map[string]any{"buckets": []any{"uploads"}},
		"sidecars": []any{
			map[string]any{"name": "logship", "image": "ghcr.io/x/logship:latest"},
			map[string]any{"name": "worker", "image": "ghcr.io/x/app:latest", "secrets": []any{"app-db", "myapp-minio"}},
			map[string]any{"name": "proxy", "image": "ghcr.io/x/proxy:latest", "secrets": []any{"proxy-tls"}},
		},
	}))

	// The primary keeps the full bundle: every spec.secrets entry + the bucket credentials.
	primary := containerBlock(t, out, "app")
	for _, s := range []string{"app-db", "app-api", "myapp-minio"} {
		if !strings.Contains(primary, `secretRef: { name: "`+s+`", optional: true }`) {
			t.Errorf("the primary container must get secret %s via envFrom; got:\n%s", s, primary)
		}
	}

	// A sidecar that lists no secrets gets no envFrom at all.
	if logship := containerBlock(t, out, "logship"); strings.Contains(logship, "envFrom") || strings.Contains(logship, "secretRef") {
		t.Errorf("a sidecar without `secrets` must receive NO secrets (least privilege); got:\n%s", logship)
	}

	// A sidecar that opts in gets exactly what it lists — no more.
	worker := containerBlock(t, out, "worker")
	for _, s := range []string{"app-db", "myapp-minio"} {
		if !strings.Contains(worker, `secretRef: { name: "`+s+`", optional: true }`) {
			t.Errorf("sidecar worker listed %s and must get it via envFrom; got:\n%s", s, worker)
		}
	}
	if strings.Contains(worker, "app-api") {
		t.Errorf("sidecar worker did not list app-api and must not get it; got:\n%s", worker)
	}

	// A listed Secret need not be one of spec.secrets (any Secret in the namespace).
	proxy := containerBlock(t, out, "proxy")
	if !strings.Contains(proxy, `secretRef: { name: "proxy-tls", optional: true }`) {
		t.Errorf("sidecar proxy listed proxy-tls and must get it; got:\n%s", proxy)
	}
	for _, s := range []string{"app-db", "app-api", "myapp-minio"} {
		if strings.Contains(proxy, s) {
			t.Errorf("sidecar proxy must not get the app's secret %s; got:\n%s", s, proxy)
		}
	}
}

// #347 follow-up: startupGraceSeconds becomes the startup probe's failureThreshold in whole 10s
// periods, rounded up, and NEVER below 1 — the API server rejects failureThreshold < 1, so a small or
// zero grace must still render a valid probe. An explicit 0 is honored (the minimum), not treated as
// unset. Values are float64 here because that is how the go-templating function sees JSON numbers.
func TestApplication_StartupGraceFailureThreshold(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	ft := regexp.MustCompile(`startupProbe:.*failureThreshold: (-?\d+) }`)
	cases := []struct {
		name  string
		grace any // nil = unset
		want  int
	}{
		{"unset -> default 150s", nil, 15},
		{"0 -> minimum one period", float64(0), 1},
		{"5 -> one period", float64(5), 1},
		{"10 -> one period", float64(10), 1},
		{"15 -> rounded up to two", float64(15), 2},
		{"150", float64(150), 15},
		{"int64 300", int64(300), 30},
		{"negative (schema minimum rejects it; the template stays valid)", float64(-30), 1},
	}
	for _, c := range cases {
		spec := map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080}
		if c.grace != nil {
			spec["startupGraceSeconds"] = c.grace
		}
		out := render(t, tmpl, appCtx(spec))
		m := ft.FindStringSubmatch(out)
		if m == nil {
			t.Errorf("%s: no startupProbe failureThreshold rendered; got:\n%s", c.name, grepCtx(out, "startupProbe"))
			continue
		}
		got, _ := strconv.Atoi(m[1])
		if got != c.want {
			t.Errorf("%s: failureThreshold = %d, want %d", c.name, got, c.want)
		}
		if got < 1 {
			t.Errorf("%s: failureThreshold %d < 1 is rejected by the API server", c.name, got)
		}
	}

	xrd := mustRead(t, "../../platform/abstraction/xrd.yaml")
	if !regexp.MustCompile(`startupGraceSeconds:\n\s+type: integer\n\s+minimum: 0\n`).MatchString(xrd) {
		t.Error("xrd.yaml startupGraceSeconds must declare minimum: 0 (a negative grace is meaningless)")
	}
}

// #347 follow-up: a container port is declared once per protocol. An additionalPorts entry whose
// targetPort is spec.port (or two entries sharing a targetPort) must not repeat containerPort on the
// container — that is invalid — while the Service keeps every Service port.
func TestApplication_ContainerPortsDeduped(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, appCtx(map[string]any{
		"image": "ghcr.io/x/app:latest",
		"port":  8080,
		"additionalPorts": []any{
			map[string]any{"name": "alt", "port": 8081, "targetPort": 8080},                         // = spec.port
			map[string]any{"name": "metrics", "port": 9090},                                         // new
			map[string]any{"name": "metrics2", "port": 9091, "targetPort": 9090},                    // = metrics
			map[string]any{"name": "dns", "port": 5353, "protocol": "UDP"},                          // new (UDP)
			map[string]any{"name": "dns-tcp", "port": 5353, "protocol": "TCP"},                      // same number, other protocol
			map[string]any{"name": "http-tcp", "port": 8082, "targetPort": 8080, "protocol": "TCP"}, // explicit TCP = spec.port
		},
	}))
	app := containerBlock(t, out, "app")
	for port, want := range map[string]int{
		"containerPort: 8080 }":                1,
		"containerPort: 9090 }":                1,
		"containerPort: 5353, protocol: UDP }": 1,
		"containerPort: 5353, protocol: TCP }": 1,
	} {
		if n := strings.Count(app, port); n != want {
			t.Errorf("container must declare %q exactly %d time(s), got %d:\n%s", port, want, n, app)
		}
	}
	if n := strings.Count(app, "containerPort:"); n != 4 {
		t.Errorf("container must declare 4 unique ports (8080, 9090, 5353/UDP, 5353/TCP), got %d:\n%s", n, app)
	}

	// The Service keeps every Service port, several of them targeting the same container port.
	for _, sp := range []string{
		"- { name: http, port: 80, targetPort: 8080 }",
		"- { name: alt, port: 8081, targetPort: 8080 }",
		"- { name: metrics, port: 9090, targetPort: 9090 }",
		"- { name: metrics2, port: 9091, targetPort: 9090 }",
		"- { name: dns, port: 5353, targetPort: 5353, protocol: UDP }",
		"- { name: dns-tcp, port: 5353, targetPort: 5353, protocol: TCP }",
		"- { name: http-tcp, port: 8082, targetPort: 8080, protocol: TCP }",
	} {
		if !strings.Contains(out, sp) {
			t.Errorf("the Service must keep port %q; got:\n%s", sp, grepCtx(out, "kind: Service"))
		}
	}
}

// #347 follow-up: a domain is served by an Ingress routed to the Service's HTTP port (80 ->
// spec.port). Without spec.port that port does not exist — even when additionalPorts renders a
// Service — so the composition refuses the claim instead of rendering an Ingress that points at
// nothing, and the XRD rejects the same combination at admission.
func TestApplication_DomainRequiresPort(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	for name, spec := range map[string]map[string]any{
		"domain, no port": {"image": "ghcr.io/x/app:latest", "domain": "app.example.com"},
		"domain + additionalPorts, no port": {"image": "ghcr.io/x/app:latest", "domain": "app.example.com",
			"additionalPorts": []any{map[string]any{"name": "smtp", "port": 1025}}},
		"domain, port 0":            {"image": "ghcr.io/x/app:latest", "domain": "app.example.com", "port": 0},
		"domain on a data-only app": {"domain": "app.example.com", "queues": []any{"jobs"}},
	} {
		err := renderErr(tmpl, appCtx(spec))
		if err == nil {
			t.Errorf("%s: must be refused (the Ingress would route to a Service port that doesn't exist)", name)
			continue
		}
		if !strings.Contains(err.Error(), "spec.domain requires spec.port") {
			t.Errorf("%s: refusal must name the fix (spec.domain requires spec.port); got: %v", name, err)
		}
	}

	// With a port, the domain renders its Ingress to Service port 80, and the Service has it.
	ok := render(t, tmpl, appCtx(map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080, "domain": "app.example.com"}))
	if !strings.Contains(ok, "kind: Ingress") || !strings.Contains(ok, "port: { number: 80 }") {
		t.Errorf("domain + port must render the Ingress to Service port 80; got:\n%s", grepCtx(ok, "Ingress"))
	}
	if !strings.Contains(ok, "- { name: http, port: 80, targetPort: 8080 }") {
		t.Errorf("domain + port must render the Service's http port 80; got:\n%s", grepCtx(ok, "kind: Service"))
	}
	// No domain, no port: a plain worker still renders (the guard only fires with a domain).
	if err := renderErr(tmpl, appCtx(map[string]any{"image": "ghcr.io/x/app:latest"})); err != nil {
		t.Errorf("a port-less worker without a domain must still render; got: %v", err)
	}

	// The admission-time rule on the XRD: domain requires a positive port.
	xrd := mustRead(t, "../../platform/abstraction/xrd.yaml")
	rule := regexp.MustCompile(`rule: "!has\(self\.domain\) \|\| size\(self\.domain\) == 0 \|\| \(has\(self\.port\) && self\.port > 0\)"`)
	if !rule.MatchString(xrd) {
		t.Error("xrd.yaml must carry the x-kubernetes-validations rule rejecting spec.domain without spec.port at admission")
	}
}

// manifestDoc returns the rendered YAML document (between --- separators) that contains needle.
func manifestDoc(t *testing.T, out, needle string) string {
	t.Helper()
	for _, doc := range strings.Split(out, "\n---") {
		if strings.Contains(doc, needle) {
			return doc
		}
	}
	t.Fatalf("no rendered document contains %q", needle)
	return ""
}

// #347 follow-up: expose puts the pod on a LAN IP through a LAN Service (<name>-lan), the
// lan-expose controller's handle on the pod. The EIP is a 1:1 floating IP onto the pod, so LAN
// clients reach the container's own port numbers; the LAN Service declares exactly those (the
// deduped container ports, port == targetPort). A ClusterIP Service needs at least one port, so
// expose with neither spec.port nor additionalPorts is refused — in the composition and the XRD.
func TestApplication_ExposeRequiresPort(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)

	for name, spec := range map[string]map[string]any{
		"expose, no ports":              {"image": "ghcr.io/x/app:latest", "expose": true},
		"expose, empty additionalPorts": {"image": "ghcr.io/x/app:latest", "expose": true, "additionalPorts": []any{}},
		"expose on a data-only app":     {"expose": true, "queues": []any{"jobs"}},
	} {
		err := renderErr(tmpl, appCtx(spec))
		if err == nil {
			t.Errorf("%s: must be refused (the LAN Service would have no port)", name)
			continue
		}
		if !strings.Contains(err.Error(), "spec.expose requires spec.port or spec.additionalPorts") {
			t.Errorf("%s: refusal must name the fix; got: %v", name, err)
		}
	}

	// spec.port only: the single-port LAN Service, unnamed (as it has always rendered).
	single := manifestDoc(t, render(t, tmpl, appCtx(map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080, "expose": true})), "name: myapp-lan")
	if !strings.Contains(single, "ports: [ { port: 8080, targetPort: 8080 } ]") {
		t.Errorf("expose + port must render the LAN Service on the container port; got:\n%s", single)
	}

	// additionalPorts only: the LAN Service carries their CONTAINER ports (targetPort), named.
	addl := manifestDoc(t, render(t, tmpl, appCtx(map[string]any{
		"image":  "ghcr.io/x/app:latest",
		"expose": true,
		"additionalPorts": []any{
			map[string]any{"name": "smtp", "port": 25, "targetPort": 1025},
			map[string]any{"name": "dns", "port": 5353, "protocol": "UDP"},
		},
	})), "name: myapp-lan")
	for _, want := range []string{
		"- { name: smtp, port: 1025, targetPort: 1025 }",
		"- { name: dns, port: 5353, targetPort: 5353, protocol: UDP }",
	} {
		if !strings.Contains(addl, want) {
			t.Errorf("expose + additionalPorts must carry container port %q on the LAN Service; got:\n%s", want, addl)
		}
	}
	if strings.Contains(addl, "port: 25,") {
		t.Errorf("the LAN Service must carry the container port (1025), not the Service port (25); got:\n%s", addl)
	}

	// spec.port + additionalPorts: every container port once — an entry targeting spec.port adds nothing.
	both := manifestDoc(t, render(t, tmpl, appCtx(map[string]any{
		"image":  "ghcr.io/x/app:latest",
		"port":   8080,
		"expose": true,
		"additionalPorts": []any{
			map[string]any{"name": "alt", "port": 8081, "targetPort": 8080},
			map[string]any{"name": "smtp", "port": 1025},
		},
	})), "name: myapp-lan")
	if !strings.Contains(both, "- { name: http, port: 8080, targetPort: 8080 }") || !strings.Contains(both, "- { name: smtp, port: 1025, targetPort: 1025 }") {
		t.Errorf("expose + port + additionalPorts must carry each container port, named; got:\n%s", both)
	}
	if n := strings.Count(both, "port: 8080,"); n != 1 || strings.Contains(both, "name: alt") {
		t.Errorf("the LAN Service must list container port 8080 once (alt maps onto it); got:\n%s", both)
	}

	xrd := mustRead(t, "../../platform/abstraction/xrd.yaml")
	rule := regexp.MustCompile(`rule: "!has\(self\.expose\) \|\| !self\.expose \|\| \(has\(self\.port\) && self\.port > 0\) \|\| \(has\(self\.additionalPorts\) && size\(self\.additionalPorts\) > 0\)"`)
	if !rule.MatchString(xrd) {
		t.Error("xrd.yaml must carry the x-kubernetes-validations rule rejecting spec.expose without a port at admission")
	}
}

// #347 follow-up: the Service's ports — 80 named http (-> spec.port) plus each additionalPorts
// entry — need unique names and unique port/protocol pairs, or the API server rejects the Service.
// The composition refuses a collision and names both sides; the XRD rejects an entry that takes
// http or 80/TCP beside spec.port at admission.
func TestApplication_ServicePortCollisions(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	ap := func(entries ...map[string]any) []any {
		out := make([]any, len(entries))
		for i, e := range entries {
			out[i] = e
		}
		return out
	}
	for _, c := range []struct {
		name string
		spec map[string]any
		want []string // substrings the refusal must contain
	}{
		{"name http beside spec.port",
			map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080, "additionalPorts": ap(map[string]any{"name": "http", "port": 8081})},
			[]string{"spec.additionalPorts[0]", "name http", "spec.port (Service port 80, named http)"}},
		{"port 80 beside spec.port",
			map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080, "additionalPorts": ap(map[string]any{"name": "web", "port": 80})},
			[]string{"spec.additionalPorts[0]", "Service port 80/TCP", "spec.port (Service port 80, named http)"}},
		{"port 80/TCP explicit beside spec.port",
			map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080, "additionalPorts": ap(map[string]any{"name": "web", "port": 80, "protocol": "TCP"})},
			[]string{"Service port 80/TCP"}},
		{"two entries share a name",
			map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080, "additionalPorts": ap(map[string]any{"name": "smtp", "port": 1025}, map[string]any{"name": "smtp", "port": 1026})},
			[]string{"spec.additionalPorts[1]", "name smtp", "spec.additionalPorts[0]"}},
		{"two entries share a port",
			map[string]any{"image": "ghcr.io/x/app:latest", "additionalPorts": ap(map[string]any{"name": "a", "port": 1025}, map[string]any{"name": "b", "port": 1025})},
			[]string{"spec.additionalPorts[1]", "Service port 1025/TCP", "spec.additionalPorts[0]"}},
	} {
		err := renderErr(tmpl, appCtx(c.spec))
		if err == nil {
			t.Errorf("%s: must be refused (the Service would carry a duplicate port)", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: refusal must mention %q; got: %v", c.name, w, err)
			}
		}
	}

	// Allowed: the same number on another protocol, and http/80 when there is no spec.port.
	udp := render(t, tmpl, appCtx(map[string]any{"image": "ghcr.io/x/app:latest", "port": 8080,
		"additionalPorts": ap(map[string]any{"name": "web-udp", "port": 80, "protocol": "UDP"})}))
	if !strings.Contains(udp, "- { name: http, port: 80, targetPort: 8080 }") || !strings.Contains(udp, "- { name: web-udp, port: 80, targetPort: 80, protocol: UDP }") {
		t.Errorf("port 80/UDP beside spec.port (80/TCP) is a distinct Service port and must render; got:\n%s", grepCtx(udp, "kind: Service"))
	}
	noPort := render(t, tmpl, appCtx(map[string]any{"image": "ghcr.io/x/app:latest",
		"additionalPorts": ap(map[string]any{"name": "http", "port": 80, "targetPort": 8080})}))
	if !strings.Contains(noPort, "- { name: http, port: 80, targetPort: 8080 }") {
		t.Errorf("without spec.port, an additionalPorts entry may use http/80; got:\n%s", grepCtx(noPort, "kind: Service"))
	}

	xrd := mustRead(t, "../../platform/abstraction/xrd.yaml")
	rule := regexp.MustCompile(`self\.additionalPorts\.all\(p, p\.name != 'http' && \(p\.port != 80 \|\| \(has\(p\.protocol\) && p\.protocol != 'TCP'\)\)\)`)
	if !rule.MatchString(xrd) {
		t.Error("xrd.yaml must carry the x-kubernetes-validations rule rejecting an additionalPorts entry that takes http or 80/TCP beside spec.port")
	}
}
