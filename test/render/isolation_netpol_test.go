package render

// Tenant isolation: every pod a composition runs in a tenant namespace is selected by an ingress
// NetworkPolicy that admits only that namespace and named platform callers. Before this, only
// Application app pods were covered: database pods, directories, file shares, user pools and the
// rest answered any namespace that called them.
//
// TestIsolation_EveryPodIsSelected renders each pod-running kind and checks every workload it
// emits. TestIsolation_EveryPodRunningCompositionIsCovered fails when a composition that renders
// pods is in neither table below, so a new kind cannot ship unisolated.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const isoNS = "tenant-a"

// isoPlatformPeers are the namespaces an isolating policy may admit besides the pod's own: the
// ingress controller (kube-system), the console, Prometheus, the database operators, Knative's
// data path and the aws-shim front door.
var isoPlatformPeers = map[string]bool{
	"kube-system": true, "open-infra-console": true, "monitoring": true, "cnpg-system": true,
	"mariadb-operator": true, "knative-serving": true, "open-infra-aws-shim": true,
}

// isoPlatformNamespaces run platform setup work (bucket, queue and image jobs), not tenant pods.
var isoPlatformNamespaces = map[string]bool{
	"minio": true, "nats": true, "openinfra-images": true, "crossplane-system": true,
}

const isoJoinCIDR = "100.64.0.0/16"

func isoCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"name":              "iso-x7k2p",
			"uid":               "00000000-0000-0000-0000-0000000150a0",
			"creationTimestamp": "2026-11-01T00:00:00Z",
			"labels": map[string]any{
				"crossplane.io/claim-name":      "iso",
				"crossplane.io/claim-namespace": isoNS,
			},
		},
	}}}}
}

type isoFixture struct {
	name string // test label
	file string // composition under platform/abstraction
	spec map[string]any
}

func isoFixtures() []isoFixture {
	app := func(db map[string]any) map[string]any {
		return map[string]any{"image": "ghcr.io/x/app:1", "port": int64(8080), "database": db}
	}
	return []isoFixture{
		{"application", "composition.yaml", map[string]any{"image": "ghcr.io/x/app:1", "port": int64(8080)}},
		{"application/postgres", "composition.yaml", app(map[string]any{"engine": "postgres"})},
		{"application/mongo", "composition.yaml", app(map[string]any{"engine": "mongo"})},
		{"application/mysql", "composition.yaml", app(map[string]any{"engine": "mysql"})},
		{"application/babelfish", "composition.yaml", app(map[string]any{"engine": "babelfish"})},
		{"application/sqlserver", "composition.yaml", app(map[string]any{"engine": "sqlserver", "acceptEula": true})},
		{"databaseproxy", "databaseproxy-composition.yaml", map[string]any{"target": "db", "engine": "sqlserver"}},
		{"directory", "directory-composition.yaml", map[string]any{"domain": "corp.example.test"}},
		{"fileshare", "fileshare-composition.yaml", map[string]any{"size": "1Gi"}},
		{"userpool", "userpool-composition.yaml", map[string]any{}},
		{"model", "model-composition.yaml", map[string]any{"model": "tiny"}},
		{"model/serve", "model-composition.yaml", map[string]any{"serve": map[string]any{"image": "ghcr.io/x/serve:1"}}},
		{"featuregroup", "featuregroup-composition.yaml", map[string]any{"recordIdentifier": "id", "features": []any{map[string]any{"name": "id", "type": "String"}}}},
		{"httpapi/validated", "httpapi-composition.yaml", map[string]any{"routes": []any{map[string]any{
			"path": "/v", "methods": []any{"POST"}, "backend": map[string]any{"name": "svc", "port": int64(80)},
			"requestModel": map[string]any{"type": "object"}}}}},
		{"staticsite", "staticsite-composition.yaml", map[string]any{"domain": "app.example.test"}},
		{"staticsite/build", "staticsite-composition.yaml", map[string]any{"build": map[string]any{
			"repo": "https://git.example.test/site.git", "command": "make", "outputDir": "dist"}}},
		{"stream", "stream-composition.yaml", map[string]any{"source": map[string]any{
			"engine": "postgres", "host": "db", "database": "app", "user": "u",
			"passwordSecretRef": map[string]any{"name": "s", "key": "p"}}}},
		{"trainingjob", "trainingjob-composition.yaml", map[string]any{"image": "x", "cpu": "50m", "memory": "64Mi", "gpu": int64(0)}},
		{"processingjob", "processingjob-composition.yaml", map[string]any{"image": "x", "cpu": "50m", "memory": "64Mi", "gpu": int64(0)}},
		{"batchtransform", "batchtransform-composition.yaml", map[string]any{"image": "x", "cpu": "50m", "memory": "64Mi", "gpu": int64(0)}},
		{"modelmonitor", "modelmonitor-composition.yaml", map[string]any{"image": "x", "schedule": "0 * * * *", "cpu": "50m", "memory": "64Mi",
			"baseline": map[string]any{"bucket": "mon-data", "key": "base.csv"},
			"current":  map[string]any{"bucket": "mon-data", "key": "cur.csv"},
			"output":   map[string]any{"bucket": "mon-out"}}},
		{"scheduledjob", "scheduledjob-composition.yaml", map[string]any{"image": "x", "schedule": "0 * * * *", "cpu": "50m", "memory": "64Mi"}},
		{"vm", "vm-composition.yaml", map[string]any{"os": "ubuntu-22.04", "size": "small"}},
		{"vm/securitygroup", "vm-composition.yaml", map[string]any{"os": "ubuntu-22.04", "size": "small", "securityGroups": []any{"web"}}},
		{"vm/exposed", "vm-composition.yaml", map[string]any{"os": "windows-2022", "size": "small", "expose": true,
			"ports": []any{map[string]any{"port": int64(443)}, map[string]any{"port": int64(53), "protocol": "UDP"}}}},
		{"autoscalinggroup", "autoscalinggroup-composition.yaml", map[string]any{"minSize": int64(1), "maxSize": int64(2),
			"launchTemplate": map[string]any{"os": "ubuntu-22.04", "size": "small"}}},
		{"graphqlapi", "graphqlapi-composition.yaml", map[string]any{"schema": "type Query { a: String }"}},
		// DataFlow: replication, migration and pipe edges plus a function node, so every pod shape
		// renders (capture, multi-master prep, reconciler, drift, pump, sinks, loads, sync jobs).
		{"dataflow", "dataflow-composition.yaml", map[string]any{
			"nodes": []any{isoDBNode("a"), isoDBNode("b"), isoDBNode("c"),
				map[string]any{"name": "f", "role": "function"}},
			"edges": []any{
				map[string]any{"type": "replication", "from": "a", "to": "b", "bootstrap": true},
				map[string]any{"type": "migration", "from": "a", "to": "c"},
				map[string]any{"type": "pipe", "from": "a", "to": "f"},
				map[string]any{"type": "pipe", "from": "b", "to": "c"},
			},
			"tables":         []any{"public.orders"},
			"driftDetection": true,
			"autoSyncTables": true,
		}},
		{"migration", "migration-composition.yaml", map[string]any{
			"source": isoDBNode("src"), "target": isoDBNode("tgt"), "tables": []any{"public.orders"}}},
		{"replication", "replication-composition.yaml", map[string]any{
			"siteA": isoDBNode("a"), "siteB": isoDBNode("b"), "tables": []any{"public.orders"}}},
	}
}

func isoDBNode(name string) map[string]any {
	return map[string]any{
		"name": name, "engine": "postgres", "username": "u", "host": "db-" + name,
		"port": int64(5432), "database": "app", "role": "database",
		"passwordSecretRef": map[string]any{"name": name + "-sec", "key": "password"},
	}
}

// isoExempt lists compositions that render pods but need no tenant isolation of their own, and why.
var isoExempt = map[string]string{
	"bucket-composition.yaml":   "its only pod is the setup Job in the minio namespace",
	"query-composition.yaml":    "its Job runs in the minio namespace; queries run in query-runtime, which has its own policy",
	"queue-composition.yaml":    "its only pod is the setup Job in the nats namespace",
	"vmimage-composition.yaml":  "image builds run in the openinfra-images platform namespace",
	"function-composition.yaml": "Functions get their ingress isolation in a follow-up change (one shared policy per namespace)",
}

// isoExemptWorkload is a workload that needs no policy: it opens no port to anyone.
func isoExemptWorkload(file, kind, name string) string {
	if file == "function-composition.yaml" && kind == "Deployment" && strings.HasSuffix(name, "-pump") {
		return "the trigger pump only consumes from NATS"
	}
	return ""
}

type isoWorkload struct {
	kind, name, ns string
	labels         map[string]string
}

type isoPolicy struct {
	name, ns string
	selector map[string]any
	ingress  []any
	isolates bool // carries openinfra.dev/isolation: tenant
}

func mget(m any, path ...string) any {
	for _, k := range path {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil
		}
		m = mm[k]
	}
	return m
}

func mstr(m any, path ...string) string { s, _ := mget(m, path...).(string); return s }

func strMap(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, x := range m {
			if s, ok := x.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

// isoLB is a LoadBalancer Service a render publishes: the pods it selects and their target ports.
type isoLB struct {
	ns       string
	selector map[string]string
	ports    map[string]bool // "TCP/22"
}

func isoLBs(t *testing.T, out string) []isoLB {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse rendered output: %v", err)
	}
	var lbs []isoLB
	for _, d := range docs {
		m := mget(d, "spec", "forProvider", "manifest")
		if mstr(m, "kind") != "Service" || mstr(m, "apiVersion") != "v1" || mstr(m, "spec", "type") != "LoadBalancer" {
			continue
		}
		lb := isoLB{ns: mstr(m, "metadata", "namespace"), selector: strMap(mget(m, "spec", "selector")), ports: map[string]bool{}}
		ps, _ := mget(m, "spec", "ports").([]any)
		for _, p := range ps {
			proto := mstr(p, "protocol")
			if proto == "" {
				proto = "TCP"
			}
			port := mstr(p, "targetPort")
			if port == "" {
				port = mstr(p, "port")
			}
			lb.ports[proto+"/"+port] = true
		}
		lbs = append(lbs, lb)
	}
	return lbs
}

// isoPublished reports whether every port of a from-less ingress rule is published to these pods by
// a LoadBalancer in the same render: such a rule opens no more than the Service already does.
func isoPublished(rule any, w isoWorkload, lbs []isoLB) bool {
	ports, _ := mget(rule, "ports").([]any)
	if len(ports) == 0 {
		return false
	}
	for _, p := range ports {
		proto := mstr(p, "protocol")
		if proto == "" {
			proto = "TCP"
		}
		key := proto + "/" + mstr(p, "port")
		ok := false
		for _, lb := range lbs {
			if lb.ns == w.ns && lb.ports[key] && len(lb.selector) > 0 && isoSelects(map[string]any{"matchLabels": toAnyMap(lb.selector)}, w.labels) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func toAnyMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// isoCollect returns the workloads (with their pods' labels) and NetworkPolicies a render emits.
func isoCollect(t *testing.T, out string) ([]isoWorkload, []isoPolicy) {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse rendered output: %v", err)
	}
	var wl []isoWorkload
	var np []isoPolicy
	for _, d := range docs {
		m := map[string]any(d)
		if mstr(m, "kind") == "Object" && strings.HasPrefix(mstr(m, "apiVersion"), "kubernetes.crossplane.io/") {
			mm, _ := mget(m, "spec", "forProvider", "manifest").(map[string]any)
			if mm == nil {
				continue
			}
			m = mm
		}
		kind, api, name, ns := mstr(m, "kind"), mstr(m, "apiVersion"), mstr(m, "metadata", "name"), mstr(m, "metadata", "namespace")
		var labels map[string]string
		switch {
		case kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "Job":
			labels = strMap(mget(m, "spec", "template", "metadata", "labels"))
		case kind == "CronJob":
			labels = strMap(mget(m, "spec", "jobTemplate", "spec", "template", "metadata", "labels"))
		case kind == "VirtualMachine" && strings.HasPrefix(api, "kubevirt.io/"):
			labels = strMap(mget(m, "spec", "template", "metadata", "labels"))
		case kind == "VirtualMachinePool":
			labels = strMap(mget(m, "spec", "virtualMachineTemplate", "spec", "template", "metadata", "labels"))
		case kind == "Cluster" && strings.HasPrefix(api, "postgresql.cnpg.io/"):
			labels = map[string]string{"cnpg.io/cluster": name}
		case kind == "MariaDB":
			labels = map[string]string{"app.kubernetes.io/instance": name, "app.kubernetes.io/name": "mariadb"}
		case kind == "Service" && strings.HasPrefix(api, "serving.knative.dev/"):
			labels = strMap(mget(m, "spec", "template", "metadata", "labels"))
			labels["serving.knative.dev/service"] = name
		case kind == "NetworkPolicy":
			types, _ := mget(m, "spec", "policyTypes").([]any)
			ingressType := len(types) == 0
			for _, x := range types {
				if x == "Ingress" {
					ingressType = true
				}
			}
			if !ingressType {
				continue
			}
			sel, _ := mget(m, "spec", "podSelector").(map[string]any)
			ing, _ := mget(m, "spec", "ingress").([]any)
			np = append(np, isoPolicy{name: name, ns: ns, selector: sel, ingress: ing,
				isolates: strMap(mget(m, "metadata", "labels"))["openinfra.dev/isolation"] == "tenant"})
			continue
		default:
			continue
		}
		wl = append(wl, isoWorkload{kind: kind, name: name, ns: ns, labels: labels})
	}
	return wl, np
}

// isoSelects reports whether a podSelector selects pods with these labels.
func isoSelects(sel map[string]any, labels map[string]string) bool {
	for k, v := range strMap(sel["matchLabels"]) {
		if labels[k] != v {
			return false
		}
	}
	exprs, _ := sel["matchExpressions"].([]any)
	for _, e := range exprs {
		key, op := mstr(e, "key"), mstr(e, "operator")
		val, has := labels[key]
		vals, _ := mget(e, "values").([]any)
		in := false
		for _, x := range vals {
			if x == val {
				in = true
			}
		}
		switch op {
		case "In":
			if !has || !in {
				return false
			}
		case "NotIn":
			if has && in {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// isoPeersProblems lists every ingress peer that would admit more than the pod's namespace and the
// named platform callers: an empty `from` (unless it only opens ports a LoadBalancer in the same
// render already publishes to these pods), an all-namespaces selector, an unknown namespace, or an
// address block other than the join subnet.
func isoPeersProblems(p isoPolicy, w isoWorkload, lbs []isoLB) []string {
	var probs []string
	if len(p.ingress) == 0 {
		probs = append(probs, "no ingress rules")
	}
	for _, r := range p.ingress {
		from, _ := mget(r, "from").([]any)
		if len(from) == 0 {
			if !isoPublished(r, w, lbs) {
				probs = append(probs, "an ingress rule with no `from` admits everyone (and its ports are not ones a LoadBalancer publishes)")
			}
			continue
		}
		for _, peer := range from {
			pm, _ := peer.(map[string]any)
			if ib, ok := pm["ipBlock"]; ok {
				if mstr(ib, "cidr") != isoJoinCIDR || mget(ib, "except") != nil {
					probs = append(probs, "ipBlock "+mstr(ib, "cidr")+" (only the join subnet "+isoJoinCIDR+" is expected)")
				}
				continue
			}
			nsSel, hasNS := pm["namespaceSelector"]
			if !hasNS {
				if _, ok := pm["podSelector"]; ok {
					continue // pods of this namespace
				}
				probs = append(probs, "an empty peer admits everyone")
				continue
			}
			nsm, _ := nsSel.(map[string]any)
			n := strMap(nsm["matchLabels"])["kubernetes.io/metadata.name"]
			if n == "" || len(nsm) != 1 || len(strMap(nsm["matchLabels"])) != 1 {
				probs = append(probs, "a namespaceSelector that is not one named namespace")
				continue
			}
			if n != p.ns && !isoPlatformPeers[n] {
				probs = append(probs, "admits namespace "+n)
			}
		}
	}
	return probs
}

func isoCheck(t *testing.T, label, file string, out string) {
	t.Helper()
	wl, np := isoCollect(t, out)
	lbs := isoLBs(t, out)
	for _, w := range wl {
		if isoPlatformNamespaces[w.ns] {
			continue
		}
		if why := isoExemptWorkload(file, w.kind, w.name); why != "" {
			continue
		}
		if w.ns != isoNS {
			t.Errorf("%s: %s %s renders into namespace %q, not the claim's", label, w.kind, w.name, w.ns)
			continue
		}
		if sgMember(w.labels) {
			continue // a SecurityGroup's policies govern its members
		}
		var hit []isoPolicy
		for _, p := range np {
			if p.ns == w.ns && isoSelects(p.selector, w.labels) {
				hit = append(hit, p)
			}
		}
		if len(hit) == 0 {
			t.Errorf("%s: %s %s (pod labels %v) is selected by no ingress NetworkPolicy", label, w.kind, w.name, w.labels)
			continue
		}
		for _, p := range hit {
			for _, prob := range isoPeersProblems(p, w, lbs) {
				t.Errorf("%s: NetworkPolicy %s selecting %s %s: %s", label, p.name, w.kind, w.name, prob)
			}
		}
	}
}

func sgMember(labels map[string]string) bool {
	for k := range labels {
		if strings.HasPrefix(k, "openinfra.dev/sg-") {
			return true
		}
	}
	return false
}

func TestIsolation_EveryPodIsSelected(t *testing.T) {
	for _, f := range isoFixtures() {
		t.Run(f.name, func(t *testing.T) {
			tmpl := extractInlineTemplate(t, "../../platform/abstraction/"+f.file)
			out := render(t, tmpl, isoCtx(f.spec))
			wl, _ := isoCollect(t, out)
			n := 0
			for _, w := range wl {
				if !isoPlatformNamespaces[w.ns] && isoExemptWorkload(f.file, w.kind, w.name) == "" {
					n++
				}
			}
			if n == 0 {
				t.Fatalf("fixture renders no tenant workload; fix the fixture so the check means something:\n%s", out)
			}
			isoCheck(t, f.name, f.file, out)
		})
	}
}

// A VM with a security group is governed by that group's policies alone: the default isolation
// policy is only for VMs without one (adding it would widen what the group allows).
func TestIsolation_VMDefaultOnlyWithoutSecurityGroup(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	for _, c := range []struct {
		sgs  []any
		want bool
	}{{nil, true}, {[]any{"web"}, false}} {
		spec := map[string]any{"os": "ubuntu-22.04", "size": "small"}
		if c.sgs != nil {
			spec["securityGroups"] = c.sgs
		}
		_, np := isoCollect(t, render(t, tmpl, isoCtx(spec)))
		got := false
		for _, p := range np {
			if p.name == "iso-vm-isolation" {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("securityGroups=%v: default isolation policy rendered=%v, want %v", c.sgs, got, c.want)
		}
	}
}

// An exposed VM without a security group keeps its LAN clients: its LoadBalancer keeps the client's
// IP, so the default policy opens exactly the published ports (the access port and spec.ports).
func TestIsolation_ExposedVMKeepsPublishedPorts(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, isoCtx(map[string]any{"os": "windows-2022", "size": "small", "expose": true,
		"ports": []any{map[string]any{"port": int64(443)}, map[string]any{"port": int64(53), "protocol": "UDP"}}}))
	_, np := isoCollect(t, out)
	lbs := isoLBs(t, out)
	if len(lbs) != 1 {
		t.Fatalf("want one LAN LoadBalancer, got %d", len(lbs))
	}
	for _, p := range np {
		if p.name != "iso-vm-isolation" {
			continue
		}
		got := map[string]bool{}
		for _, r := range p.ingress {
			if _, hasFrom := mget(r, "from").([]any); hasFrom {
				continue
			}
			ports, _ := mget(r, "ports").([]any)
			for _, x := range ports {
				got[mstr(x, "protocol")+"/"+mstr(x, "port")] = true
			}
		}
		for k := range lbs[0].ports {
			if !got[k] {
				t.Errorf("published port %s is not open in the VM's isolation policy (LAN clients would be refused); open: %v", k, got)
			}
		}
		if len(got) != len(lbs[0].ports) {
			t.Errorf("the policy opens %v, the LoadBalancer publishes %v", got, lbs[0].ports)
		}
		return
	}
	t.Fatal("no iso-vm-isolation policy rendered")
}

var isoWorkloadRe = regexp.MustCompile(`(?m)^\s+kind: (Deployment|StatefulSet|DaemonSet|Job|CronJob|VirtualMachine|VirtualMachinePool|MariaDB)\s*$|apiVersion: postgresql\.cnpg\.io/v1\s*\n\s+kind: Cluster|apiVersion: serving\.knative\.dev/v1\s*\n\s+kind: Service`)

func TestIsolation_EveryPodRunningCompositionIsCovered(t *testing.T) {
	covered := map[string]bool{}
	for _, f := range isoFixtures() {
		covered[f.file] = true
	}
	files, _ := filepath.Glob("../../platform/abstraction/*.yaml")
	var missing []string
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		if !strings.Contains(s, "kind: Composition") || !isoWorkloadRe.MatchString(s) {
			continue
		}
		b := filepath.Base(p)
		if !covered[b] && isoExempt[b] == "" {
			missing = append(missing, b)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("compositions that run pods with no isolation fixture (add one to isoFixtures, or an isoExempt reason): %v", missing)
	}
}
