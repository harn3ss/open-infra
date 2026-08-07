package render

// Composition-render assertion tests. These render the ACTUAL committed
// go-templating template out of platform/abstraction/composition.yaml and assert
// on the emitted manifests. They exist because a composition-logic bug shipped to
// production once: the managed-DB CNPG "hibernation" annotation was only added when
// stopped, so pressing Start never wrote "off" and the DB stayed hibernated. A
// render test like TestManagedDB_HibernationAlwaysExplicit would have caught it.
//
// Faithful enough without the Crossplane runtime: composition.yaml uses only the
// sprig funcs re-implemented in sprigLite() (verified: default, sha256sum, trunc,
// dict, list, join). If a future edit introduces another func, Parse fails loudly
// (add it here) rather than silently mis-rendering.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"text/template"
)

const compositionPath = "../../platform/abstraction/composition.yaml"

func TestManagedDB_HibernationAlwaysExplicit(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)

	stopped := render(t, tmpl, dbCtx(true, false))
	if !strings.Contains(stopped, `cnpg.io/hibernation: "on"`) {
		t.Errorf("stopped DB must render hibernation \"on\"; got cluster:\n%s", grepCtx(stopped, "hibernation"))
	}

	// The regression guard: a RUNNING db must EXPLICITLY set the annotation to "off".
	// Omitting it does not reliably clear an existing "on" (that was the prod bug).
	running := render(t, tmpl, dbCtx(false, false))
	if !strings.Contains(running, `cnpg.io/hibernation: "off"`) {
		t.Errorf("running DB must render hibernation \"off\" EXPLICITLY (regression: omitting it never clears 'on'); got cluster:\n%s", grepCtx(running, "hibernation"))
	}
	if strings.Contains(running, `cnpg.io/hibernation: "on"`) {
		t.Errorf("running DB must not be hibernated")
	}
}

func TestManagedDB_HAInstancesAndAntiAffinity(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)

	ha := render(t, tmpl, dbCtx(false, true))
	if !strings.Contains(ha, "instances: 2") {
		t.Errorf("HA postgres must render instances: 2; got:\n%s", grepCtx(ha, "instances:"))
	}
	if !strings.Contains(ha, "enablePodAntiAffinity: true") {
		t.Errorf("HA postgres must set required pod anti-affinity (node-local PVs need one instance per node)")
	}

	single := render(t, tmpl, dbCtx(false, false))
	if !strings.Contains(single, "instances: 1") {
		t.Errorf("non-HA postgres must render instances: 1; got:\n%s", grepCtx(single, "instances:"))
	}
	if strings.Contains(single, "enablePodAntiAffinity") {
		t.Errorf("non-HA must not declare anti-affinity")
	}
}

// TestFileShare_NodeIPExternalIPs guards the masquerade-VM escape hatch: when a
// FileShare sets spec.nodeIP, the Service must also bind SMB 445 on that node IP
// (externalIPs) so a NAT'd VM can mount it; without nodeIP it must not.
func TestFileShare_NodeIPExternalIPs(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/fileshare-composition.yaml")

	// 192.0.2.0/24 is the RFC 5737 documentation range — never a real site IP.
	with := render(t, tmpl, fileshareCtx("192.0.2.50"))
	if !strings.Contains(with, "externalIPs: [192.0.2.50]") {
		t.Errorf("nodeIP set must render externalIPs; got:\n%s", grepCtx(with, "type:"))
	}
	without := render(t, tmpl, fileshareCtx(""))
	if strings.Contains(without, "externalIPs") {
		t.Errorf("no nodeIP must not render externalIPs; got:\n%s", grepCtx(without, "type:"))
	}
}

// TestSecurityGroup_AlwaysAllowsConsole guards the invariant that any ingress-restricted
// SecurityGroup still lets the console (open-infra-console) reach the workload — else a
// user's SG silently breaks console features like DB Peek (a real prod incident).
func TestSecurityGroup_AlwaysAllowsConsole(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/securitygroup-composition.yaml")

	// An ingress-restricted SG (e.g. on a DB) must always allow the console namespace.
	withIngress := render(t, tmpl, sgCtx(true))
	if !strings.Contains(withIngress, "open-infra-console") {
		t.Errorf("ingress-restricted SG must allow the console namespace (Peek); got:\n%s", grepCtx(withIngress, "ingress"))
	}
	// With no ingress rules the pod isn't ingress-restricted, so nothing is injected.
	noIngress := render(t, tmpl, sgCtx(false))
	if strings.Contains(noIngress, "open-infra-console") {
		t.Errorf("SG with no ingress must not inject a console allow (pod not ingress-restricted)")
	}
}

func TestHttpApi_RendersIngressWithRoutes(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/httpapi-composition.yaml")
	out := render(t, tmpl, httpApiCtx(true))

	// One Traefik Ingress, in the claim namespace, on the declared host.
	for _, want := range []string{"kind: Ingress", "ingressClassName: traefik",
		"name: httpapi-storefront", "namespace: shop", "host: api.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("HttpApi ingress missing %q; got:\n%s", want, grepCtx(out, "Ingress"))
		}
	}
	// Every declared route becomes a path → its backend Service (both Function and Application
	// backends resolve to a Service named after the resource).
	for _, want := range []string{"path: /", "path: /fn", "name: web", "name: hello"} {
		if !strings.Contains(out, want) {
			t.Errorf("HttpApi ingress missing route %q; got:\n%s", want, grepCtx(out, "path"))
		}
	}
	// TLS on → cert-manager issuer + websecure entrypoint + a tls block.
	for _, want := range []string{"cert-manager.io/cluster-issuer: openinfra-issuer",
		"entrypoints: websecure", "secretName: httpapi-storefront-tls"} {
		if !strings.Contains(out, want) {
			t.Errorf("HttpApi (tls) missing %q; got:\n%s", want, out)
		}
	}
}

func TestHttpApi_NoTLS(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/httpapi-composition.yaml")
	out := render(t, tmpl, httpApiCtx(false))
	// TLS off → plain-HTTP entrypoint, and no cert-manager / tls block.
	if !strings.Contains(out, "entrypoints: web") {
		t.Errorf("HttpApi (no tls) should use the web entrypoint; got:\n%s", out)
	}
	if strings.Contains(out, "cert-manager.io/cluster-issuer") || strings.Contains(out, "secretName: httpapi-") {
		t.Errorf("HttpApi (no tls) must not emit cert-manager/tls; got:\n%s", out)
	}
}

// TestGraphQLApi_RendersConfigAndEngine pins the neutral authoring plane (open-appsync §2): the
// composition must render (a) a ConfigMap whose config.json + per-resolver .vtl files match the shape
// server.Load reads, carrying the resolver's `runtime`, and (b) an engine Deployment with a config
// checksum annotation (the reload mechanism) + a Service. The resolver author's VTL must appear
// verbatim — the load-bearing "specialist learns nothing" promise (§4.1).
func TestGraphQLApi_RendersConfigAndEngine(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	out := render(t, tmpl, graphqlApiCtx(""))

	for _, want := range []string{
		// (a) config + templates, in the claim namespace, named after the claim.
		"kind: ConfigMap", "open-appsync-notes-config", "namespace: team-a",
		`"field": "getNote"`, `"runtime": "appsync-vtl"`, `"dataSource": "notes"`,
		"Query.getNote.request.vtl:", "Mutation.putNote.response.vtl:",
		"$util.dynamodb.toDynamoDBJson($ctx.args.id)", // the author's VTL, verbatim
		// (b) engine + reload + service.
		"kind: Deployment", "open-appsync-notes", "openinfra.dev/config-checksum:",
		"readOnlyRootFilesystem: true", "drop: [ALL]",
		"kind: Service", "targetPort: 8080",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("GraphQLApi render missing %q; got:\n%s", want, grepCtx(out, "open-appsync-notes"))
		}
	}
	// A memory-only API must NOT wire Mongo env.
	if strings.Contains(out, "MONGO_URI") {
		t.Errorf("memory-only GraphQLApi must not set MONGO_URI; got:\n%s", grepCtx(out, "env:"))
	}
}

// A dynamodb data source with a mongoURI must wire the FerretDB env onto the engine.
func TestGraphQLApi_DynamoDBWiresMongo(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	out := render(t, tmpl, graphqlApiCtx("mongodb://ferretdb.data.svc:27017"))
	for _, want := range []string{"MONGO_URI", "mongodb://ferretdb.data.svc:27017", `"type": "dynamodb"`, `"collection": "notes"`} {
		if !strings.Contains(out, want) {
			t.Errorf("dynamodb GraphQLApi missing %q; got:\n%s", want, grepCtx(out, "MONGO"))
		}
	}
}

// A pipeline resolver + hostile-load limits render into config.json + the per-step .vtl files.
func TestGraphQLApi_PipelineAndLimits(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	out := render(t, tmpl, graphqlApiPipelineCtx())
	for _, want := range []string{
		`"limits"`, `"maxDepth": 6`, `"persistedOnly": false`,
		`"functions"`,
		"Mutation.createAndFetch.before.vtl:", "Mutation.createAndFetch.after.vtl:",
		"Mutation.createAndFetch.fn0.request.vtl:", "Mutation.createAndFetch.fn1.request.vtl:",
		`$ctx.stash.put`,        // before step's VTL, verbatim
		`$ctx.prev.result.id`,   // fn1 threading, verbatim
	} {
		if !strings.Contains(out, want) {
			t.Errorf("GraphQLApi pipeline render missing %q; got:\n%s", want, grepCtx(out, "functions"))
		}
	}
}

// An http data source renders its endpoint into config.json (the §5 second call-source).
func TestGraphQLApi_HTTPDataSource(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"dataSources": []any{map[string]any{"name": "api", "type": "http", "endpoint": "https://api.example.com"}},
				"resolvers": []any{map[string]any{
					"type": "Query", "field": "getUser", "dataSource": "api",
					"request": "{\"method\":\"GET\",\"resourcePath\":\"/u\"}", "response": "$util.toJson($ctx.result.body)",
				}},
			},
			"metadata": map[string]any{"uid": "u", "labels": map[string]any{"crossplane.io/claim-name": "u", "crossplane.io/claim-namespace": "team-a"}},
		}}},
	}
	out := render(t, tmpl, ctx)
	for _, want := range []string{`"type": "http"`, `"endpoint": "https://api.example.com"`} {
		if !strings.Contains(out, want) {
			t.Errorf("http data source render missing %q; got:\n%s", want, grepCtx(out, "dataSources"))
		}
	}
}

// TestManagedDB_BabelfishEngine guards the SQL-Server-compatible engine: it must render
// a StatefulSet on the pinned Babelfish image with a TDS (1433) connection secret, and
// must NOT fall through to the CNPG Postgres path.
func TestManagedDB_BabelfishEngine(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"database": map[string]any{"engine": "babelfish", "name": "appdb"},
			},
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000bf",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "sqlapp",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
	out := render(t, tmpl, ctx)
	for _, want := range []string{"SQLSERVER_URL", "kind: StatefulSet", "open-infra-babelfish", "/start.sh", `port: 1433`, "kind: Certificate", "BABELFISH_TLS_DIR"} {
		if !strings.Contains(out, want) {
			t.Errorf("babelfish render missing %q; got:\n%s", want, grepCtx(out, "babelfish"))
		}
	}
	if strings.Contains(out, "postgresql.cnpg.io/v1") {
		t.Errorf("babelfish engine must not render a CNPG Cluster (should not fall through to Postgres)")
	}
}

// ---- helpers ----

// TestQuery_SecurityHardening pins the kind: Query engine-pod sandbox. The query pod runs
// ATTACKER-CONTROLLED SQL, so each of these lines is load-bearing: dropping any one of them
// silently re-opens the credential-scope / exfiltration hole that was closed once already.
// The hardening shipped; this is what KEEPS it. A refactor that quietly removes
// automountServiceAccountToken, flips readOnlyRootFilesystem, or swaps the scoped identity
// back to the MinIO root secret must turn this red.
func TestQuery_SecurityHardening(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/query-composition.yaml")
	out := render(t, tmpl, queryCtx())

	// Positive: every protection must be present.
	for _, want := range []string{
		"automountServiceAccountToken: false", // no cluster API from the sandbox
		"runAsNonRoot: true",
		"runAsUser: 65532",
		"type: RuntimeDefault", // seccompProfile
		"readOnlyRootFilesystem: true",
		"drop: [ALL]",       // capabilities
		"query-runner-s3",   // least-privilege S3 identity
	} {
		if !strings.Contains(out, want) {
			t.Errorf("query pod lost a hardening guarantee: %q missing from the rendered Job.\n"+
				"This pod runs untrusted SQL — restore it.\n%s", want, grepCtx(out, "securityContext"))
		}
	}

	// Negative: the engine must NEVER be handed the MinIO root credentials again. This is
	// the specific regression that would re-grant read/write over every bucket on the
	// platform (backups, golden images, every app's data) to anyone who can submit a query.
	for _, forbidden := range []string{"rootUser", "rootPassword"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("query pod references the MinIO ROOT credential %q — it must use the "+
				"scoped query-runner-s3 identity instead.\n%s", forbidden, grepCtx(out, forbidden))
		}
	}
}

// queryCtx builds the observed composite for the Query composition.
func queryCtx() map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"sql":    "SELECT 1",
				"engine": "duckdb",
			},
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-00000000qry",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "q1",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

func sgCtx(withIngress bool) map[string]any {
	spec := map[string]any{}
	if withIngress {
		spec["ingress"] = []any{
			map[string]any{"from": []any{map[string]any{"namespace": "default"}}, "protocol": "TCP"},
		}
	}
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000sg",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "dbtest",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

func fileshareCtx(nodeIP string) map[string]any {
	spec := map[string]any{"size": "100Gi", "expose": true}
	if nodeIP != "" {
		spec["nodeIP"] = nodeIP
	}
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000fs",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "iis-work",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

// httpApiCtx builds the context for a kind: HttpApi with two routes and a toggle for TLS.
func httpApiCtx(tls bool) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"domain": "api.example.com",
				"tls":    tls,
				"routes": []any{
					map[string]any{"path": "/", "backend": map[string]any{"kind": "Application", "name": "web", "port": int64(80)}},
					map[string]any{"path": "/fn", "pathType": "Prefix", "backend": map[string]any{"kind": "Function", "name": "hello"}},
				},
			},
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000ap",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "storefront",
					"crossplane.io/claim-namespace": "shop",
				},
			},
		}}},
	}
}

// graphqlApiCtx builds a kind: GraphQLApi with two resolvers. Pass a non-empty mongoURI and the data
// source becomes dynamodb (FerretDB-backed); empty keeps it in-memory (the §6 default for the bar).
func graphqlApiCtx(mongoURI string) map[string]any {
	dsType := "memory"
	ds := map[string]any{"name": "notes"}
	if mongoURI != "" {
		dsType = "dynamodb"
		ds["collection"] = "notes"
	}
	ds["type"] = dsType
	spec := map[string]any{
		"dataSources": []any{ds},
		"resolvers": []any{
			map[string]any{
				"type": "Query", "field": "getNote", "dataSource": "notes", "runtime": "appsync-vtl",
				"request":  "{\n  \"operation\": \"GetItem\",\n  \"key\": { \"id\": $util.dynamodb.toDynamoDBJson($ctx.args.id) }\n}",
				"response": "$util.toJson($ctx.result)",
			},
			map[string]any{
				"type": "Mutation", "field": "putNote", "dataSource": "notes",
				"request":  "{\n  \"operation\": \"PutItem\",\n  \"key\": { \"id\": $util.dynamodb.toDynamoDBJson($util.autoId()) },\n  \"attributeValues\": $util.dynamodb.toMapValuesJson($ctx.args.input)\n}",
				"response": "$util.toJson($ctx.result)",
			},
		},
	}
	if mongoURI != "" {
		spec["mongoURI"] = mongoURI
	}
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000ga",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "notes",
					"crossplane.io/claim-namespace": "team-a",
				},
			},
		}}},
	}
}

// graphqlApiPipelineCtx builds a kind: GraphQLApi with a pipeline resolver (before → 2 functions →
// after) and hostile-load limits — the drop-33 §2/§7 surface.
func graphqlApiPipelineCtx() map[string]any {
	spec := map[string]any{
		"dataSources": []any{map[string]any{"name": "things", "type": "memory"}},
		"limits":      map[string]any{"maxDepth": int64(6), "maxCost": int64(200)},
		"resolvers": []any{
			map[string]any{
				"type": "Mutation", "field": "createAndFetch",
				"before": "#set($d = $ctx.stash.put(\"tag\", $ctx.args.tag))",
				"after":  "$util.toJson($ctx.prev.result)",
				"functions": []any{
					map[string]any{
						"dataSource": "things",
						"request":    "{\"operation\":\"PutItem\",\"key\":{\"id\":$util.dynamodb.toDynamoDBJson($util.autoId())},\"attributeValues\":$util.dynamodb.toMapValuesJson({\"name\":$ctx.args.name,\"tag\":$ctx.stash.tag})}",
						"response":   "$util.toJson($ctx.result)",
					},
					map[string]any{
						"dataSource": "things",
						"request":    "{\"operation\":\"GetItem\",\"key\":{\"id\":$util.dynamodb.toDynamoDBJson($ctx.prev.result.id)}}",
						"response":   "$util.toJson($ctx.result)",
					},
				},
			},
		},
	}
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-0000000000gp",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "notes",
					"crossplane.io/claim-namespace": "team-a",
				},
			},
		}}},
	}
}

// dbCtx builds the minimal .observed.composite.resource context that reaches the
// managed-Postgres branch (spec.database.engine defaults to postgres). No image =>
// the workload section is skipped; no storage/securityGroups => those are skipped.
func dbCtx(stopped, ha bool) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"database": map[string]any{
					"engine":           "postgres",
					"name":             "appdb",
					"stopped":          stopped,
					"highAvailability": ha,
				},
			},
			"metadata": map[string]any{
				"uid": "00000000-0000-0000-0000-000000000abc",
				"labels": map[string]any{
					"crossplane.io/claim-name":      "myapp",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

func render(t *testing.T, tmplStr string, ctx any) string {
	t.Helper()
	tmpl, err := template.New("comp").Funcs(sprigLite()).Parse(tmplStr)
	if err != nil {
		t.Fatalf("parse composition template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		t.Fatalf("execute composition template: %v", err)
	}
	return buf.String()
}

// extractInlineTemplate pulls the `template: |` block-scalar body out of the
// composition YAML and dedents it, reproducing the exact string the go-templating
// function receives — no YAML dependency needed.
func extractInlineTemplate(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	start, keyIndent := -1, 0
	for i, ln := range lines {
		trimmed := strings.TrimLeft(ln, " ")
		if strings.HasPrefix(trimmed, "template: |") {
			start = i + 1
			keyIndent = len(ln) - len(trimmed)
			break
		}
	}
	if start < 0 {
		t.Fatalf("no 'template: |' block found in %s", filepath.Base(path))
	}
	contentIndent := -1
	var out []string
	for _, ln := range lines[start:] {
		if strings.TrimSpace(ln) == "" {
			out = append(out, "")
			continue
		}
		ind := len(ln) - len(strings.TrimLeft(ln, " "))
		if ind <= keyIndent {
			break // dedented to a sibling key: block ended
		}
		if contentIndent < 0 {
			contentIndent = ind
		}
		if ind < contentIndent {
			break
		}
		out = append(out, ln[contentIndent:])
	}
	return strings.Join(out, "\n")
}

// grepCtx returns lines around the first match of needle, for readable failures.
func grepCtx(s, needle string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.Contains(ln, needle) {
			lo, hi := i-2, i+3
			if lo < 0 {
				lo = 0
			}
			if hi > len(lines) {
				hi = len(lines)
			}
			return strings.Join(lines[lo:hi], "\n")
		}
	}
	return "(needle " + needle + " not found in output)"
}

// sprigLite implements the exact subset of Sprig funcs composition.yaml uses,
// matching Sprig semantics (piped last-arg convention).
func sprigLite() template.FuncMap {
	return template.FuncMap{
		"default": func(d any, given ...any) any {
			if len(given) == 0 || isEmpty(given[0]) {
				return d
			}
			return given[0]
		},
		"sha256sum": func(s string) string {
			h := sha256.Sum256([]byte(s))
			return hex.EncodeToString(h[:])
		},
		"trunc": func(c int, s string) string {
			if c < 0 {
				if -c > len(s) {
					return s
				}
				return s[len(s)+c:]
			}
			if c > len(s) {
				return s
			}
			return s[:c]
		},
		"dict": func(v ...any) map[string]any {
			d := map[string]any{}
			for i := 0; i+1 < len(v); i += 2 {
				d[fmt.Sprint(v[i])] = v[i+1]
			}
			return d
		},
		"list": func(v ...any) []any { return v },
		// query-composition.yaml quotes user-supplied SQL into the Job env. Faithful to
		// sprig: %q on the string form (the render assertions only need the value present).
		"quote": func(v ...any) string {
			out := make([]string, len(v))
			for i, x := range v {
				out[i] = fmt.Sprintf("%q", fmt.Sprint(x))
			}
			return strings.Join(out, " ")
		},
		"hasKey": func(m map[string]any, k string) bool {
			_, ok := m[k]
			return ok
		},
		"set": func(d map[string]any, k string, v any) map[string]any {
			if d == nil {
				d = map[string]any{}
			}
			d[k] = v
			return d
		},
		// Minimal, substring-faithful (not a full YAML marshaller): every scalar value
		// appears in the output, which is all the render assertions check.
		"toYaml": func(v any) string { return toYAMLish(v) },
		"nindent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			lines := strings.Split(s, "\n")
			for i := range lines {
				lines[i] = pad + lines[i]
			}
			return "\n" + strings.Join(lines, "\n")
		},
		"append": func(list any, v any) []any {
			var out []any
			if rv := reflect.ValueOf(list); rv.Kind() == reflect.Slice {
				for i := 0; i < rv.Len(); i++ {
					out = append(out, rv.Index(i).Interface())
				}
			}
			return append(out, v)
		},
		"join": func(sep string, v any) string {
			rv := reflect.ValueOf(v)
			if rv.Kind() != reflect.Slice {
				return ""
			}
			parts := make([]string, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				parts[i] = fmt.Sprint(rv.Index(i).Interface())
			}
			return strings.Join(parts, sep)
		},
	}
}

// toYAMLish recursively renders a value so every scalar (incl. nested map values like
// "open-infra-console") appears in the output. Not valid nested YAML — enough for the
// substring-based render assertions, deterministic via sorted keys.
func toYAMLish(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+": "+toYAMLish(t[k]))
		}
		return strings.Join(parts, "\n")
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, "- "+toYAMLish(item))
		}
		return strings.Join(parts, "\n")
	case string:
		return t
	default:
		return fmt.Sprint(v)
	}
}

func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String, reflect.Slice, reflect.Map, reflect.Array:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// TestConsoleRoles_NoKindDrift guards a silent failure mode in the console's RBAC.
//
// `open-infra-poweruser` ENUMERATES the openinfra.dev kinds it may manage. AWS avoids this with
// `NotAction` (deny-by-omission, so new services are automatically included), but Kubernetes RBAC
// has no such construct — and a bare `resources: ["*"]` would be worse here, because RBAC is
// purely additive: a wildcard would auto-grant any future identity CRD (kind: User, kind: Policy)
// to powerusers and readers the moment it existed.
//
// The enumeration is therefore deliberate, and this test keeps it honest: add an XRD without
// listing its plural and CI fails, instead of powerusers silently losing access to the new kind.
func TestConsoleRoles_NoKindDrift(t *testing.T) {
	xrds, err := filepath.Glob("../../platform/abstraction/*xrd*.yaml")
	if err != nil || len(xrds) == 0 {
		t.Fatalf("could not list XRDs: %v", err)
	}

	// Plurals intentionally NOT granted to powerusers. Identity/policy kinds belong here:
	// managing them is privilege escalation, which is why AWS's PowerUser excludes iam:*.
	excluded := map[string]bool{
		"users": true, "groups": true, "policies": true, "roles": true,
	}

	roleBytes, err := os.ReadFile("../../platform/console/manifests/rbac-roles.yaml")
	if err != nil {
		t.Fatalf("read rbac-roles.yaml: %v", err)
	}
	roleYAML := string(roleBytes)

	var missing []string
	for _, path := range xrds {
		plural := pluralFromXRD(t, path)
		if plural == "" || excluded[plural] {
			continue
		}
		if !strings.Contains(roleYAML, "- "+plural+"\n") {
			missing = append(missing, plural+"  (from "+filepath.Base(path)+")")
		}
	}

	if len(missing) > 0 {
		t.Errorf("these open-infra kinds are missing from platform/console/manifests/rbac-roles.yaml,\n"+
			"so console powerusers cannot manage them. Add them to the poweruser ClusterRole, or add the\n"+
			"plural to this test's `excluded` map if that is deliberate:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// pluralFromXRD pulls the CLAIM plural out of a Crossplane XRD without a YAML
// dependency. An XRD carries two: spec.names.plural is the composite (X-prefixed,
// e.g. xvirtualmachines) and spec.claimNames.plural is what users actually create
// (virtualmachines) — the latter is what RBAC grants on. Falls back to names.plural
// for XRDs with no claim.
func pluralFromXRD(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var namesPlural, claimPlural string
	inClaim := false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "claimNames:"):
			inClaim = true
		case strings.HasPrefix(trimmed, "names:"):
			inClaim = false
		case strings.HasPrefix(trimmed, "plural:"):
			v := strings.TrimSpace(strings.TrimPrefix(trimmed, "plural:"))
			if inClaim {
				claimPlural = v
			} else if namesPlural == "" {
				namesPlural = v
			}
		}
	}
	if claimPlural != "" {
		return claimPlural
	}
	return namesPlural
}
