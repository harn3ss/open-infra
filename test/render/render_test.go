package render

// Composition-render assertion tests. These render the ACTUAL committed
// go-templating template out of platform/abstraction/composition.yaml and assert
// on the emitted manifests. They exist because a composition-logic bug shipped to
// production once: the managed-DB CNPG "hibernation" annotation was only added when
// stopped, so pressing Start never wrote "off" and the DB stayed hibernated. A
// render test like TestManagedDB_HibernationAlwaysExplicit would have caught it.
//
// Faithful enough without the Crossplane runtime: composition.yaml uses only the
// sprig funcs re-implemented in sprigLite (default, sha256sum, trunc, dict, list,
// join, quote, nindent, upper, replace, …). If a future edit introduces another
// func, Parse fails loudly (add it here) rather than silently mis-rendering.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/adler32"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
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

// An APPROVED kind: Grant (temporal access) renders ONE ClusterRoleBinding binding openinfra:<subject>
// to the requested ClusterRole, carrying the reason + duration + requester/approver annotations the
// reconciler and audit rely on. Approval requires a second party (approvedBy != requestedBy).
func TestGrant_RendersTimeBoundedBinding(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/grant-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"subject":     map[string]any{"kind": "User", "name": "alice"},
			"clusterRole": "openinfra-role-dev",
			"duration":    "4h",
			"reason":      "oncall incident 1234",
			"requestedBy": "alice",
			"approval":    map[string]any{"approvedBy": "carol", "approvedAt": "2026-08-20T10:00:00Z"},
		},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "jit-alice"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		"kind: ClusterRoleBinding", "openinfra-grant-jit-alice",
		"name: openinfra-role-dev",              // roleRef
		"kind: User", `name: "openinfra:alice"`, // subject bound as the namespaced identity
		"openinfra.dev/grant-duration:", "openinfra.dev/grant-reason:", "oncall incident 1234",
		"openinfra.dev/grant-approved-by:", "carol", // approver recorded on the binding for audit
		"phase: Active",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Grant render missing %q; got:\n%s", want, grepCtx(out, "grant"))
		}
	}
}

// The approval gate (AC-2(2)/AC-5): a grant for an in-ceiling role confers NOTHING until a distinct
// second party approves it. No approval → AwaitingApproval, no binding. Self-approval (approvedBy ==
// requestedBy) → NotGrantable, no binding (self-service elevation is not separation of duties).
func TestGrant_ApprovalGate(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/grant-composition.yaml")
	base := func(approval map[string]any, requestedBy string) map[string]any {
		spec := map[string]any{
			"subject": map[string]any{"kind": "User", "name": "alice"}, "clusterRole": "openinfra-role-dev", "duration": "4h",
		}
		if requestedBy != "" {
			spec["requestedBy"] = requestedBy
		}
		if approval != nil {
			spec["approval"] = approval
		}
		return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec, "metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "jit-alice"}},
		}}}}
	}
	cases := []struct {
		name          string
		ctx           map[string]any
		wantPhase     string
		wantNoBinding bool
	}{
		{"no approval", base(nil, "alice"), "AwaitingApproval", true},
		{"empty approval object", base(map[string]any{}, "alice"), "AwaitingApproval", true},
		{"self-approval refused", base(map[string]any{"approvedBy": "alice", "approvedAt": "2026-08-20T10:00:00Z"}, "alice"), "NotGrantable", true},
		{"approved by second party", base(map[string]any{"approvedBy": "carol", "approvedAt": "2026-08-20T10:00:00Z"}, "alice"), "Active", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := render(t, tmpl, c.ctx)
			if !strings.Contains(out, "phase: "+c.wantPhase) {
				t.Errorf("want phase %q; got:\n%s", c.wantPhase, out)
			}
			if got := strings.Contains(out, "kind: ClusterRoleBinding"); got == c.wantNoBinding {
				t.Errorf("binding present=%v, wantNoBinding=%v; got:\n%s", got, c.wantNoBinding, out)
			}
		})
	}
}

// A Grant naming a role OUTSIDE the grantable ceiling (a provider/setup role, open-infra-console,
// or anything not openinfra-role-*/readonly/poweruser) must render NO ClusterRoleBinding — the
// fail-safe that keeps a temporal grant from leaking cluster-wide secrets/RBAC via the RBAC
// "cover" rule. It reports the refusal in status instead.
func TestGrant_DeniesRoleOutsideCeiling(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/grant-composition.yaml")
	for _, role := range []string{"openinfra-provider-kubernetes", "openinfra-bucket-setup", "open-infra-console", "cluster-admin"} {
		ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"subject":     map[string]any{"kind": "User", "name": "mallory"},
				"clusterRole": role,
				"duration":    "4h",
			},
			"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "jit-mallory"}},
		}}}}
		out := render(t, tmpl, ctx)
		if strings.Contains(out, "kind: ClusterRoleBinding") {
			t.Errorf("Grant for disallowed role %q rendered a ClusterRoleBinding; got:\n%s", role, out)
		}
		if !strings.Contains(out, "is not grantable") {
			t.Errorf("Grant for disallowed role %q should report refusal in status; got:\n%s", role, out)
		}
	}
	// The two bounded built-in console roles ARE allowed (readonly, poweruser) — once approved.
	for _, role := range []string{"open-infra-readonly", "open-infra-poweruser"} {
		ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"subject": map[string]any{"kind": "User", "name": "alice"}, "clusterRole": role, "duration": "1h",
				"requestedBy": "alice", "approval": map[string]any{"approvedBy": "carol", "approvedAt": "2026-08-20T10:00:00Z"},
			},
			"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "jit-alice"}},
		}}}}
		out := render(t, tmpl, ctx)
		if !strings.Contains(out, "kind: ClusterRoleBinding") {
			t.Errorf("Grant for allowed built-in role %q should render a binding; got:\n%s", role, out)
		}
	}
}

// kind: DatabaseProxy with TLS off (default): renders the pooler Deployment + Service + conn Secret,
// and does NOT render a cert or pass -tls-cert (the plaintext path, unchanged).
func TestDatabaseProxy_TLSOff(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/databaseproxy-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec":     map[string]any{"targetDatabase": "shop", "poolMax": 10},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "shopproxy", "crossplane.io/claim-namespace": "app"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{"kind: Deployment", "shopproxy-proxy", "-backend=shop-babelfish.app.svc.cluster.local:1433", "ENCRYPT: \"disable\""} {
		if !strings.Contains(out, want) {
			t.Errorf("TLS-off render missing %q; got:\n%s", want, grepCtx(out, "proxy"))
		}
	}
	for _, absent := range []string{"kind: Certificate", "-tls-cert", "/tls/tls.crt"} {
		if strings.Contains(out, absent) {
			t.Errorf("TLS-off render should NOT contain %q", absent)
		}
	}
}

// kind: DatabaseProxy with tls.terminate=true: renders a cert-manager Certificate signed by the named
// issuer, mounts it, and passes -tls-cert/-tls-key so the proxy terminates client TLS (#6).
func TestDatabaseProxy_TLSOn(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/databaseproxy-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"targetDatabase": "shop",
			"tls": map[string]any{
				"terminate": true,
				"issuerRef": map[string]any{"name": "openinfra-issuer", "kind": "ClusterIssuer"},
				"dnsNames":  []any{"shop.example.com"},
			},
		},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "shopproxy", "crossplane.io/claim-namespace": "app"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		"kind: Certificate", "secretName: shopproxy-proxy-tls",
		"name: openinfra-issuer", "shop.example.com", // custom SAN carried through
		"- -tls-cert=/tls/tls.crt", "- -tls-key=/tls/tls.key",
		"mountPath: /tls", "secretName: shopproxy-proxy-tls",
		"ENCRYPT: \"supported\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("TLS-on render missing %q; got:\n%s", want, grepCtx(out, "tls"))
		}
	}
}

// kind: DataClassification renders a ConfigMap mirror in the console namespace carrying the level
// and handling requirements, so the compliance auditor can read the taxonomy by label.
func TestDataClassification_RendersConfigMapMirror(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/dataclassification-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"level":       "restricted",
			"description": "CUI / regulated",
			"requires": map[string]any{
				"encryptionAtRest":   true,
				"networkRestricted":  true,
				"noPublicExposure":   true,
				"residencyNodeLabel": "openinfra.dev/residency",
				"retentionDays":      2555,
			},
		},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "restricted"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		"kind: ConfigMap", "name: openinfra-dataclass-restricted", "namespace: open-infra-console",
		"openinfra.dev/dataclass: restricted",
		`level: "restricted"`, `encryptionAtRest: "true"`, `networkRestricted: "true"`,
		`residencyNodeLabel: "openinfra.dev/residency"`, `retentionDays: "2555"`,
		"ready: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("DataClassification render missing %q; got:\n%s", want, out)
		}
	}
}

// kind: EncryptionKey renders a spec-mirror ConfigMap the reconciler reads, and echoes the Vault
// Transit path in status.
func TestEncryptionKey_RendersMirrorAndKeyPath(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/encryptionkey-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"description":  "tenant A KEK",
			"keyType":      "aes256-gcm96",
			"rotationDays": 90,
		},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "tenant-a"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		"kind: ConfigMap", "name: openinfra-enckey-tenant-a", "namespace: open-infra-console",
		"openinfra.dev/enckey: tenant-a",
		`vaultKeyPath: "transit/keys/tenant-a"`, `rotationDays: "90"`, `keyType: "aes256-gcm96"`,
		"ready: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("EncryptionKey render missing %q; got:\n%s", want, out)
		}
	}
}

// kind: Destruction renders a spec-mirror ConfigMap the destroyer reads, and starts Pending.
func TestDestruction_RendersMirrorAndPending(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/destruction-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"encryptionKey": "tenant-a",
			"confirm":       "tenant-a",
			"reason":        "contract ended",
		},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "erase-tenant-a"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		"kind: ConfigMap", "name: openinfra-destruction-erase-tenant-a", "namespace: open-infra-console",
		"openinfra.dev/destruction: erase-tenant-a",
		`encryptionKey: "tenant-a"`, `confirm: "tenant-a"`,
		"phase: Pending",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Destruction render missing %q; got:\n%s", want, out)
		}
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

// TestGraphQLApi_RendersConfigAndEngine pins the neutral authoring plane (open-appsync): the
// composition must render (a) a ConfigMap whose config.json + per-resolver.vtl files match the shape
// server.Load reads, carrying the resolver's `runtime`, and (b) an engine Deployment with a config
// checksum annotation (the reload mechanism) + a Service. The resolver author's VTL must appear
// verbatim — the load-bearing "specialist learns nothing" promise.
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
		// (c) ingress isolation: default-deny, each front door POD-scoped (namespace+pod), on the pod port.
		"kind: NetworkPolicy", "policyTypes: [Ingress]",
		"open-infra-aws-shim", "app: aws-shim",
		"open-infra-console", "app: console",
		"kubernetes.io/metadata.name: monitoring", "app.kubernetes.io/name: prometheus",
		"port: 8080",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("GraphQLApi render missing %q; got:\n%s", want, grepCtx(out, "open-appsync-notes"))
		}
	}
	// A memory-only API must NOT wire Mongo env.
	if strings.Contains(out, "MONGO_URI") {
		t.Errorf("memory-only GraphQLApi must not set MONGO_URI; got:\n%s", grepCtx(out, "env:"))
	}
	// An auth-less API keeps the default SA (immediate start) — no dedicated SA reference (#68).
	if strings.Contains(out, "serviceAccountName") {
		t.Errorf("an auth-less GraphQLApi must not set serviceAccountName; got:\n%s", grepCtx(out, "serviceAccount"))
	}
	// The netpol must NOT carry a blanket same-namespace allow: a co-tenant pod could otherwise forge
	// identity headers. The only namespaceSelectors are in the netpol, so the API's own namespace name
	// appearing as a metadata.name selector would mean the same-ns peer is still present.
	if strings.Contains(out, "kubernetes.io/metadata.name: team-a") {
		t.Errorf("netpol still has a blanket same-namespace allow (co-tenant could forge identity):\n%s", grepCtx(out, "metadata.name"))
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

// A kind: Function renders memory (→ container resources) and timeout (→ Knative revision timeout) —
// the AWS Lambda memory/timeout parity knobs — without spuriously requesting a GPU on a CPU function.
func TestFunction_MemoryAndTimeout(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/function-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"image":   "ghcr.io/x/fn:latest",
			"memory":  "512Mi",
			"timeout": int64(60),
		},
		"metadata": map[string]any{"labels": map[string]any{
			"crossplane.io/claim-name": "fn", "crossplane.io/claim-namespace": "team-a"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{"kind: Service", "timeoutSeconds: 60", "resources:", `memory: "512Mi"`, "requests:"} {
		if !strings.Contains(out, want) {
			t.Errorf("Function render missing %q; got:\n%s", want, grepCtx(out, "resources"))
		}
	}
	// A CPU function must NOT request a GPU device.
	if strings.Contains(out, "nvidia.com/gpu") {
		t.Errorf("a memory-only (CPU) function must not request a GPU:\n%s", grepCtx(out, "resources"))
	}
}

// A resolver with a caching block renders its ttl + keys into config.json.
func TestGraphQLApi_ResolverCaching(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{
			"dataSources": []any{map[string]any{"name": "notes", "type": "memory"}},
			"resolvers": []any{map[string]any{
				"type": "Query", "field": "getNote", "dataSource": "notes",
				"request": "$util.toJson({})", "response": "$util.toJson($ctx.result)",
				"caching": map[string]any{"ttlSeconds": int64(60), "keys": []any{"arguments.id", "identity.sub"}},
			}},
		},
		"metadata": map[string]any{"uid": "u", "labels": map[string]any{
			"crossplane.io/claim-name": "notes", "crossplane.io/claim-namespace": "team-a"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		`"caching"`, `"ttlSeconds": 60`, `"arguments.id"`, `"identity.sub"`,
		// caching wires the shared cache backend: NATS + a per-API KV bucket.
		"nats://nats.nats.svc.cluster.local:4222", "APPSYNC_CACHE_BUCKET", "open_appsync_cache_notes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("resolver caching render missing %q; got:\n%s", want, grepCtx(out, "caching"))
		}
	}
}

// A pipeline resolver + hostile-load limits render into config.json + the per-step.vtl files.
func TestGraphQLApi_PipelineAndLimits(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	out := render(t, tmpl, graphqlApiPipelineCtx())
	for _, want := range []string{
		`"limits"`, `"maxDepth": 6`, `"persistedOnly": false`,
		`"functions"`,
		"Mutation.createAndFetch.before.vtl:", "Mutation.createAndFetch.after.vtl:",
		"Mutation.createAndFetch.fn0.request.vtl:", "Mutation.createAndFetch.fn1.request.vtl:",
		`$ctx.stash.put`,      // before step's VTL, verbatim
		`$ctx.prev.result.id`, // fn1 threading, verbatim
	} {
		if !strings.Contains(out, want) {
			t.Errorf("GraphQLApi pipeline render missing %q; got:\n%s", want, grepCtx(out, "functions"))
		}
	}
}

// A resolver's field-auth requirement renders into config.json (the field-level authz).
func TestGraphQLApi_FieldAuth(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"dataSources": []any{map[string]any{"name": "t", "type": "memory"}},
				"resolvers": []any{map[string]any{
					"type": "Query", "field": "getTodo", "dataSource": "t",
					"request": "{\"operation\":\"Scan\"}", "response": "$util.toJson($ctx.result)",
					"auth": map[string]any{"group": "openinfra.dev", "resource": "graphqlapis", "verb": "get"},
				}},
			},
			"metadata": map[string]any{"uid": "u", "labels": map[string]any{"crossplane.io/claim-name": "u", "crossplane.io/claim-namespace": "team-a"}},
		}}},
	}
	out := render(t, tmpl, ctx)
	for _, want := range []string{`"auth"`, `"resource": "graphqlapis"`, `"verb": "get"`} {
		if !strings.Contains(out, want) {
			t.Errorf("field-auth render missing %q; got:\n%s", want, grepCtx(out, "auth"))
		}
	}
	// An auth-using API must run under the dedicated SA (the reconciler binds it to create SARs);
	// without it every auth: field fails closed (#68).
	if !strings.Contains(out, "serviceAccountName: open-appsync") {
		t.Errorf("an auth-using GraphQLApi must set serviceAccountName: open-appsync; got:\n%s", grepCtx(out, "serviceAccount"))
	}
}

// A subscription field renders into config.json + its response.vtl file (the subscription rung).
func TestGraphQLApi_Subscriptions(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"dataSources": []any{map[string]any{"name": "t", "type": "memory"}},
				"resolvers": []any{map[string]any{
					"type": "Mutation", "field": "createTodo", "dataSource": "t",
					"request": "{\"operation\":\"Scan\"}", "response": "$util.toJson($ctx.result)",
				}},
				"subscriptions": []any{map[string]any{
					"field": "onCreateTodo", "response": "$util.toJson($ctx.result)", "triggeredBy": []any{"createTodo"},
				}},
			},
			"metadata": map[string]any{"uid": "u", "labels": map[string]any{"crossplane.io/claim-name": "u", "crossplane.io/claim-namespace": "team-a"}},
		}}},
	}
	out := render(t, tmpl, ctx)
	for _, want := range []string{`"subscriptions"`, `"field": "onCreateTodo"`, `"triggeredBy"`, "onCreateTodo.subscription.response.vtl:"} {
		if !strings.Contains(out, want) {
			t.Errorf("subscription render missing %q; got:\n%s", want, grepCtx(out, "subscriptions"))
		}
	}
}

// An http data source renders its endpoint into config.json (the second call-source).
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

// An rds data source injects its DSN into the engine as env APPSYNC_RDS_DSN_<NAME> from a Secret
// (connectionSecret) — the credentials never appear in the CR/config.
func TestGraphQLApi_RDSDataSource(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"dataSources": []any{map[string]any{"name": "orders-db", "type": "rds", "connectionSecret": "orders-dsn"}},
				"resolvers": []any{map[string]any{
					"type": "Query", "field": "getOrder", "dataSource": "orders-db",
					"request": "{\"statements\":[\"SELECT 1\"]}", "response": "$util.toJson($ctx.result)",
				}},
			},
			"metadata": map[string]any{"uid": "u", "labels": map[string]any{"crossplane.io/claim-name": "u", "crossplane.io/claim-namespace": "team-a"}},
		}}},
	}
	out := render(t, tmpl, ctx)
	for _, want := range []string{"APPSYNC_RDS_DSN_ORDERS_DB", `name: "orders-dsn"`, "key: dsn"} {
		if !strings.Contains(out, want) {
			t.Errorf("rds data source render missing %q; got:\n%s", want, grepCtx(out, "APPSYNC_RDS_DSN"))
		}
	}
}

// An opensearch data source with a connectionSecret injects optional basic-auth env from that Secret.
func TestGraphQLApi_OpenSearchDataSource(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"dataSources": []any{map[string]any{"name": "search", "type": "opensearch", "endpoint": "https://os.example.com", "connectionSecret": "os-creds"}},
				"resolvers": []any{map[string]any{
					"type": "Query", "field": "find", "dataSource": "search",
					"request": "{\"operation\":\"POST\",\"path\":\"/i/_search\"}", "response": "$util.toJson($ctx.result)",
				}},
			},
			"metadata": map[string]any{"uid": "u", "labels": map[string]any{"crossplane.io/claim-name": "u", "crossplane.io/claim-namespace": "team-a"}},
		}}},
	}
	out := render(t, tmpl, ctx)
	for _, want := range []string{`"type": "opensearch"`, "APPSYNC_OPENSEARCH_USER_SEARCH", "APPSYNC_OPENSEARCH_PASS_SEARCH", `name: "os-creds"`, "key: username", "key: password"} {
		if !strings.Contains(out, want) {
			t.Errorf("opensearch data source render missing %q; got:\n%s", want, grepCtx(out, "OPENSEARCH"))
		}
	}
}

// An eventbridge data source wires the engine to the platform NATS bus; a plain API does not.
func TestGraphQLApi_EventBridgeWiresNats(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")
	ebCtx := func(dsType string) map[string]any {
		return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{
				"dataSources": []any{map[string]any{"name": "bus", "type": dsType}},
				"resolvers": []any{map[string]any{
					"type": "Mutation", "field": "emit", "dataSource": "bus",
					"request": "{\"operation\":\"PutEvents\",\"events\":[]}", "response": "$util.toJson($ctx.result)",
				}},
			},
			"metadata": map[string]any{"uid": "u", "labels": map[string]any{"crossplane.io/claim-name": "u", "crossplane.io/claim-namespace": "team-a"}},
		}}}}
	}
	eb := render(t, tmpl, ebCtx("eventbridge"))
	if !strings.Contains(eb, `"type": "eventbridge"`) || !strings.Contains(eb, "nats://nats.nats.svc.cluster.local:4222") {
		t.Errorf("eventbridge api must wire NATS_URL; got:\n%s", grepCtx(eb, "NATS_URL"))
	}
	// A plain (memory) API must NOT get NATS_URL.
	plain := render(t, tmpl, ebCtx("memory"))
	if strings.Contains(plain, "NATS_URL") {
		t.Errorf("a plain API must not wire NATS_URL; got:\n%s", grepCtx(plain, "NATS_URL"))
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

// TestVirtualMachine_ArchPin: a Windows VM is STRUCTURALLY amd64 (q35/MBR/amd64 sysprep) and must pin
// nodeSelector arch: amd64 so it can never schedule onto an arm64 node; a Linux VM (multi-arch
// containerDisk) stays flexible unless a per-resource openinfra.dev/arch targets one.
func TestVirtualMachine_ArchPin(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")

	win := render(t, tmpl, vmCtx("windows-server-2022", ""))
	// Windows is structurally amd64: it must pin BOTH the VMI architecture (admission gate on a
	// non-amd64 control plane) and the launcher node arch. (#51)
	if !strings.Contains(win, "kubernetes.io/arch: amd64") {
		t.Errorf("Windows VM must pin nodeSelector arch: amd64 (structural); got:\n%s", grepCtx(win, "arch"))
	}
	if !strings.Contains(win, "architecture: amd64") {
		t.Errorf("Windows VM must set spec.architecture: amd64 (else virt-api on an arm64 CP rejects q35); got:\n%s", grepCtx(win, "arch"))
	}

	lin := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if strings.Contains(lin, "kubernetes.io/arch:") || strings.Contains(lin, "architecture:") {
		t.Errorf("Linux VM (no annotation) must NOT be arch-pinned (multi-arch containerDisk) — neither nodeSelector nor architecture; got:\n%s", grepCtx(lin, "arch"))
	}

	arm := render(t, tmpl, vmCtx("ubuntu-24.04", "arm64"))
	if !strings.Contains(arm, "kubernetes.io/arch: arm64") {
		t.Errorf("Linux VM annotated arm64 must pin nodeSelector arch: arm64; got:\n%s", grepCtx(arm, "arch"))
	}
	if !strings.Contains(arm, "architecture: arm64") {
		t.Errorf("Linux VM annotated arm64 must set spec.architecture: arm64; got:\n%s", grepCtx(arm, "arch"))
	}
}

// TestVmImage_ArchAmd64 asserts the golden-building installer VM declares architecture: amd64 — the
// golden catalog is x86 Windows, and without this virt-api on a non-amd64 control plane rejects the q35
// installer at admission (inferring the CP arch). (#51)
func TestVmImage_ArchAmd64(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vmimage-composition.yaml")
	out := render(t, tmpl, map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec":     map[string]any{"os": "windows-server-2022"},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "win2022", "crossplane.io/claim-namespace": "openinfra-images"}},
	}}}})
	if !strings.Contains(out, "architecture: amd64") {
		t.Errorf("VmImage installer VM must declare architecture: amd64 (x86 golden); got:\n%s", grepCtx(out, "arch"))
	}
}

// TestArchNodeSelectorMerge validates the exact merge expression the replication composition uses to
// combine the arch pin with any user-supplied nodeSelector: the user's selector must be preserved AND
// kubernetes.io/arch added (arch authoritative). This is the one novel construct the per-composition
// rollout introduced beyond query's plain nodeSelector.
func TestArchNodeSelectorMerge(t *testing.T) {
	tmpl := `nodeSelector:{{ toYaml (merge (dict "kubernetes.io/arch" $.nodeArch) ($.sched.nodeSelector | default dict)) | nindent 2 }}`

	withUser := render(t, tmpl, map[string]any{"nodeArch": "arm64", "sched": map[string]any{"nodeSelector": map[string]any{"disktype": "ssd"}}})
	if !strings.Contains(withUser, "kubernetes.io/arch: arm64") || !strings.Contains(withUser, "disktype: ssd") {
		t.Errorf("merge must keep the user nodeSelector AND add the arch pin; got:\n%s", withUser)
	}
	noUser := render(t, tmpl, map[string]any{"nodeArch": "amd64", "sched": map[string]any{}})
	if !strings.Contains(noUser, "kubernetes.io/arch: amd64") {
		t.Errorf("merge with no user selector must still pin the arch; got:\n%s", noUser)
	}
}

func vmCtx(os, arch string) map[string]any {
	res := map[string]any{
		"spec": map[string]any{"os": os, "cpu": int64(2), "memory": "4Gi"},
		"metadata": map[string]any{
			"uid":    "00000000-0000-0000-0000-0000000000vm",
			"labels": map[string]any{"crossplane.io/claim-name": "myvm", "crossplane.io/claim-namespace": "default"},
		},
	}
	if arch != "" {
		res["metadata"].(map[string]any)["annotations"] = map[string]any{"openinfra.dev/arch": arch}
	}
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": res}}}
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
		"drop: [ALL]",     // capabilities
		"query-runner-s3", // least-privilege S3 identity
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
// TestQuery_ImageArchSuffix pins the arch-select wiring (#42): the first-party query image is
// :latest on amd64 (default, or ANY missing/empty context — the amd64 path MUST NOT change or break),
// and :latest-arm64 only when the openinfra-platform EnvironmentConfig sets imageArchSuffix="-arm64".
func TestQuery_ImageArchSuffix(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/query-composition.yaml")

	// amd64 default (no .context): :latest image + a kubernetes.io/arch: amd64 nodeSelector so the
	// amd64 image can never land on an arm64 node in a mixed cluster.
	amd := render(t, tmpl, queryCtx())
	if !strings.Contains(amd, "open-infra-query:latest") || strings.Contains(amd, "open-infra-query:latest-") {
		t.Errorf("amd64 default must render :latest with NO suffix; got:\n%s", grepCtx(amd, "open-infra-query"))
	}
	if !strings.Contains(amd, "kubernetes.io/arch: amd64") {
		t.Errorf("amd64 default must pin nodeSelector arch: amd64; got:\n%s", grepCtx(amd, "arch"))
	}

	// arm64 via cluster EnvironmentConfig: :latest-arm64 image + arch: arm64 nodeSelector.
	ctx := queryCtx()
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"imageArchSuffix": "-arm64"}}
	arm := render(t, tmpl, ctx)
	if !strings.Contains(arm, "open-infra-query:latest-arm64") || !strings.Contains(arm, "kubernetes.io/arch: arm64") {
		t.Errorf("cluster arm64 must render :latest-arm64 + arch: arm64; got:\n%s", grepCtx(arm, "open-infra-query")+grepCtx(arm, "arch"))
	}
}

// TestQuery_ArchAnnotationOverride: a per-resource annotation openinfra.dev/arch=arm64 selects the
// arm64 image + arch nodeSelector even when the cluster default is amd64 — per-resource targeting in
// a mixed cluster.
func TestQuery_ArchAnnotationOverride(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/query-composition.yaml")
	ctx := queryCtx() // cluster default amd64 (no context)
	res := ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)
	res["metadata"].(map[string]any)["annotations"] = map[string]any{"openinfra.dev/arch": "arm64"}
	out := render(t, tmpl, ctx)
	if !strings.Contains(out, "open-infra-query:latest-arm64") || !strings.Contains(out, "kubernetes.io/arch: arm64") {
		t.Errorf("openinfra.dev/arch=arm64 must select the -arm64 image + arch: arm64; got:\n%s", grepCtx(out, "open-infra-query")+grepCtx(out, "arch"))
	}
}

// TestDatabaseProxy_ImageArchSuffix covers the literal-image interpolation style (`:latest{{ $arch }}`,
// distinct from query's printf): amd64 default -> tds-proxy:latest, arm64 -> :latest-arm64.
func TestDatabaseProxy_ImageArchSuffix(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/databaseproxy-composition.yaml")
	base := func(archCtx map[string]any) map[string]any {
		m := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec":     map[string]any{"targetDatabase": "shop", "poolMax": 10},
			"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "shopproxy", "crossplane.io/claim-namespace": "app"}},
		}}}}
		if archCtx != nil {
			m["context"] = archCtx
		}
		return m
	}
	amdFull := render(t, tmpl, base(nil))
	amd := grepCtx(amdFull, "open-infra-tds-proxy")
	if !strings.Contains(amd, "open-infra-tds-proxy:latest") || strings.Contains(amd, "open-infra-tds-proxy:latest-") {
		t.Errorf("amd64 default must render tds-proxy:latest with NO suffix; got:\n%s", amd)
	}
	if !strings.Contains(amdFull, "kubernetes.io/arch: amd64") {
		t.Errorf("amd64 default must pin nodeSelector arch: amd64; got:\n%s", grepCtx(amdFull, "arch"))
	}
	armFull := render(t, tmpl, base(map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"imageArchSuffix": "-arm64"}}))
	arm := grepCtx(armFull, "open-infra-tds-proxy")
	if !strings.Contains(arm, "open-infra-tds-proxy:latest-arm64") {
		t.Errorf("imageArchSuffix=-arm64 must render tds-proxy:latest-arm64; got:\n%s", arm)
	}
	if !strings.Contains(armFull, "kubernetes.io/arch: arm64") {
		t.Errorf("imageArchSuffix=-arm64 must pin nodeSelector arch: arm64; got:\n%s", grepCtx(armFull, "arch"))
	}
}

// TestGraphQLApi_ArchPin: the engine Deployment pins to a matching-arch node for the DEFAULT
// first-party image (amd64 :latest → arch: amd64; cluster -arm64 → :latest-arm64 + arch: arm64), but a
// user-supplied spec.image (unknown arch) must NOT be arch-pinned.
func TestGraphQLApi_ArchPin(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/graphqlapi-composition.yaml")

	amd := render(t, tmpl, graphqlApiCtx(""))
	if !strings.Contains(amd, "open-infra-open-appsync:latest") || strings.Contains(amd, "open-infra-open-appsync:latest-") {
		t.Errorf("amd64 default must render open-appsync:latest; got:\n%s", grepCtx(amd, "open-appsync:latest"))
	}
	if !strings.Contains(amd, "kubernetes.io/arch: amd64") {
		t.Errorf("default image must pin nodeSelector arch: amd64; got:\n%s", grepCtx(amd, "arch"))
	}

	armCtx := graphqlApiCtx("")
	armCtx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"imageArchSuffix": "-arm64"}}
	arm := render(t, tmpl, armCtx)
	if !strings.Contains(arm, "open-infra-open-appsync:latest-arm64") || !strings.Contains(arm, "kubernetes.io/arch: arm64") {
		t.Errorf("cluster arm64 must render :latest-arm64 + arch: arm64; got:\n%s", grepCtx(arm, "open-appsync")+grepCtx(arm, "arch"))
	}

	ovCtx := graphqlApiCtx("")
	ovRes := ovCtx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)
	ovRes["spec"].(map[string]any)["image"] = "registry.example.com/custom/appsync:v1"
	ov := render(t, tmpl, ovCtx)
	if strings.Contains(ov, "kubernetes.io/arch:") {
		t.Errorf("a user-supplied image must NOT be arch-pinned (unknown arch); got:\n%s", grepCtx(ov, "arch"))
	}
}

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
// source becomes dynamodb (FerretDB-backed); empty keeps it in-memory (the default for the bar).
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
// after) and hostile-load limits — the / surface.
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

// dbCtx builds the minimal.observed.composite.resource context that reaches the
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
		// sprig: is `needle` an element of `list`? (dataflow uses `has "*" $tables`).
		"has": func(needle any, list any) bool {
			rv := reflect.ValueOf(list)
			if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
				return false
			}
			for i := 0; i < rv.Len(); i++ {
				if reflect.DeepEqual(rv.Index(i).Interface(), needle) {
					return true
				}
			}
			return false
		},
		// sprig: regex replace (dataflow uses it to sanitize node names into env-var keys).
		"regexReplaceAll": func(pattern, src, repl string) string {
			return regexp.MustCompile(pattern).ReplaceAllString(src, repl)
		},
		// sprig: JSON-encode (dataflow passes $members/$dmembers as a JSON env var).
		"toJson": func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				return ""
			}
			return string(b)
		},
		// sprig: ternary trueVal falseVal cond.
		"ternary": func(vt any, vf any, cond bool) any {
			if cond {
				return vt
			}
			return vf
		},
		// sprig: adler32 checksum as a decimal string (dataflow uses it for short stable suffixes).
		"adler32sum": func(s string) string {
			return strconv.FormatUint(uint64(adler32.Checksum([]byte(s))), 10)
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
		// sprig's int: coerce any scalar to an int (compositions use `gt (int $gpu) 0`).
		"int": func(v any) int {
			switch n := v.(type) {
			case int:
				return n
			case int64:
				return int(n)
			case float64:
				return int(n)
			case string:
				i, _ := strconv.Atoi(n)
				return i
			}
			return 0
		},
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
		"upper": func(s string) string { return strings.ToUpper(s) },
		"lower": func(s string) string { return strings.ToLower(s) },
		// sprig's replace is replace(old, new, src) — used piped: `s | replace "-" "_"`.
		"replace":   func(old, new, src string) string { return strings.ReplaceAll(src, old, new) },
		"hasPrefix": func(prefix, s string) bool { return strings.HasPrefix(s, prefix) },
		// sprig's merge(dst, src...): copy src keys into dst, dst wins on conflict. The arch pin
		// uses it to add kubernetes.io/arch to any user nodeSelector (arch is authoritative → dst).
		"merge": func(dst map[string]any, srcs ...map[string]any) map[string]any {
			if dst == nil {
				dst = map[string]any{}
			}
			for _, src := range srcs {
				for k, v := range src {
					if _, ok := dst[k]; !ok {
						dst[k] = v
					}
				}
			}
			return dst
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
	// DataClassification is a central security-team categorization scheme, not a project knob.
	excluded := map[string]bool{
		"users": true, "groups": true, "policies": true, "roles": true, "grants": true,
		"dataclassifications": true, "encryptionkeys": true, "destructions": true,
		// A private CA is a trust-minting authority — issue/revoke is gated on `update` over
		// certificateauthorities, so it stays admin-only, not a poweruser knob (like encryptionkeys).
		"certificateauthorities": true,
		// A UserPool is a customer-facing identity provider that issues tokens the platform trusts —
		// admin-gated like certificateauthorities, not a poweruser knob (mirrors policy-boundary).
		"userpools": true,
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

// TestConsoleAdminRole_NoKindDrift guards the SAME silent drift for the admin/console role
// (open-infra-console in rbac.yaml), which root/admins bind to (see rbac-roles.yaml:
// openinfra:admins -> open-infra-console). The poweruser guard above did NOT cover it, so a new
// kind could be listable via kubectl yet "Not authorized" in the console for root — exactly how
// statemachines/trainingjobs (and, pre-existing, databaseproxies/certificateauthorities) fell out
// of admin access. Every openinfra.dev XRD claim kind must appear in rbac.yaml: under the
// openinfra.dev rule for workload kinds, or the iam.openinfra.dev rule for identity kinds.
func TestConsoleAdminRole_NoKindDrift(t *testing.T) {
	xrds, err := filepath.Glob("../../platform/abstraction/*xrd*.yaml")
	if err != nil || len(xrds) == 0 {
		t.Fatalf("could not list XRDs: %v", err)
	}
	roleBytes, err := os.ReadFile("../../platform/console/manifests/rbac.yaml")
	if err != nil {
		t.Fatalf("read rbac.yaml: %v", err)
	}
	roleYAML := string(roleBytes)

	var missing []string
	for _, path := range xrds {
		plural := pluralFromXRD(t, path)
		if plural == "" {
			continue
		}
		if !strings.Contains(roleYAML, "- "+plural+"\n") {
			missing = append(missing, plural+"  (from "+filepath.Base(path)+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf("these open-infra kinds are missing from the open-infra-console ClusterRole in\n"+
			"platform/console/manifests/rbac.yaml, so console admins (root) get \"Not authorized\" on them.\n"+
			"Add each plural to the openinfra.dev rule (or iam.openinfra.dev for identity kinds):\n  %s",
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

// #36: the dataflow composition template (reconciler + the new schema-drift companion) must parse
// with the same funcmap the go-templating function uses. A template syntax error here breaks EVERY
// DataFlow render, so this guards the drift-companion edit.
func TestDataFlow_TemplateParses(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/dataflow-composition.yaml")
	if _, err := template.New("df").Funcs(sprigLite()).Parse(tmpl); err != nil {
		t.Fatalf("dataflow-composition template must parse: %v", err)
	}
}

// #36: the schema-drift detector is auto-deployed as a per-flow companion, opt-in via
// spec.driftDetection. On -> a `<flow>-flow-drift` Deployment with MODE=schema-drift renders next to
// the reconciler for the multi-master repl set; off (default) -> nothing. Guards the composition edit.
func dataflowCtx(drift bool) any {
	node := func(name, host, secret string) map[string]any {
		return map[string]any{
			"name": name, "engine": "postgres", "username": "u", "host": host,
			"port": 5432, "database": "db", "role": "database",
			"passwordSecretRef": map[string]any{"name": secret, "key": "password"},
		}
	}
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"metadata": map[string]any{"name": "flow1", "labels": map[string]any{}, "annotations": map[string]any{}},
		"spec": map[string]any{
			"nodes":          []any{node("a", "ha", "a-sec"), node("b", "hb", "b-sec")},
			"edges":          []any{map[string]any{"type": "replication", "from": "a", "to": "b"}},
			"tables":         []any{"public.orders"},
			"driftDetection": drift,
		},
	}}}}
}

func TestDataFlow_DriftCompanionOptIn(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/dataflow-composition.yaml")

	on := render(t, tmpl, dataflowCtx(true))
	if !strings.Contains(on, "flow1-flow-drift") {
		t.Errorf("driftDetection:true must render the -flow-drift Deployment; got:\n%s", grepCtx(on, "flow-drift"))
	}
	if !strings.Contains(on, "value: schema-drift") {
		t.Errorf("drift companion must set MODE=schema-drift; got:\n%s", grepCtx(on, "MODE"))
	}

	off := render(t, tmpl, dataflowCtx(false))
	if strings.Contains(off, "flow-drift") {
		t.Errorf("driftDetection:false (default) must NOT render the -flow-drift Deployment; got:\n%s", grepCtx(off, "flow-drift"))
	}
}
