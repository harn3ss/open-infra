package render

import (
	"os"
	"strings"
	"testing"
)

// The application composition renders every kind: Application on the platform, and any change to what an
// Application renders makes its Deployment roll new pods — every app at once. So a change to the
// composition must leave every Application that does not use the change rendering byte for byte as
// before. This test holds that line for the task role (spec.assumeRole): it renders a representative set
// of Applications that set no assumeRole (web apps, workers, fixed-size apps, LAN-exposed apps, sidecars
// and volumes, every database engine and its options, a database-only app, buckets, queues, security
// groups, subnets, observed composed resources, extra resources on the call) and compares the output with
// a golden captured from the composition before the task-role change. A difference fails with the first
// differing line. A deliberate change to these renders regenerates the golden
// (OPENINFRA_UPDATE_GOLDEN=1 go test -run TestApplication_RolelessRenderIsByteIdentical) — and is then a
// change that restarts every app, to be rolled in paced batches.

const applicationRolelessGolden = "testdata/application-roleless.golden"

// rolelessApplicationCases are the assumeRole-less specs whose render must never change. Numbers are
// float64, as an Application's spec reaches the composition (decoded from JSON), except in int-typed.
func rolelessApplicationCases() []struct {
	name, ns string
	spec     map[string]any
	observed map[string]any // .observed.resources (composed resources already observed)
	extra    map[string]any // .extraResources present on the call (an app without assumeRole ignores it)
} {
	envs := []any{map[string]any{"name": "MODE", "value": "fast"}, map[string]any{"name": "Q", "value": `say "hi"`}}
	observedCreds := map[string]any{
		"app-pcreds":       map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{"metadata": map[string]any{"uid": "u-1"}}}}}},
		"db-backup-pcreds": map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{"metadata": map[string]any{"uid": "u-2"}}}}}},
	}
	return []struct {
		name, ns string
		spec     map[string]any
		observed map[string]any
		extra    map[string]any
	}{
		{name: "image-minimal", ns: "team-a", spec: map[string]any{"image": "ghcr.io/me/hello:1"}},
		{name: "web-full", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": float64(8080), "domain": "api.example.com",
			"command": []any{"/app/server"}, "args": []any{"--listen", ":8080"},
			"cpu": "500m", "memory": "1Gi", "startupGraceSeconds": float64(45),
			"additionalPorts": []any{
				map[string]any{"name": "smtp", "port": float64(1025)},
				map[string]any{"name": "metrics", "port": float64(9090), "targetPort": float64(9100)},
				map[string]any{"name": "dns", "port": float64(53), "protocol": "UDP"},
			},
			"env": envs, "secrets": []any{"api-config", "api-keys"},
			"securityGroups": []any{"web", "db-clients"}, "subnet": "private-a",
			"scaling": map[string]any{"min": float64(2), "max": float64(10), "targetCPUPercent": float64(60)},
			"quota":   map[string]any{"services": "80", "pods": "120", "persistentvolumeclaims": "40"},
		}},
		{name: "fixed-size", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": float64(8080), "scaling": map[string]any{"min": float64(3), "max": float64(3)},
		}},
		{name: "startup-zero", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": float64(8080), "startupGraceSeconds": float64(0),
		}},
		{name: "worker", ns: "team-b", spec: map[string]any{
			"image": "ghcr.io/me/worker:1", "queues": []any{"orders", "events"}, "env": envs,
		}},
		{name: "lan-exposed", ns: "team-b", spec: map[string]any{
			"image": "ghcr.io/me/mail:1", "expose": true,
			"additionalPorts": []any{map[string]any{"name": "smtp", "port": float64(25), "targetPort": float64(2525)}},
		}},
		{name: "sidecars-volumes", ns: "team-c", spec: map[string]any{
			"image": "ghcr.io/me/app:3", "port": float64(3000),
			"volumes": []any{map[string]any{"name": "scratch"}, map[string]any{"name": "data", "volume": "app-data"}},
			"volumeMounts": []any{map[string]any{"name": "scratch", "mountPath": "/tmp/work"},
				map[string]any{"name": "data", "mountPath": "/var/lib/app"}},
			"sidecars": []any{
				map[string]any{"name": "log-shipper", "image": "fluent/fluent-bit:3",
					"env":          []any{map[string]any{"name": "LEVEL", "value": "info"}},
					"volumeMounts": []any{map[string]any{"name": "scratch", "mountPath": "/logs"}},
					"secrets":      []any{"shipper-token"}},
				map[string]any{"name": "proxy", "image": "envoyproxy/envoy:v1.30", "port": float64(9901),
					"command": []any{"envoy"}, "args": []any{"-c", "/etc/envoy.yaml"}, "cpu": "100m", "memory": "128Mi"},
			},
			"storage": map[string]any{"buckets": []any{"app-uploads", "app-exports"}},
		}},
		{name: "db-postgres-full", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": float64(8080),
			"database": map[string]any{"engine": "postgres", "name": "orders", "size": "20Gi", "cpu": "1", "memory": "2Gi",
				"highAvailability": true, "readerEndpoint": true, "pointInTimeRecovery": true, "backtrackWindow": "3d",
				"storageEncrypted": true, "encryptionKey": "orders-key", "vector": true, "storageClass": "longhorn"},
		}},
		{name: "db-postgres-replicas-autoscaling", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": float64(8080),
			"database": map[string]any{"replicas": float64(3), "readerEndpoint": true,
				"autoscaling": map[string]any{"minReplicas": float64(2), "maxReplicas": float64(5), "targetCPUPercent": float64(65)}},
		}},
		{name: "db-postgres-expose", ns: "team-a", spec: map[string]any{
			"database": map[string]any{"engine": "postgres", "expose": true},
		}},
		{name: "db-mongo", ns: "team-b", spec: map[string]any{
			"image": "ghcr.io/me/catalog:1", "port": float64(8080), "database": map[string]any{"engine": "mongo", "size": "5Gi"},
		}},
		{name: "db-mysql", ns: "team-b", spec: map[string]any{
			"image": "ghcr.io/me/shop:1", "port": float64(8080), "database": map[string]any{"engine": "mysql", "cpu": "500m", "memory": "1Gi"},
		}},
		{name: "db-babelfish", ns: "team-c", spec: map[string]any{
			"image": "ghcr.io/me/legacy:1", "port": float64(8080), "database": map[string]any{"engine": "babelfish"},
		}},
		{name: "db-sqlserver", ns: "team-c", spec: map[string]any{
			"image": "ghcr.io/me/legacy:2", "port": float64(8080),
			"database": map[string]any{"engine": "sqlserver", "acceptEula": true, "edition": "Express", "recoveryModel": "full",
				"size": "50Gi", "memory": "4Gi", "placement": map[string]any{"openinfra.dev/disk-class": "nvme"},
				"restoreFrom": map[string]any{"bucket": "migrations", "secret": "migr-s3", "key": "estate/db.bak"}},
		}},
		{name: "db-sqlserver-no-eula", ns: "team-c", spec: map[string]any{
			"image": "ghcr.io/me/legacy:2", "port": float64(8080), "database": map[string]any{"engine": "sqlserver"},
		}},
		{name: "db-only-stopped", ns: "team-a", spec: map[string]any{
			"database": map[string]any{"engine": "postgres", "stopped": true, "size": "10Gi"},
		}},
		{name: "buckets-only", ns: "team-a", spec: map[string]any{
			"storage": map[string]any{"buckets": []any{"reports"}},
		}},
		{name: "observed-composed", ns: "team-a", observed: observedCreds, spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": float64(8080), "storage": map[string]any{"buckets": []any{"app-uploads"}},
			"database": map[string]any{"pointInTimeRecovery": true},
		}},
		{name: "int-typed", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/api:2", "port": 8081, "startupGraceSeconds": 15,
			"scaling":         map[string]any{"min": 1, "max": 4, "targetCPUPercent": 50},
			"additionalPorts": []any{map[string]any{"name": "grpc", "port": 9000}},
		}},
		{name: "vm-named-no-role", ns: "team-a", spec: map[string]any{"image": "ghcr.io/me/hello:1", "port": float64(8080)}},
		{name: "extra-resources-ignored", ns: "team-a",
			spec: map[string]any{"image": "ghcr.io/me/hello:1", "port": float64(8080)},
			extra: map[string]any{
				"assumed-role": map[string]any{"items": []any{map[string]any{"resource": map[string]any{"spec": map[string]any{"trust": []any{"alice"}}}}}},
				"accounts":     map[string]any{"items": []any{}},
				"aws-identity": map[string]any{"items": []any{}},
			}},
		{name: "empty-assume-role", ns: "team-a", spec: map[string]any{"image": "ghcr.io/me/hello:1", "port": float64(8080), "assumeRole": ""}},
	}
}

func renderRolelessApplications(t *testing.T) string {
	t.Helper()
	tmpl := extractInlineTemplate(t, compositionPath)
	var b strings.Builder
	for _, c := range rolelessApplicationCases() {
		name := c.name
		if c.name == "vm-named-no-role" {
			name = "vm-web01" // vm-* is refused only with assumeRole
		}
		xr := map[string]any{
			"spec": c.spec,
			"metadata": map[string]any{"name": name + "-x7k2p", "uid": "6f1c2d3e-0000-4000-8000-" + c.name,
				"creationTimestamp": "2026-11-01T10:00:00Z", "labels": map[string]any{
					"crossplane.io/claim-name": name, "crossplane.io/claim-namespace": c.ns}},
		}
		ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": xr}}}
		if c.observed != nil {
			ctx["observed"].(map[string]any)["resources"] = c.observed
		}
		if c.extra != nil {
			ctx["extraResources"] = c.extra
		}
		b.WriteString("=== " + c.name + "\n")
		b.WriteString(render(t, tmpl, ctx))
		b.WriteString("\n")
	}
	return b.String()
}

func TestApplication_RolelessRenderIsByteIdentical(t *testing.T) {
	got := renderRolelessApplications(t)
	if os.Getenv("OPENINFRA_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(applicationRolelessGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", applicationRolelessGolden)
		return
	}
	want, err := os.ReadFile(applicationRolelessGolden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got == string(want) {
		return
	}
	g, w := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	section := ""
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if strings.HasPrefix(wl, "=== ") {
			section = wl
		}
		if gl != wl {
			t.Fatalf("an Application without assumeRole no longer renders byte-identically (%s, line %d):\n  golden: %q\n  now:    %q\n"+
				"every Application on the platform would roll new pods; if that is intended, regenerate the golden and roll in paced batches",
				section, i+1, wl, gl)
		}
	}
}

// The golden covers what it claims: every case renders its workload (or, database-/bucket-only, none), and
// the cases reach the branches named above — so a golden that silently lost a case would not pass.
func TestApplication_RolelessGoldenCoversTheShapes(t *testing.T) {
	b, err := os.ReadFile(applicationRolelessGolden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	g := string(b)
	for _, c := range rolelessApplicationCases() {
		if !strings.Contains(g, "=== "+c.name+"\n") {
			t.Errorf("the golden has no section for %s", c.name)
		}
	}
	for _, want := range []string{
		"kind: Deployment", "kind: HorizontalPodAutoscaler", "kind: Ingress", "replicas: 3",
		"ovn.kubernetes.io/logical_switch: private-a", "openinfra.dev/sg-web", "name: log-shipper",
		"claimName: app-data", "DATABASE_RO_HOST", "MONGODB_URI", "SQLSERVER_URL", "NATS_URL", "app-uploads",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("the golden never renders %q: a case lost its shape", want)
		}
	}
	for _, forbidden := range []string{"composition-resource-name: workload-sa", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"openinfra-sts-token", "kind: ExtraResources", "RoleTrustsWorkload"} {
		if strings.Contains(g, forbidden) {
			t.Errorf("an Application without assumeRole renders %q", forbidden)
		}
	}
}
