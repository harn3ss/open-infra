package main

import (
	"strings"
	"testing"
	"time"
)

// mapAt walks a nested map[string]any, failing the test if a step is missing or mistyped.
func mapAt(t *testing.T, m map[string]any, keys ...string) map[string]any {
	t.Helper()
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("expected map at %q (have %T)", k, cur[k])
		}
		cur = next
	}
	return cur
}

func TestBuildDynamoRecoveryCluster(t *testing.T) {
	var s dynamoClusterSpec
	s.Spec.ImageName = "ghcr.io/ferretdb/postgres-documentdb:17-0.102.0-ferretdb-2.1.0"
	s.Spec.PostgresUID = 999
	s.Spec.PostgresGID = 999
	s.Spec.Storage.Size = "20Gi"
	s.Spec.Storage.StorageClass = "longhorn"
	s.Spec.PostgreSQL = map[string]any{"shared_preload_libraries": []any{"pg_documentdb"}}

	c := buildDynamoRecoveryCluster("open-infra-aws-shim", "dynamo-docdb", "dynamo-docdb-store",
		"dynamo-restore-abc123", "2026-10-10T12:00:00Z", "orders", s)

	if c["apiVersion"] != "postgresql.cnpg.io/v1" || c["kind"] != "Cluster" {
		t.Fatalf("wrong apiVersion/kind: %v / %v", c["apiVersion"], c["kind"])
	}
	meta := mapAt(t, c, "metadata")
	if meta["name"] != "dynamo-restore-abc123" || meta["namespace"] != "open-infra-aws-shim" {
		t.Fatalf("wrong metadata: %v", meta)
	}
	labels, _ := meta["labels"].(map[string]string)
	if labels["openinfra.dev/dynamo-restore-of"] != "orders" {
		t.Fatalf("missing/wrong restore-of label: %v", labels)
	}

	rec := mapAt(t, c, "spec", "bootstrap", "recovery")
	if rec["source"] != "dynamo-docdb" {
		t.Errorf("bootstrap.recovery.source = %v, want dynamo-docdb", rec["source"])
	}
	rt := mapAt(t, rec, "recoveryTarget")
	if rt["targetTime"] != "2026-10-10T12:00:00Z" {
		t.Errorf("recoveryTarget.targetTime = %v", rt["targetTime"])
	}

	spec := mapAt(t, c, "spec")
	if spec["imageName"] != s.Spec.ImageName {
		t.Errorf("imageName not inherited: %v", spec["imageName"])
	}
	if spec["postgresUID"] != 999 {
		t.Errorf("postgresUID not inherited: %v", spec["postgresUID"])
	}
	if spec["postgresql"] == nil {
		t.Errorf("postgresql block not inherited")
	}
	storage := mapAt(t, c, "spec", "storage")
	if storage["size"] != "20Gi" || storage["storageClass"] != "longhorn" {
		t.Errorf("storage not inherited: %v", storage)
	}

	ext, ok := spec["externalClusters"].([]any)
	if !ok || len(ext) != 1 {
		t.Fatalf("externalClusters shape: %v", spec["externalClusters"])
	}
	plugin := mapAt(t, ext[0].(map[string]any), "plugin")
	if plugin["name"] != "barman-cloud.cloudnative-pg.io" {
		t.Errorf("plugin name = %v", plugin["name"])
	}
	params := mapAt(t, plugin, "parameters")
	if params["barmanObjectName"] != "dynamo-docdb-store" || params["serverName"] != "dynamo-docdb" {
		t.Errorf("plugin parameters = %v", params)
	}
}

func TestBuildDynamoRecoveryCluster_StorageDefaults(t *testing.T) {
	// A source with no storage size/class gets sane defaults rather than an empty (invalid) spec.
	c := buildDynamoRecoveryCluster("ns", "dynamo-docdb", "dynamo-docdb-store", "dynamo-restore-x", "t", "src", dynamoClusterSpec{})
	storage := mapAt(t, c, "spec", "storage")
	if storage["size"] != "10Gi" || storage["storageClass"] != "local-path" {
		t.Errorf("storage defaults = %v", storage)
	}
	spec := mapAt(t, c, "spec")
	if _, set := spec["imageName"]; set {
		t.Errorf("imageName should be omitted when the source did not set it")
	}
	if _, set := spec["postgresUID"]; set {
		t.Errorf("postgresUID should be omitted when zero")
	}
}

func TestBuildRestoreJob(t *testing.T) {
	args := []string{"restore-pitr", "--source", "orders", "--target", "orders-restored",
		"--target-time", "2026-10-10T12:00:00Z", "--restore-id", "abc123", "--namespace", "open-infra-aws-shim"}
	j := buildRestoreJob("open-infra-aws-shim", "dynamo-restore-abc123", "ghcr.io/harn3ss/open-infra-aws-shim:latest",
		"aws-shim-restore", "dynamo-mongo-app", "open_infra_dynamodb", args)

	if j.Name != "dynamo-restore-abc123" || j.Namespace != "open-infra-aws-shim" {
		t.Fatalf("job meta = %s/%s", j.Namespace, j.Name)
	}
	if j.Spec.BackoffLimit == nil || *j.Spec.BackoffLimit != 0 {
		t.Errorf("backoffLimit must be 0 (terminal), got %v", j.Spec.BackoffLimit)
	}
	if j.Spec.TTLSecondsAfterFinished == nil || *j.Spec.TTLSecondsAfterFinished != 3600 {
		t.Errorf("ttlSecondsAfterFinished = %v, want 3600", j.Spec.TTLSecondsAfterFinished)
	}
	pod := j.Spec.Template.Spec
	if pod.ServiceAccountName != "aws-shim-restore" {
		t.Errorf("SA = %q, want aws-shim-restore", pod.ServiceAccountName)
	}
	if pod.RestartPolicy != "Never" {
		t.Errorf("restartPolicy = %q, want Never", pod.RestartPolicy)
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("want 1 container, got %d", len(pod.Containers))
	}
	c := pod.Containers[0]
	if c.Image != "ghcr.io/harn3ss/open-infra-aws-shim:latest" {
		t.Errorf("image = %q", c.Image)
	}
	if strings.Join(c.Args, " ") != strings.Join(args, " ") {
		t.Errorf("args = %v, want %v", c.Args, args)
	}
	env := map[string]string{} // name -> value (literal) ; secretRefs tracked separately
	secretRef := map[string][2]string{}
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			secretRef[e.Name] = [2]string{e.ValueFrom.SecretKeyRef.Name, e.ValueFrom.SecretKeyRef.Key}
		} else {
			env[e.Name] = e.Value
		}
	}
	if secretRef["MONGO_URI"] != [2]string{"dynamo-mongo-app", "MONGODB_URI"} {
		t.Errorf("MONGO_URI secretRef = %v", secretRef["MONGO_URI"])
	}
	if secretRef["MONGO_PG_URI"] != [2]string{"dynamo-mongo-app", "POSTGRESQL_URL"} {
		t.Errorf("MONGO_PG_URI secretRef = %v", secretRef["MONGO_PG_URI"])
	}
	if env["MONGO_DB"] != "open_infra_dynamodb" {
		t.Errorf("MONGO_DB = %q", env["MONGO_DB"])
	}
}

func TestBuildRestoreFerretDeployment(t *testing.T) {
	d := buildRestoreFerretDeployment("open-infra-aws-shim", "dynamo-restore-ferret-abc123",
		"postgres://app:pw@dynamo-restore-abc123-rw.open-infra-aws-shim.svc.cluster.local:5432/postgres")
	c := d.Spec.Template.Spec.Containers[0]
	if c.Image != ferretDBImage {
		t.Errorf("image = %q, want %q", c.Image, ferretDBImage)
	}
	if len(c.Env) != 1 || c.Env[0].Name != "FERRETDB_POSTGRESQL_URL" {
		t.Fatalf("env = %v", c.Env)
	}
	if !strings.Contains(c.Env[0].Value, "dynamo-restore-abc123-rw") {
		t.Errorf("FERRETDB_POSTGRESQL_URL host not swapped: %q", c.Env[0].Value)
	}
	if len(c.Ports) != 1 || c.Ports[0].ContainerPort != 27017 {
		t.Errorf("ports = %v", c.Ports)
	}
	if c.ReadinessProbe == nil || c.ReadinessProbe.TCPSocket == nil || c.ReadinessProbe.TCPSocket.Port.IntValue() != 27017 {
		t.Errorf("readiness probe tcp:27017 missing: %+v", c.ReadinessProbe)
	}
	if d.Spec.Selector.MatchLabels["app.kubernetes.io/name"] != "dynamo-restore-ferret-abc123" {
		t.Errorf("selector = %v", d.Spec.Selector.MatchLabels)
	}
}

func TestBuildRestoreFerretService(t *testing.T) {
	s := buildRestoreFerretService("open-infra-aws-shim", "dynamo-restore-ferret-abc123")
	if s.Spec.Selector["app.kubernetes.io/name"] != "dynamo-restore-ferret-abc123" {
		t.Errorf("selector = %v", s.Spec.Selector)
	}
	if len(s.Spec.Ports) != 1 || s.Spec.Ports[0].Port != 27017 || s.Spec.Ports[0].TargetPort.IntValue() != 27017 {
		t.Errorf("ports = %v", s.Spec.Ports)
	}
}

func TestParseRestoreArgs(t *testing.T) {
	p, err := parseRestoreArgs([]string{"--source", "a", "--target", "b", "--target-time", "2026-10-10T12:00:00Z",
		"--restore-id", "id1", "--namespace", "ns"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.source != "a" || p.target != "b" || p.targetTime != "2026-10-10T12:00:00Z" || p.restoreID != "id1" || p.namespace != "ns" {
		t.Fatalf("parsed = %+v", p)
	}
	if _, err := parseRestoreArgs([]string{"--source", "a"}); err == nil {
		t.Errorf("expected an error when required flags are missing")
	}
}

func TestSwapMongoHost(t *testing.T) {
	out, err := swapMongoHost("mongodb://user:p%40ss@dynamo-mongo.open-infra-aws-shim.svc.cluster.local:27017/?authMechanism=PLAIN",
		"dynamo-restore-ferret-x.open-infra-aws-shim.svc.cluster.local:27017")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(out, "@dynamo-restore-ferret-x.open-infra-aws-shim.svc.cluster.local:27017/") {
		t.Errorf("host not swapped: %q", out)
	}
	if !strings.Contains(out, "user:") || !strings.Contains(out, "authMechanism=PLAIN") {
		t.Errorf("creds/query not preserved: %q", out)
	}
}

func TestResolveRestoreTargetTime(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	window := 7 * 24 * time.Hour

	// UseLatestRestorableTime -> now.
	tt, rfc, err := resolveRestoreTargetTime(map[string]any{"UseLatestRestorableTime": true}, now, window)
	if err != nil || !tt.Equal(now) || rfc != "2026-10-10T12:00:00Z" {
		t.Fatalf("latest: %v %q %v", tt, rfc, err)
	}

	// A valid epoch within the window.
	within := float64(now.Add(-24 * time.Hour).Unix())
	_, rfc, err = resolveRestoreTargetTime(map[string]any{"RestoreDateTime": within}, now, window)
	if err != nil || rfc != "2026-10-09T12:00:00Z" {
		t.Fatalf("within: %q %v", rfc, err)
	}

	// In the future -> error.
	if _, _, err := resolveRestoreTargetTime(map[string]any{"RestoreDateTime": float64(now.Add(time.Hour).Unix())}, now, window); err == nil {
		t.Errorf("future time should be rejected")
	}
	// Older than the window -> error.
	if _, _, err := resolveRestoreTargetTime(map[string]any{"RestoreDateTime": float64(now.Add(-8 * 24 * time.Hour).Unix())}, now, window); err == nil {
		t.Errorf("out-of-window time should be rejected")
	}
	// Neither field -> error.
	if _, _, err := resolveRestoreTargetTime(map[string]any{}, now, window); err == nil {
		t.Errorf("missing time fields should be rejected")
	}
	// Wrong type -> error.
	if _, _, err := resolveRestoreTargetTime(map[string]any{"RestoreDateTime": "nope"}, now, window); err == nil {
		t.Errorf("non-numeric RestoreDateTime should be rejected")
	}
}
