package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CSI (physical) snapshots for managed engines whose data lives on Longhorn — babelfish,
// mysql (MariaDB), mongo (FerretDB/DocumentDB-Postgres). Unlike CNPG-on-local-path (which
// has no CSI snapshot support and uses the logical pg_dump path in snapshots.go), these are
// StatefulSet/Deployment workloads on Longhorn, so we snapshot the DATA PVC with a
// VolumeSnapshot using the `longhorn-backup` class — which backs the snapshot up to the
// Longhorn backup target (MinIO) so it SURVIVES deletion of the source database. A plain
// pg_dump is WRONG for babelfish: it drags in the babelfishpg_* extensions and the
// sys/master_/msdb_/tempdb_ catalog schemas, which fight a fresh babelfish's own bootstrap.
//
// Validated 2026-07-16: bak snapshot -> delete source PVC entirely -> restore new PVC ->
// data returned; and a babelfish PVC snapshot -> new pod -> canary + sys catalog intact.

const (
	// longhorn-backup (type: bak) uploads to the backup target (MinIO) → durable past delete.
	// longhorn-snapshot (type: snap) is in-volume and dies with the PVC — do NOT use it here.
	csiSnapClass = "longhorn-backup"

	snapLabel  = "openinfra.dev/snapshot"      // marks VolumeSnapshots we manage
	annEngine  = "openinfra.dev/snap-engine"   // babelfish | mysql | mongo
	annSource  = "openinfra.dev/snap-source"   // source Application name
	annDBName  = "openinfra.dev/snap-dbname"   // logical database name (best effort)
	annCreated = "openinfra.dev/snap-createdat"
)

// managedEngine reports the engine + data-PVC name for a database whose data is on Longhorn
// (→ durable CSI snapshot). In this platform that's ONLY babelfish; every other engine —
// Postgres, mongo (DocumentDB), mysql (MariaDB) — is on local-path, which has no CSI snapshot,
// so those take a logical dump instead (see logicalDumpPlan). Detected by the connection secret.
func managedEngine(cs kubernetes.Interface, ns, app string) (engine, pvc string, ok bool) {
	if _, err := cs.CoreV1().Secrets(ns).Get(context.Background(), app+"-babelfish", metav1.GetOptions{}); err == nil {
		// StatefulSet <app>-babelfish, volumeClaimTemplate "data" → data-<app>-babelfish-0.
		return "babelfish", fmt.Sprintf("data-%s-babelfish-0", app), true
	}
	return "", "", false
}

// volumeSnapshot is the slice of the snapshot.storage.k8s.io/v1 object we read/write.
type volumeSnapshot struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Spec struct {
		VolumeSnapshotClassName string `json:"volumeSnapshotClassName"`
		Source                  struct {
			PersistentVolumeClaimName string `json:"persistentVolumeClaimName"`
		} `json:"source"`
	} `json:"spec"`
	Status *struct {
		ReadyToUse  *bool  `json:"readyToUse,omitempty"`
		RestoreSize string `json:"restoreSize,omitempty"`
		Error       *struct {
			Message string `json:"message,omitempty"`
		} `json:"error,omitempty"`
	} `json:"status,omitempty"`
}

func vsAbsPath(ns string) string {
	if ns == "" {
		return "/apis/snapshot.storage.k8s.io/v1/volumesnapshots"
	}
	return "/apis/snapshot.storage.k8s.io/v1/namespaces/" + ns + "/volumesnapshots"
}

// csiCreateSnapshot creates a durable (longhorn-backup) VolumeSnapshot of a managed DB's
// data PVC, tagged so the list endpoint can render it alongside the logical snapshots.
func csiCreateSnapshot(ctx context.Context, cs kubernetes.Interface, ns, app, engine, pvc, id string) error {
	vs := map[string]any{
		"apiVersion": "snapshot.storage.k8s.io/v1",
		"kind":       "VolumeSnapshot",
		"metadata": map[string]any{
			"name":      id,
			"namespace": ns,
			"labels":    map[string]string{snapLabel: "true"},
			"annotations": map[string]string{
				annEngine:  engine,
				annSource:  app,
				annDBName:  app,
				annCreated: time.Now().UTC().Format(time.RFC3339),
			},
		},
		"spec": map[string]any{
			"volumeSnapshotClassName": csiSnapClass,
			"source":                  map[string]any{"persistentVolumeClaimName": pvc},
		},
	}
	body, _ := json.Marshal(vs)
	return cs.CoreV1().RESTClient().Post().
		AbsPath(vsAbsPath(ns)).
		Body(body).
		SetHeader("Content-Type", "application/json").
		Do(ctx).Error()
}

// csiListSnapshots returns all managed-DB VolumeSnapshots (across namespaces) as dbSnapshots.
func csiListSnapshots(ctx context.Context, cs kubernetes.Interface) ([]dbSnapshot, error) {
	raw, err := cs.CoreV1().RESTClient().Get().
		AbsPath(vsAbsPath("")).
		Param("labelSelector", snapLabel+"=true").
		DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []volumeSnapshot `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	out := make([]dbSnapshot, 0, len(list.Items))
	for _, vs := range list.Items {
		a := vs.Metadata.Annotations
		s := dbSnapshot{
			dbSnapshotMeta: dbSnapshotMeta{
				ID:         vs.Metadata.Name,
				Namespace:  vs.Metadata.Namespace,
				SourceName: a[annSource],
				Engine:     a[annEngine],
				DBName:     a[annDBName],
				CreatedAt:  a[annCreated],
			},
			Kind:   "volume",
			Status: "creating",
		}
		if vs.Status != nil {
			if vs.Status.Error != nil && vs.Status.Error.Message != "" {
				s.Status = "failed"
			} else if vs.Status.ReadyToUse != nil && *vs.Status.ReadyToUse {
				s.Status = "ready"
			}
			s.SizeBytes = parseQuantityBytes(vs.Status.RestoreSize)
		}
		out = append(out, s)
	}
	return out, nil
}

// csiDeleteSnapshot removes a managed-DB VolumeSnapshot (and, via the backup deletionPolicy,
// its backup in MinIO).
func csiDeleteSnapshot(ctx context.Context, cs kubernetes.Interface, ns, name string) error {
	return cs.CoreV1().RESTClient().Delete().
		AbsPath(vsAbsPath(ns) + "/" + name).
		Do(ctx).Error()
}

// csiSnapshotEngine reads a managed-DB VolumeSnapshot's engine + logical db name (or ok=false
// if there's no such snapshot — i.e. it's a logical/pg_dump snapshot instead).
func csiSnapshotEngine(ctx context.Context, cs kubernetes.Interface, ns, id string) (engine, dbName, size string, ok bool) {
	raw, err := cs.CoreV1().RESTClient().Get().AbsPath(vsAbsPath(ns) + "/" + id).DoRaw(ctx)
	if err != nil {
		return "", "", "", false
	}
	var vs volumeSnapshot
	if err := json.Unmarshal(raw, &vs); err != nil {
		return "", "", "", false
	}
	size = "10Gi"
	if vs.Status != nil && vs.Status.RestoreSize != "" {
		size = vs.Status.RestoreSize
	}
	return vs.Metadata.Annotations[annEngine], vs.Metadata.Annotations[annDBName], size, true
}

// csiRestore restores a managed-DB VolumeSnapshot into a NEW database (AWS-style — never
// resurrects the old one): it pre-seeds the target's data PVC FROM the snapshot (the
// StatefulSet then adopts it by name) and creates a data-only Application. The restored
// data carries the source's password, but the babelfish entrypoint reconciles the app +
// superuser password to the new instance's generated secret on boot (start.sh), so the new
// connection secret authenticates — no exec needed. v1: babelfish only.
func csiRestore(ctx context.Context, cs kubernetes.Interface, ns, id, target string) error {
	engine, dbName, size, ok := csiSnapshotEngine(ctx, cs, ns, id)
	if !ok {
		return fmt.Errorf("volume snapshot %q not found in %s", id, ns)
	}
	if engine != "babelfish" {
		return fmt.Errorf("restore-as-new is currently supported for babelfish only (this snapshot is %q)", engine)
	}
	if dbName == "" {
		dbName = target
	}

	// 1) pre-seed the target data PVC from the snapshot (STS adopts data-<target>-babelfish-0).
	pvc := map[string]any{
		"apiVersion": "v1", "kind": "PersistentVolumeClaim",
		"metadata": map[string]any{"name": fmt.Sprintf("data-%s-babelfish-0", target), "namespace": ns},
		"spec": map[string]any{
			"storageClassName": "longhorn",
			"accessModes":      []string{"ReadWriteOnce"},
			"dataSource":       map[string]any{"name": id, "kind": "VolumeSnapshot", "apiGroup": "snapshot.storage.k8s.io"},
			"resources":        map[string]any{"requests": map[string]any{"storage": size}},
		},
	}
	pb, _ := json.Marshal(pvc)
	if err := cs.CoreV1().RESTClient().Post().
		AbsPath("/api/v1/namespaces/" + ns + "/persistentvolumeclaims").
		Body(pb).SetHeader("Content-Type", "application/json").Do(ctx).Error(); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("create restore PVC: %w", err)
	}

	// 2) create a data-only Application; database.name = the source's logical db so the
	//    restored physical database matches. StatefulSet adopts the pre-seeded PVC.
	app := map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Application",
		"metadata": map[string]any{"name": target, "namespace": ns},
		"spec":     map[string]any{"database": map[string]any{"engine": "babelfish", "name": dbName}},
	}
	ab, _ := json.Marshal(app)
	if err := cs.CoreV1().RESTClient().Post().
		AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/applications").
		Body(ab).SetHeader("Content-Type", "application/json").Do(ctx).Error(); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("create restored application: %w", err)
	}
	return nil
}

// parseQuantityBytes turns a k8s resource.Quantity string ("10Gi", "5368709120") into bytes.
// Good enough for display; unknown units → 0.
func parseQuantityBytes(q string) int64 {
	q = strings.TrimSpace(q)
	if q == "" {
		return 0
	}
	mult := int64(1)
	for suffix, m := range map[string]int64{
		"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40,
	} {
		if strings.HasSuffix(q, suffix) {
			mult = m
			q = strings.TrimSuffix(q, suffix)
			break
		}
	}
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(q), "%d", &n); err != nil {
		return 0
	}
	return n * mult
}
