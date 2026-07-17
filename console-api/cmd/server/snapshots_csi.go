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

// managedEngine reports the engine + data-PVC name for a managed (Longhorn) database, or
// ok=false when the Application isn't one (e.g. it's CNPG Postgres → the pg_dump path). We
// detect the engine by which generated connection secret exists — the same signal the rest
// of the BFF uses — so no CRD read is needed.
func managedEngine(cs kubernetes.Interface, ns, app string) (engine, pvc string, ok bool) {
	get := func(name string) bool {
		_, err := cs.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
		return err == nil
	}
	switch {
	case get(app + "-babelfish"):
		// StatefulSet <app>-babelfish, volumeClaimTemplate "data" → data-<app>-babelfish-0.
		return "babelfish", fmt.Sprintf("data-%s-babelfish-0", app), true
	case get(app + "-mongo-app"):
		// FerretDB/DocumentDB-Postgres Deployment mounts <app>-docdb-data.
		return "mongo", app + "-docdb-data", true
	case get(app + "-mysql-app"):
		// MariaDB operator StatefulSet <app>-mysql, PVC storage-<app>-mysql-0.
		return "mysql", fmt.Sprintf("storage-%s-mysql-0", app), true
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
