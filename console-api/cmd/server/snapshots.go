package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Database snapshots — open-infra's "final snapshot before you deprovision", like an RDS
// snapshot: a logical dump (pg_dump -Fc) streamed to MinIO, decoupled from the resource so
// it SURVIVES the resource's deletion, and restorable into a NEW database. Logical (not a
// CSI volume snapshot) because managed DB data lives on local-path, which has no CSI
// snapshot support — and logical is engine-portable and obviously survives deletion.
//
// In-cluster durability caveat: the artifact lives in MinIO (survives resource deletion),
// NOT off-cluster DR. Labeled honestly in the console.
//
// v1: Postgres (CloudNativePG). The connection comes from the composition's <app>-db-app
// secret (key `uri`). MySQL/Mongo are follow-ups (different dump tools).

const (
	snapBucket   = "db-snapshots"
	snapImage    = "ghcr.io/cloudnative-pg/postgresql:17.0" // pg_dump/pg_restore (postgres + mongo backend)
	mariadbImage = "mariadb:11.4"                            // mariadb-dump/mariadb (mysql)
	mcImage      = "minio/mc:latest"
	snapEndpoint = "http://minio.minio.svc.cluster.local:9000"
)

type dbSnapshotMeta struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	SourceName string `json:"sourceName"`
	Engine     string `json:"engine"`
	DBName     string `json:"dbName"`
	CreatedAt  string `json:"createdAt"`
}

// what the console renders — meta + computed status/size.
type dbSnapshot struct {
	dbSnapshotMeta
	Kind      string `json:"kind"`   // logical (pg_dump→MinIO) | volume (CSI→Longhorn backup)
	Status    string `json:"status"` // creating | ready | failed
	SizeBytes int64  `json:"sizeBytes"`
}

func snapPrefix(ns, name, id string) string { return fmt.Sprintf("%s/%s/%s/", ns, name, id) }

// pgURISecret returns the connection-URI secret ref for a Postgres Application, or false
// if the app isn't a snapshot-supported (Postgres) database.
func pgURISecret(cs kubernetes.Interface, ns, app string) (string, bool) {
	name := app + "-db-app"
	if _, err := cs.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{}); err != nil {
		return "", false
	}
	return name, true
}

// ensureSnapMinioSecret copies the MinIO root creds into the app namespace so the dump/
// restore Job (which runs there, next to the DB secret) can reach MinIO. (Scoping this to a
// db-snapshots-only MinIO user is a tracked follow-up, as with the Query hardening.)
func ensureSnapMinioSecret(ctx context.Context, cs kubernetes.Interface, ns string) error {
	root, err := cs.CoreV1().Secrets(getenv("MINIO_SECRET_NAMESPACE", "minio")).
		Get(ctx, getenv("MINIO_SECRET_NAME", "minio"), metav1.GetOptions{})
	if err != nil {
		return err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "snapshot-minio-creds", Namespace: ns},
		Data: map[string][]byte{
			"ak": root.Data["rootUser"],
			"sk": root.Data["rootPassword"],
		},
	}
	if _, err := cs.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// mcInit is the shared init container that brings `mc` in offline (no runtime download).
func mcInit() corev1.Container {
	return corev1.Container{
		Name: "fetch-mc", Image: mcImage,
		Command:      []string{"sh", "-c", "cp /usr/bin/mc /mc/mc && chmod +x /mc/mc"},
		VolumeMounts: []corev1.VolumeMount{{Name: "mc", MountPath: "/mc"}},
	}
}

func snapEnv(uriSecret, uriKey string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "PGURI", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: uriSecret}, Key: uriKey}}},
		{Name: "AK", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "snapshot-minio-creds"}, Key: "ak"}}},
		{Name: "SK", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "snapshot-minio-creds"}, Key: "sk"}}},
	}
}

func snapJob(name, ns, script string, env []corev1.EnvVar) *batchv1.Job {
	return snapJobImg(name, ns, script, env, snapImage)
}

// snapJobImg runs a dump/restore script in the given image (postgres for pg_dump/pg_restore,
// mariadb for mariadb-dump/mariadb), with `mc` brought in offline via an init container.
func snapJobImg(name, ns, script string, env []corev1.EnvVar, image string) *batchv1.Job {
	ttl := int32(3600)
	backoff := int32(2)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"openinfra.dev/snapshot": "true"}},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			BackoffLimit:            &backoff,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"openinfra.dev/snapshot": "true"}},
				Spec: corev1.PodSpec{
					RestartPolicy:  corev1.RestartPolicyNever,
					Volumes:        []corev1.Volume{{Name: "mc", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
					InitContainers: []corev1.Container{mcInit()},
					Containers: []corev1.Container{{
						Name: "snap", Image: image, Command: []string{"bash", "-c"}, Args: []string{script},
						Env: env, VolumeMounts: []corev1.VolumeMount{{Name: "mc", MountPath: "/mc"}},
					}},
				},
			},
		},
	}
}

// logicalDumpPlan resolves how to logically dump a local-path database — engine, the
// connection-URI secret + key, and the tool. Postgres and mongo (DocumentDB has a Postgres
// backend) use pg_dump; mysql (MariaDB) uses mariadb-dump. Detected by the connection secret.
func logicalDumpPlan(cs kubernetes.Interface, ns, app string) (engine, secret, key, tool string, ok bool) {
	has := func(n string) bool {
		_, err := cs.CoreV1().Secrets(ns).Get(context.Background(), n, metav1.GetOptions{})
		return err == nil
	}
	switch {
	case has(app + "-mongo-app"):
		return "mongo", app + "-mongo-app", "POSTGRESQL_URL", "pgdump", true
	case has(app + "-mysql-app"):
		return "mysql", app + "-mysql-app", "DATABASE_URL", "mariadbdump", true
	case has(app + "-db-app"):
		return "postgres", app + "-db-app", "uri", "pgdump", true
	}
	return "", "", "", "", false
}

// mariadbDumpScript parses a mysql:// URL from $PGURI and streams a mariadb-dump to MinIO.
func mariadbDumpScript(key string) string {
	return fmt.Sprintf(`set -euo pipefail
/mc/mc alias set m %s "$AK" "$SK" >/dev/null
U="${PGURI#mysql://}"; creds="${U%%%%@*}"; rest="${U#*@}"
user="${creds%%%%:*}"; pass="${creds#*:}"
hp="${rest%%%%/*}"; db="${rest#*/}"; db="${db%%%%\?*}"
host="${hp%%%%:*}"; port="${hp#*:}"; [ "$port" = "$hp" ] && port=3306
echo "dumping mysql db $db -> %s"
mariadb-dump --host="$host" --port="$port" --user="$user" --password="$pass" --single-transaction --routines --databases "$db" | /mc/mc pipe m/%s/%sdump.sql
echo "SNAPSHOT OK"`, snapEndpoint, key, snapBucket, key)
}

// mariadbRestoreScript waits for the target MariaDB, then streams the SQL dump back in.
func mariadbRestoreScript(key string) string {
	return fmt.Sprintf(`set -euo pipefail
/mc/mc alias set m %s "$AK" "$SK" >/dev/null
U="${PGURI#mysql://}"; creds="${U%%%%@*}"; rest="${U#*@}"
user="${creds%%%%:*}"; pass="${creds#*:}"
hp="${rest%%%%/*}"; host="${hp%%%%:*}"; port="${hp#*:}"; [ "$port" = "$hp" ] && port=3306
for i in $(seq 1 60); do mariadb-admin --host="$host" --port="$port" --user="$user" --password="$pass" ping && break; sleep 3; done
echo "restoring m/%s/%sdump.sql -> mysql"
/mc/mc cat m/%s/%sdump.sql | mariadb --host="$host" --port="$port" --user="$user" --password="$pass"
echo "RESTORE OK"`, snapEndpoint, snapBucket, key, snapBucket, key)
}

// POST /api/databases/{namespace}/{name}/snapshot  — take a snapshot now.
func handleSnapshotCreate(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, app := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		ctx := r.Context()

		// Managed engines (babelfish/mysql/mongo) live on Longhorn → durable CSI snapshot of
		// the data PVC. Only CNPG Postgres (local-path, no CSI) uses the logical pg_dump path.
		if engine, pvc, ok := managedEngine(cs, ns, app); ok {
			id := fmt.Sprintf("snap-%s-%d", app, time.Now().Unix())
			if err := csiCreateSnapshot(ctx, cs, ns, app, engine, pvc, id); err != nil {
				logger.Error("snapshot: csi create", "err", err, "engine", engine, "pvc", pvc)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create volume snapshot: " + err.Error()})
				return
			}
			writeJSON(w, http.StatusAccepted, dbSnapshotMeta{ID: id, Namespace: ns, SourceName: app,
				Engine: engine, DBName: app, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
			return
		}

		// Every other engine is on local-path (no CSI) → a logical dump to MinIO. Postgres and
		// mongo (DocumentDB's Postgres backend) use pg_dump; mysql (MariaDB) uses mariadb-dump.
		engine, secret, key0, tool, ok := logicalDumpPlan(cs, ns, app)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this database isn't snapshot-supported (no recognised connection secret for " + app + ")"})
			return
		}
		if err := ensureSnapMinioSecret(ctx, cs, ns); err != nil {
			logger.Error("snapshot: minio creds", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "prepare MinIO creds"})
			return
		}
		id := fmt.Sprintf("%s-%d", app, time.Now().Unix())
		key := snapPrefix(ns, app, id)

		// record metadata up front (status is computed from the dump object's presence)
		mc, err := minioClient(cs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "minio"})
			return
		}
		_ = mc.MakeBucket(ctx, snapBucket, minio.MakeBucketOptions{})
		meta := dbSnapshotMeta{ID: id, Namespace: ns, SourceName: app, Engine: engine,
			DBName: app, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
		mb, _ := json.Marshal(meta)
		if _, err := mc.PutObject(ctx, snapBucket, key+"meta.json", bytes.NewReader(mb), int64(len(mb)),
			minio.PutObjectOptions{ContentType: "application/json"}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write metadata"})
			return
		}

		jobName := "snap-" + strings.ReplaceAll(id, ".", "-")
		if len(jobName) > 63 {
			jobName = jobName[:63]
		}
		var job *batchv1.Job
		switch tool {
		case "mariadbdump":
			job = snapJobImg(jobName, ns, mariadbDumpScript(key), snapEnv(secret, key0), mariadbImage)
		default: // pgdump (postgres, mongo)
			script := fmt.Sprintf(`set -euo pipefail
/mc/mc alias set m %s "$AK" "$SK" >/dev/null
echo "dumping %s -> %s"
pg_dump -Fc "$PGURI" | /mc/mc pipe m/%s/%sdump.pgc
echo "SNAPSHOT OK"`, snapEndpoint, app, key, snapBucket, key)
			job = snapJob(jobName, ns, script, snapEnv(secret, key0))
		}
		if _, err := cs.BatchV1().Jobs(ns).Create(ctx, job, metav1.CreateOptions{}); err != nil {
			logger.Error("snapshot: create job", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create snapshot job"})
			return
		}
		writeJSON(w, http.StatusAccepted, meta)
	}
}

// GET /api/snapshots  — list all database snapshots (ready + in-progress).
func handleSnapshotList(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		mc, err := minioClient(cs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "minio"})
			return
		}
		// gather meta.json + dump.pgc (size) across the bucket.
		metas := map[string]*dbSnapshot{}
		for obj := range mc.ListObjects(ctx, snapBucket, minio.ListObjectsOptions{Recursive: true}) {
			if obj.Err != nil {
				break // bucket may not exist yet → empty list
			}
			parts := strings.Split(obj.Key, "/")
			if len(parts) < 4 {
				continue
			}
			dir := strings.Join(parts[:3], "/") // ns/app/id
			base := parts[len(parts)-1]
			s := metas[dir]
			if s == nil {
				s = &dbSnapshot{Kind: "logical", Status: "creating"}
				metas[dir] = s
			}
			switch base {
			case "meta.json":
				o, e := mc.GetObject(ctx, snapBucket, obj.Key, minio.GetObjectOptions{})
				if e == nil {
					b, _ := io.ReadAll(o)
					_ = json.Unmarshal(b, &s.dbSnapshotMeta)
				}
			case "dump.pgc", "dump.sql": // pg_dump (postgres/mongo) / mariadb-dump (mysql)
				s.Status = "ready"
				s.SizeBytes = obj.Size
			}
		}
		out := make([]dbSnapshot, 0, len(metas))
		for _, s := range metas {
			out = append(out, *s)
		}
		// merge in managed-engine CSI (VolumeSnapshot) snapshots
		if csi, err := csiListSnapshots(ctx, cs); err != nil {
			logger.Warn("snapshot: list csi", "err", err)
		} else {
			out = append(out, csi...)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
		writeJSON(w, http.StatusOK, out)
	}
}

// POST /api/snapshots/restore  {id, namespace, target}  — restore a snapshot into an
// already-created (empty) target database. The console creates the new Application (New
// Database, engine from the snapshot); this streams the dump back into it once it's up.
func handleSnapshotRestore(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, Namespace, Target string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.ID == "" || in.Target == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id, namespace, target required"})
			return
		}
		ctx := r.Context()

		// Managed-engine (CSI) snapshots restore into a NEW database the BFF creates itself
		// (pre-seed PVC from the snapshot + a data-only Application). Detected by the snapshot
		// being a VolumeSnapshot named by id in the namespace.
		if _, _, _, isCSI := csiSnapshotEngine(ctx, cs, in.Namespace, in.ID); isCSI {
			if err := csiRestore(ctx, cs, in.Namespace, in.ID, in.Target); err != nil {
				logger.Error("restore: csi", "err", err)
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "restoring", "target": in.Target})
			return
		}

		// the snapshot's dump; source app name is embedded in the id (app-<unix>)
		srcApp := in.ID
		if i := strings.LastIndexByte(in.ID, '-'); i > 0 {
			srcApp = in.ID[:i]
		}
		key := snapPrefix(in.Namespace, srcApp, in.ID)

		// Resolve how to restore INTO the (already-created, empty) target by its engine.
		engine, secret, key0, tool, ok := logicalDumpPlan(cs, in.Namespace, in.Target)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target " + in.Target + " is not a ready database yet"})
			return
		}
		if err := ensureSnapMinioSecret(ctx, cs, in.Namespace); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "prepare MinIO creds"})
			return
		}
		jobName := "restore-" + strings.ReplaceAll(in.Target, ".", "-")
		if len(jobName) > 63 {
			jobName = jobName[:63]
		}
		var job *batchv1.Job
		switch tool {
		case "mariadbdump":
			job = snapJobImg(jobName, in.Namespace, mariadbRestoreScript(key), snapEnv(secret, key0), mariadbImage)
		default: // pgdump (postgres, mongo). --role=app only for CNPG Postgres.
			role := ""
			if engine == "postgres" {
				role = "--role=app"
			}
			script := fmt.Sprintf(`set -euo pipefail
/mc/mc alias set m %s "$AK" "$SK" >/dev/null
for i in $(seq 1 60); do pg_isready -d "$PGURI" && break; sleep 3; done
echo "restoring m/%s/%sdump.pgc -> %s"
/mc/mc cat m/%s/%sdump.pgc | pg_restore --no-owner %s --clean --if-exists -d "$PGURI"
echo "RESTORE OK"`, snapEndpoint, snapBucket, key, in.Target, snapBucket, key, role)
			job = snapJob(jobName, in.Namespace, script, snapEnv(secret, key0))
		}
		_ = cs.BatchV1().Jobs(in.Namespace).Delete(ctx, jobName, metav1.DeleteOptions{})
		if _, err := cs.BatchV1().Jobs(in.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
			logger.Error("restore: create job", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create restore job"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "restoring", "target": in.Target})
	}
}

// DELETE /api/snapshots?namespace=&name=&id=  — remove a snapshot artifact.
func handleSnapshotDelete(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name, id := r.URL.Query().Get("namespace"), r.URL.Query().Get("name"), r.URL.Query().Get("id")
		if ns == "" || name == "" || id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "namespace, name, id required"})
			return
		}
		ctx := r.Context()

		// managed-engine (CSI) snapshots are VolumeSnapshots named by id in ns; if one exists
		// there, delete it (and its Longhorn backup) — otherwise fall through to logical/MinIO.
		if r.URL.Query().Get("kind") == "volume" {
			if err := csiDeleteSnapshot(ctx, cs, ns, id); err != nil {
				logger.Error("snapshot: csi delete", "err", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete volume snapshot: " + err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
			return
		}

		mc, err := minioClient(cs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "minio"})
			return
		}
		prefix := snapPrefix(ns, name, id)
		for obj := range mc.ListObjects(ctx, snapBucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
			if obj.Err == nil {
				_ = mc.RemoveObject(ctx, snapBucket, obj.Key, minio.RemoveObjectOptions{})
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}
