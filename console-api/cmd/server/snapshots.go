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
	snapImage    = "ghcr.io/cloudnative-pg/postgresql:17.0"
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
						Name: "snap", Image: snapImage, Command: []string{"bash", "-c"}, Args: []string{script},
						Env: env, VolumeMounts: []corev1.VolumeMount{{Name: "mc", MountPath: "/mc"}},
					}},
				},
			},
		},
	}
}

// POST /api/databases/{namespace}/{name}/snapshot  — take a snapshot now.
func handleSnapshotCreate(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, app := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		uriSecret, ok := pgURISecret(cs, ns, app)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "snapshots are supported for Postgres databases only (no " + app + "-db-app secret found)"})
			return
		}
		ctx := r.Context()
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
		meta := dbSnapshotMeta{ID: id, Namespace: ns, SourceName: app, Engine: "postgres",
			DBName: app, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
		mb, _ := json.Marshal(meta)
		if _, err := mc.PutObject(ctx, snapBucket, key+"meta.json", bytes.NewReader(mb), int64(len(mb)),
			minio.PutObjectOptions{ContentType: "application/json"}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write metadata"})
			return
		}

		script := fmt.Sprintf(`set -euo pipefail
/mc/mc alias set m %s "$AK" "$SK" >/dev/null
echo "dumping %s -> %s"
pg_dump -Fc "$PGURI" | /mc/mc pipe m/%s/%sdump.pgc
echo "SNAPSHOT OK"`, snapEndpoint, app, key, snapBucket, key)

		jobName := "snap-" + strings.ReplaceAll(id, ".", "-")
		if jobName == "" {
			jobName = "snap-" + app
		}
		if len(jobName) > 63 {
			jobName = jobName[:63]
		}
		if _, err := cs.BatchV1().Jobs(ns).Create(ctx, snapJob(jobName, ns, script, snapEnv(uriSecret, "uri")), metav1.CreateOptions{}); err != nil {
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
				s = &dbSnapshot{Status: "creating"}
				metas[dir] = s
			}
			switch base {
			case "meta.json":
				o, e := mc.GetObject(ctx, snapBucket, obj.Key, minio.GetObjectOptions{})
				if e == nil {
					b, _ := io.ReadAll(o)
					_ = json.Unmarshal(b, &s.dbSnapshotMeta)
				}
			case "dump.pgc":
				s.Status = "ready"
				s.SizeBytes = obj.Size
			}
		}
		out := make([]dbSnapshot, 0, len(metas))
		for _, s := range metas {
			out = append(out, *s)
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
		// the snapshot's dump; source app name is embedded in the id (app-<unix>)
		srcApp := in.ID
		if i := strings.LastIndexByte(in.ID, '-'); i > 0 {
			srcApp = in.ID[:i]
		}
		key := snapPrefix(in.Namespace, srcApp, in.ID)

		uriSecret, ok := pgURISecret(cs, in.Namespace, in.Target)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target " + in.Target + " is not a ready Postgres database yet"})
			return
		}
		if err := ensureSnapMinioSecret(ctx, cs, in.Namespace); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "prepare MinIO creds"})
			return
		}
		// wait for the target to accept connections, then restore (--clean so a re-run is idempotent).
		script := fmt.Sprintf(`set -euo pipefail
/mc/mc alias set m %s "$AK" "$SK" >/dev/null
for i in $(seq 1 60); do pg_isready -d "$PGURI" && break; sleep 3; done
echo "restoring m/%s/%sdump.pgc -> %s"
/mc/mc cat m/%s/%sdump.pgc | pg_restore --no-owner --role=app --clean --if-exists -d "$PGURI"
echo "RESTORE OK"`, snapEndpoint, snapBucket, key, in.Target, snapBucket, key)

		jobName := "restore-" + strings.ReplaceAll(in.Target, ".", "-")
		if len(jobName) > 63 {
			jobName = jobName[:63]
		}
		_ = cs.BatchV1().Jobs(in.Namespace).Delete(ctx, jobName, metav1.DeleteOptions{})
		if _, err := cs.BatchV1().Jobs(in.Namespace).Create(ctx, snapJob(jobName, in.Namespace, script, snapEnv(uriSecret, "uri")), metav1.CreateOptions{}); err != nil {
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
