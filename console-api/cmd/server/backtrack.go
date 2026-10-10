package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// Database point-in-time recovery ("backtrack"). When an Application sets
// spec.database.pointInTimeRecovery, its CNPG Cluster continuously archives WAL to a barman
// ObjectStore (see platform/abstraction/composition.yaml). CNPG has no in-place rewind, so a
// restore recovers to a NEW cluster at a target time (bootstrap.recovery + externalClusters[].plugin
// pointed at the source's ObjectStore — the same recipe the DynamoDB backend uses), and the operator
// cuts the application over to the recovered cluster's -rw endpoint. This is the faithful Aurora
// Backtrack / RDS RestoreDBInstanceToPointInTime analog for the managed-Postgres abstraction.
//
// POST /api/databases/{namespace}/{name}/backtrack  body: {"targetTime":"<RFC3339>","targetName":"<optional>"}

func cnpgClustersPath(ns, name string) string {
	p := "/apis/postgresql.cnpg.io/v1/namespaces/" + ns + "/clusters"
	if name != "" {
		p += "/" + name
	}
	return p
}

// cnpgClusterSpec is the slice of a source CNPG Cluster the recovery cluster must inherit so the
// recovered database is a faithful copy (same engine image, storage, and preloaded libraries).
type cnpgClusterSpec struct {
	Spec struct {
		ImageName   string `json:"imageName"`
		PostgresUID int    `json:"postgresUID"`
		PostgresGID int    `json:"postgresGID"`
		Storage     struct {
			Size         string `json:"size"`
			StorageClass string `json:"storageClass"`
		} `json:"storage"`
		PostgreSQL map[string]any `json:"postgresql"`
	} `json:"spec"`
}

// buildRecoveryCluster renders the recovery CNPG Cluster manifest: a new single-instance cluster that
// bootstraps by replaying the source's WAL archive up to targetTime. Kept pure for unit testing.
// src is the source cluster's name (e.g. "<app>-db"); store is its barman ObjectStore name.
func buildRecoveryCluster(ns, src, store, newName, targetTime string, s cnpgClusterSpec) map[string]any {
	cluster := map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      newName,
			"namespace": ns,
			"labels":    map[string]string{"openinfra.dev/backtrack-of": src},
			// A recovery is a CR-kind apply through the root app-of-apps path only if GitOps-managed;
			// this one is created imperatively, but keep the dry-run hint harmless.
			"annotations": map[string]string{"argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true"},
		},
		"spec": map[string]any{
			"instances": 1,
			"storage": map[string]any{
				"size":         orDefault(s.Spec.Storage.Size, "5Gi"),
				"storageClass": orDefault(s.Spec.Storage.StorageClass, "local-path"),
			},
			// Replay the source's archive to the requested instant.
			"bootstrap": map[string]any{
				"recovery": map[string]any{
					"source":         src,
					"recoveryTarget": map[string]any{"targetTime": targetTime},
				},
			},
			// Where to read the archive from: the source's barman ObjectStore, via the CNPG-I plugin.
			"externalClusters": []any{
				map[string]any{
					"name": src,
					"plugin": map[string]any{
						"name": "barman-cloud.cloudnative-pg.io",
						"parameters": map[string]any{
							"barmanObjectName": store,
							"serverName":       src,
						},
					},
				},
			},
		},
	}
	spec := cluster["spec"].(map[string]any)
	if s.Spec.ImageName != "" {
		spec["imageName"] = s.Spec.ImageName
	}
	// The DocumentDB image runs as uid/gid 999; carry it so initdb/recovery doesn't fail (see
	// memory dynamodb-pitr-cnpg). Only set when the source set it (non-zero).
	if s.Spec.PostgresUID != 0 {
		spec["postgresUID"] = s.Spec.PostgresUID
	}
	if s.Spec.PostgresGID != 0 {
		spec["postgresGID"] = s.Spec.PostgresGID
	}
	if len(s.Spec.PostgreSQL) > 0 {
		spec["postgresql"] = s.Spec.PostgreSQL
	}
	return cluster
}

// handleBacktrack restores a managed Postgres database to a point in time as a new cluster.
func handleBacktrack(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, app := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		// Restoring is a mutating operation on that database's world — same right as changing it,
		// checked AS the signed-in user (not the ServiceAccount).
		if !authorize(w, r, cs, auth, logger, "update", "openinfra.dev", "applications", ns, app) {
			return
		}
		ctx := r.Context()

		var req struct {
			TargetTime string `json:"targetTime"`
			TargetName string `json:"targetName"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if _, err := time.Parse(time.RFC3339, req.TargetTime); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targetTime must be RFC3339 (e.g. 2026-10-10T12:00:00Z)"})
			return
		}

		src := app + "-db"
		store := app + "-db-backup"

		// The source must have point-in-time recovery enabled (its barman ObjectStore must exist),
		// else there is no WAL archive to replay — refuse honestly rather than create a cluster that
		// can never bootstrap.
		if err := cs.CoreV1().RESTClient().Get().
			AbsPath("/apis/barmancloud.cnpg.io/v1/namespaces/" + ns + "/objectstores/" + store).
			Do(ctx).Error(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "point-in-time recovery is not enabled for '" + app + "' (set spec.database.pointInTimeRecovery on the Application, then wait for WAL to accumulate)"})
			return
		}

		// Read the source cluster so the recovered copy inherits its image/storage/params.
		raw, err := cs.CoreV1().RESTClient().Get().AbsPath(cnpgClustersPath(ns, src)).DoRaw(ctx)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "source database cluster '" + src + "' not found"})
			return
		}
		var srcSpec cnpgClusterSpec
		if err := json.Unmarshal(raw, &srcSpec); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "parse source cluster"})
			return
		}

		newName := req.TargetName
		if newName == "" {
			newName = fmt.Sprintf("%s-db-restored-%d", app, time.Now().Unix())
		}
		if len(newName) > 50 { // CNPG derives longer service/resource names from this; keep headroom
			newName = newName[:50]
		}

		cluster := buildRecoveryCluster(ns, src, store, newName, req.TargetTime, srcSpec)
		body, _ := json.Marshal(cluster)
		if err := cs.CoreV1().RESTClient().Post().
			AbsPath(cnpgClustersPath(ns, "")).
			Body(body).
			SetHeader("Content-Type", "application/json").
			Do(ctx).Error(); err != nil {
			logger.Error("backtrack: create recovery cluster", "err", err, "cluster", newName)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create recovery cluster: " + err.Error()})
			return
		}
		logger.Info("backtrack started", "app", app, "ns", ns, "restoredCluster", newName, "targetTime", req.TargetTime)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"restoredCluster": newName,
			"host":            newName + "-rw." + ns + ".svc.cluster.local",
			"targetTime":      req.TargetTime,
			"note":            "recovering to the target time; when the cluster is ready, point the app at the host above (or its " + newName + "-app secret) to complete the cutover",
		})
	}
}
