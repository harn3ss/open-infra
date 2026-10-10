// DynamoDB point-in-time restore ORCHESTRATOR (polyhedron#291): the `aws-shim restore-pitr` subcommand.
//
// The RestoreTableToPointInTime front door (dynamo_pitr.go) records a CREATING target and launches this
// as a Kubernetes Job. Running out-of-process in a Job is what makes the restore durable — it survives a
// shim restart, and its outcome is recorded in the table registry (ACTIVE / CREATE_FAILED), observable
// through DescribeTable.
//
// The recovery itself mirrors the proven managed-Postgres backtrack (cmd/server/backtrack.go): CNPG has
// no in-place rewind, so a point-in-time restore bootstraps a NEW CNPG cluster that replays the source's
// WAL archive to the target instant. We then stand a throwaway FerretDB over the recovered Postgres,
// copy the source table's collection + indexes into the (live) target table, flip it ACTIVE, and tear
// the recovery resources down. On any failure the target is flipped CREATE_FAILED and the Job exits
// non-zero — never a false success.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/harn3ss/open-infra/console-api/internal/k8s"
)

const (
	// The DynamoDB backend's source CNPG cluster + its barman ObjectStore + its -rw service host
	// (see platform/aws-shim/dynamodb-backend.yaml). The recovery replays this cluster's archive.
	dynamoSourceCluster = "dynamo-docdb"
	dynamoSourceStore   = "dynamo-docdb-store"
	dynamoSourceRWHost  = "dynamo-docdb-rw"
	// ferretDBImage is the throwaway FerretDB the orchestrator stands over the recovered Postgres.
	ferretDBImage = "ghcr.io/ferretdb/ferretdb:2"
)

// restoreParams are the parsed `restore-pitr` flags.
type restoreParams struct {
	source     string
	target     string
	targetTime string
	restoreID  string
	namespace  string
}

// parseRestoreArgs parses the orchestrator's flags. Pure, so it is unit-testable.
func parseRestoreArgs(args []string) (restoreParams, error) {
	fs := flag.NewFlagSet("restore-pitr", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var p restoreParams
	fs.StringVar(&p.source, "source", "", "source table name")
	fs.StringVar(&p.target, "target", "", "target table name")
	fs.StringVar(&p.targetTime, "target-time", "", "RFC3339 recovery target time")
	fs.StringVar(&p.restoreID, "restore-id", "", "unique restore id")
	fs.StringVar(&p.namespace, "namespace", "", "DynamoDB backend namespace")
	if err := fs.Parse(args); err != nil {
		return p, err
	}
	if p.source == "" || p.target == "" || p.targetTime == "" || p.restoreID == "" || p.namespace == "" {
		return p, errors.New("restore-pitr requires --source --target --target-time --restore-id --namespace")
	}
	return p, nil
}

// runRestorePITR is the `aws-shim restore-pitr` entrypoint. It connects to the LIVE FerretDB (for the
// registry + the target write), runs the recovery, and — on any failure — flips the target table
// CREATE_FAILED with the reason before returning the (non-nil) error so the Job exits non-zero.
func runRestorePITR(args []string) error {
	logger := slog.Default()
	p, err := parseRestoreArgs(args)
	if err != nil {
		return err
	}
	ctx := context.Background()

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		return errors.New("restore-pitr: MONGO_URI is required (the live FerretDB)")
	}
	mongoDBName := getenv("MONGO_DB", "open_infra_dynamodb")

	kc, err := k8s.New("")
	if err != nil {
		return fmt.Errorf("restore-pitr: build k8s client: %w", err)
	}
	cs := *kc.Clientset

	liveClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return fmt.Errorf("restore-pitr: connect live FerretDB: %w", err)
	}
	defer func() { _ = liveClient.Disconnect(context.Background()) }()
	liveDB := liveClient.Database(mongoDBName)

	rerr := doRestore(ctx, logger, cs, liveDB, mongoURI, mongoDBName, p)
	if rerr != nil {
		logger.Error("restore-pitr failed", "source", p.source, "target", p.target, "err", rerr.Error())
		// Record the failure so DescribeTable reports CREATE_FAILED (the operator deletes the table to
		// clean up). Best-effort — the returned error is still what fails the Job.
		_, _ = liveDB.Collection(tableRegistry).UpdateOne(ctx, bson.M{"_id": p.target}, bson.M{"$set": bson.M{
			"status":           "CREATE_FAILED",
			"restore.error":    rerr.Error(),
			"restore.failedAt": time.Now().Unix(),
		}})
		return rerr
	}
	return nil
}

// doRestore performs the recovery. A deferred best-effort cleanup ALWAYS removes the recovery cluster +
// the temp FerretDB Deployment/Service (the recovery cluster's PVC may linger — logged, not fatal).
func doRestore(ctx context.Context, logger *slog.Logger, cs kubernetes.Interface, liveDB *mongo.Database, liveMongoURI, mongoDBName string, p restoreParams) error {
	clusterName := "dynamo-restore-" + p.restoreID
	ferretName := "dynamo-restore-ferret-" + p.restoreID

	defer cleanupRestore(context.Background(), logger, cs, p.namespace, clusterName, ferretName)

	// (a) Read the source cluster spec and POST a recovery cluster that replays its archive to the time.
	srcSpec, err := readDynamoClusterSpec(ctx, cs, p.namespace, dynamoSourceCluster)
	if err != nil {
		return fmt.Errorf("read source cluster %s: %w", dynamoSourceCluster, err)
	}
	cluster := buildDynamoRecoveryCluster(p.namespace, dynamoSourceCluster, dynamoSourceStore, clusterName, p.targetTime, p.source, srcSpec)
	cbody, err := json.Marshal(cluster)
	if err != nil {
		return fmt.Errorf("marshal recovery cluster: %w", err)
	}
	if err := cs.CoreV1().RESTClient().Post().
		AbsPath(cnpgClusterAbsPath(p.namespace, "")).
		Body(cbody).SetHeader("Content-Type", "application/json").Do(ctx).Error(); err != nil {
		return fmt.Errorf("create recovery cluster %s: %w", clusterName, err)
	}
	logger.Info("restore-pitr: recovery cluster created", "cluster", clusterName, "targetTime", p.targetTime)

	// (b) Wait for the recovery cluster to finish bootstrapping (WAL replay can be slow).
	if err := waitClusterReady(ctx, logger, cs, p.namespace, clusterName, 10*time.Minute); err != nil {
		return err
	}

	// (c) Stand a throwaway FerretDB over the recovered Postgres (-rw service of the recovery cluster).
	pgURL, err := recoveryPostgresURL(ctx, cs, p.namespace, clusterName)
	if err != nil {
		return err
	}
	if _, err := cs.AppsV1().Deployments(p.namespace).Create(ctx, buildRestoreFerretDeployment(p.namespace, ferretName, pgURL), metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create temp FerretDB deployment %s: %w", ferretName, err)
	}
	if _, err := cs.CoreV1().Services(p.namespace).Create(ctx, buildRestoreFerretService(p.namespace, ferretName), metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create temp FerretDB service %s: %w", ferretName, err)
	}

	// (d) Wait for the temp FerretDB, then connect to it over the mongo wire (same creds, swapped host).
	if err := waitDeploymentReady(ctx, logger, cs, p.namespace, ferretName, 3*time.Minute); err != nil {
		return err
	}
	recoveredURI, err := swapMongoHost(liveMongoURI, ferretName+"."+p.namespace+".svc.cluster.local:27017")
	if err != nil {
		return err
	}
	recClient, err := mongo.Connect(ctx, options.Client().ApplyURI(recoveredURI))
	if err != nil {
		return fmt.Errorf("connect recovered FerretDB: %w", err)
	}
	defer func() { _ = recClient.Disconnect(context.Background()) }()
	recDB := recClient.Database(mongoDBName)

	// (e) Copy the recovered source collection + its indexes into the LIVE target collection.
	n, err := copyCollection(ctx, recDB.Collection(p.source), liveDB.Collection(p.target))
	if err != nil {
		return fmt.Errorf("copy items: %w", err)
	}
	if err := copyIndexes(ctx, recDB.Collection(p.source), liveDB.Collection(p.target)); err != nil {
		return fmt.Errorf("copy indexes: %w", err)
	}

	// (f) Flip the target ACTIVE and record the outcome.
	if _, err := liveDB.Collection(tableRegistry).UpdateOne(ctx, bson.M{"_id": p.target}, bson.M{"$set": bson.M{
		"status":              "ACTIVE",
		"restore.completedAt": time.Now().Unix(),
		"restore.itemCount":   n,
	}}); err != nil {
		return fmt.Errorf("mark target ACTIVE: %w", err)
	}
	logger.Info("restore-pitr complete", "source", p.source, "target", p.target, "items", n, "targetTime", p.targetTime)
	return nil
}

// dynamoClusterSpec is the slice of the source CNPG Cluster the recovery cluster inherits (same engine
// image, uid/gid, storage, and preloaded libraries) so the recovered database is a faithful copy.
type dynamoClusterSpec struct {
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

func cnpgClusterAbsPath(ns, name string) string {
	p := "/apis/postgresql.cnpg.io/v1/namespaces/" + ns + "/clusters"
	if name != "" {
		p += "/" + name
	}
	return p
}

func readDynamoClusterSpec(ctx context.Context, cs kubernetes.Interface, ns, name string) (dynamoClusterSpec, error) {
	var s dynamoClusterSpec
	raw, err := cs.CoreV1().RESTClient().Get().AbsPath(cnpgClusterAbsPath(ns, name)).DoRaw(ctx)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse cluster %s: %w", name, err)
	}
	return s, nil
}

// buildDynamoRecoveryCluster renders the recovery CNPG Cluster: a new single-instance cluster that
// bootstraps by replaying the source's WAL archive up to targetTime, inheriting the source's engine
// image / uid / gid / postgresql so FerretDB can connect to it identically. Mirrors
// cmd/server/backtrack.go's buildRecoveryCluster. Pure, so it is unit-testable.
func buildDynamoRecoveryCluster(ns, src, store, newName, targetTime, srcTable string, s dynamoClusterSpec) map[string]any {
	cluster := map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      newName,
			"namespace": ns,
			"labels": map[string]string{
				"openinfra.dev/dynamo-restore-of": srcTable,
				"app.kubernetes.io/managed-by":    "aws-shim-dynamo-restore",
			},
			// Created imperatively (not GitOps); keep the dry-run hint harmless.
			"annotations": map[string]string{"argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true"},
		},
		"spec": map[string]any{
			"instances": 1,
			"storage": map[string]any{
				"size":         strOrDefault(s.Spec.Storage.Size, "10Gi"),
				"storageClass": strOrDefault(s.Spec.Storage.StorageClass, "local-path"),
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
	// The DocumentDB image runs as uid/gid 999; carry it so recovery doesn't fail (memory dynamodb-pitr-cnpg).
	if s.Spec.PostgresUID != 0 {
		spec["postgresUID"] = s.Spec.PostgresUID
	}
	if s.Spec.PostgresGID != 0 {
		spec["postgresGID"] = s.Spec.PostgresGID
	}
	// Carry shared_preload_libraries (pg_documentdb*) so the recovered Postgres speaks documentdb.
	if len(s.Spec.PostgreSQL) > 0 {
		spec["postgresql"] = s.Spec.PostgreSQL
	}
	return cluster
}

// buildRestoreFerretDeployment renders the throwaway FerretDB over the recovered Postgres. Pure.
func buildRestoreFerretDeployment(ns, name, pgURL string) *appsv1.Deployment {
	replicas := int32(1)
	podLabels := map[string]string{"app.kubernetes.io/name": name}
	labels := map[string]string{"app.kubernetes.io/name": name, "app.kubernetes.io/managed-by": "aws-shim-dynamo-restore"}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: podLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "ferretdb",
						Image: ferretDBImage,
						Env:   []corev1.EnvVar{{Name: "FERRETDB_POSTGRESQL_URL", Value: pgURL}},
						Ports: []corev1.ContainerPort{{ContainerPort: 27017}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler:        corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(27017)}},
							InitialDelaySeconds: 5,
							PeriodSeconds:       5,
						},
					}},
				},
			},
		},
	}
}

// buildRestoreFerretService renders the ClusterIP Service fronting the throwaway FerretDB. Pure.
func buildRestoreFerretService(ns, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"app.kubernetes.io/managed-by": "aws-shim-dynamo-restore"}},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app.kubernetes.io/name": name},
			Ports:    []corev1.ServicePort{{Port: 27017, TargetPort: intstr.FromInt32(27017)}},
		},
	}
}

// recoveryPostgresURL builds the recovered FerretDB's FERRETDB_POSTGRESQL_URL: the shared basic-auth
// secret's POSTGRESQL_URL with the source cluster's -rw host swapped for the recovery cluster's. The
// recovered app role + password are a physical WAL replay of the source, so the same creds authenticate.
func recoveryPostgresURL(ctx context.Context, cs kubernetes.Interface, ns, clusterName string) (string, error) {
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, restoreMongoSecret, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read %s secret: %w", restoreMongoSecret, err)
	}
	pg := string(sec.Data["POSTGRESQL_URL"])
	if pg == "" {
		return "", fmt.Errorf("%s has no POSTGRESQL_URL", restoreMongoSecret)
	}
	return strings.ReplaceAll(pg, dynamoSourceRWHost, clusterName+"-rw"), nil
}

// swapMongoHost returns the mongo URI with its host[:port] replaced (preserving user/pass + query).
func swapMongoHost(uri, newHost string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("parse mongo uri: %w", err)
	}
	u.Host = newHost
	return u.String(), nil
}

// waitClusterReady polls a CNPG cluster CR until it is healthy (readyInstances>=1 or a healthy phase).
func waitClusterReady(ctx context.Context, logger *slog.Logger, cs kubernetes.Interface, ns, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		raw, err := cs.CoreV1().RESTClient().Get().AbsPath(cnpgClusterAbsPath(ns, name)).DoRaw(ctx)
		if err == nil {
			var st struct {
				Status struct {
					Phase          string `json:"phase"`
					ReadyInstances int    `json:"readyInstances"`
				} `json:"status"`
			}
			if json.Unmarshal(raw, &st) == nil {
				if st.Status.ReadyInstances >= 1 || strings.Contains(strings.ToLower(st.Status.Phase), "healthy") {
					logger.Info("restore-pitr: recovery cluster ready", "cluster", name, "phase", st.Status.Phase, "readyInstances", st.Status.ReadyInstances)
					return nil
				}
				logger.Info("restore-pitr: waiting for recovery cluster", "cluster", name, "phase", st.Status.Phase, "readyInstances", st.Status.ReadyInstances)
			}
		} else {
			logger.Info("restore-pitr: recovery cluster not yet readable", "cluster", name, "err", err.Error())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("recovery cluster %s not ready within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

// waitDeploymentReady polls a Deployment until it has at least one ready replica.
func waitDeploymentReady(ctx context.Context, logger *slog.Logger, cs kubernetes.Interface, ns, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		d, err := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil && d.Status.ReadyReplicas >= 1 {
			logger.Info("restore-pitr: temp FerretDB ready", "deployment", name)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("temp FerretDB %s not ready within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// copyCollection copies every document (preserving _id, i.e. the item's primary key) from src to dst in
// batches. An empty source is success (0 docs copied, no InsertMany call).
func copyCollection(ctx context.Context, src, dst *mongo.Collection) (int, error) {
	cur, err := src.Find(ctx, bson.M{})
	if err != nil {
		return 0, err
	}
	defer cur.Close(ctx)

	total := 0
	batch := make([]any, 0, 500)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if _, err := dst.InsertMany(ctx, batch); err != nil {
			return err
		}
		total += len(batch)
		batch = batch[:0]
		return nil
	}
	for cur.Next(ctx) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			return total, err
		}
		batch = append(batch, doc)
		if len(batch) >= 500 {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := cur.Err(); err != nil {
		return total, err
	}
	if err := flush(); err != nil {
		return total, err
	}
	return total, nil
}

// copyIndexes recreates src's Mongo indexes on dst (the GSI/LSI backend artifacts), skipping the
// implicit _id_ index. The key is decoded as bson.D so compound-index order is preserved.
func copyIndexes(ctx context.Context, src, dst *mongo.Collection) error {
	cur, err := src.Indexes().List(ctx)
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var idx struct {
			Name   string `bson:"name"`
			Key    bson.D `bson:"key"`
			Unique bool   `bson:"unique"`
		}
		if err := cur.Decode(&idx); err != nil {
			return err
		}
		if idx.Name == "" || idx.Name == "_id_" || len(idx.Key) == 0 {
			continue
		}
		opts := options.Index().SetName(idx.Name)
		if idx.Unique {
			opts.SetUnique(true)
		}
		if _, err := dst.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: idx.Key, Options: opts}); err != nil {
			return fmt.Errorf("create index %s: %w", idx.Name, err)
		}
	}
	return cur.Err()
}

// cleanupRestore best-effort removes the temp FerretDB Deployment/Service + the recovery cluster CR.
// The recovery cluster's PVC may linger (CNPG does not always garbage-collect it) — logged, not fatal.
func cleanupRestore(ctx context.Context, logger *slog.Logger, cs kubernetes.Interface, ns, clusterName, ferretName string) {
	if err := cs.AppsV1().Deployments(ns).Delete(ctx, ferretName, metav1.DeleteOptions{}); err != nil {
		logger.Warn("restore-pitr cleanup: delete temp FerretDB deployment", "name", ferretName, "err", err.Error())
	}
	if err := cs.CoreV1().Services(ns).Delete(ctx, ferretName, metav1.DeleteOptions{}); err != nil {
		logger.Warn("restore-pitr cleanup: delete temp FerretDB service", "name", ferretName, "err", err.Error())
	}
	if err := cs.CoreV1().RESTClient().Delete().AbsPath(cnpgClusterAbsPath(ns, clusterName)).Do(ctx).Error(); err != nil {
		logger.Warn("restore-pitr cleanup: delete recovery cluster", "name", clusterName, "err", err.Error())
	}
	logger.Info("restore-pitr cleanup done (recovery cluster PVC may linger — reclaim manually if needed)", "cluster", clusterName, "ferret", ferretName)
}
