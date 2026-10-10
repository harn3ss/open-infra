// DynamoDB continuous backups / point-in-time recovery (PITR). The backend is DocumentDB-on-CNPG with
// the barman-cloud plugin archiving WAL continuously to object storage (see
// platform/aws-shim/dynamodb-backend.yaml), so the DATA is continuously backed up for every table.
// DescribeContinuousBackups reports that, and UpdateContinuousBackups records the per-table PITR opt-in
// (mirroring the AWS toggle) in the table registry.
//
// RestoreTableToPointInTime is REAL and durable (polyhedron#291): the synchronous front door here
// validates the request, records a CREATING target in the registry, and launches an asynchronous
// Kubernetes Job (the shim's own image, subcommand `restore-pitr` — see dynamo_restore.go) that
// bootstraps a recovery CNPG cluster to the target time, stands up a throwaway FerretDB over it, copies
// the source collection + its indexes into the new table, and flips the target to ACTIVE (or
// CREATE_FAILED on any error). The work survives a shim restart because it lives in the Job, not this
// process; progress is observable through DescribeTable (TableStatus). This is the faithful analog of
// the managed-Postgres backtrack (cmd/server/backtrack.go) for the DynamoDB abstraction.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// defaultAWSShimImage is the image the restore Job runs (the shim's own image, so the Job carries
	// exactly the code that launched it). Overridden by the AWS_SHIM_IMAGE env in the Deployment.
	defaultAWSShimImage = "ghcr.io/harn3ss/open-infra-aws-shim:latest"
	// restoreServiceAccount is the least-privilege SA the restore Job runs as (CNPG cluster + temp
	// Deployment/Service lifecycle only — see platform/aws-shim/dynamo-restore-rbac.yaml).
	restoreServiceAccount = "aws-shim-restore"
	// restoreMongoSecret is the basic-auth Secret holding the live FerretDB MONGODB_URI/POSTGRESQL_URL
	// the restore Job reads (same Secret the shim Deployment reads).
	restoreMongoSecret = "dynamo-mongo-app"
)

// pitrWindow is how far back a restore can reach — the backend's WAL-archive retention (matches the
// ObjectStore retentionPolicy, default 7d). Configurable via DYNAMO_PITR_WINDOW (a Go duration).
func pitrWindow() time.Duration {
	if v := os.Getenv("DYNAMO_PITR_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 7 * 24 * time.Hour
}

// dynamoBackendNS resolves the namespace the DynamoDB backend (dynamo-docdb + its ObjectStore + the
// shared connection Secret) lives in.
func (h *dynamoHandler) dynamoBackendNS() string {
	if h.restoreNS != "" {
		return h.restoreNS
	}
	return getenv("DYNAMO_BACKEND_NAMESPACE", getenv("KEYS_NAMESPACE", "open-infra-aws-shim"))
}

// earliestRestorable returns the backend's ACTUAL oldest restorable instant — the source CNPG cluster's
// status.firstRecoverabilityPoint (the start of the WAL archive from the oldest retained base backup).
// ok=false when no base backup has completed yet, so the reported window is never faked: with no base
// backup, nothing earlier than "now" is restorable regardless of the retention policy.
func (h *dynamoHandler) earliestRestorable(ctx context.Context) (time.Time, bool) {
	raw, err := h.cs.CoreV1().RESTClient().Get().
		AbsPath("/apis/postgresql.cnpg.io/v1/namespaces/" + h.dynamoBackendNS() + "/clusters/" + dynamoSourceCluster).
		DoRaw(ctx)
	if err != nil {
		return time.Time{}, false
	}
	var st struct {
		Status struct {
			FirstRecoverabilityPoint string `json:"firstRecoverabilityPoint"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &st) != nil || st.Status.FirstRecoverabilityPoint == "" {
		return time.Time{}, false
	}
	t, perr := time.Parse(time.RFC3339, st.Status.FirstRecoverabilityPoint)
	if perr != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// continuousBackupsDesc builds the ContinuousBackupsDescription for a table. Continuous backups are
// always ENABLED (the backend archives WAL for every table); point-in-time recovery is the per-table
// opt-in recorded in the registry. When enabled, EarliestRestorableDateTime is the backend's REAL oldest
// restorable instant (firstRecoverabilityPoint, clamped to the retention window) — never a blind
// now-retention claim, which would promise restores that no base backup can satisfy.
func (h *dynamoHandler) continuousBackupsDesc(ctx context.Context, table string) map[string]any {
	var doc struct {
		PITR struct {
			Enabled bool `bson:"enabled"`
		} `bson:"pitr"`
	}
	_ = h.registry().FindOne(ctx, bson.M{"_id": table}).Decode(&doc)

	pitr := map[string]any{"PointInTimeRecoveryStatus": "DISABLED"}
	if doc.PITR.Enabled {
		now := time.Now().UTC()
		pitr["PointInTimeRecoveryStatus"] = "ENABLED"
		// DynamoDB returns these as epoch-second numbers.
		pitr["LatestRestorableDateTime"] = float64(now.Unix())
		earliest := now // no base backup yet -> nothing earlier than now is restorable
		if fr, ok := h.earliestRestorable(ctx); ok {
			earliest = fr
			if floor := now.Add(-pitrWindow()); earliest.Before(floor) {
				earliest = floor // never advertise earlier than the retention policy keeps
			}
		}
		pitr["EarliestRestorableDateTime"] = float64(earliest.Unix())
	}
	return map[string]any{
		"ContinuousBackupsStatus":        "ENABLED",
		"PointInTimeRecoveryDescription": pitr,
	}
}

// describeContinuousBackups — DynamoDB_20120810.DescribeContinuousBackups.
func (h *dynamoHandler) describeContinuousBackups(ctx context.Context, w http.ResponseWriter, requestID, table string) {
	if table == "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "TableName is required.")
		return
	}
	if err := h.registry().FindOne(ctx, bson.M{"_id": table}).Err(); err != nil {
		writeDynamoError(w, http.StatusBadRequest, "TableNotFoundException", requestID,
			"Requested resource not found: Table: "+table+" not found")
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{"ContinuousBackupsDescription": h.continuousBackupsDesc(ctx, table)})
}

// updateContinuousBackups — DynamoDB_20120810.UpdateContinuousBackups. Records the per-table PITR
// opt-in. The backend archives WAL for all tables regardless; this is the AWS-visible toggle, so
// Describe reports what the caller set.
func (h *dynamoHandler) updateContinuousBackups(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	if table == "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "TableName is required.")
		return
	}
	spec, ok := body["PointInTimeRecoverySpecification"].(map[string]any)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"PointInTimeRecoverySpecification is required.")
		return
	}
	enabled, _ := spec["PointInTimeRecoveryEnabled"].(bool)
	res, err := h.registry().UpdateOne(ctx, bson.M{"_id": table}, bson.M{"$set": bson.M{"pitr.enabled": enabled}})
	if err != nil {
		writeDynamoError(w, http.StatusInternalServerError, "InternalServerError", requestID, err.Error())
		return
	}
	if res.MatchedCount == 0 {
		writeDynamoError(w, http.StatusBadRequest, "TableNotFoundException", requestID,
			"Requested resource not found: Table: "+table+" not found")
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{"ContinuousBackupsDescription": h.continuousBackupsDesc(ctx, table)})
}

// dynamoRegistryDoc is the slice of a table's registry entry the restore front door reads from the
// SOURCE table (to seed the new table's schema) and writes for the TARGET (status + restore record).
type dynamoRegistryDoc struct {
	ID       string   `bson:"_id"`
	KeyAttrs []string `bson:"keyAttrs"`
	GSI      []gsiDef `bson:"gsi"`
	LSI      []gsiDef `bson:"lsi"`
	PITR     struct {
		Enabled bool `bson:"enabled"`
	} `bson:"pitr"`
	Status string `bson:"status"`
}

// resolveRestoreTargetTime resolves the RestoreTableToPointInTime target instant from the request and
// validates it against the restorable window [now-window, now]. UseLatestRestorableTime wins if set;
// otherwise RestoreDateTime (DynamoDB sends it as an epoch-second number) is required. It returns the
// resolved time, its RFC3339 (UTC) rendering (what CNPG recoveryTarget.targetTime wants), or a
// validation error whose message is safe to surface to the caller. Pure, so it is unit-testable.
func resolveRestoreTargetTime(body map[string]any, now time.Time, window time.Duration) (time.Time, string, error) {
	now = now.UTC()
	earliest := now.Add(-window)
	if latest, ok := body["UseLatestRestorableTime"].(bool); ok && latest {
		return now, now.Format(time.RFC3339), nil
	}
	raw, present := body["RestoreDateTime"]
	if !present {
		return time.Time{}, "", fmt.Errorf("either RestoreDateTime or UseLatestRestorableTime must be specified")
	}
	secs, ok := raw.(float64)
	if !ok {
		return time.Time{}, "", fmt.Errorf("RestoreDateTime must be a number (epoch seconds)")
	}
	t := time.Unix(int64(secs), 0).UTC()
	if t.After(now) {
		return time.Time{}, "", fmt.Errorf("RestoreDateTime cannot be in the future")
	}
	if t.Before(earliest) {
		return time.Time{}, "", fmt.Errorf(
			"RestoreDateTime is outside the restorable window [%s, %s]",
			earliest.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return t, t.Format(time.RFC3339), nil
}

// restoreTableToPointInTime — DynamoDB_20120810.RestoreTableToPointInTime. The synchronous front door:
// validate, record a CREATING target in the registry, and launch the async restore Job. The actual
// recovery (bootstrap a CNPG cluster to the target time, copy the collection) runs in the Job so it
// survives a shim restart; the caller polls DescribeTable for CREATING -> ACTIVE / CREATE_FAILED.
func (h *dynamoHandler) restoreTableToPointInTime(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	src, _ := body["SourceTableName"].(string)
	tgt, _ := body["TargetTableName"].(string)
	if src == "" || tgt == "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"RestoreTableToPointInTime requires SourceTableName and TargetTableName.")
		return
	}

	// The source table must exist...
	var srcDoc dynamoRegistryDoc
	if err := h.registry().FindOne(ctx, bson.M{"_id": src}).Decode(&srcDoc); err != nil {
		writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
			"Requested resource not found: Table: "+src+" not found")
		return
	}
	// ...and have point-in-time recovery enabled (else there is no window to restore to).
	if !srcDoc.PITR.Enabled {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"point-in-time recovery is not enabled for table "+src)
		return
	}
	// The target table must NOT already exist (AWS: ResourceInUseException).
	if err := h.registry().FindOne(ctx, bson.M{"_id": tgt}).Err(); err == nil {
		writeDynamoError(w, http.StatusBadRequest, "ResourceInUseException", requestID,
			"Table already exists: "+tgt)
		return
	}

	resolved, targetTime, err := resolveRestoreTargetTime(body, time.Now(), pitrWindow())
	if err != nil {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
		return
	}
	// Reject a target earlier than the backend can actually restore to (no base backup covers it) — an
	// honest up-front error, not a slow CREATE_FAILED after the recovery cluster fails to bootstrap.
	if earliest, ok := h.earliestRestorable(ctx); ok && resolved.Before(earliest) {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"RestoreDateTime is before the earliest restorable time "+earliest.Format(time.RFC3339)+" (no base backup covers it)")
		return
	}

	ns := h.restoreNS
	if ns == "" {
		ns = getenv("DYNAMO_BACKEND_NAMESPACE", getenv("KEYS_NAMESPACE", "open-infra-aws-shim"))
	}
	image := h.restoreImage
	if image == "" {
		image = getenv("AWS_SHIM_IMAGE", defaultAWSShimImage)
	}

	id := shortID(8)
	jobName := "dynamo-restore-" + id

	// Record the CREATING target up-front (copies schema from the source; deliberately NOT the stream —
	// AWS restores a table without its stream). DescribeTable reports CREATING until the Job finishes.
	entry := bson.M{
		"_id":      tgt,
		"keyAttrs": srcDoc.KeyAttrs,
		"status":   "CREATING",
		"restore": bson.M{
			"source":     src,
			"targetTime": targetTime,
			"startedAt":  time.Now().Unix(),
			"jobName":    jobName,
		},
	}
	if len(srcDoc.GSI) > 0 {
		entry["gsi"] = srcDoc.GSI
	}
	if len(srcDoc.LSI) > 0 {
		entry["lsi"] = srcDoc.LSI
	}
	if _, err := h.registry().InsertOne(ctx, entry); err != nil {
		h.internal(w, requestID, err)
		return
	}

	args := []string{
		"restore-pitr",
		"--source", src,
		"--target", tgt,
		"--target-time", targetTime,
		"--restore-id", id,
		"--namespace", ns,
	}
	job := buildRestoreJob(ns, jobName, image, restoreServiceAccount, restoreMongoSecret, h.dbName, args)
	if _, err := h.cs.BatchV1().Jobs(ns).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		// Roll the CREATING registry entry back so a retry isn't wrongly blocked by ResourceInUse.
		_, _ = h.registry().DeleteOne(ctx, bson.M{"_id": tgt})
		h.internal(w, requestID, err)
		return
	}
	h.logger.Info("dynamodb restore started", "source", src, "target", tgt, "targetTime", targetTime, "job", jobName)

	writeDynamoJSON(w, requestID, map[string]any{"TableDescription": map[string]any{
		"TableName":   tgt,
		"TableStatus": "CREATING",
		"KeySchema":   keySchemaFromAttrs(srcDoc.KeyAttrs),
		"ItemCount":   float64(0),
	}})
}

// buildRestoreJob renders the async restore Job: the shim's own image running the `restore-pitr`
// subcommand, as the least-privilege aws-shim-restore SA, with the live FerretDB connection env from
// the shared basic-auth Secret. backoffLimit 0 (a failed restore is terminal — the orchestrator has
// already recorded CREATE_FAILED), restartPolicy Never, ttl 1h so the Job self-reaps. Kept pure for
// unit testing (image / SA / args / env / backoffLimit are asserted without a cluster).
func buildRestoreJob(ns, name, image, saName, mongoSecret, mongoDB string, args []string) *batchv1.Job {
	backoff := int32(0)
	ttl := int32(3600)
	labels := map[string]string{"openinfra.dev/dynamo-restore": "true"}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: saName,
					RestartPolicy:      corev1.RestartPolicyNever,
					// Mirror the shim Deployment's posture so a restricted PSA namespace admits the Job.
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   boolPtr(true),
						RunAsUser:      int64Ptr(65532),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:  "restore",
						Image: image,
						Args:  args,
						Env: []corev1.EnvVar{
							{Name: "MONGO_URI", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: mongoSecret}, Key: "MONGODB_URI"}}},
							{Name: "MONGO_PG_URI", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: mongoSecret}, Key: "POSTGRESQL_URL"}}},
							{Name: "MONGO_DB", Value: mongoDB},
						},
					}},
				},
			},
		},
	}
}

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }
