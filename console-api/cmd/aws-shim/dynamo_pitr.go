// DynamoDB continuous backups / point-in-time recovery (PITR). The backend is DocumentDB-on-CNPG with
// the barman-cloud plugin archiving WAL continuously to object storage (see
// platform/aws-shim/dynamodb-backend.yaml), so the DATA is continuously backed up for every table.
// DescribeContinuousBackups reports that, and UpdateContinuousBackups records the per-table PITR opt-in
// (mirroring the AWS toggle) in the table registry. A real point-in-time restore of a single table to a
// NEW table is a backend recovery (bootstrap a CNPG cluster to the target time, copy the collection) —
// an operator/async operation, so RestoreTableToPointInTime returns an honest, explanatory error rather
// than faking a synchronous success.
package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
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

// continuousBackupsDesc builds the ContinuousBackupsDescription for a table. Continuous backups are
// always ENABLED (the backend archives WAL for every table); point-in-time recovery is the per-table
// opt-in recorded in the registry. When enabled, the restorable window is [now-retention, now].
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
		pitr["EarliestRestorableDateTime"] = float64(now.Add(-pitrWindow()).Unix())
		pitr["LatestRestorableDateTime"] = float64(now.Unix())
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

// restoreTableToPointInTime — DynamoDB_20120810.RestoreTableToPointInTime. The backend keeps a
// continuous WAL archive, so a point-in-time restore is possible, but restoring a single table to a NEW
// table means a backend recovery (bootstrap a CNPG cluster to the target time, then copy the source
// collection) — an asynchronous operator operation, not something this synchronous front door should
// fake. Return an honest, explanatory error with the restorable window rather than a false success.
func (h *dynamoHandler) restoreTableToPointInTime(w http.ResponseWriter, requestID string) {
	writeDynamoError(w, http.StatusNotImplemented, "InternalServerError", requestID,
		"RestoreTableToPointInTime is not yet automated by the open-infra shim. The DynamoDB backend "+
			"(DocumentDB on CloudNativePG) retains a continuous WAL archive, so a point-in-time restore "+
			"is performed as a backend recovery to the target time; DescribeContinuousBackups reports the "+
			"restorable window.")
}
