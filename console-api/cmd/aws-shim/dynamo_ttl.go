// DynamoDB Time-To-Live for the aws-shim front door.
//
// DynamoDB TTL keys off an epoch-SECONDS number attribute — a Mongo TTL index acts only on Date
// fields, so it can't enforce this. Instead the TTL config is recorded per table and a background
// reaper sweeps expired items (attribute <= now), which matches DynamoDB's own model: TTL
// deletion is a background process, not immediate.
package main

import (
	"context"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func (h *dynamoHandler) updateTimeToLive(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	spec, ok := body["TimeToLiveSpecification"].(map[string]any)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "UpdateTimeToLive requires a TimeToLiveSpecification.")
		return
	}
	enabled, _ := spec["Enabled"].(bool)
	attr, _ := spec["AttributeName"].(string)
	if enabled && attr == "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "AttributeName is required when TTL is Enabled.")
		return
	}
	if _, ok := h.tableKeyAttrs(ctx, table); !ok {
		writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Cannot do operations on a non-existent table: "+table)
		return
	}
	if _, err := h.registry().UpdateOne(ctx, bson.M{"_id": table},
		bson.M{"$set": bson.M{"ttl": bson.M{"enabled": enabled, "attribute": attr}}}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{"TimeToLiveSpecification": map[string]any{"Enabled": enabled, "AttributeName": attr}})
}

func (h *dynamoHandler) describeTimeToLive(ctx context.Context, w http.ResponseWriter, requestID, table string) {
	var doc struct {
		TTL struct {
			Enabled   bool   `bson:"enabled"`
			Attribute string `bson:"attribute"`
		} `bson:"ttl"`
	}
	desc := map[string]any{"TimeToLiveStatus": "DISABLED"}
	if err := h.registry().FindOne(ctx, bson.M{"_id": table}).Decode(&doc); err == nil && doc.TTL.Enabled {
		desc["TimeToLiveStatus"] = "ENABLED"
		desc["AttributeName"] = doc.TTL.Attribute
	}
	writeDynamoJSON(w, requestID, map[string]any{"TimeToLiveDescription": desc})
}

// startTTLReaper runs a background sweep (every interval) that deletes expired items from every
// TTL-enabled table. Started once, for the process lifetime, when the mongo data layer is present.
func (h *dynamoHandler) startTTLReaper(ctx context.Context, interval time.Duration) {
	if h.db == nil {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.reapExpired(ctx)
			}
		}
	}()
}

// reapExpired deletes items whose TTL attribute is at or before now, across TTL-enabled tables.
func (h *dynamoHandler) reapExpired(ctx context.Context) {
	cur, err := h.registry().Find(ctx, bson.M{"ttl.enabled": true})
	if err != nil {
		return
	}
	defer cur.Close(ctx)
	now := time.Now().Unix()
	for cur.Next(ctx) {
		var doc struct {
			ID  string `bson:"_id"`
			TTL struct {
				Attribute string `bson:"attribute"`
			} `bson:"ttl"`
		}
		if err := cur.Decode(&doc); err != nil || doc.TTL.Attribute == "" {
			continue
		}
		res, err := h.db.Collection(doc.ID).DeleteMany(ctx, bson.M{doc.TTL.Attribute: bson.M{"$lte": now}})
		if err != nil {
			h.logger.Warn("ttl reaper sweep failed", "table", doc.ID, "err", err)
			continue
		}
		if res.DeletedCount > 0 {
			h.logger.Info("ttl reaper expired items", "table", doc.ID, "count", res.DeletedCount)
		}
	}
}
