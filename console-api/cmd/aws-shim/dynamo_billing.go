package main

import (
	"context"
	"encoding/json"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
)

// Billing mode + provisioned capacity for a DynamoDB table (#263).
//
// The open-infra DynamoDB backend (FerretDB/documentdb on CloudNativePG) is an ON-DEMAND store: it does
// not meter or throttle on read/write capacity units. So PAY_PER_REQUEST is the honest native behaviour.
// We nonetheless ACCEPT and ROUND-TRIP BillingMode + ProvisionedThroughput so an estate's SDK/CloudFormation
// CreateTable calls (and tools that read BillingMode back) are faithful — DescribeTable echoes exactly what
// CreateTable declared. The declared capacity is NOT enforced (there is nothing to throttle); that caveat
// is documented, never hidden. Capacity AUTOSCALING (Application Auto Scaling) is a non-goal: there is no
// provisioned throughput to scale on an on-demand backend.

type billingSpec struct {
	Mode  string // PROVISIONED | PAY_PER_REQUEST
	Read  float64
	Write float64
}

// billingFromCreateTable reads + validates the BillingMode/ProvisionedThroughput of a CreateTable body,
// AWS-faithfully. It returns the spec, or a non-empty validation message (→ ValidationException). Defaults
// match the shim's on-demand backend: an omitted BillingMode with no ProvisionedThroughput is
// PAY_PER_REQUEST (AWS defaults to PROVISIONED, but this backend does not meter — and this keeps the
// no-capacity CreateTable, which real clients and the existing suite use, working).
func billingFromCreateTable(body map[string]any) (billingSpec, string) {
	mode := strings.ToUpper(strings.TrimSpace(strField(body["BillingMode"])))
	pt, hasPT := body["ProvisionedThroughput"].(map[string]any)
	switch mode {
	case "":
		if hasPT {
			mode = "PROVISIONED"
		} else {
			mode = "PAY_PER_REQUEST"
		}
	case "PROVISIONED", "PAY_PER_REQUEST":
	default:
		return billingSpec{}, "BillingMode must be one of PROVISIONED or PAY_PER_REQUEST"
	}
	if mode == "PROVISIONED" {
		if !hasPT {
			return billingSpec{}, "One or more parameter values were invalid: BillingMode PROVISIONED requires ProvisionedThroughput"
		}
		read, write := numField(pt["ReadCapacityUnits"]), numField(pt["WriteCapacityUnits"])
		if read < 1 || write < 1 {
			return billingSpec{}, "One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits must be >= 1 for PROVISIONED"
		}
		return billingSpec{Mode: mode, Read: read, Write: write}, ""
	}
	// PAY_PER_REQUEST: AWS rejects a ProvisionedThroughput on an on-demand table.
	if hasPT {
		return billingSpec{}, "One or more parameter values were invalid: ProvisionedThroughput cannot be set when BillingMode is PAY_PER_REQUEST"
	}
	return billingSpec{Mode: mode}, ""
}

// tableBilling reads a table's stored billing mode + capacity. A table created before this field existed
// (no billingMode in the registry) reports PAY_PER_REQUEST — the backend's honest on-demand default.
func (h *dynamoHandler) tableBilling(ctx context.Context, table string) billingSpec {
	var doc struct {
		BillingMode string  `bson:"billingMode"`
		Read        float64 `bson:"ptRead"`
		Write       float64 `bson:"ptWrite"`
	}
	if err := h.registry().FindOne(ctx, bson.M{"_id": table}).Decode(&doc); err != nil || doc.BillingMode == "" {
		return billingSpec{Mode: "PAY_PER_REQUEST"}
	}
	return billingSpec{Mode: doc.BillingMode, Read: doc.Read, Write: doc.Write}
}

// storeBilling records the billing mode + capacity on a CreateTable registry entry.
func storeBilling(entry bson.M, b billingSpec) {
	entry["billingMode"] = b.Mode
	if b.Mode == "PROVISIONED" {
		entry["ptRead"] = b.Read
		entry["ptWrite"] = b.Write
	}
}

// billingModeSummary / provisionedThroughputDesc render the AWS DescribeTable/CreateTable response fields.
// AWS reports ProvisionedThroughput with 0/0 for an on-demand (PAY_PER_REQUEST) table.
func billingModeSummary(b billingSpec) map[string]any {
	return map[string]any{"BillingMode": b.Mode}
}

func provisionedThroughputDesc(b billingSpec) map[string]any {
	return map[string]any{
		"ReadCapacityUnits":      b.Read,
		"WriteCapacityUnits":     b.Write,
		"NumberOfDecreasesToday": float64(0),
	}
}

func strField(v any) string { s, _ := v.(string); return s }

func numField(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		// AWS numbers are JSON numbers, but tolerate a stringified one.
		var f float64
		_ = json.Unmarshal([]byte(n), &f)
		return f
	}
	return 0
}
