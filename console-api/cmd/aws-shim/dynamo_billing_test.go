package main

import "testing"

// billingFromCreateTable is the AWS-faithful validation + defaulting for a CreateTable's billing mode and
// provisioned capacity (#263). The backend is on-demand, so an omitted mode defaults to PAY_PER_REQUEST.
func TestBillingFromCreateTable(t *testing.T) {
	cases := []struct {
		name     string
		body     map[string]any
		wantMode string
		wantR    float64
		wantW    float64
		wantErr  bool
	}{
		{"omitted → on-demand default", map[string]any{}, "PAY_PER_REQUEST", 0, 0, false},
		{"explicit on-demand", map[string]any{"BillingMode": "PAY_PER_REQUEST"}, "PAY_PER_REQUEST", 0, 0, false},
		{"provisioned with throughput", map[string]any{
			"BillingMode":           "PROVISIONED",
			"ProvisionedThroughput": map[string]any{"ReadCapacityUnits": float64(50), "WriteCapacityUnits": float64(25)},
		}, "PROVISIONED", 50, 25, false},
		{"throughput without mode → provisioned", map[string]any{
			"ProvisionedThroughput": map[string]any{"ReadCapacityUnits": float64(5), "WriteCapacityUnits": float64(5)},
		}, "PROVISIONED", 5, 5, false},
		// AWS-faithful rejections:
		{"provisioned without throughput", map[string]any{"BillingMode": "PROVISIONED"}, "", 0, 0, true},
		{"provisioned with zero capacity", map[string]any{
			"BillingMode":           "PROVISIONED",
			"ProvisionedThroughput": map[string]any{"ReadCapacityUnits": float64(0), "WriteCapacityUnits": float64(5)},
		}, "", 0, 0, true},
		{"on-demand with throughput (invalid)", map[string]any{
			"BillingMode":           "PAY_PER_REQUEST",
			"ProvisionedThroughput": map[string]any{"ReadCapacityUnits": float64(5), "WriteCapacityUnits": float64(5)},
		}, "", 0, 0, true},
		{"bogus mode", map[string]any{"BillingMode": "MAGIC"}, "", 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, verr := billingFromCreateTable(c.body)
			if c.wantErr {
				if verr == "" {
					t.Fatalf("expected a validation error, got none (spec=%+v)", got)
				}
				return
			}
			if verr != "" {
				t.Fatalf("unexpected validation error: %s", verr)
			}
			if got.Mode != c.wantMode || got.Read != c.wantR || got.Write != c.wantW {
				t.Errorf("got %+v, want mode=%s r=%v w=%v", got, c.wantMode, c.wantR, c.wantW)
			}
		})
	}
}

// The DescribeTable response fields: on-demand tables report 0/0 capacity (as AWS does), provisioned
// tables echo the declared numbers.
func TestBillingResponseShape(t *testing.T) {
	od := provisionedThroughputDesc(billingSpec{Mode: "PAY_PER_REQUEST"})
	if od["ReadCapacityUnits"].(float64) != 0 || od["WriteCapacityUnits"].(float64) != 0 {
		t.Errorf("on-demand must report 0/0 capacity, got %+v", od)
	}
	if billingModeSummary(billingSpec{Mode: "PAY_PER_REQUEST"})["BillingMode"] != "PAY_PER_REQUEST" {
		t.Error("billing mode summary wrong for on-demand")
	}
	pr := provisionedThroughputDesc(billingSpec{Mode: "PROVISIONED", Read: 100, Write: 40})
	if pr["ReadCapacityUnits"].(float64) != 100 || pr["WriteCapacityUnits"].(float64) != 40 {
		t.Errorf("provisioned must echo declared capacity, got %+v", pr)
	}
}
