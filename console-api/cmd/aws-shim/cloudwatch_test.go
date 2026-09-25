package main

import (
	"net/url"
	"testing"
	"time"
)

func TestCanonicalDimsOrderIndependent(t *testing.T) {
	a := canonicalDims(map[string]string{"InstanceId": "i-1", "Env": "prod"})
	b := canonicalDims(map[string]string{"Env": "prod", "InstanceId": "i-1"})
	if a != b {
		t.Errorf("canonicalDims not order-independent: %q vs %q", a, b)
	}
	if dimsHash(map[string]string{"a": "1"}) == dimsHash(map[string]string{"a": "2"}) {
		t.Error("different dim values must hash differently")
	}
	if dimsHash(map[string]string{"InstanceId": "i-1"}) == dimsHash(map[string]string{"InstanceId": "i-2"}) {
		t.Error("{InstanceId:i-1} and {InstanceId:i-2} are different series")
	}
	if dimsHash(nil) != dimsHash(map[string]string{}) {
		t.Error("nil and empty dims should hash the same")
	}
}

func TestBucketizeAndStats(t *testing.T) {
	// 4 datapoints in one 60s bucket: values 10,20,30,40
	base := int64(1_000_000_000_000) // aligned start
	dps := []cwDatum{
		{TsMs: base + 1000, Value: 10, Sum: 10, Min: 10, Max: 10, Count: 1},
		{TsMs: base + 2000, Value: 20, Sum: 20, Min: 20, Max: 20, Count: 1},
		{TsMs: base + 3000, Value: 30, Sum: 30, Min: 30, Max: 30, Count: 1},
		{TsMs: base + 4000, Value: 40, Sum: 40, Min: 40, Max: 40, Count: 1},
	}
	buckets := bucketize(dps, 60, base, base+60_000)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(buckets))
	}
	b := buckets[0]
	check := func(stat string, want float64) {
		v, ok := statOf(b, stat)
		if !ok || v != want {
			t.Errorf("%s = %v (ok=%v), want %v", stat, v, ok, want)
		}
	}
	check("Sum", 100)
	check("SampleCount", 4)
	check("Average", 25)
	check("Minimum", 10)
	check("Maximum", 40)
}

func TestBucketizeSplitsByPeriod(t *testing.T) {
	base := int64(1_000_000_000_000)
	dps := []cwDatum{
		{TsMs: base + 1000, Value: 1, Sum: 1, Min: 1, Max: 1, Count: 1},
		{TsMs: base + 61000, Value: 2, Sum: 2, Min: 2, Max: 2, Count: 1}, // next 60s bucket
	}
	buckets := bucketize(dps, 60, base, base+120_000)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets across two periods, got %d", len(buckets))
	}
}

func TestPercentile(t *testing.T) {
	var vals []float64
	for i := 1; i <= 100; i++ {
		vals = append(vals, float64(i))
	}
	p50 := percentile(vals, 50)
	if p50 < 50 || p50 > 51 {
		t.Errorf("p50 of 1..100 = %v, want ~50", p50)
	}
	p99 := percentile(vals, 99)
	if p99 < 99 || p99 > 100 {
		t.Errorf("p99 of 1..100 = %v, want ~99", p99)
	}
	if percentile([]float64{42}, 90) != 42 {
		t.Error("percentile of a single value should be that value")
	}
}

func TestParsePercentile(t *testing.T) {
	for _, s := range []string{"p95", "p99.9", "P50"} {
		if _, ok := parsePercentile(s); !ok {
			t.Errorf("parsePercentile(%q) should succeed", s)
		}
	}
	for _, s := range []string{"Average", "p", "p101", "x95", ""} {
		if _, ok := parsePercentile(s); ok {
			t.Errorf("parsePercentile(%q) should fail", s)
		}
	}
}

func TestBreaches(t *testing.T) {
	cases := []struct {
		v    float64
		op   string
		thr  float64
		want bool
	}{
		{10, "GreaterThanThreshold", 5, true},
		{5, "GreaterThanThreshold", 5, false},
		{5, "GreaterThanOrEqualToThreshold", 5, true},
		{4, "LessThanThreshold", 5, true},
		{5, "LessThanOrEqualToThreshold", 5, true},
		{6, "LessThanThreshold", 5, false},
	}
	for _, c := range cases {
		if got := breaches(c.v, c.op, c.thr); got != c.want {
			t.Errorf("breaches(%v,%s,%v) = %v, want %v", c.v, c.op, c.thr, got, c.want)
		}
	}
	if breaches(1, "BogusOperator", 0) {
		t.Error("unknown operator should not breach")
	}
}

func TestVerbForCWOp(t *testing.T) {
	for _, op := range []string{"GetMetricData", "GetMetricStatistics", "ListMetrics", "DescribeAlarms"} {
		if v, ok := verbForCWOp(op); !ok || v != "get" {
			t.Errorf("%s => (%q,%v) want get", op, v, ok)
		}
	}
	for _, op := range []string{"PutMetricData", "PutMetricAlarm", "SetAlarmState"} {
		if v, ok := verbForCWOp(op); !ok || v != "create" {
			t.Errorf("%s => (%q,%v) want create", op, v, ok)
		}
	}
	if v, ok := verbForCWOp("DeleteAlarms"); !ok || v != "delete" {
		t.Errorf("DeleteAlarms => (%q,%v) want delete", v, ok)
	}
	if _, ok := verbForCWOp("Nope"); ok {
		t.Error("unknown op should be unknown")
	}
}

func TestParseMetricData(t *testing.T) {
	form := url.Values{}
	form.Set("MetricData.member.1.MetricName", "Latency")
	form.Set("MetricData.member.1.Value", "42.5")
	form.Set("MetricData.member.1.Unit", "Milliseconds")
	form.Set("MetricData.member.1.Dimensions.member.1.Name", "InstanceId")
	form.Set("MetricData.member.1.Dimensions.member.1.Value", "i-123")
	form.Set("MetricData.member.2.MetricName", "Errors")
	form.Set("MetricData.member.2.StatisticValues.Sum", "100")
	form.Set("MetricData.member.2.StatisticValues.Minimum", "1")
	form.Set("MetricData.member.2.StatisticValues.Maximum", "40")
	form.Set("MetricData.member.2.StatisticValues.SampleCount", "10")
	data := parseMetricData(form)
	if len(data) != 2 {
		t.Fatalf("expected 2 metric data members, got %d", len(data))
	}
	if data[0].MetricName != "Latency" || data[0].Value != 42.5 || data[0].Dims["InstanceId"] != "i-123" {
		t.Errorf("member 1 parsed wrong: %+v", data[0])
	}
	if data[1].Sum != 100 || data[1].Count != 10 || data[1].Max != 40 || data[1].Value != 10 {
		t.Errorf("member 2 (StatisticValues) parsed wrong: %+v", data[1])
	}
}

func TestMemberLeavesAndIndices(t *testing.T) {
	form := url.Values{}
	form.Set("Statistics.member.1", "Average")
	form.Set("Statistics.member.2", "Sum")
	form.Set("AlarmActions.member.1", "arn:aws:sns:us-east-1:acct:topic")
	if got := memberLeaves(form, "Statistics"); len(got) != 2 || got[0] != "Average" || got[1] != "Sum" {
		t.Errorf("memberLeaves(Statistics) = %v", got)
	}
	if got := memberIndices(form, "Statistics"); len(got) != 2 {
		t.Errorf("memberIndices(Statistics) = %v", got)
	}
	if got := memberLeaves(form, "AlarmActions"); len(got) != 1 {
		t.Errorf("memberLeaves(AlarmActions) = %v", got)
	}
}

func TestFlattenQueryMatchesMemberParsers(t *testing.T) {
	// A JSON query-mode PutMetricData body must flatten to the .member.N shape parseMetricData reads.
	body := map[string]any{
		"Namespace": "openinfra/app",
		"MetricData": []any{
			map[string]any{
				"MetricName": "Latency",
				"Value":      float64(42),
				"Unit":       "Milliseconds",
				"Dimensions": []any{
					map[string]any{"Name": "InstanceId", "Value": "i-1"},
				},
			},
		},
	}
	form := url.Values{}
	for k, v := range body {
		flattenQuery(k, v, form)
	}
	if form.Get("Namespace") != "openinfra/app" {
		t.Errorf("Namespace flattened wrong: %q", form.Get("Namespace"))
	}
	if form.Get("MetricData.member.1.MetricName") != "Latency" {
		t.Errorf("MetricName flattened wrong: %q", form.Get("MetricData.member.1.MetricName"))
	}
	if form.Get("MetricData.member.1.Dimensions.member.1.Name") != "InstanceId" {
		t.Errorf("Dimension flattened wrong")
	}
	data := parseMetricData(form)
	if len(data) != 1 || data[0].MetricName != "Latency" || data[0].Value != 42 || data[0].Dims["InstanceId"] != "i-1" {
		t.Errorf("round-trip JSON→form→parseMetricData wrong: %+v", data)
	}
}

func TestFlattenQueryStringList(t *testing.T) {
	form := url.Values{}
	flattenQuery("Statistics", []any{"Average", "Sum"}, form)
	got := memberLeaves(form, "Statistics")
	if len(got) != 2 || got[0] != "Average" || got[1] != "Sum" {
		t.Errorf("string list flatten wrong: %v", got)
	}
}

func TestParseAWSTime(t *testing.T) {
	def := parseAWSTime("", time.Unix(1000, 0))
	if !def.Equal(time.Unix(1000, 0)) {
		t.Errorf("empty should return the default")
	}
	rfc := parseAWSTime("2026-01-02T03:04:05Z", time.Unix(1000, 0))
	if rfc.Year() != 2026 || rfc.Month() != 1 {
		t.Errorf("RFC3339 parse wrong: %v", rfc)
	}
}
