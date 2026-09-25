// CloudWatch metric math for the aws-shim (polyhedron#170): period bucketing, the AWS statistics
// (Average/Sum/Minimum/Maximum/SampleCount), percentiles (pNN), dimension identity, and the alarm
// comparison operators. Kept pure and side-effect-free so the aggregation an operator will TRUST is
// unit-tested — a dimension silently dropped or a statistic computed wrong is a monitoring false green.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
)

// cwDatum is one stored datapoint. For a plain PutMetricData Value: Sum=Min=Max=Value, Count=1. For a
// StatisticValues set: Sum/Min/Max/Count are as sent, and Value is the mean (Sum/Count) — a representative
// used for percentiles when raw values are not available.
type cwDatum struct {
	TsMs  int64
	Value float64
	Sum   float64
	Min   float64
	Max   float64
	Count float64
}

// cwBucket is a period's worth of aggregated datapoints.
type cwBucket struct {
	StartMs int64
	Sum     float64
	Count   float64 // total SampleCount
	Min     float64
	Max     float64
	Values  []float64 // representative values (for percentiles)
	N       int       // number of datapoints (not sample count)
}

// canonicalDims renders dimensions to a stable string (sorted by name) — the metric's identity beyond
// namespace+name. Order-independent so {a,b} and {b,a} are the same series.
func canonicalDims(dims map[string]string) string {
	if len(dims) == 0 {
		return ""
	}
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('\x00')
		b.WriteString(dims[k])
	}
	return b.String()
}

func dimsHash(dims map[string]string) string {
	sum := sha256.Sum256([]byte(canonicalDims(dims)))
	return hex.EncodeToString(sum[:16])
}

// bucketize groups datapoints into fixed period buckets over [startMs, endMs). Empty buckets are omitted
// (as CloudWatch omits datapoints with no data), which the alarm evaluator treats via TreatMissingData.
func bucketize(dps []cwDatum, periodSec int, startMs, endMs int64) []cwBucket {
	if periodSec <= 0 {
		periodSec = 60
	}
	pms := int64(periodSec) * 1000
	byStart := map[int64]*cwBucket{}
	for _, d := range dps {
		if d.TsMs < startMs || d.TsMs >= endMs {
			continue
		}
		bs := startMs + ((d.TsMs-startMs)/pms)*pms
		b := byStart[bs]
		if b == nil {
			b = &cwBucket{StartMs: bs, Min: math.Inf(1), Max: math.Inf(-1)}
			byStart[bs] = b
		}
		b.Sum += d.Sum
		b.Count += d.Count
		if d.Min < b.Min {
			b.Min = d.Min
		}
		if d.Max > b.Max {
			b.Max = d.Max
		}
		b.Values = append(b.Values, d.Value)
		b.N++
	}
	out := make([]cwBucket, 0, len(byStart))
	for _, b := range byStart {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartMs < out[j].StartMs })
	return out
}

// statOf returns the named standard statistic for a bucket, or ok=false if the name is not a standard one
// (the caller then tries extStatOf for a percentile).
func statOf(b cwBucket, stat string) (float64, bool) {
	switch stat {
	case "Sum":
		return b.Sum, true
	case "SampleCount":
		return b.Count, true
	case "Average":
		if b.Count == 0 {
			return 0, true
		}
		return b.Sum / b.Count, true
	case "Minimum":
		return b.Min, true
	case "Maximum":
		return b.Max, true
	}
	return 0, false
}

// extStatOf returns an extended statistic (a percentile, "pNN" / "pNN.N"). ok=false if unrecognized.
func extStatOf(b cwBucket, ext string) (float64, bool) {
	p, ok := parsePercentile(ext)
	if !ok {
		return 0, false
	}
	return percentile(b.Values, p), true
}

// statValue resolves either a standard statistic or a percentile.
func statValue(b cwBucket, stat string) (float64, bool) {
	if v, ok := statOf(b, stat); ok {
		return v, true
	}
	return extStatOf(b, stat)
}

// parsePercentile parses "p95" / "p99.9" into a 0..100 float.
func parsePercentile(s string) (float64, bool) {
	if len(s) < 2 || (s[0] != 'p' && s[0] != 'P') {
		return 0, false
	}
	p, err := strconv.ParseFloat(s[1:], 64)
	if err != nil || p < 0 || p > 100 {
		return 0, false
	}
	return p, true
}

// percentile computes the p-th percentile (0..100) of the values by linear interpolation between closest
// ranks — the standard method, stable for the datasets an operator will check.
func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	if len(v) == 1 {
		return v[0]
	}
	rank := (p / 100.0) * float64(len(v)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return v[lo]
	}
	frac := rank - float64(lo)
	return v[lo] + frac*(v[hi]-v[lo])
}

// breaches reports whether value breaches the threshold under the comparison operator.
func breaches(value float64, op string, threshold float64) bool {
	switch op {
	case "GreaterThanThreshold":
		return value > threshold
	case "GreaterThanOrEqualToThreshold":
		return value >= threshold
	case "LessThanThreshold":
		return value < threshold
	case "LessThanOrEqualToThreshold":
		return value <= threshold
	}
	return false
}

func validComparison(op string) bool {
	switch op {
	case "GreaterThanThreshold", "GreaterThanOrEqualToThreshold", "LessThanThreshold", "LessThanOrEqualToThreshold":
		return true
	}
	return false
}
