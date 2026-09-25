package main

import (
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	s, err := parseSchedule("rate(5 minutes)")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 1, 7, 13, 0, 0, 0, time.UTC)
	next, _ := s.nextFire(after)
	if !next.Equal(after.Add(5 * time.Minute)) {
		t.Errorf("rate(5 minutes) next=%v", next)
	}
	// singular/plural enforcement + unit validation
	for _, bad := range []string{"rate(1 minutes)", "rate(5 minute)", "rate(0 minutes)", "rate(5 fortnights)", "rate(5)"} {
		if _, err := parseSchedule(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if _, err := parseSchedule("rate(1 minute)"); err != nil {
		t.Errorf("rate(1 minute) should be valid: %v", err)
	}
}

// The six-field trap: AWS cron has a year field. A five-field (Unix) expression must be refused, not
// silently misread.
func TestCronSixFieldsRequired(t *testing.T) {
	if _, err := parseSchedule("cron(0 12 * * ?)"); err == nil {
		t.Error("five-field cron must be rejected (AWS cron has six fields)")
	}
}

func TestCronDailyNoon(t *testing.T) {
	s, err := parseSchedule("cron(0 12 * * ? *)")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 1, 7, 13, 0, 0, 0, time.UTC) // 13:00 — past today's noon
	next, err := s.nextFire(after)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 1, 8, 12, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("daily-noon next=%v want %v", next, want)
	}
}

// AWS day-of-week numbering is 1=SUN..7=SAT (differs from Unix). cron(0 0 ? * 2 *) is every Monday.
func TestCronMondayDOW(t *testing.T) {
	s, err := parseSchedule("cron(0 0 ? * 2 *)")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 1, 7, 0, 0, 0, 0, time.UTC) // a Wednesday
	next, err := s.nextFire(after)
	if err != nil {
		t.Fatal(err)
	}
	if next.Weekday() != time.Monday {
		t.Errorf("expected a Monday, got %v (%v)", next.Weekday(), next)
	}
	want := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("next Monday next=%v want %v", next, want)
	}
}

// Named DOW must also work and use AWS numbering.
func TestCronNamedDOW(t *testing.T) {
	s, err := parseSchedule("cron(30 9 ? * MON-FRI *)")
	if err != nil {
		t.Fatal(err)
	}
	// from a Saturday, the next weekday fire is Monday 09:30.
	after := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC) // Saturday
	next, _ := s.nextFire(after)
	if next.Weekday() != time.Monday || next.Hour() != 9 || next.Minute() != 30 {
		t.Errorf("weekday 09:30 next=%v", next)
	}
}

func TestCronRefusesBothDOMandDOW(t *testing.T) {
	if _, err := parseSchedule("cron(0 0 1 * 2 *)"); err == nil {
		t.Error("specifying both day-of-month and day-of-week (neither '?') must be refused")
	}
}

func TestCronStepAndRange(t *testing.T) {
	s, err := parseSchedule("cron(0/15 * * * ? *)") // every 15 minutes
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 1, 7, 10, 3, 0, 0, time.UTC)
	next, _ := s.nextFire(after)
	want := time.Date(2026, 1, 7, 10, 15, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("*/15 next=%v want %v", next, want)
	}
}

// --- event pattern matching ---

func TestPatternExactAndArray(t *testing.T) {
	pat := map[string]any{"source": []any{"aws.ec2", "aws.s3"}, "detail-type": []any{"X"}}
	if !matchPattern(pat, map[string]any{"source": "aws.s3", "detail-type": "X"}) {
		t.Error("array-OR + exact should match")
	}
	if matchPattern(pat, map[string]any{"source": "aws.rds", "detail-type": "X"}) {
		t.Error("non-listed source should not match")
	}
	if matchPattern(pat, map[string]any{"detail-type": "X"}) {
		t.Error("missing required key should not match")
	}
}

func TestPatternNested(t *testing.T) {
	pat := map[string]any{"detail": map[string]any{"state": []any{"running"}}}
	if !matchPattern(pat, map[string]any{"detail": map[string]any{"state": "running", "x": 1.0}}) {
		t.Error("nested match should succeed")
	}
	if matchPattern(pat, map[string]any{"detail": map[string]any{"state": "stopped"}}) {
		t.Error("nested non-match should fail")
	}
}

func TestPatternContentFilters(t *testing.T) {
	cases := []struct {
		name  string
		pat   map[string]any
		ev    map[string]any
		match bool
	}{
		{"prefix", map[string]any{"k": []any{map[string]any{"prefix": "ord"}}}, map[string]any{"k": "orders"}, true},
		{"prefix-no", map[string]any{"k": []any{map[string]any{"prefix": "ord"}}}, map[string]any{"k": "widgets"}, false},
		{"suffix", map[string]any{"k": []any{map[string]any{"suffix": ".json"}}}, map[string]any{"k": "a.json"}, true},
		{"exists", map[string]any{"k": []any{map[string]any{"exists": true}}}, map[string]any{"k": "x"}, true},
		{"exists-false", map[string]any{"k": []any{map[string]any{"exists": false}}}, map[string]any{"other": "x"}, true},
		{"anything-but", map[string]any{"k": []any{map[string]any{"anything-but": "no"}}}, map[string]any{"k": "yes"}, true},
		{"anything-but-hit", map[string]any{"k": []any{map[string]any{"anything-but": []any{"no", "nope"}}}}, map[string]any{"k": "no"}, false},
		{"numeric", map[string]any{"k": []any{map[string]any{"numeric": []any{">", 10.0, "<=", 20.0}}}}, map[string]any{"k": 15.0}, true},
		{"numeric-no", map[string]any{"k": []any{map[string]any{"numeric": []any{">", 10.0}}}}, map[string]any{"k": 5.0}, false},
		{"ieq", map[string]any{"k": []any{map[string]any{"equals-ignore-case": "Prod"}}}, map[string]any{"k": "PROD"}, true},
		{"cidr", map[string]any{"k": []any{map[string]any{"cidr": "10.0.0.0/8"}}}, map[string]any{"k": "10.1.2.3"}, true},
		{"cidr-no", map[string]any{"k": []any{map[string]any{"cidr": "10.0.0.0/8"}}}, map[string]any{"k": "192.168.1.1"}, false},
	}
	for _, c := range cases {
		if got := matchPattern(c.pat, c.ev); got != c.match {
			t.Errorf("%s: matchPattern=%v want %v", c.name, got, c.match)
		}
	}
}

func TestValidatePatternRejectsUnknownOp(t *testing.T) {
	if err := validatePattern(map[string]any{"k": []any{map[string]any{"regex": "x.*"}}}); err == nil {
		t.Error("unknown operator 'regex' must be refused")
	}
	if err := validatePattern(map[string]any{"k": []any{map[string]any{"prefix": "ok"}}}); err != nil {
		t.Errorf("known operator should validate: %v", err)
	}
	if err := validatePattern(map[string]any{"k": "not-an-array"}); err == nil {
		t.Error("a scalar pattern value (not array/object) must be refused")
	}
}

func TestTargetTypeAndArn(t *testing.T) {
	if ty, ok := targetType("arn:aws:lambda:us-east-1:open-infra:function:echo"); !ok || ty != "lambda" {
		t.Errorf("lambda arn: %q %v", ty, ok)
	}
	if ty, ok := targetType("arn:aws:sqs:us-east-1:open-infra:jobs"); !ok || ty != "sqs" {
		t.Errorf("sqs arn: %q %v", ty, ok)
	}
	if _, ok := targetType("arn:aws:kinesis:us-east-1:open-infra:stream/x"); ok {
		t.Error("unsupported target type must be refused")
	}
	if n := lambdaNameFromArn("arn:aws:lambda:us-east-1:open-infra:function:echo:PROD"); n != "echo" {
		t.Errorf("lambdaNameFromArn stripped wrong: %q", n)
	}
	if n := arnLast("arn:aws:sqs:us-east-1:open-infra:jobs"); n != "jobs" {
		t.Errorf("arnLast wrong: %q", n)
	}
}
