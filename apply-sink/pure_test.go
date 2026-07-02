package main

// Tier 0 — pure-function unit tests. No DB, no network, no env by default.
// These lock down the small deterministic helpers that decide driver dialects,
// subject/schema mapping, table parsing, and the cross-engine value/type coercion
// that has caused real data bugs (see TestCoerce_TemporalMagnitude). Run: go test ./...

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDriverName(t *testing.T) {
	cases := map[string]string{
		"postgres":   "pgx",
		"postgresql": "pgx",
		"pgx":        "pgx",
		"Postgres":   "pgx", // case-insensitive
		"mysql":      "mysql",
		"mariadb":    "mysql",
		"MariaDB":    "mysql",
		"sqlserver":  "sqlserver",
		"mssql":      "sqlserver",
		"cockroach":  "cockroach", // unknown -> passthrough
	}
	for in, want := range cases {
		if got := driverName(in); got != want {
			t.Errorf("driverName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTargetSchema(t *testing.T) {
	// Default behavior (no TARGET_SCHEMA override).
	if got := targetSchema("mysql", "myapp"); got != "" {
		t.Errorf("mysql target schema = %q, want empty (MySQL has no schema layer)", got)
	}
	if got := targetSchema("sqlserver", "myapp"); got != "dbo" {
		t.Errorf("sqlserver target schema = %q, want dbo", got)
	}
	if got := targetSchema("postgres", "myapp"); got != "myapp" {
		t.Errorf("postgres target schema = %q, want the source schema myapp", got)
	}
}

func TestTargetSchema_EnvOverride(t *testing.T) {
	t.Setenv("TARGET_SCHEMA", "forced")
	for _, eng := range []string{"mysql", "sqlserver", "postgres"} {
		if got := targetSchema(eng, "src"); got != "forced" {
			t.Errorf("targetSchema(%q) with TARGET_SCHEMA=forced = %q, want forced", eng, got)
		}
	}
}

func TestSplitTables(t *testing.T) {
	got := splitTables(" public.orders, inventory.items ,bareword,, ")
	want := [][2]string{
		{"public", "orders"},
		{"inventory", "items"},
		{"public", "bareword"}, // unqualified -> public
	}
	if len(got) != len(want) {
		t.Fatalf("splitTables len = %d (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitTables[%d] = %v, want %v", i, got[i], want[i])
		}
	}
	if len(splitTables("")) != 0 {
		t.Errorf("splitTables(\"\") should yield no entries")
	}
}

func TestDropHelperTables(t *testing.T) {
	in := [][2]string{
		{"public", "orders"},
		{"public", "mm_hlc_state"}, // our HLC state — drop
		{"dbo", "systranschemas"},  // SQL Server marker — drop
		{"cdc", "dbo_orders_CT"},   // CDC schema — drop
		{"sys", "objects"},         // system schema — drop
		{"inventory", "items"},     // keep
	}
	got := dropHelperTables(in)
	want := [][2]string{{"public", "orders"}, {"inventory", "items"}}
	if len(got) != len(want) {
		t.Fatalf("dropHelperTables = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dropHelperTables[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestAckWaitDur(t *testing.T) {
	// Default when unset.
	t.Run("default", func(t *testing.T) {
		t.Setenv("ACK_WAIT", "")
		if got := ackWaitDur(); got != 2*time.Minute {
			t.Errorf("ackWaitDur() default = %v, want 2m", got)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv("ACK_WAIT", "45s")
		if got := ackWaitDur(); got != 45*time.Second {
			t.Errorf("ackWaitDur() = %v, want 45s", got)
		}
	})
	t.Run("garbage falls back to default", func(t *testing.T) {
		t.Setenv("ACK_WAIT", "not-a-duration")
		if got := ackWaitDur(); got != 2*time.Minute {
			t.Errorf("ackWaitDur() with garbage = %v, want 2m fallback", got)
		}
	})
	t.Run("zero/negative falls back", func(t *testing.T) {
		t.Setenv("ACK_WAIT", "0s")
		if got := ackWaitDur(); got != 2*time.Minute {
			t.Errorf("ackWaitDur() with 0s = %v, want 2m fallback", got)
		}
	})
}

func TestLastTwoSeg(t *testing.T) {
	cases := map[string]string{
		"cdc.default.public.orders": "public.orders",
		"public.orders":             "public.orders",
		"orders":                    "orders", // fewer than 2 segments -> as-is
		"":                          "",
	}
	for in, want := range cases {
		if got := lastTwoSeg(in); got != want {
			t.Errorf("lastTwoSeg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuoteIdent(t *testing.T) {
	if got := quoteIdent("mysql", "col"); got != "`col`" {
		t.Errorf("mysql quote = %q, want `col`", got)
	}
	if got := quoteIdent("sqlserver", "col"); got != "[col]" {
		t.Errorf("sqlserver quote = %q, want [col]", got)
	}
	if got := quoteIdent("postgres", "col"); got != `"col"` {
		t.Errorf("postgres quote = %q, want \"col\"", got)
	}
}

func TestPlaceholder(t *testing.T) {
	// index is 0-based; output is 1-based.
	if got := placeholder("postgres", 0); got != "$1" {
		t.Errorf("pg placeholder = %q, want $1", got)
	}
	if got := placeholder("sqlserver", 2); got != "@p3" {
		t.Errorf("sqlserver placeholder = %q, want @p3", got)
	}
	if got := placeholder("mysql", 5); got != "?" {
		t.Errorf("mysql placeholder = %q, want ?", got)
	}
}

func TestQualified(t *testing.T) {
	if got := qualified("postgres", "public", "orders"); got != `"public"."orders"` {
		t.Errorf("qualified pg = %q", got)
	}
	if got := qualified("mysql", "", "orders"); got != "`orders`" {
		t.Errorf("qualified mysql no-schema = %q, want `orders`", got)
	}
	if got := qualified("sqlserver", "dbo", "orders"); got != "[dbo].[orders]" {
		t.Errorf("qualified mssql = %q", got)
	}
}

func TestIsTemporal(t *testing.T) {
	for _, tt := range []string{"timestamp", "timestamp without time zone", "date", "datetime", "datetime2"} {
		if !isTemporal(tt) {
			t.Errorf("isTemporal(%q) = false, want true", tt)
		}
	}
	for _, tt := range []string{"integer", "text", "numeric", "boolean"} {
		if isTemporal(tt) {
			t.Errorf("isTemporal(%q) = true, want false", tt)
		}
	}
}

// TestCoerce_TemporalMagnitude guards the T3 fix: Debezium encodes non-tz temporals
// as epoch integers whose UNIT depends on magnitude (days / seconds / millis / micros
// / nanos). A DATE (~20000 days) landing in a column the target reports as "timestamp"
// must NOT be read as ~20000 *seconds* (1970). The <1e5 bucket => days is the crux.
func TestCoerce_TemporalMagnitude(t *testing.T) {
	num := func(s string) json.Number { return json.Number(s) }
	mustTime := func(got any) time.Time {
		tm, ok := got.(time.Time)
		if !ok {
			t.Fatalf("coerce returned %T, want time.Time", got)
		}
		return tm
	}

	// Explicit DATE column: value is days since epoch.
	if d := mustTime(coerce(num("19723"), "date")); !d.Equal(time.Unix(19723*86400, 0).UTC()) {
		t.Errorf("date days = %v, want %v", d, time.Unix(19723*86400, 0).UTC())
	}
	// The regression: small value in a generic temporal column => days, not seconds.
	small := mustTime(coerce(num("20000"), "timestamp"))
	if !small.Equal(time.Unix(20000*86400, 0).UTC()) {
		t.Errorf("small temporal = %v, want days-based %v (NOT 1970)", small, time.Unix(20000*86400, 0).UTC())
	}
	if small.Year() < 2000 {
		t.Errorf("small temporal fell into the seconds(1970) bug: %v", small)
	}
	// Boundary: >=1e5 => seconds.
	if s := mustTime(coerce(num("100000"), "timestamp")); !s.Equal(time.Unix(100000, 0).UTC()) {
		t.Errorf("seconds bucket = %v, want %v", s, time.Unix(100000, 0).UTC())
	}
	// millis / micros / nanos buckets.
	if ms := mustTime(coerce(num("1700000000000"), "timestamp")); !ms.Equal(time.UnixMilli(1700000000000).UTC()) {
		t.Errorf("millis bucket wrong: %v", ms)
	}
	if us := mustTime(coerce(num("1700000000000000"), "timestamp")); !us.Equal(time.UnixMicro(1700000000000000).UTC()) {
		t.Errorf("micros bucket wrong: %v", us)
	}
	if ns := mustTime(coerce(num("1700000000000000000"), "timestamp")); !ns.Equal(time.Unix(0, 1700000000000000000).UTC()) {
		t.Errorf("nanos bucket wrong: %v", ns)
	}
}

func TestCoerce_Strings(t *testing.T) {
	// RFC3339 and bare-date strings parse into time.Time.
	if _, ok := coerce("2024-06-27T03:04:05Z", "timestamp").(time.Time); !ok {
		t.Errorf("RFC3339 string should coerce to time.Time")
	}
	if _, ok := coerce("2024-06-27", "date").(time.Time); !ok {
		t.Errorf("bare date string should coerce to time.Time")
	}
	// Unparseable temporal string is returned untouched (not dropped).
	if got := coerce("tuesday", "timestamp"); got != "tuesday" {
		t.Errorf("unparseable temporal = %v, want passthrough", got)
	}
}

func TestCoerce_Numbers(t *testing.T) {
	if got := coerce(json.Number("42"), "integer"); got != int64(42) {
		t.Errorf("int coerce = %v (%T), want int64(42)", got, got)
	}
	if got := coerce(json.Number("3.14"), "numeric"); got != 3.14 {
		t.Errorf("float coerce = %v (%T), want 3.14", got, got)
	}
	if got := coerce(json.Number("1e3"), "double precision"); got != float64(1000) {
		t.Errorf("exp-notation coerce = %v, want 1000.0", got)
	}
	if coerce(nil, "timestamp") != nil {
		t.Errorf("coerce(nil) must stay nil")
	}
}

func TestSplitType(t *testing.T) {
	cases := []struct{ in, base, params string }{
		{"VARCHAR(255)", "varchar", "(255)"},
		{"int", "int", ""},
		{"  Decimal(10, 2) ", "decimal", "(10, 2)"},
		{"TIMESTAMP", "timestamp", ""},
	}
	for _, c := range cases {
		b, p := splitType(c.in)
		if b != c.base || p != c.params {
			t.Errorf("splitType(%q) = (%q,%q), want (%q,%q)", c.in, b, p, c.base, c.params)
		}
	}
}

func TestMapType(t *testing.T) {
	// Same driver family => passthrough (no lossy round-trip).
	if got := mapType("postgres", "postgresql", "jsonb"); got != "jsonb" {
		t.Errorf("same-driver mapType = %q, want passthrough jsonb", got)
	}
	// MySQL -> Postgres, incl. the tinyint(1)->boolean special case and unsigned strip.
	cases := []struct{ src, want string }{
		{"tinyint(1)", "boolean"},
		{"tinyint", "smallint"},
		{"int unsigned", "integer"},
		{"bigint unsigned", "bigint"},
		{"varchar(255)", "varchar(255)"},
		{"varchar", "text"},
		{"json", "jsonb"},
		{"datetime", "timestamp"},
	}
	for _, c := range cases {
		if got := mapType("mysql", "postgres", c.src); got != c.want {
			t.Errorf("mapType(mysql->pg, %q) = %q, want %q", c.src, got, c.want)
		}
	}
}
