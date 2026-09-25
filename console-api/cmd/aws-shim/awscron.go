// AWS EventBridge schedule-expression parsing for the aws-shim (polyhedron#163).
//
// Two forms: rate(N unit) and cron(<6 fields>). AWS cron is NOT Unix cron — it has SIX fields (adding a
// year), uses "?" for "no specific value" in day-of-month/day-of-week, and numbers day-of-week 1..7 with
// 1=Sunday. Handing an AWS cron straight to a Unix scheduler would run jobs at the WRONG time silently,
// so this is parsed and evaluated deliberately, in UTC, and any expression we cannot faithfully evaluate
// is rejected at PutRule rather than approximated.
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// schedule is a parsed schedule expression that can compute its next fire time (UTC).
type schedule struct {
	rate time.Duration // >0 => a rate() schedule
	cron *cronSpec     // non-nil => a cron() schedule
}

// nextFire returns the first fire strictly after `after` (UTC).
func (s schedule) nextFire(after time.Time) (time.Time, error) {
	if s.rate > 0 {
		return after.Add(s.rate), nil
	}
	if s.cron != nil {
		return s.cron.next(after)
	}
	return time.Time{}, fmt.Errorf("empty schedule")
}

// parseSchedule parses "rate(...)" or "cron(...)". A malformed/unsupported expression is an error, which
// the handler surfaces as a ValidationException (never a silently-approximated schedule).
func parseSchedule(expr string) (schedule, error) {
	expr = strings.TrimSpace(expr)
	switch {
	case strings.HasPrefix(expr, "rate(") && strings.HasSuffix(expr, ")"):
		return parseRate(expr[len("rate(") : len(expr)-1])
	case strings.HasPrefix(expr, "cron(") && strings.HasSuffix(expr, ")"):
		c, err := parseCron(expr[len("cron(") : len(expr)-1])
		if err != nil {
			return schedule{}, err
		}
		return schedule{cron: c}, nil
	}
	return schedule{}, fmt.Errorf("schedule expression must be rate(...) or cron(...)")
}

func parseRate(body string) (schedule, error) {
	parts := strings.Fields(body)
	if len(parts) != 2 {
		return schedule{}, fmt.Errorf("rate() must be 'rate(value unit)'")
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 1 {
		return schedule{}, fmt.Errorf("rate() value must be a positive integer")
	}
	var unit time.Duration
	switch strings.TrimSuffix(parts[1], "s") { // accept singular or plural
	case "minute":
		unit = time.Minute
	case "hour":
		unit = time.Hour
	case "day":
		unit = 24 * time.Hour
	default:
		return schedule{}, fmt.Errorf("rate() unit must be minute(s), hour(s), or day(s)")
	}
	if n == 1 && strings.HasSuffix(parts[1], "s") {
		return schedule{}, fmt.Errorf("rate() of 1 must be singular (e.g. rate(1 minute))")
	}
	if n != 1 && !strings.HasSuffix(parts[1], "s") {
		return schedule{}, fmt.Errorf("rate() greater than 1 must be plural (e.g. rate(5 minutes))")
	}
	return schedule{rate: time.Duration(n) * unit}, nil
}

// cronSpec is a parsed AWS six-field cron. Each field is the set of allowed values; dom/dow carry a
// "wildcard" flag (either "*" or "?") meaning the field does not constrain the match.
type cronSpec struct {
	min, hour, dom, month, dow, year map[int]bool
	domWild, dowWild                 bool
}

var monthNames = map[string]int{"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12}
var dowNames = map[string]int{"SUN": 1, "MON": 2, "TUE": 3, "WED": 4, "THU": 5, "FRI": 6, "SAT": 7}

func parseCron(body string) (*cronSpec, error) {
	f := strings.Fields(body)
	if len(f) != 6 {
		return nil, fmt.Errorf("AWS cron must have 6 fields (minute hour day-of-month month day-of-week year); got %d", len(f))
	}
	c := &cronSpec{}
	var err error
	if c.min, err = cronField(f[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if c.hour, err = cronField(f[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if f[2] == "?" {
		c.domWild = true
	} else if c.dom, err = cronField(f[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	if c.month, err = cronField(f[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if f[4] == "?" {
		c.dowWild = true
	} else if c.dow, err = cronField(f[4], 1, 7, dowNames); err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}
	if c.year, err = cronField(f[5], 1970, 2199, nil); err != nil {
		return nil, fmt.Errorf("year: %w", err)
	}
	// AWS requires exactly one of day-of-month / day-of-week to be "?" (you cannot constrain both, nor
	// leave both unconstrained with "*/*" — one must yield). "*" in one with a value in the other is fine.
	if !c.domWild && !c.dowWild && f[2] != "*" && f[4] != "*" {
		return nil, fmt.Errorf("cannot specify both day-of-month and day-of-week; set one to '?'")
	}
	if c.domWild && c.dowWild {
		return nil, fmt.Errorf("day-of-month and day-of-week cannot both be '?'")
	}
	return c, nil
}

// cronField parses one field into the set of matching ints. Supports *, a, a-b, a-b/step, */step, and
// comma lists, plus named values (months/days) when a names map is given.
func cronField(field string, min, max int, names map[string]int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(field, ",") {
		step := 1
		rng := part
		hasStep := false
		if i := strings.Index(part, "/"); i >= 0 {
			s, err := strconv.Atoi(part[i+1:])
			if err != nil || s < 1 {
				return nil, fmt.Errorf("bad step in %q", part)
			}
			step = s
			rng = part[:i]
			hasStep = true
		}
		lo, hi := min, max
		if rng == "*" {
			// full range with step
		} else if i := strings.Index(rng, "-"); i >= 0 {
			var err error
			if lo, err = cronNum(rng[:i], names); err != nil {
				return nil, err
			}
			if hi, err = cronNum(rng[i+1:], names); err != nil {
				return nil, err
			}
		} else {
			v, err := cronNum(rng, names)
			if err != nil {
				return nil, err
			}
			// "N" alone is a single value; "N/step" means N, N+step, ... up to the field max.
			lo = v
			if hasStep {
				hi = max
			} else {
				hi = v
			}
		}
		if lo < min || hi > max || lo > hi {
			return nil, fmt.Errorf("value %d-%d out of range %d-%d", lo, hi, min, max)
		}
		for v := lo; v <= hi; v += step {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty field %q", field)
	}
	return out, nil
}

func cronNum(s string, names map[string]int) (int, error) {
	s = strings.TrimSpace(s)
	if names != nil {
		if v, ok := names[strings.ToUpper(s)]; ok {
			return v, nil
		}
	}
	return strconv.Atoi(s)
}

// next returns the first minute strictly after `after` that matches the spec (UTC). Steps minute by
// minute, capped so an impossible expression (e.g. a past-only year) terminates rather than spins.
func (c *cronSpec) next(after time.Time) (time.Time, error) {
	t := after.UTC().Truncate(time.Minute).Add(time.Minute)
	const capMinutes = 6 * 366 * 24 * 60 // ~6 years
	for i := 0; i < capMinutes; i++ {
		if c.matches(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("cron expression has no next fire time within 6 years")
}

func (c *cronSpec) matches(t time.Time) bool {
	if !c.min[t.Minute()] || !c.hour[t.Hour()] || !c.month[int(t.Month())] || !c.year[t.Year()] {
		return false
	}
	// AWS day-of-week: 1=Sun..7=Sat; Go Weekday: 0=Sun..6=Sat.
	awsDow := int(t.Weekday()) + 1
	domOK := c.domWild || c.dom[t.Day()]
	dowOK := c.dowWild || c.dow[awsDow]
	return domOK && dowOK
}
