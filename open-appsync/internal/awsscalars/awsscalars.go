// Package awsscalars is the EDGE registration of AppSync's custom scalar validators for open-appsync's
// neutral validation seam (graphql.ScalarValidator). The engine core knows nothing about any vendor's
// scalars; this package supplies the AWS-specific rules and the server wires them in.
//
// TWO CLOCKS, do not conflate (per the graph-dependents handoff):
//   - Tier 0 (this package, GREEN now): best-effort *format* validation — a declared AWS scalar rejects a
//     clearly-malformed literal (AWSJSON that isn't valid JSON, AWSDateTime that isn't a datetime, …).
//     Unit-testable with no AWS. Lenient by design: it rejects the obviously-wrong, not the merely-
//     unusual, to avoid false negatives against inputs AWS would accept.
//   - Tier 1 (NOT claimed here): byte-exact fidelity to AppSync's own scalar coercion. That earns a
//     fidelity golden — the scoped-IAM-user capture dance, same as the runtime goldens — and graduates on
//     its own evidence, later. Nothing here asserts AppSync-exact behavior.
package awsscalars

import (
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
)

// Validators returns the AWS custom-scalar validators keyed by scalar name, for
// graphql.WithScalarValidators. Only scalars a schema actually declares are ever consulted.
func Validators() map[string]graphql.ScalarValidator {
	return map[string]graphql.ScalarValidator{
		"AWSDateTime":  validateDateTime,
		"AWSDate":      validateDate,
		"AWSTime":      validateTime,
		"AWSTimestamp": validateTimestamp,
		"AWSEmail":     validateEmail,
		"AWSJSON":      validateJSON,
		"AWSURL":       validateURL,
		"AWSPhone":     validatePhone,
		"AWSIPAddress": validateIPAddress,
	}
}

func asString(v any, scalar string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a String, got %T", scalar, v)
	}
	return s, nil
}

// validateDateTime accepts an ISO-8601 / RFC3339 datetime with a time-zone offset (what AWSDateTime uses).
func validateDateTime(v any) (any, error) {
	s, err := asString(v, "AWSDateTime")
	if err != nil {
		return nil, err
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, s); err2 != nil {
			return nil, fmt.Errorf("not an ISO-8601 datetime with offset (e.g. 2006-01-02T15:04:05Z)")
		}
	}
	return s, nil
}

func validateDate(v any) (any, error) {
	s, err := asString(v, "AWSDate")
	if err != nil {
		return nil, err
	}
	// The date, optionally followed by a timezone offset (AWSDate allows a trailing offset).
	base := s
	if i := strings.IndexAny(s, "Z+"); i > 0 {
		base = s[:i]
	} else if i := strings.LastIndex(s, "-"); i > 7 { // offset '-' after the YYYY-MM-DD dashes
		base = s[:i]
	}
	if _, err := time.Parse("2006-01-02", base); err != nil {
		return nil, fmt.Errorf("not an ISO-8601 date (YYYY-MM-DD)")
	}
	return s, nil
}

func validateTime(v any) (any, error) {
	s, err := asString(v, "AWSTime")
	if err != nil {
		return nil, err
	}
	base := s
	if i := strings.IndexAny(s, "Z+"); i >= 0 {
		base = s[:i]
	} else if i := strings.LastIndex(s, "-"); i >= 0 {
		base = s[:i]
	}
	for _, layout := range []string{"15:04:05.999999999", "15:04:05", "15:04"} {
		if _, err := time.Parse(layout, base); err == nil {
			return s, nil
		}
	}
	return nil, fmt.Errorf("not an ISO-8601 time (hh:mm:ss)")
}

// validateTimestamp accepts an integer number of seconds (AWSTimestamp is a Unix epoch integer).
func validateTimestamp(v any) (any, error) {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return n, nil
		}
	case int, int64:
		return v, nil
	}
	return nil, fmt.Errorf("AWSTimestamp must be an integer number of seconds")
}

func validateEmail(v any) (any, error) {
	s, err := asString(v, "AWSEmail")
	if err != nil {
		return nil, err
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || !strings.Contains(s, "@") {
		return nil, fmt.Errorf("not a valid email address")
	}
	return s, nil
}

// validateJSON accepts any non-string JSON value as-is, or a string that is itself well-formed JSON
// (AWSJSON is a JSON document, commonly carried as a JSON string).
func validateJSON(v any) (any, error) {
	if s, ok := v.(string); ok {
		if !json.Valid([]byte(s)) {
			return nil, fmt.Errorf("AWSJSON string is not well-formed JSON")
		}
	}
	return v, nil
}

func validateURL(v any) (any, error) {
	s, err := asString(v, "AWSURL")
	if err != nil {
		return nil, err
	}
	u, err := url.ParseRequestURI(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("not an absolute URL (scheme://host)")
	}
	return s, nil
}

var phoneRe = regexp.MustCompile(`^\+?[0-9 ()\-.]{5,}$`)

func validatePhone(v any) (any, error) {
	s, err := asString(v, "AWSPhone")
	if err != nil {
		return nil, err
	}
	if !phoneRe.MatchString(s) {
		return nil, fmt.Errorf("not a valid phone number")
	}
	return s, nil
}

func validateIPAddress(v any) (any, error) {
	s, err := asString(v, "AWSIPAddress")
	if err != nil {
		return nil, err
	}
	// Accept a bare IP or CIDR (AWSIPAddress permits either).
	if net.ParseIP(s) == nil {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return nil, fmt.Errorf("not a valid IPv4/IPv6 address or CIDR")
		}
	}
	return s, nil
}
