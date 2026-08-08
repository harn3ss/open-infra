package awsscalars

import "testing"

// Tier-0 format validation: a declared AWS scalar rejects a clearly-malformed literal and accepts a
// plausibly-valid one. NOT AWS-byte-exact fidelity — that is a separate golden clock.
func TestAWSScalars_AcceptAndReject(t *testing.T) {
	v := Validators()
	cases := []struct {
		scalar string
		value  any
		ok     bool
	}{
		{"AWSDateTime", "2026-08-07T12:00:00Z", true},
		{"AWSDateTime", "2026-08-07T12:00:00-07:00", true},
		{"AWSDateTime", "not-a-date", false},
		{"AWSDateTime", 12345, false},
		{"AWSDate", "2026-08-07", true},
		{"AWSDate", "2026-13-99", false},
		{"AWSTime", "12:30:00", true},
		{"AWSTime", "99:99", false},
		{"AWSTimestamp", float64(1723032000), true},
		{"AWSTimestamp", 1.5, false},
		{"AWSEmail", "ada@example.com", true},
		{"AWSEmail", "not-an-email", false},
		{"AWSJSON", `{"a":1}`, true},
		{"AWSJSON", `{bad json`, false},
		{"AWSURL", "https://example.com/x", true},
		{"AWSURL", "notaurl", false},
		{"AWSPhone", "+1 (555) 123-4567", true},
		{"AWSPhone", "phone", false},
		{"AWSIPAddress", "192.168.1.1", true},
		{"AWSIPAddress", "10.0.0.0/8", true},
		{"AWSIPAddress", "999.1.1.1", false},
	}
	for _, c := range cases {
		fn, ok := v[c.scalar]
		if !ok {
			t.Fatalf("no validator for %s", c.scalar)
		}
		_, err := fn(c.value)
		if c.ok && err != nil {
			t.Errorf("%s(%v): expected accept, got error %v", c.scalar, c.value, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s(%v): expected reject, got accept", c.scalar, c.value)
		}
	}
}
