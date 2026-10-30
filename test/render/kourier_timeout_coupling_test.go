package render

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// The request-timeout ceiling is enforced in THREE independent places that must agree, or a tenant can
// declare a timeout the data path silently will not deliver:
//
//  1. the shared Kourier gateway's Envoy stream-idle-timeout (config.kourier in knative-serving.yaml) —
//     an IDLE timeout that cuts any request producing no bytes for that long, regardless of anything the
//     revision says. Left unset it falls back to Envoy's 300s default and cuts quiet requests at 300s;
//  2. config-defaults max-revision-timeout-seconds (also knative-serving.yaml) — the per-request budget
//     the platform admits, and the Knative webhook's hard cap on a revision's spec.timeoutSeconds;
//  3. the kind: Function XRD `timeout` field maximum — the ceiling a tenant's claim may declare.
//
// The failure this guards: the gateway idle (1) was left at its 300s default while (2) and (3) were
// raised to 900. A claim could declare timeout:900, have it admitted, and still be cut at exactly 300s
// by the gateway — invisibly, because every value the tenant can see said 900. The fix set the gateway
// idle ABOVE the 900s ceiling. This test keeps the invariant from regressing:
//
//   - the gateway stream-idle-timeout MUST be present (absent ⇒ the 300s-default bug), and
//   - it MUST be >= max-revision-timeout-seconds (so the gateway never undercuts the promised budget), and
//   - the XRD `timeout` maximum MUST equal max-revision-timeout-seconds (claim ceiling == revision ceiling,
//     so a claim can never declare more than the revision — and thus the gateway — will honour).
//
// Bump any one of the three without the others and this goes red, blocking the image builds (needs: test).
func TestKourierTimeoutCeilingsAgree(t *testing.T) {
	serving := mustRead(t, "../../platform/serverless/knative-serving.yaml")
	xrd := mustRead(t, "../../platform/abstraction/function-xrd.yaml")

	// (1) gateway Envoy stream-idle-timeout — a duration string (e.g. "960s"). Anchored to a non-comment
	// line (^\s*key:) so the prose in the surrounding comment block never matches.
	streamIdle, ok := matchDurationSeconds(serving, `(?m)^\s*stream-idle-timeout:\s*"?([0-9][0-9a-z.]*)"?`)
	if !ok {
		t.Fatalf("stream-idle-timeout is not set under config.kourier in knative-serving.yaml — the gateway " +
			"then falls back to Envoy's 300s default and silently cuts any quiet request at 300s, whatever " +
			"the revision timeout says (the #336 bug). It must be set, and >= max-revision-timeout-seconds.")
	}

	// (2) max-revision-timeout-seconds — a plain integer-seconds string ("900"), likewise non-comment.
	maxRev, ok := matchInt(serving, `(?m)^\s*max-revision-timeout-seconds:\s*"?([0-9]+)"?`)
	if !ok {
		t.Fatal("max-revision-timeout-seconds not found in knative-serving.yaml config.defaults")
	}

	// (3) XRD `timeout` field maximum — the inline schema map on one line.
	xrdMax, ok := matchInt(xrd, `timeout:\s*\{[^}]*maximum:\s*([0-9]+)`)
	if !ok {
		t.Fatal("could not find the `timeout` field maximum in function-xrd.yaml")
	}

	if streamIdle < maxRev {
		t.Errorf("gateway stream-idle-timeout (%ds) < max-revision-timeout-seconds (%ds): the gateway will "+
			"cut a quiet request BEFORE its admitted budget, so a claim's declared timeout is silently "+
			"under-served. Set stream-idle-timeout >= %ds.", streamIdle, maxRev, maxRev)
	}
	if xrdMax != maxRev {
		t.Errorf("XRD timeout maximum (%d) != max-revision-timeout-seconds (%d): a claim could declare a "+
			"timeout the revision cap rejects at admission, or (if XRD max is lower) the platform silently "+
			"under-advertises the budget it honours. Keep them equal.", xrdMax, maxRev)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// matchInt returns the first capture group of re in s as an int.
func matchInt(s, re string) (int, bool) {
	m := regexp.MustCompile(re).FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// matchDurationSeconds returns re's first capture (a duration token like "960s", or a bare integer read
// as seconds) in whole seconds.
func matchDurationSeconds(s, re string) (int, bool) {
	m := regexp.MustCompile(re).FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	if d, err := time.ParseDuration(m[1]); err == nil {
		return int(d.Seconds()), true
	}
	if n, err := strconv.Atoi(m[1]); err == nil {
		return n, true
	}
	return 0, false
}
