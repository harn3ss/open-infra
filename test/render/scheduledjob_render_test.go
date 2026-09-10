package render

import (
	"strings"
	"testing"
)

const scheduledjobCompositionPath = "../../platform/abstraction/scheduledjob-composition.yaml"

func scheduledjobCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"labels": map[string]any{
				"crossplane.io/claim-name":      "nightly-rollup",
				"crossplane.io/claim-namespace": "shop",
			},
		},
	}}}}
}

// A basic ScheduledJob renders a batch/v1 CronJob in the claim namespace with the container
// body and the run-policy knobs mapped onto the CronJob/Job spec.
func TestScheduledJob_RendersCronJob(t *testing.T) {
	tmpl := extractInlineTemplate(t, scheduledjobCompositionPath)
	out := render(t, tmpl, scheduledjobCtx(map[string]any{
		"schedule":          "0 2 * * *",
		"image":             "ghcr.io/x/rollup:latest",
		"command":           []any{"/bin/rollup"},
		"env":               []any{map[string]any{"name": "REGION", "value": "us"}},
		"secrets":           []any{"shop-db"},
		"retries":           int64(3),
		"timeout":           int64(3600),
		"concurrencyPolicy": "Forbid",
	}))
	for _, want := range []string{
		"kind: CronJob", "name: nightly-rollup-scheduled", "namespace: shop",
		`schedule: "0 2 * * *"`,
		"concurrencyPolicy: Forbid",
		"backoffLimit: 3",          // retries
		"activeDeadlineSeconds: 3600", // timeout
		"image: ghcr.io/x/rollup:latest",
		`command: ["/bin/rollup"]`,
		`{ name: "REGION", value: "us" }`,
		"secretRef: { name: \"shop-db\" }", // envFrom
		"cronJob: nightly-rollup-scheduled", // status
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ScheduledJob render missing %q; got:\n%s", want, grepCtx(out, "CronJob"))
		}
	}
	// A CPU job must NOT request a GPU or an nvidia runtime class.
	if strings.Contains(out, "nvidia.com/gpu") || strings.Contains(out, "runtimeClassName: nvidia") {
		t.Errorf("a CPU ScheduledJob must not request a GPU:\n%s", grepCtx(out, "resources"))
	}
}

// The AWS-style cron() sugar is normalized to a 5-field cron: the wrapper is stripped, the
// 6th (year) field dropped, and "?" mapped to "*".
func TestScheduledJob_NormalizesAwsCron(t *testing.T) {
	tmpl := extractInlineTemplate(t, scheduledjobCompositionPath)
	out := render(t, tmpl, scheduledjobCtx(map[string]any{
		"schedule": "cron(0 12 * * ? *)", "image": "x",
	}))
	if !strings.Contains(out, `schedule: "0 12 * * *"`) {
		t.Errorf("cron(0 12 * * ? *) must normalize to \"0 12 * * *\"; got:\n%s", grepCtx(out, "schedule"))
	}
}

// The AWS-style rate() sugar maps the evenly-dividing cases to a 5-field cron.
func TestScheduledJob_NormalizesAwsRate(t *testing.T) {
	tmpl := extractInlineTemplate(t, scheduledjobCompositionPath)
	cases := map[string]string{
		"rate(5 minutes)": `schedule: "*/5 * * * *"`,
		"rate(1 hour)":    `schedule: "0 */1 * * *"`,
		"rate(1 day)":     `schedule: "0 0 */1 * *"`,
	}
	for in, want := range cases {
		out := render(t, tmpl, scheduledjobCtx(map[string]any{"schedule": in, "image": "x"}))
		if !strings.Contains(out, want) {
			t.Errorf("%s must normalize to %q; got:\n%s", in, want, grepCtx(out, "schedule"))
		}
	}
}

// A GPU ScheduledJob requests the device and pins the nvidia runtime + gpu-tier affinity.
func TestScheduledJob_GpuRequestsDeviceAndAffinity(t *testing.T) {
	tmpl := extractInlineTemplate(t, scheduledjobCompositionPath)
	out := render(t, tmpl, scheduledjobCtx(map[string]any{
		"schedule": "0 * * * *", "image": "x", "gpu": int64(1), "gpuTier": "largegpu",
	}))
	for _, want := range []string{"runtimeClassName: nvidia", "nvidia.com/gpu: 1", "openinfra.dev/gpu-tier", "values: [large]"} {
		if !strings.Contains(out, want) {
			t.Errorf("GPU ScheduledJob missing %q; got:\n%s", want, grepCtx(out, "gpu"))
		}
	}
}

// timeZone + suspend + startingDeadline render onto the CronJob when set, and are absent otherwise.
func TestScheduledJob_OptionalCronKnobs(t *testing.T) {
	tmpl := extractInlineTemplate(t, scheduledjobCompositionPath)
	with := render(t, tmpl, scheduledjobCtx(map[string]any{
		"schedule": "0 * * * *", "image": "x",
		"timeZone": "America/New_York", "suspend": true, "startingDeadline": int64(120),
	}))
	for _, want := range []string{`timeZone: "America/New_York"`, "suspend: true", "startingDeadlineSeconds: 120"} {
		if !strings.Contains(with, want) {
			t.Errorf("optional knob %q missing when set; got:\n%s", want, grepCtx(with, "CronJob"))
		}
	}
	without := render(t, tmpl, scheduledjobCtx(map[string]any{"schedule": "0 * * * *", "image": "x"}))
	for _, absent := range []string{"timeZone:", "suspend: true", "startingDeadlineSeconds:"} {
		if strings.Contains(without, absent) {
			t.Errorf("optional knob %q must be absent when unset; got:\n%s", absent, grepCtx(without, "CronJob"))
		}
	}
}
