import type { WidgetProps } from "@rjsf/utils";

// Custom RJSF widgets for the schema-driven create form. Both are native combobox inputs
// (`<input list>` + `<datalist>`): the user can type any value OR pick from a dropdown of
// suggestions. A plain <input> is used (not the Input component) so it inherits the same
// `.oi-rjsf input` styling as every other field on the form.

/** Common cron presets offered under the schedule field (the user can still type any cron). */
const CRON_PRESETS: { value: string; label: string }[] = [
  { value: "*/5 * * * *", label: "Every 5 minutes" },
  { value: "*/15 * * * *", label: "Every 15 minutes" },
  { value: "*/30 * * * *", label: "Every 30 minutes" },
  { value: "0 * * * *", label: "Every hour" },
  { value: "0 */6 * * *", label: "Every 6 hours" },
  { value: "0 0 * * *", label: "Every day at midnight (UTC)" },
  { value: "0 2 * * *", label: "Every day at 02:00" },
  { value: "0 8 * * MON-FRI", label: "Weekdays at 08:00" },
  { value: "0 0 * * 0", label: "Every Sunday at midnight" },
  { value: "0 0 1 * *", label: "First of the month" },
  { value: "rate(1 hour)", label: "AWS rate() — hourly" },
  { value: "rate(1 day)", label: "AWS rate() — daily" },
];

function commonInputProps(props: WidgetProps) {
  const { id, value, required, disabled, readonly, onChange, onBlur, onFocus, placeholder } = props;
  return {
    id,
    type: "text",
    value: (value as string | undefined) ?? "",
    required,
    disabled: disabled || readonly,
    placeholder,
    autoComplete: "off",
    onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
      onChange(e.target.value === "" ? undefined : e.target.value),
    onBlur: (e: React.FocusEvent<HTMLInputElement>) => onBlur(id, e.target.value),
    onFocus: (e: React.FocusEvent<HTMLInputElement>) => onFocus(id, e.target.value),
  };
}

/** Cron schedule: free-text input + a datalist of common presets. */
export function CronScheduleWidget(props: WidgetProps) {
  const listId = `${props.id}-cron-presets`;
  return (
    <>
      <input list={listId} {...commonInputProps(props)} />
      <datalist id={listId}>
        {CRON_PRESETS.map((p) => (
          <option key={p.value} value={p.value} label={p.label} />
        ))}
      </datalist>
    </>
  );
}

// The full IANA time-zone list, resolved once at module load. Intl.supportedValuesOf is ES2023
// (widely supported); fall back to a short common list if the runtime lacks it.
const FALLBACK_TZ = [
  "UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
  "America/Sao_Paulo", "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
  "Asia/Dubai", "Asia/Kolkata", "Asia/Shanghai", "Asia/Tokyo", "Australia/Sydney",
];
const TZ_LIST: string[] = (() => {
  try {
    const svo = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf;
    const zones = svo?.("timeZone");
    if (zones && zones.length) return ["UTC", ...zones.filter((z) => z !== "UTC")];
  } catch {
    /* fall through */
  }
  return FALLBACK_TZ;
})();

/** Time zone: a searchable dropdown of valid IANA zones (type to filter, or pick). */
export function TimeZoneWidget(props: WidgetProps) {
  const listId = `${props.id}-tz-list`;
  return (
    <>
      <input list={listId} {...commonInputProps(props)} />
      <datalist id={listId}>
        {TZ_LIST.map((tz) => (
          <option key={tz} value={tz} />
        ))}
      </datalist>
    </>
  );
}

/** The custom-widget registry passed to the RJSF <Form>. Keyed by the `ui:widget` name. */
export const customWidgets = {
  cronSchedule: CronScheduleWidget,
  timezone: TimeZoneWidget,
};
