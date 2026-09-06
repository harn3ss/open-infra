import { type ReactNode } from "react";
import { ArrowLeft, ArrowRight, Check, Rocket } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Spinner } from "@/components/common/states";
import { InfoLink } from "@/components/help/info-link";
import { KeyValuePairs, type KeyValuePair } from "@/components/common/key-value-pairs";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

/** One step in a {@link Wizard}. Its `content` is any form body you supply. */
export interface WizardStep {
  /** Short step title shown in the left navigator and step header. */
  title: string;
  /** Optional sub-text under the step header. */
  description?: string;
  /** The step's body (form fields, or a {@link WizardReview} on the last step). */
  content: ReactNode;
  /** Optional Info link opening the help panel from the step header. */
  info?: { title: string; body: ReactNode; docsHref?: string };
  /** Marks the step "optional" in the navigator. */
  isOptional?: boolean;
}

/**
 * The AWS/Cloudscape multi-step create `Wizard`: a left step navigator (numbered,
 * with complete/current/upcoming states) beside one content section per step, a
 * Cancel/Previous/Next footer that becomes `Create <Kind>` on the last (Review)
 * step, and an optional live side preview pane (as the "VPC and more" flow needs).
 *
 * Controlled like Cloudscape's Wizard: you own `activeStepIndex` and handle
 * `onNavigate`. Per the spec the primary is never disabled for validity — return
 * `false` from `onValidateStep` to block a forward move and show inline errors.
 *
 * @example
 * const [step, setStep] = useState(0);
 * <Wizard
 *   title="Create VPC"
 *   steps={steps}
 *   activeStepIndex={step}
 *   onNavigate={setStep}
 *   onValidateStep={(i) => validate(i)}
 *   onCancel={() => nav({ to: "/vpcs" })}
 *   onSubmit={create}
 *   submitLabel="Create VPC"
 *   submitting={mutation.isPending}
 *   preview={<VpcPreview draft={draft} />}
 * />
 */
export function Wizard({
  title,
  steps,
  activeStepIndex,
  onNavigate,
  onCancel,
  onSubmit,
  submitLabel,
  submitting = false,
  onValidateStep,
  error,
  preview,
  cancelLabel = "Cancel",
  /** Allow clicking not-yet-reached steps in the navigator. Default false. */
  allowSkipAhead = false,
}: {
  title: string;
  steps: WizardStep[];
  activeStepIndex: number;
  /** Requested move to a step index (nav click, Previous, or a validated Next). */
  onNavigate: (index: number) => void;
  onCancel: () => void;
  onSubmit: () => void;
  submitLabel: string;
  submitting?: boolean;
  /** Validate a step before advancing past it; return false to block. */
  onValidateStep?: (index: number) => boolean;
  error?: unknown;
  /** Live side preview pane rendered right of the step content. */
  preview?: ReactNode;
  cancelLabel?: string;
  allowSkipAhead?: boolean;
}) {
  const active = Math.min(Math.max(0, activeStepIndex), steps.length - 1);
  const step = steps[active];
  const isLast = active === steps.length - 1;

  if (!step) return null;

  const goTo = (i: number) => {
    if (submitting || i === active) return;
    if (i > active && onValidateStep && !onValidateStep(active)) return;
    onNavigate(i);
  };
  const next = () => {
    if (submitting) return;
    if (onValidateStep && !onValidateStep(active)) return;
    onNavigate(active + 1);
  };
  const previous = () => {
    if (submitting) return;
    onNavigate(active - 1);
  };

  return (
    <div className="space-y-6 pb-8">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[220px_minmax(0,1fr)]">
        {/* Left step navigator */}
        <nav aria-label="Steps" className="lg:pt-2">
          <ol className="space-y-1">
            {steps.map((s, i) => {
              const state =
                i < active ? "complete" : i === active ? "current" : "upcoming";
              const clickable =
                state === "complete" || (allowSkipAhead && state === "upcoming");
              return (
                <li key={i}>
                  <button
                    type="button"
                    onClick={() => goTo(i)}
                    disabled={!clickable && state !== "current"}
                    aria-current={state === "current" ? "step" : undefined}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-sm transition-colors",
                      state === "current" && "bg-secondary font-medium",
                      clickable && "hover:bg-secondary",
                      !clickable && state === "upcoming" && "cursor-default",
                    )}
                  >
                    <span
                      className={cn(
                        "flex size-6 shrink-0 items-center justify-center rounded-full border text-xs",
                        state === "complete" &&
                          "border-primary bg-primary text-primary-foreground",
                        state === "current" &&
                          "border-primary text-primary",
                        state === "upcoming" &&
                          "border-border text-muted-foreground",
                      )}
                    >
                      {state === "complete" ? (
                        <Check className="size-3.5" />
                      ) : (
                        i + 1
                      )}
                    </span>
                    <span className="min-w-0">
                      <span
                        className={cn(
                          "block truncate",
                          state === "upcoming" && "text-muted-foreground",
                        )}
                      >
                        {s.title}
                      </span>
                      {s.isOptional ? (
                        <span className="block text-xs text-muted-foreground">
                          optional
                        </span>
                      ) : null}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </nav>

        {/* Step content (+ optional preview) */}
        <div className="min-w-0 space-y-4">
          <div
            className={cn(
              "grid grid-cols-1 gap-6",
              preview && "xl:grid-cols-[minmax(0,1fr)_320px]",
            )}
          >
            <div className="min-w-0 space-y-4">
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Step {active + 1} of {steps.length}
                </p>
                <h2 className="flex items-center gap-2 text-lg font-semibold">
                  {step.title}
                  {step.info ? <InfoLink {...step.info} /> : null}
                </h2>
                {step.description ? (
                  <p className="mt-0.5 text-sm text-muted-foreground">
                    {step.description}
                  </p>
                ) : null}
              </div>

              <Card>
                <CardContent className="space-y-5 p-5">{step.content}</CardContent>
              </Card>

              {error ? (
                <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                  {error instanceof ApiError
                    ? error.message
                    : "Failed to create the resource."}
                </div>
              ) : null}
            </div>

            {preview ? (
              <aside className="min-w-0 xl:sticky xl:top-4 xl:self-start">
                {preview}
              </aside>
            ) : null}
          </div>

          {/* Footer nav */}
          <div className="flex items-center justify-between gap-3 border-t border-border pt-4">
            <Button
              variant="ghost"
              onClick={onCancel}
              disabled={submitting}
              className="text-muted-foreground"
            >
              {cancelLabel}
            </Button>
            <div className="flex items-center gap-3">
              {active > 0 ? (
                <Button
                  variant="outline"
                  onClick={previous}
                  disabled={submitting}
                >
                  <ArrowLeft className="size-4" /> Previous
                </Button>
              ) : null}
              {isLast ? (
                <Button onClick={onSubmit} disabled={submitting}>
                  {submitting ? (
                    <Spinner className="text-current" />
                  ) : (
                    <Rocket className="size-4" />
                  )}
                  {submitLabel}
                </Button>
              ) : (
                <Button onClick={next} disabled={submitting}>
                  Next <ArrowRight className="size-4" />
                </Button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/** One grouped section on the {@link WizardReview} page. */
export interface WizardReviewSection {
  /** Section title — keep identical to its step's title (Cloudscape rule). */
  title: string;
  /** The step index this section summarizes; its "Edit" link jumps back here. */
  stepIndex: number;
  /** Attribute pairs, or arbitrary content, summarizing that step's inputs. */
  pairs?: KeyValuePair[];
  content?: ReactNode;
  /** Columns for the pairs grid. Default 2. */
  columns?: 1 | 2 | 3 | 4;
}

/**
 * The Wizard's final Review step: a read-only summary of every step, grouped and
 * ordered identically to the steps, each with an "Edit" link back to its step.
 * Drop it in as the last step's `content`.
 *
 * @example
 * { title: "Review and create", content: (
 *     <WizardReview onEditStep={setStep} sections={[
 *       { title: "VPC settings", stepIndex: 0, pairs: [{ label: "Name", value: name }] },
 *       { title: "Subnets", stepIndex: 1, pairs: [{ label: "Count", value: String(subnets.length) }] },
 *     ]} />
 *   ) }
 */
export function WizardReview({
  sections,
  onEditStep,
}: {
  sections: WizardReviewSection[];
  onEditStep: (stepIndex: number) => void;
}) {
  return (
    <div className="space-y-4">
      {sections.map((section, i) => (
        <div key={i} className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-semibold">{section.title}</h3>
            <Button
              variant="link"
              size="sm"
              className="h-auto p-0"
              onClick={() => onEditStep(section.stepIndex)}
            >
              Edit
            </Button>
          </div>
          {section.pairs ? (
            <KeyValuePairs
              items={section.pairs}
              columns={section.columns ?? 2}
            />
          ) : null}
          {section.content}
          {i < sections.length - 1 ? (
            <div className="border-t border-border" />
          ) : null}
        </div>
      ))}
    </div>
  );
}
