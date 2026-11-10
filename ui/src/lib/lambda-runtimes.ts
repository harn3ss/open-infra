/**
 * When AWS deprecates each Lambda runtime open-infra runs, keyed by its `kind: Function` spec.code.runtime
 * value (Lambda's identifier without ".x"), as cfn/lambda_runtimes.go has them (a Go test keeps the two
 * the same). From that date the Lambda console no longer creates a function on the runtime, so neither does
 * this console; the Lambda API and CloudFormation refuse later, from AWS's block-create date.
 */
export const LAMBDA_RUNTIME_DEPRECATION: Record<string, string> = {
  "nodejs16": "2024-06-12",
  "nodejs18": "2025-09-01",
  "nodejs20": "2026-04-30",
  "nodejs22": "2027-04-30",
  "nodejs24": "2028-04-30",
  "python3.8": "2024-10-14",
  "python3.9": "2025-12-15",
  "python3.10": "2026-10-31",
  "python3.11": "2027-06-30",
  "python3.12": "2028-10-31",
  "python3.13": "2029-06-30",
  "python3.14": "2029-06-30",
  "dotnet8": "2026-11-10",
  "dotnet10": "2028-11-14",
};

/** The spec.code.runtime values deprecated at `now`, which the create form offers disabled. */
export function deprecatedRuntimes(now: Date = new Date()): string[] {
  return Object.entries(LAMBDA_RUNTIME_DEPRECATION)
    .filter(([, day]) => now.getTime() >= Date.parse(day + "T00:00:00Z"))
    .map(([runtime]) => runtime)
    .sort();
}
