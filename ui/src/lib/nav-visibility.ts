/**
 * Who sees a navigation entry (the rail, the services launcher, the ⌘K palette, pins, recents).
 *
 * An entry can be gated two ways:
 *   - `flag`: a deployment switch in AppConfig (Chaos → chaosUiEnabled), so a non-essential or
 *     privileged surface stays hidden unless the install enables it — least functionality (NIST CM-7);
 *   - `requires`: a capability of the signed-in principal, as /api/auth/me reports it. `operator` is the
 *     platform's operator (IAM policy allows it the whole openinfra-operator:* surface), for whom the
 *     cluster views under Platform operations appear.
 *
 * Visibility is not authorization: every call a page makes is still authorized on its own. A capability
 * the session does not report is not held, so a gated entry stays hidden until the session says so.
 *
 * Kept free of runtime imports so `npm test` (node --test with type stripping) can load it directly.
 */

export type NavFlag = "chaosUiEnabled";
export type NavCapability = "operator";
export type NavCapabilities = Partial<Record<NavCapability, boolean>>;

/** The gates an entry may carry. */
export interface NavGate {
  flag?: NavFlag;
  requires?: NavCapability;
}

/** Whether an entry with these gates is shown for this config and these capabilities. */
export function navGateOpen(
  gate: NavGate,
  config: Partial<Record<NavFlag, unknown>>,
  caps: NavCapabilities = {},
): boolean {
  if (gate.flag && !config[gate.flag]) return false;
  if (gate.requires && caps[gate.requires] !== true) return false;
  return true;
}

/** A parent service's gates carried onto one of its sub-nav entries (the entry's own win). */
export function inheritGates<T extends NavGate>(child: T, parent: NavGate): T {
  const out: T = { ...child };
  if (!out.flag && parent.flag) out.flag = parent.flag;
  if (!out.requires && parent.requires) out.requires = parent.requires;
  return out;
}
