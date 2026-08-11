// The one RFC-1123 label rule for resource names — previously copy-pasted into ~10 create dialogs.
// Kubernetes object names must be a DNS-1123 label: lowercase alphanumerics and hyphens, starting
// and ending alphanumeric, ≤63 chars.
export const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Returns a human error string if the name is invalid, or null if it's fine (or empty/untouched). */
export function rfc1123Error(name: string): string | null {
  if (!name) return null;
  if (name.length > 63) return "Name must be 63 characters or fewer.";
  if (!RFC1123.test(name)) {
    return "Lowercase letters, numbers and hyphens; must start and end with a letter or number.";
  }
  return null;
}

export function isValidName(name: string): boolean {
  return name.length > 0 && name.length <= 63 && RFC1123.test(name);
}
