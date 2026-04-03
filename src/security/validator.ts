/**
 * Input validation and sanitization.
 * Prevents injection via selectors and step values.
 */

const BLOCKED_SELECTOR_PATTERNS = [
  "javascript:",
  "onclick=",
  "<script",
  "data:",
  "vbscript:",
  "on(",
  "eval(",
  "expression(",
];

export function validateSelector(selector: string): { valid: boolean; reason?: string } {
  if (selector.length > 500) {
    return { valid: false, reason: "Selector exceeds 500 character limit" };
  }

  const lower = selector.toLowerCase();
  for (const pattern of BLOCKED_SELECTOR_PATTERNS) {
    if (lower.includes(pattern)) {
      return { valid: false, reason: `Selector contains blocked pattern: ${pattern}` };
    }
  }

  return { valid: true };
}

export function validateServiceName(name: string): { valid: boolean; reason?: string } {
  if (name.length > 100) {
    return { valid: false, reason: "Service name exceeds 100 character limit" };
  }

  // No shell metacharacters
  if (/[;&|`$(){}[\]<>!#~*?\\]/.test(name)) {
    return { valid: false, reason: "Service name contains shell metacharacters" };
  }

  return { valid: true };
}
