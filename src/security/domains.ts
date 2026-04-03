/**
 * Domain allowlist enforcement.
 * Deny-by-default: credentials are only injectable to explicitly listed domains.
 * Checks AFTER each navigation step to catch redirects.
 */

/**
 * Check if a URL's domain is in the allowlist.
 * Supports subdomain matching: allowlist entry "example.com" matches "sub.example.com".
 */
export function isDomainAllowed(url: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) return false;

  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }

  return allowedDomains.some((domain) => {
    const d = domain.toLowerCase();
    return hostname === d || hostname.endsWith(`.${d}`);
  });
}
