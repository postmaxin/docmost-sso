// Validation of the post-sign-in redirect target. Pure, no I/O.

export const DEFAULT_RETURN_TO = '/home';

/**
 * Return a safe same-origin path (path + query + fragment) for `candidate`,
 * or `fallback`. Only relative paths beginning with a single "/" are
 * accepted; absolute URLs, scheme-relative ("//host") and backslash tricks
 * ("/\host") are rejected even when they would resolve to our own origin.
 *
 * A bare "/" or "/home" also yields `fallback`: Docmost's client sends
 * `?redirect=/home` for any signed-out visit to the root, which names no
 * particular page, so people land on the configured front page instead.
 */
export function safeReturnTo(candidate: unknown, appUrl: URL, fallback: string = DEFAULT_RETURN_TO): string {
  const checked = checkPath(candidate, appUrl);
  if (checked === null) return fallback;
  if (checked === '/' || checked === '/home' || checked === '/home/') return fallback;
  return checked;
}

/** The normalised same-origin path for `candidate`, or null if it is unsafe. */
export function checkPath(candidate: unknown, appUrl: URL): string | null {
  if (typeof candidate !== 'string') return null;
  if (candidate.length === 0 || candidate.length > 2048) return null;
  if (!candidate.startsWith('/')) return null;
  if (candidate.startsWith('//')) return null;
  // Browsers treat "\" like "/" in special URLs; any control char/whitespace is suspect.
  if (/[\\\s\p{Cc}]/u.test(candidate)) return null;

  let resolved: URL;
  try {
    resolved = new URL(candidate, appUrl);
  } catch {
    return null;
  }
  if (resolved.origin !== appUrl.origin) return null;

  // Never bounce back into the sign-in machinery (loops) or to Docmost's login.
  const p = resolved.pathname;
  if (p === '/sso' || p.startsWith('/sso/') || p === '/login' || p.startsWith('/login/')) {
    return null;
  }
  return resolved.pathname + resolved.search + resolved.hash;
}
