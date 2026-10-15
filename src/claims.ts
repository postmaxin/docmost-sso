// Admission checks on validated ID-token claims. Pure functions, no I/O.

export const GOOGLE_ISSUER = 'https://accounts.google.com';

/**
 * `SSO_ALLOWED_DOMAINS=*`: admit any domain. For an IdP that already decides
 * who may sign in (group-bound applications, say), where a domain list would
 * only repeat that decision. It must be the only entry.
 */
export const ANY_DOMAIN = '*';

export function allowsAnyDomain(allowedDomains: readonly string[]): boolean {
  return allowedDomains.length === 1 && allowedDomains[0] === ANY_DOMAIN;
}

export type Admission =
  | { ok: true; email: string; name: string | undefined }
  | { ok: false; reason: RefusalReason; email?: string };

export type RefusalReason =
  | 'missing_email'
  | 'email_not_verified'
  | 'domain_not_allowed'
  | 'hd_mismatch';

export interface IdClaims {
  iss: string;
  email?: unknown;
  email_verified?: unknown;
  hd?: unknown;
  name?: unknown;
  [k: string]: unknown;
}

// Deliberately strict: one @, no whitespace or control characters, a dotted domain.
const EMAIL_RE = /^[^\s@\p{Cc}]+@([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)$/u;

export function checkClaims(claims: IdClaims, allowedDomains: readonly string[]): Admission {
  if (typeof claims.email !== 'string' || claims.email.length === 0) {
    return { ok: false, reason: 'missing_email' };
  }
  const email = claims.email.toLowerCase();
  const m = EMAIL_RE.exec(email);
  if (!m || email.length > 254) {
    return { ok: false, reason: 'missing_email' };
  }

  // Only a JSON boolean true counts; a missing claim or the string "true" is refused.
  if (claims.email_verified !== true) {
    return { ok: false, reason: 'email_not_verified', email };
  }

  const domain = m[1]!;
  const anyDomain = allowsAnyDomain(allowedDomains);
  if (!anyDomain && !allowedDomains.includes(domain)) {
    return { ok: false, reason: 'domain_not_allowed', email };
  }

  // Google: `hd` is the Workspace domain the account belongs to. A consumer
  // account can carry a Workspace-domain address as a secondary email; only
  // `hd` proves the account is managed by that Workspace. With any domain
  // allowed there is no Workspace to prove, and consumer accounts have no hd.
  const isGoogle = claims.iss === GOOGLE_ISSUER || claims.iss === 'accounts.google.com';
  if (!anyDomain && (isGoogle || claims.hd !== undefined)) {
    if (typeof claims.hd !== 'string' || !allowedDomains.includes(claims.hd.toLowerCase())) {
      return { ok: false, reason: 'hd_mismatch', email };
    }
  }

  const name =
    typeof claims.name === 'string' && claims.name.trim() ? sanitiseName(claims.name) : undefined;
  return { ok: true, email, name };
}

/** Docmost limits names to 50 chars on its own forms; strip control characters. */
export function sanitiseName(name: string): string {
  return name.replace(/\p{Cc}/gu, '').trim().slice(0, 50);
}

export function refusalMessage(reason: RefusalReason, allowedDomains: readonly string[]): string {
  const domains = allowedDomains.map((d) => `@${d}`).join(' or ');
  switch (reason) {
    case 'missing_email':
      return 'Your identity provider did not supply an email address.';
    case 'email_not_verified':
      return 'Your email address is not verified with your identity provider.';
    case 'domain_not_allowed':
    case 'hd_mismatch':
      // Unreachable with any domain allowed, but never print "Only @* accounts".
      if (allowsAnyDomain(allowedDomains)) return 'This account cannot sign in here.';
      return `Only ${domains} accounts can sign in here.`;
  }
}
