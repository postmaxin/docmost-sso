// Configuration, read once from the environment at start-up.

import { ANY_DOMAIN } from './claims.js';
import { checkPath, DEFAULT_RETURN_TO } from './return-to.js';

export interface Config {
  /** Public origin of Docmost and the shim, e.g. https://docs.example.com (no path). */
  appUrl: URL;
  /** Docmost's APP_SECRET: HS256 key for the access JWT. */
  appSecret: string;
  databaseUrl: string;
  oidcIssuer: string;
  oidcClientId: string;
  oidcClientSecret: string;
  /** Lower-cased email domains allowed to sign in. */
  allowedDomains: string[];
  /** Session/JWT/cookie lifetime in milliseconds; must equal Docmost's JWT_TOKEN_EXPIRES_IN. */
  sessionTtlMs: number;
  port: number;
  host: string;
  /**
   * Fastify trustProxy: comma-separated addresses/CIDRs/proxy-addr presets
   * whose X-Forwarded-For / -Proto entries are trusted, or true/false.
   */
  trustProxy: boolean | string;
  /** Development only: allow an http:// OIDC issuer (the integration test's mock). */
  oidcAllowInsecure: boolean;
  /** Label for the sign-in button. */
  providerName: string;
  /** Where people land after sign-in when no particular page was requested. */
  defaultReturnTo: string;
}

const UNIT_MS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
  // vercel/ms (used by Docmost and jsonwebtoken) defines a year as 365.25 days.
  y: 31_557_600_000,
};

/**
 * Parse a duration such as "7d", "12h" or "90d" the way the `ms` package does
 * for the short forms. Bare numbers are rejected: Docmost feeds the same value
 * to jsonwebtoken (where a number means seconds) and to `ms` (where it means
 * milliseconds), so a unit is the only unambiguous form.
 */
export function parseDuration(input: string): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w|y)\s*$/i.exec(input);
  if (!m) {
    throw new Error(`invalid duration "${input}" (use e.g. 7d, 12h, 30m)`);
  }
  const value = Number(m[1]) * UNIT_MS[m[2]!.toLowerCase()]!;
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`invalid duration "${input}"`);
  }
  return Math.round(value);
}

// Private-network peers (the ALB inside the VPC, Docker's bridge gateway, a
// local reverse proxy). The client IP is then the right-most X-Forwarded-For
// entry that is not itself a trusted proxy, so client-supplied entries are ignored.
export const DEFAULT_TRUST_PROXY = 'loopback,linklocal,uniquelocal';

function parseTrustProxy(v: string | undefined): boolean | string {
  if (v === undefined || v === '') return DEFAULT_TRUST_PROXY;
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^\d+$/.test(v)) {
    // Fastify fails closed on hop counts (it cannot validate the peer).
    throw new Error('TRUST_PROXY must be addresses/CIDRs/presets or true/false, not a hop count');
  }
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const missing: string[] = [];
  const req = (name: string): string => {
    const v = env[name];
    if (!v) missing.push(name);
    return v ?? '';
  };

  const appUrlRaw = req('APP_URL');
  const appSecret = req('APP_SECRET');
  const databaseUrl = req('DATABASE_URL');
  const oidcIssuer = req('OIDC_ISSUER');
  const oidcClientId = req('OIDC_CLIENT_ID');
  const oidcClientSecret = req('OIDC_CLIENT_SECRET');
  const domainsRaw = req('SSO_ALLOWED_DOMAINS');
  const ttlRaw = req('SESSION_TTL');
  if (missing.length) {
    throw new Error(`missing required environment: ${missing.join(', ')}`);
  }

  const parsed = new URL(appUrlRaw);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('APP_URL must be http(s)');
  }
  // Docmost uses only the origin of APP_URL; so do we.
  const appUrl = new URL(parsed.origin);

  if (appSecret.length < 32) {
    throw new Error('APP_SECRET must be at least 32 characters');
  }

  const allowedDomains = domainsRaw
    .split(',')
    .map((d) => d.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean);
  if (allowedDomains.length === 0) {
    throw new Error('SSO_ALLOWED_DOMAINS must list at least one domain');
  }
  if (allowedDomains.includes(ANY_DOMAIN) && allowedDomains.length > 1) {
    throw new Error(`SSO_ALLOWED_DOMAINS: '${ANY_DOMAIN}' allows every domain and must be the only entry`);
  }

  const port = Number(env.PORT ?? '8080');
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('PORT must be a valid port number');
  }

  const defaultReturnTo = env.SSO_DEFAULT_RETURN_TO || DEFAULT_RETURN_TO;
  if (checkPath(defaultReturnTo, appUrl) !== defaultReturnTo) {
    throw new Error('SSO_DEFAULT_RETURN_TO must be a same-origin path such as /s/general/p/home-abc123');
  }

  return {
    appUrl,
    appSecret,
    databaseUrl,
    oidcIssuer,
    oidcClientId,
    oidcClientSecret,
    allowedDomains,
    sessionTtlMs: parseDuration(ttlRaw),
    port,
    host: env.HOST ?? '0.0.0.0',
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    oidcAllowInsecure: env.OIDC_ALLOW_INSECURE_ISSUER === 'true',
    providerName: env.SSO_PROVIDER_NAME || 'Google',
    defaultReturnTo,
  };
}
