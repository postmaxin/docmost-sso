// Normalise the client address Fastify derives from X-Forwarded-For. Pure.

import { isIP } from 'node:net';

const IPV4_WITH_PORT = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/;
const BRACKETED_IPV6 = /^\[([^\]]+)\](?::\d{1,5})?$/;

/**
 * The address part of `raw`, or null. Accepts a bare IPv4/IPv6 address,
 * `a.b.c.d:port`, or `[ipv6]` / `[ipv6]:port`. AWS ALBs with
 * `routing.http.xff_client_port.enabled` append the client port to the
 * X-Forwarded-For entry they add, and that entry becomes `req.ip`.
 */
export function clientIp(raw: string | undefined): string | null {
  if (!raw) return null;
  if (isIP(raw)) return raw;
  const v4 = IPV4_WITH_PORT.exec(raw);
  if (v4 && isIP(v4[1]!) === 4) return v4[1]!;
  const v6 = BRACKETED_IPV6.exec(raw);
  if (v6 && isIP(v6[1]!) === 6) return v6[1]!;
  return null;
}
