import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeProtectedHeader, jwtVerify } from 'jose';
import { authCookieAttributes, DOCMOST_JWT_ISSUER, signAccessToken } from '../../src/token.js';
import { parseDuration } from '../../src/config.js';
import { deriveFlowKey, openFlow, sealFlow } from '../../src/flow-cookie.js';

const secret = 'x'.repeat(40);

test('access JWT has exactly the Docmost payload shape', async () => {
  const now = new Date('2026-10-14T12:00:00Z');
  const ttl = parseDuration('7d');
  const token = await signAccessToken(
    { userId: 'u-1', email: 'a@example.com', workspaceId: 'w-1', sessionId: 's-1', now },
    secret,
    ttl,
  );
  assert.deepEqual(decodeProtectedHeader(token), { alg: 'HS256', typ: 'JWT' });
  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
    algorithms: ['HS256'],
    currentDate: now,
  });
  const iat = now.getTime() / 1000;
  assert.deepEqual(payload, {
    sub: 'u-1',
    email: 'a@example.com',
    workspaceId: 'w-1',
    type: 'access',
    sessionId: 's-1',
    iat,
    exp: iat + 7 * 24 * 3600,
    iss: DOCMOST_JWT_ISSUER,
  });
});

test('access JWT is rejected with another secret', async () => {
  const token = await signAccessToken(
    { userId: 'u', email: 'e@example.com', workspaceId: 'w', sessionId: 's' },
    secret,
    60_000,
  );
  await assert.rejects(jwtVerify(token, new TextEncoder().encode('y'.repeat(40))));
});

test('cookie attributes match Docmost setAuthCookie', () => {
  const expires = new Date('2026-10-21T12:00:00Z');
  assert.deepEqual(authCookieAttributes(new URL('https://docs.example.com'), expires), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: true,
    expires,
  });
  assert.equal(authCookieAttributes(new URL('http://localhost:3000'), expires).secure, false);
});

test('parseDuration matches ms for short forms and rejects bare numbers', () => {
  assert.equal(parseDuration('7d'), 604_800_000);
  assert.equal(parseDuration('90d'), 7_776_000_000);
  assert.equal(parseDuration('12h'), 43_200_000);
  assert.equal(parseDuration('30m'), 1_800_000);
  assert.equal(parseDuration('1y'), 31_557_600_000);
  for (const bad of ['7', '', 'seven days', '-1d', '0d', '7 days']) {
    assert.throws(() => parseDuration(bad), bad);
  }
});

test('flow cookie round-trips and rejects tampering / other keys', async () => {
  const key = deriveFlowKey(secret);
  const flow = { state: 's', nonce: 'n', codeVerifier: 'v', returnTo: '/home' };
  const sealed = await sealFlow(flow, key);
  assert.deepEqual(await openFlow(sealed, key), flow);
  assert.equal(await openFlow(sealed, deriveFlowKey('z'.repeat(40))), null);
  const parts = sealed.split('.');
  parts[3] = parts[3]!.slice(0, -2) + (parts[3]!.endsWith('AA') ? 'BB' : 'AA');
  assert.equal(await openFlow(parts.join('.'), key), null);
  assert.equal(await openFlow(undefined, key), null);
  assert.equal(await openFlow('garbage', key), null);
});
