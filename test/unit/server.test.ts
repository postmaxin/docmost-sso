import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jwtVerify } from 'jose';
import { loadConfig } from '../../src/config.js';
import { RefusedError, type SignInInput, type SignInResult } from '../../src/docmost.js';
import type { FlowState } from '../../src/flow-cookie.js';
import type { IdClaims } from '../../src/claims.js';
import { buildApp, type Deps } from '../../src/server.js';

const SECRET = 's'.repeat(48);

function setup(over: { claims?: IdClaims; signIn?: (i: SignInInput) => Promise<SignInResult>; schemaOk?: boolean } = {}) {
  const config = loadConfig({
    APP_URL: 'https://docs.example.com/',
    APP_SECRET: SECRET,
    DATABASE_URL: 'postgres://x@localhost/x',
    OIDC_ISSUER: 'https://accounts.google.com',
    OIDC_CLIENT_ID: 'cid',
    OIDC_CLIENT_SECRET: 'csecret',
    SSO_ALLOWED_DOMAINS: 'example.com',
    SESSION_TTL: '7d',
  });
  const logs: Record<string, unknown>[] = [];
  const signIns: SignInInput[] = [];
  let lastFlow: FlowState | undefined;
  const deps: Deps = {
    config,
    oidc: {
      async begin(returnTo) {
        lastFlow = { state: 'st', nonce: 'no', codeVerifier: 'cv', returnTo };
        return { url: new URL('https://idp.example/auth?state=st'), flow: lastFlow };
      },
      async complete(url, flow) {
        assert.equal(url.origin + url.pathname, 'https://docs.example.com/sso/callback');
        assert.equal(flow.state, 'st');
        return (
          over.claims ?? { iss: 'https://accounts.google.com', email: 'Bob@example.com', email_verified: true, hd: 'example.com', name: 'Bob' }
        );
      },
    },
    db: {
      async signIn(input) {
        signIns.push(input);
        if (over.signIn) return over.signIn(input);
        return {
          userId: 'u-1',
          email: input.email,
          workspaceId: 'w-1',
          sessionId: 'sess-1',
          expiresAt: new Date(Date.now() + config.sessionTtlMs),
          created: true,
        };
      },
      async checkSchema() {
        return over.schemaOk === false
          ? { ok: false, migration: '29990101T000000-future', error: 'unsupported Docmost schema version' }
          : { ok: true, migration: '20260904T171920-public-spaces' };
      },
    },
    log: (e) => logs.push(e),
  };
  return { app: buildApp(deps), logs, signIns, config };
}

function cookiesOf(res: { headers: Record<string, unknown> }): string[] {
  const h = res.headers['set-cookie'];
  return Array.isArray(h) ? h : h ? [String(h)] : [];
}

async function startFlow(app: ReturnType<typeof setup>['app'], query = '') {
  const res = await app.inject({ method: 'GET', url: `/sso/start${query}` });
  assert.equal(res.statusCode, 302);
  const flowCookie = cookiesOf(res).find((c) => c.startsWith('docmost_sso_flow='))!;
  assert.ok(flowCookie);
  assert.match(flowCookie, /HttpOnly/);
  assert.match(flowCookie, /Secure/);
  assert.match(flowCookie, /SameSite=Lax/);
  assert.match(flowCookie, /Path=\/sso\//);
  return flowCookie.split(';')[0]!;
}

test('login page shows a button and does not auto-redirect', async () => {
  const { app } = setup();
  const res = await app.inject({ method: 'GET', url: '/sso/login?redirect=/s/x' });
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /Sign in with Google/);
  assert.match(res.body, /href="\/sso\/start\?redirect=%2Fs%2Fx"/);
  const auto = await app.inject({ method: 'GET', url: '/sso/login?auto=1' });
  assert.equal(auto.statusCode, 302);
  assert.equal(auto.headers.location, '/sso/start');
});

test('callback: success sets the Docmost auth cookie and redirects to returnTo', async () => {
  const { app, logs, signIns } = setup();
  const flow = await startFlow(app, '?redirect=/s/general');
  const res = await app.inject({
    method: 'GET',
    url: '/sso/callback?code=c&state=st',
    headers: { cookie: flow, 'x-forwarded-for': '6.6.6.6, 203.0.113.9', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0 Safari/537.36' },
    remoteAddress: '10.0.0.5',
  });
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.location, '/s/general');
  const auth = cookiesOf(res).find((c) => c.startsWith('authToken='))!;
  assert.ok(auth);
  const attrs = auth.split('; ').slice(1).sort();
  assert.equal(attrs.length, 5);
  assert.ok(attrs.some((a) => /^Expires=/.test(a)));
  assert.deepEqual(attrs.filter((a) => !a.startsWith('Expires=')), ['HttpOnly', 'Path=/', 'SameSite=Lax', 'Secure']);
  const token = auth.split(';')[0]!.slice('authToken='.length);
  const { payload } = await jwtVerify(token, new TextEncoder().encode(SECRET), { issuer: 'Docmost' });
  assert.equal(payload.sub, 'u-1');
  assert.equal(payload.sessionId, 'sess-1');
  assert.equal(payload.type, 'access');
  // Flow cookie cleared.
  assert.ok(cookiesOf(res).some((c) => /^docmost_sso_flow=;/.test(c)));
  assert.equal(signIns[0]!.email, 'bob@example.com');
  // Right-most untrusted hop: a client-supplied left entry (6.6.6.6) is ignored.
  assert.equal(signIns[0]!.ipAddress, '203.0.113.9');
  assert.equal(signIns[0]!.deviceName, 'Chrome on macOS');
  const line = logs.find((l) => l.event === 'signin')!;
  assert.equal(line.outcome, 'success');
  assert.ok(!JSON.stringify(logs).includes(token), 'token must not be logged');
});

test('callback: wrong domain is refused with a plain page, no session', async () => {
  const { app, signIns, logs } = setup({
    claims: { iss: 'https://accounts.google.com', email: 'eve@gmail.com', email_verified: true },
  });
  const flow = await startFlow(app);
  const res = await app.inject({ method: 'GET', url: '/sso/callback?code=c&state=st', headers: { cookie: flow } });
  assert.equal(res.statusCode, 403);
  assert.match(res.body, /Only @example\.com accounts can sign in here\./);
  assert.ok(!cookiesOf(res).some((c) => c.startsWith('authToken=')));
  assert.equal(signIns.length, 0);
  assert.equal(logs.at(-1)!.reason, 'domain_not_allowed');
});

test('callback: missing flow cookie is refused before any token exchange', async () => {
  const { app } = setup();
  const res = await app.inject({ method: 'GET', url: '/sso/callback?code=c&state=st' });
  assert.equal(res.statusCode, 400);
  assert.ok(!cookiesOf(res).some((c) => c.startsWith('authToken=')));
});

test('callback: deactivated user is refused', async () => {
  const { app } = setup({ signIn: async () => { throw new RefusedError('account_disabled', 'u-9'); } });
  const flow = await startFlow(app);
  const res = await app.inject({ method: 'GET', url: '/sso/callback?code=c&state=st', headers: { cookie: flow } });
  assert.equal(res.statusCode, 403);
  assert.match(res.body, /deactivated/);
  assert.ok(!cookiesOf(res).some((c) => c.startsWith('authToken=')));
});

test('unsupported schema: healthz 503 and sign-in refused', async () => {
  const { app } = setup({ schemaOk: false });
  const h = await app.inject({ method: 'GET', url: '/sso/healthz' });
  assert.equal(h.statusCode, 503);
  const s = await app.inject({ method: 'GET', url: '/sso/start' });
  assert.equal(s.statusCode, 503);
});

test('errors never leak stack traces', async () => {
  const { app } = setup({ signIn: async () => { throw new Error('boom at /secret/path.ts:1'); } });
  const flow = await startFlow(app);
  const res = await app.inject({ method: 'GET', url: '/sso/callback?code=c&state=st', headers: { cookie: flow } });
  assert.equal(res.statusCode, 503);
  assert.ok(!res.body.includes('boom'));
});

const BASE_ENV = {
  APP_URL: 'https://docs.example.com/',
  APP_SECRET: SECRET,
  DATABASE_URL: 'postgres://x@localhost/x',
  OIDC_ISSUER: 'https://accounts.google.com',
  OIDC_CLIENT_ID: 'cid',
  OIDC_CLIENT_SECRET: 'csecret',
  SSO_ALLOWED_DOMAINS: 'example.com',
  SESSION_TTL: '7d',
};

test('SSO_DEFAULT_RETURN_TO sets the landing page and defaults to /home', () => {
  assert.equal(loadConfig(BASE_ENV).defaultReturnTo, '/home');
  assert.equal(
    loadConfig({ ...BASE_ENV, SSO_DEFAULT_RETURN_TO: '/s/general/p/home-iQE6WFhsm6' }).defaultReturnTo,
    '/s/general/p/home-iQE6WFhsm6',
  );
});

test('SSO_DEFAULT_RETURN_TO must be a same-origin path', () => {
  for (const bad of ['https://evil.example/', '//evil.example', 'home', '/sso/login']) {
    assert.throws(() => loadConfig({ ...BASE_ENV, SSO_DEFAULT_RETURN_TO: bad }), /SSO_DEFAULT_RETURN_TO/, bad);
  }
});

test("SSO_ALLOWED_DOMAINS='*' allows every domain, and only on its own", () => {
  assert.deepEqual(loadConfig({ ...BASE_ENV, SSO_ALLOWED_DOMAINS: ' * ' }).allowedDomains, ['*']);
  for (const bad of ['*,example.com', 'example.com, *']) {
    assert.throws(() => loadConfig({ ...BASE_ENV, SSO_ALLOWED_DOMAINS: bad }), /must be the only entry/, bad);
  }
});
