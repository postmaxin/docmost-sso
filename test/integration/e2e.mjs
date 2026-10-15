// End-to-end scenarios, run inside the compose network by ./run.sh.
// Plain fetch with manual cookie handling so every redirect and cookie is asserted.

import assert from 'node:assert/strict';
import pg from 'pg';

const BASE = process.env.BASE_URL; // http://docs:8000 (nginx standing in for the ALB)
const db = new pg.Client({ connectionString: process.env.DATABASE_URL });

const ADMIN = { email: 'admin@example.com', name: 'Admin Person', password: 'break-glass-Pa55word!' };

let failures = 0;
async function scenario(name, fn) {
  try {
    await fn();
    console.log(`ok   - ${name}`);
  } catch (err) {
    failures++;
    console.log(`FAIL - ${name}\n${err?.stack ?? err}`);
  }
}

function setCookies(res) {
  return res.headers.getSetCookie();
}
function cookieValue(res, name) {
  const c = setCookies(res).find((c) => c.startsWith(`${name}=`));
  return c ? c.split(';')[0].slice(name.length + 1) : undefined;
}
function unwrap(body) {
  return body && typeof body === 'object' && 'data' in body ? body.data : body;
}

async function waitFor(url, label, timeoutMs = 180_000) {
  const until = Date.now() + timeoutMs;
  let last;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.ok) return r;
      last = `HTTP ${r.status}`;
    } catch (e) {
      last = e.message;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${label} not ready: ${last}`);
}

async function api(path, authToken, body = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(authToken ? { cookie: `authToken=${authToken}` } : {}) },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, body: unwrap(json), res };
}

/** Drive the full browser flow through the shim and the mock IdP. */
async function ssoSignIn(claims, { redirect } = {}) {
  // 1. Shim login page (no auto-redirect).
  const loginUrl = `${BASE}/login${redirect ? `?redirect=${encodeURIComponent(redirect)}` : ''}`;
  const l0 = await fetch(loginUrl, { redirect: 'manual' });
  assert.equal(l0.status, 302, 'ALB-style /login redirect');
  const l1 = await fetch(new URL(l0.headers.get('location'), BASE), { redirect: 'manual' });
  assert.equal(l1.status, 200);
  const page = await l1.text();
  const href = /href="(\/sso\/start[^"]*)"/.exec(page)?.[1]?.replace(/&amp;/g, '&');
  assert.ok(href, 'login page has a sign-in button');

  // 2. /sso/start -> IdP, with the encrypted flow cookie.
  const s = await fetch(`${BASE}${href}`, { redirect: 'manual' });
  assert.equal(s.status, 302);
  const flow = cookieValue(s, 'docmost_sso_flow');
  assert.ok(flow, 'flow cookie set');
  const authorize = new URL(s.headers.get('location'));
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(authorize.searchParams.get('nonce'));
  assert.ok(authorize.searchParams.get('state'));
  assert.equal(authorize.searchParams.get('redirect_uri'), `${BASE}/sso/callback`);

  // 3. Mock IdP interactive login: username + claims.
  const form = new URLSearchParams({ username: claims.sub ?? claims.email, claims: JSON.stringify(claims) });
  const a = await fetch(authorize, { method: 'POST', body: form, redirect: 'manual' });
  assert.equal(a.status, 302, 'IdP redirects back');
  const callback = new URL(a.headers.get('location'));
  assert.equal(callback.origin + callback.pathname, `${BASE}/sso/callback`);

  // 4. Callback through the "ALB".
  const c = await fetch(callback, {
    redirect: 'manual',
    headers: { cookie: `docmost_sso_flow=${flow}`, 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0' },
  });
  const body = c.status === 302 ? '' : await c.text();
  return {
    status: c.status,
    location: c.headers.get('location'),
    authToken: cookieValue(c, 'authToken'),
    authCookie: setCookies(c).find((x) => x.startsWith('authToken=')),
    body,
    callback,
  };
}

async function main() {
  await waitFor(`${BASE}/api/health`, 'docmost');
  const hz = await waitFor(`${BASE}/sso/healthz`, 'shim healthz');
  const health = await hz.json();
  console.log(`shim healthz: ${JSON.stringify(health)}`);
  await db.connect();

  // Bootstrap Docmost exactly as deploy does: the setup API.
  const setup = await fetch(`${BASE}/api/auth/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...ADMIN, workspaceName: 'Example' }),
  });
  assert.ok(setup.ok, `setup: HTTP ${setup.status} ${await setup.text()}`);
  const adminRow = (await db.query('SELECT id, role FROM users WHERE email = $1', [ADMIN.email])).rows[0];
  assert.equal(adminRow.role, 'owner');

  await scenario('healthz reports the supported migration', async () => {
    assert.equal(health.status, 'ok');
    assert.equal(health.migration, '20260904T171920-public-spaces');
  });

  let adminToken;
  await scenario('(a) existing admin signs in via the shim and the cookie works on Docmost', async () => {
    const r = await ssoSignIn({ sub: 'admin-sub', email: 'Admin@Example.com', email_verified: true, name: 'Ignored Name' });
    assert.equal(r.status, 302, r.body);
    assert.equal(r.location, '/home');
    assert.ok(r.authToken);
    assert.match(r.authCookie, /; HttpOnly/);
    assert.match(r.authCookie, /; SameSite=Lax/);
    assert.match(r.authCookie, /; Path=\//);
    assert.match(r.authCookie, /; Expires=/);
    assert.doesNotMatch(r.authCookie, /; Secure/, 'APP_URL is http here, so no Secure (as Docmost)');
    adminToken = r.authToken;
    const me = await api('/api/users/me', adminToken);
    assert.equal(me.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.user.id, adminRow.id);
    assert.equal(me.body.user.email, ADMIN.email);
    assert.equal(me.body.user.role, 'owner');
    assert.equal(me.body.user.name, ADMIN.name, 'existing name is not overwritten');
    const sessions = await db.query(
      'SELECT device_name, host(ip_address) AS ip, expires_at - created_at AS ttl FROM user_sessions WHERE user_id = $1',
      [adminRow.id],
    );
    // One from /api/auth/setup, one from the shim.
    const shimSession = sessions.rows.find((s) => s.device_name === 'Firefox on Linux');
    assert.ok(shimSession, `shim session row: ${JSON.stringify(sessions.rows)}`);
    assert.equal(shimSession.ttl.days, 7);
    assert.ok(shimSession.ip, 'client IP recorded from X-Forwarded-For');
    const list = await api('/api/sessions', adminToken);
    if (list.status === 200) {
      console.log(`     Docmost session list sees ${JSON.stringify(list.body).match(/"id"/g)?.length ?? 0} session(s)`);
    }
  });

  let newToken;
  const NEW = 'new.person@example.com';
  await scenario('(b) new @example.com user is created as member in the default group', async () => {
    const r = await ssoSignIn({ sub: 'np', email: NEW, email_verified: true, name: 'New Person' }, { redirect: '/settings/account/profile' });
    assert.equal(r.status, 302, r.body);
    assert.equal(r.location, '/settings/account/profile', 'returnTo honoured');
    newToken = r.authToken;
    const me = await api('/api/users/me', newToken);
    assert.equal(me.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.user.email, NEW);
    assert.equal(me.body.user.name, 'New Person');
    assert.equal(me.body.user.role, 'member');
    const membership = await db.query(
      `SELECT g.name FROM group_users gu JOIN groups g ON g.id = gu.group_id
        JOIN users u ON u.id = gu.user_id WHERE u.email = $1 AND g.is_default`,
      [NEW],
    );
    assert.equal(membership.rowCount, 1, 'in the default group');
    const spaces = await api('/api/spaces', newToken);
    assert.equal(spaces.status, 200);
    const items = spaces.body.items ?? spaces.body;
    assert.ok(Array.isArray(items) && items.length >= 1, `sees the default space: ${JSON.stringify(spaces.body)}`);
    const pw = (await db.query('SELECT password, has_generated_password, email_verified_at FROM users WHERE email = $1', [NEW])).rows[0];
    assert.match(pw.password, /^\$2[aby]\$12\$/, 'bcrypt cost 12 unusable hash');
    assert.ok(pw.email_verified_at);
    // Password login with any guess fails (unusable password).
    const pl = await api('/api/auth/login', null, { email: NEW, password: 'password1234' });
    assert.equal(pl.status, 401);
  });

  await scenario('(b2) second sign-in reuses the user (no duplicate)', async () => {
    const r = await ssoSignIn({ sub: 'np', email: 'NEW.PERSON@example.com', email_verified: true, name: 'Renamed' });
    assert.equal(r.status, 302, r.body);
    const n = await db.query('SELECT name FROM users WHERE LOWER(email) = $1', [NEW]);
    assert.equal(n.rowCount, 1);
    assert.equal(n.rows[0].name, 'New Person');
  });

  await scenario('(c) a non-allowed domain is refused with a plain page and no user', async () => {
    const r = await ssoSignIn({ sub: 'eve', email: 'eve@gmail.com', email_verified: true });
    assert.equal(r.status, 403);
    assert.match(r.body, /Only @example\.com accounts can sign in here\./);
    assert.doesNotMatch(r.body, /at .*\.js:\d+/, 'no stack trace');
    assert.equal(r.authToken, undefined);
    const n = await db.query('SELECT 1 FROM users WHERE email = $1', ['eve@gmail.com']);
    assert.equal(n.rowCount, 0);
  });

  await scenario('(c2) an unverified @example.com email is refused', async () => {
    const r = await ssoSignIn({ sub: 'u', email: 'unverified@example.com', email_verified: false });
    assert.equal(r.status, 403);
    assert.match(r.body, /not verified/);
    assert.equal(r.authToken, undefined);
  });

  await scenario('(c3) replayed callback without the flow cookie is refused', async () => {
    const r = await ssoSignIn({ sub: 'np', email: NEW, email_verified: true });
    const replay = await fetch(r.callback, { redirect: 'manual' });
    assert.equal(replay.status, 400);
    assert.equal(cookieValue(replay, 'authToken'), undefined);
  });

  await scenario('(d) Docmost logout revokes the shim-created session', async () => {
    const before = await api('/api/users/me', newToken);
    assert.equal(before.status, 200);
    const out = await api('/api/auth/logout', newToken);
    assert.equal(out.status, 200, JSON.stringify(out.body));
    const after = await api('/api/users/me', newToken);
    assert.equal(after.status, 401, 'cookie no longer works');
    // The admin's separate session is unaffected.
    const admin = await api('/api/users/me', adminToken);
    assert.equal(admin.status, 200);
  });

  await scenario('(e) a deactivated user is refused', async () => {
    await db.query('UPDATE users SET deactivated_at = now() WHERE email = $1', [NEW]);
    const r = await ssoSignIn({ sub: 'np', email: NEW, email_verified: true });
    assert.equal(r.status, 403);
    assert.match(r.body, /deactivated/);
    assert.equal(r.authToken, undefined);
  });

  await db.end();
  if (failures) {
    console.log(`\n${failures} scenario(s) failed`);
    process.exit(1);
  }
  console.log('\nall integration scenarios passed');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
